# 本地服务签名密钥轮换验证器

在 **Windows 原生 Python 3.12 + 仅标准库 + 纯 CPU** 下实现的离线密钥轮换验证器。
所有密钥材料均为程序自行合成的测试字节（PBKDF2-HMAC-SHA256 确定性派生），
标准库 `hmac`/`hashlib` 仅用于合成运维事件的 HMAC-SHA256 签名，不接入任何外部密钥源、
不访问网络，全部输入在 `cases.json` 中自行合成、可重复重放。

---

## 1. 运行环境与命令

```
Python 3.12.x（实测 3.12.8，Windows 11，仅标准库 sqlite3/hashlib/hmac/os/json/subprocess…）
```

两条题目要求的命令，在仓库根目录（本 README 所在目录）执行：

```bash
# 1) 重放全部用例并产出结果
python -m solution --input cases.json --output result.json

# 2) 运行全部自动化测试（27 个，断言具体结果）
python -m unittest discover -s tests -v
```

可选参数 `--workdir <dir>` 指定运行数据根目录；默认落在 `<output 同级>/runs/<input 名>/`。
重新生成用例定义（`cases.json` 是构建产物，单一事实来源在 `tools/build_cases.py`）：

```bash
python tools/build_cases.py
```

---

## 2. 目录结构与职责

```
solution/
  __init__.py      包标识
  __main__.py      CLI 入口（--input/--output/--workdir）
  errors.py        稳定错误码与 ServiceError
  clock.py         确定性虚拟时钟（毫秒），旧代截止边界由它精确控制
  kdf.py           PBKDF2-HMAC-SHA256 确定性派生测试密钥；sha256/hmac 包装
  keystore.py      两个独立不可变副本的安全落盘、摘要校验、同代冗余读取、受限清理
  store.py         SQLite 元数据（WAL + BEGIN IMMEDIATE + busy_timeout），只存摘要不存密钥
  service.py       核心轮换服务：组/准备/发布/签名/验签/吊销/恢复/快照
  syncpoint.py     Windows 进程同步点（文件哨兵 arrive/gate/wait），用于真实终止
  worker.py        独立 OS 工作进程入口与进程拉起/结果读取
  orchestrator.py  可重放用例编排器、期望断言、全盘密钥泄漏扫描
tools/build_cases.py  用例单一事实来源，生成 cases.json
tests/             26 个 unittest（核心规则 / 真实进程 / 恢复泄漏 / CLI）
cases.json         12 个可重放场景（构建产物）
result.json        一次完整重放的逐步结果（随交付）
```

---

## 3. 核心规则（不变量）

### 3.1 代的唯一性与生命周期
- 一个设备组任一时刻只有**唯一活动代**（`groups_meta.active_gen`），
  另有**至多一个预发布代**（`staging`）和**有限期验签旧代**（`retired`）。
- 代生命周期：`staging → active → retired → revoked`；
  另有 `superseded`（被替换的预发布代）、`orphan`（不可恢复的孤立准备物）。
- **活动代由 SQLite 事务决定**，不由文件系统推断。
- **代数单调递增、绝不复用**：即使新旧代密钥内容相同（同 seed），也分配新代数，
  且派生密钥因代数标签不同而不同（用例 11）。
- **旧代一旦吊销永久作废**，记录保留为 `revoked`，该代数永不重新发行（用例 09）。

### 3.2 双副本不可变密钥库
- 每代密钥写入**两个独立本地不可变文件**：`keystore/groups/<组>/gen<N>.a.bin`、`.b.bin`。
- 数据库只保存**确切代数与两个副本的期望 SHA-256 摘要**，**绝不保存任何密钥字节**。
- 安全落盘顺序：独占临时文件（`O_EXCL`）→ 写全量并 `fsync` → 同目录 `os.replace` 原子替换
  → 目录 fsync（NTFS 同目录重命名为原子操作）→ **逐副本重读并校验摘要**。
- 正式副本一经落盘即为不可变：再次写同一路径直接 `E_FILE_ALREADY_EXISTS`，
  这是“同一代两写者竞争”的文件系统层防护。
- **文件先安全落盘并校验通过，才允许提交就绪标记/活动指针**；提交前发现材料缺失即失败关闭。

### 3.3 并发与事务
- 所有写事务使用 `BEGIN IMMEDIATE`，配合 WAL、`synchronous=FULL`、`busy_timeout=10s`，
  使两个以上独立工作进程的准备/发布被数据库写锁串行化。
- 准备阶段先在短事务内分配代数并登记 `prep_ledger(committed=0)`，事务外落盘，
  再在新事务内重读双副本摘要、确认可用后置 `committed=1`。
- 发布在 IMMEDIATE 事务内：校验令牌与基准 → 重读双副本摘要 → 原子移动活动指针、
  旧代转 `retired` 并写截止时间 → 删除就绪绑定，一次提交。

### 3.4 持久签名（失败关闭，不回退旧代）
- `sign` 在**同一 IMMEDIATE 事务内**：重读当前活动代 → 同代冗余读取并校验材料 →
  HMAC-SHA256 计算 → 原子插入结果与请求回执，一次提交。
- 材料不可用（两副本都缺失/损坏）→ `E_MATERIAL_UNAVAILABLE`，**不写回执、不静默回到旧代**。
- 同 `request_id` 重放同请求：幂等返回原 MAC（`replayed=true`），仍在事务内重读活动代；
  同 `request_id` 携带不同请求体：`E_REQUEST_CONFLICT`。
- 读者只用**通过摘要检查的同代冗余副本**：A 损坏可用 B；绝不跨代混用材料。

### 3.5 验签与截止
- 仅 `active` 或未截止的 `retired` 代可验签；`staging/superseded/orphan` 未授权，
  `revoked` 永久拒绝，`retired` 越过截止拒绝。
- 截止边界为**包含**：`now == deadline` 允许，`now == deadline+1ms` 拒绝（用例 08）。

### 3.6 恢复的三态区分与清理安全
`recover` 区分三类对象：
1. **已提交代**（active/retired/revoked/superseded/orphan）：保留，绝不删除授权材料。
2. **与就绪令牌绑定的阶段**（`staging` 且双副本均通过摘要校验）：保留为可发布预发布代；
   若绑定随进程终止丢失，则基于数据库代数记录与磁盘摘要补登恢复令牌（不新发代数）。
3. **未确认的孤立准备物**（staging 但材料缺失/摘要不过，或磁盘有文件而数据库无该代）：
   解除绑定、标记 `orphan` 后只清理本系统命名的文件。

清理只动**本题创建且可证明未被授权引用**的文件：
- 仅删除匹配 `gen<N>.{a,b}.bin[.pid.seq.tmp]` 命名、且位于本组目录内的文件；
- 任何外来文件（如 `OWNER_NOTES.txt`、`random-blob.bin`）原样保留（用例 10）；
- `safe_unlink` 对越出组目录或命名不符的路径直接 `E_UNSAFE_PATH` 拒绝。

### 3.7 密钥不泄漏
- 密钥字节只存在于两个 `.bin` 副本与进程内存；数据库、审计日志、回执、`result.json` 均无密钥。
- 审计写入有双保险：含 `key/material/secret/mac_key/raw` 字段直接抛错拒绝落日志。
- 编排器在每个用例结束后做**全盘泄漏扫描**：对该用例所有可能派生密钥的原始字节、
  小写/大写十六进制形式，在除两个 `.bin` 外的每个文件中搜索，出现即判失败。
- 回执只记录 `request_id/gen/event_digest/mac/时间`，MAC 是 HMAC 输出而非密钥本身。

---

## 4. 输入与输出

### 4.1 输入 `cases.json`
顶层 `{schema, description, clock_start_ms, cases:[...]}`，每个 case：

| 字段 | 含义 |
|---|---|
| `case_id` / `group_id` | 用例与设备组标识（组名限 `[A-Za-z0-9_-]{1,64}`） |
| `steps[]` | 确定性步骤序列 |

步骤类型：`create_group`、`clock_advance`、`prepare`、`publish`、`sign`、`verify`、
`revoke`、`recover`、`snapshot`、`list_files`、`plant_foreign`、`assert_file`、
`worker_spawn`（拉起独立进程）、`worker_gate`（同步点放行/`kill` 真实终止）、
`worker_result`、`corrupt_copy`（`delete/truncate/garbage`）。

步骤可带断言：`expect_error`（错误码）、`expect_fields`（字段等值，支持 `$refs.<id>`
前序引用、列表下标、`.__len__`）、`expect_true`、`expect_refs`（两步骤同名字段相等）、
`expect_valid`（验签布尔）。

### 4.2 输出 `result.json`
`{schema, input, workdir, all_passed, case_count, results:[...]}`，每个 result：
`case_id/group_id/steps[]/leak_scan`。每个 step 记录 `ok/code/result`，
含具体代数、摘要、MAC、恢复报告、错误码；`leak_scan.passed=true` 表示无密钥泄漏。

### 4.3 运行期数据布局
```
<workdir>/<case_id>/data/rotation.db(+wal/shm)
<workdir>/<case_id>/data/keystore/groups/<组>/gen<N>.{a,b}.bin 及 *.tmp
<workdir>/<case_id>/sync/<spawn>/<阶段>.arrived|.go   进程同步哨兵
```

---

## 5. 错误码表

| 错误码 | 触发条件 |
|---|---|
| `E_GROUP_UNKNOWN` / `E_GROUP_EXISTS` | 设备组不存在 / 已存在 |
| `E_MATERIAL_UNAVAILABLE` | 两副本均缺失或损坏；提交前材料不可用（**失败关闭**） |
| `E_DIGEST_MISMATCH` | 副本重读摘要与数据库期望不符（损坏/篡改） |
| `E_FILE_ALREADY_EXISTS` | 不可变目标文件已存在（同代写者文件系统层冲突） |
| `E_STAGING_EXISTS` | 已有预发布代且未带 `replace` |
| `E_TOKEN_SUPERSEDED` | 预发布令牌已被替换准备作废，不得发布 |
| `E_TOKEN_UNKNOWN` | 未知预发布令牌 |
| `E_GEN_NOT_STAGING` | 目标代不在可发布/可验签状态，或代数未知 |
| `E_BASELINE_STALE` | 发布携带的基准活动代与当前不一致（已被他人替换） |
| `E_OLD_GEN_EXPIRED` | 旧代验签越过截止时间 |
| `E_REVOKED_GEN` | 旧代已吊销，永久拒绝 |
| `E_REQUEST_CONFLICT` | 同一 request_id 绑定了不同请求体 |
| `E_UNSAFE_PATH` | 组名非法/路径穿越/拒绝删除非本系统文件 |
| `E_SYNC_TIMEOUT` | 等待进程同步点超时 |
| `E_WORKER_KILLED` | 独立工作进程在响应前被真实终止（无结果输出） |
| `E_WORKER_CRASH` | 独立工作进程发生未预期异常 |
| `E_RUNNER` | 编排器内部未预期异常 |

---

## 6. 真实终止与竞争场景（Windows 进程同步点）

通过 `subprocess` 拉起第二个 OS 进程执行 `solution.worker`，用文件哨兵在精确阶段握手，
编排方调用 `proc.terminate()` 制造**真实进程终止**（不是模拟异常）：

| 用例 | 注入点 / 竞争 | 断言的安全结果 |
|---|---|---|
| 02 | 第一副本写一半终止（`prepare.mid_first_write`） | 仅残留 `.tmp`，恢复清理；代 1 标 orphan，重试发代 2 |
| 03 | 两副本落盘、指针未提交终止（`after_both_written`） | 恢复保留可发布 staging，补登令牌后正常发代 1 并签名 |
| 04 | 指针已提交、未响应终止（`publish.after_commit`） | 活动代已落库；重试幂等重放（`replayed=true`），不发新代 |
| 05 | 同代两写者并发准备 | IMMEDIATE 串行化，后者 `E_STAGING_EXISTS`；仅一个 staging |
| 06 | 预发布完成后基准被另一进程替换 | 旧令牌 `E_TOKEN_SUPERSEDED`，新基准成功，签名只走授权代 3 |
| 07 | 活动代单副本损坏→双副本损坏 | 单损时 B 副本继续服务；双损 `E_MATERIAL_UNAVAILABLE` 不回退旧代 |
| 08 | 旧代截止边界 | `now==deadline` 验签通过，`+1ms` 报 `E_OLD_GEN_EXPIRED` |

另在 `tests/test_process.py` 中以无同步点方式并发发布同一令牌，验证两进程均解析到
唯一活动代、恰一为幂等重放、`next_gen` 不增长（不会签出未授权代次、不返回混合材料）。

---

## 7. 实测结果

### 7.1 自动化测试（`python -m unittest discover -s tests -v`）
实测 **27 个测试全部 OK**（Windows 11 / Python 3.12.8），分布：

- `tests/test_core.py`：12 个，轮换主路径、代数单调、staging 冲突/替换、基准过期、
  单/双副本损坏、截止边界、吊销不复用、签名幂等/冲突、不可变覆盖、摘要不符、库内无密钥、
  双副本一致与跨代不混合。
- `tests/test_process.py`：7 个，三类真实终止、同代并发准备、并发发布唯一活动代、
  外来文件保护、双损恢复后仍失败关闭。
- `tests/test_recovery.py`：5 个，恢复三态分类、无库记录孤儿清理、库/日志/回执无泄漏、
  审计拒写敏感字段、用例逐步具体结果。
- `tests/test_cli.py`：3 个，CLI 端到端、worker 子进程可独立启动、cases.json 自洽确定性。

并发竞争用例连续重复 5 次均 OK，无 flaky。

### 7.2 用例重放（`python -m solution --input cases.json --output result.json`）
实测 `all_passed=true`，12 个用例全部通过且每个 `leak_scan.passed=true`。逐用例结果：

| case_id | 步骤数 | 预期错误码（其余步骤成功） | 泄漏扫描 |
|---|---:|---|---|
| 01_happy_rotation | 12 | — | 通过 |
| 02_kill_half_written_file | 9 | `E_WORKER_KILLED` | 通过 |
| 03_kill_after_both_written | 9 | `E_WORKER_KILLED` | 通过 |
| 04_kill_after_commit | 8 | `E_WORKER_KILLED` | 通过 |
| 05_same_gen_two_writers | 7 | `E_STAGING_EXISTS`, `E_TOKEN_SUPERSEDED` | 通过 |
| 06_staging_baseline_replaced | 8 | `E_TOKEN_SUPERSEDED` | 通过 |
| 07_single_copy_corruption | 12 | `E_MATERIAL_UNAVAILABLE` | 通过 |
| 08_old_gen_deadline_boundary | 10 | `E_OLD_GEN_EXPIRED` | 通过 |
| 09_revoked_never_reissued | 10 | `E_REVOKED_GEN` | 通过 |
| 10_recover_safety_foreign_files | 11 | — | 通过 |
| 11_same_material_distinct_generation | 8 | — | 通过 |
| 12_sign_idempotency | 7 | `E_REQUEST_CONFLICT` | 通过 |

跨两次独立运行比对：代数、状态、错误码、SHA-256 摘要、HMAC MAC、恢复分类等**语义结果
完全一致**；唯一差异是临时文件名内嵌的 PID 与运行目录绝对路径（多进程固有，不影响语义），
证明离线可重放、结果确定。
