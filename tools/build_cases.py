# -*- coding: utf-8 -*-
"""构建可重放用例 cases.json（单一事实来源）。

运行：``python tools/build_cases.py`` 会在仓库根生成 ``cases.json``。
自动化测试与 CLI 使用同一份用例定义，保证离线可重放。
所有输入（seed、event）均为本题自行合成的测试数据。
"""

import json
import os

CLOCK_T = 1_700_000_000_000

# 同步点阶段名
MID_FIRST = "prepare.mid_first_write"
AFTER_BOTH = "prepare.after_both_written"
PUB_BEFORE = "publish.before_commit"
PUB_AFTER = "publish.after_commit"


def build_cases():
    cases = []

    # 01 主路径：准备 -> 发布 -> 签名 -> 轮换 -> 旧代验签 -> 冗余读取
    cases.append({
        "case_id": "01_happy_rotation",
        "group_id": "grp_happy",
        "steps": [
            {"id": "g", "type": "create_group"},
            {"id": "p1", "type": "prepare", "seed": "seed-happy",
             "expect_fields": {"gen": 1, "committed": True}},
            {"id": "pub1", "type": "publish", "token": "$refs.p1",
             "expected_active_gen": None, "old_valid_ms": 10_000,
             "expect_fields": {"gen": 1, "replayed": False}},
            {"id": "s1", "type": "sign", "request_id": "req-1", "event": "ops:event-a",
             "expect_fields": {"gen": 1, "replayed": False}},
            {"id": "v1", "type": "verify", "gen": 1, "mac": "$refs.s1",
             "event": "ops:event-a", "expect_valid": True},
            {"id": "p2", "type": "prepare", "seed": "seed-happy-2",
             "expect_fields": {"gen": 2}},
            {"id": "pub2", "type": "publish", "token": "$refs.p2",
             "expected_active_gen": 1, "old_valid_ms": 10_000,
             "expect_fields": {"gen": 2, "old_gen": 1}},
            {"id": "s2", "type": "sign", "request_id": "req-2", "event": "ops:event-b",
             "expect_fields": {"gen": 2}},
            {"id": "v_old_ok", "type": "verify", "gen": 1, "mac": "$refs.s1",
             "event": "ops:event-a", "expect_valid": True},
            {"id": "v_other_ev", "type": "verify", "gen": 1, "mac": "$refs.s2",
             "event": "ops:event-b", "expect_valid": False},
            {"id": "snap", "type": "snapshot",
             "expect_fields": {"active_gen": 2, "old_gen": 1}},
            {"id": "files", "type": "list_files",
             "expect_true": {"files": True}},
        ],
    })

    # 02 真实终止：第一个副本写一半被杀 -> 临时文件残留，恢复清理，原代数作废不复用
    cases.append({
        "case_id": "02_kill_half_written_file",
        "group_id": "grp_half",
        "steps": [
            {"id": "g", "type": "create_group"},
            {"id": "w", "type": "worker_spawn", "proc": "worker1",
             "op": "prepare", "seed": "seed-half", "hook": MID_FIRST},
            {"id": "kill", "type": "worker_gate", "proc": "worker1",
             "spawn_step": "w", "hook": MID_FIRST, "action": "kill"},
            {"id": "wr", "type": "worker_result", "proc": "worker1",
             "expect_error": "E_WORKER_KILLED"},
            {"id": "files1", "type": "list_files"},
            {"id": "rec", "type": "recover",
             "expect_true": {"tmp_files_removed": True}},
            {"id": "snap", "type": "snapshot"},
            {"id": "p2", "type": "prepare", "seed": "seed-half-retry",
             "expect_fields": {"gen": 2}},
            {"id": "files2", "type": "list_files",
             "expect_true": {"files": True}},
        ],
    })

    # 03 真实终止：两副本落盘但指针未提交 -> 恢复保留可发布预发布代
    cases.append({
        "case_id": "03_kill_after_both_written",
        "group_id": "grp_both",
        "steps": [
            {"id": "g", "type": "create_group"},
            {"id": "w", "type": "worker_spawn", "proc": "worker1",
             "op": "prepare", "seed": "seed-both", "hook": AFTER_BOTH},
            {"id": "kill", "type": "worker_gate", "proc": "worker1",
             "spawn_step": "w", "hook": AFTER_BOTH, "action": "kill"},
            {"id": "wr", "type": "worker_result", "proc": "worker1",
             "expect_error": "E_WORKER_KILLED"},
            {"id": "rec", "type": "recover",
             "expect_true": {"staging_pending": True},
             "expect_fields": {"orphan_files_removed.__len__": 0}},
            {"id": "snap", "type": "snapshot"},
            {"id": "files", "type": "list_files",
             "expect_true": {"files": True}},
            {"id": "pub", "type": "publish",
             "token_path": "rec.result.staging_pending.0.token",
             "expected_active_gen": None, "old_valid_ms": 0,
             "expect_fields": {"gen": 1, "replayed": False}},
            {"id": "s", "type": "sign", "request_id": "req-both",
             "event": "ops:both", "expect_fields": {"gen": 1}},
        ],
    })

    # 04 真实终止：指针已提交未响应 -> 重试幂等重放，不重复发代
    cases.append({
        "case_id": "04_kill_after_commit",
        "group_id": "grp_commit",
        "steps": [
            {"id": "g", "type": "create_group"},
            {"id": "p", "type": "prepare", "seed": "seed-commit",
             "expect_fields": {"gen": 1}},
            {"id": "w", "type": "worker_spawn", "proc": "worker1",
             "op": "publish", "token": "$refs.p",
             "expected_active_gen": None, "old_valid_ms": 0, "hook": PUB_AFTER},
            {"id": "kill", "type": "worker_gate", "proc": "worker1",
             "spawn_step": "w", "hook": PUB_AFTER, "action": "kill"},
            {"id": "wr", "type": "worker_result", "proc": "worker1",
             "expect_error": "E_WORKER_KILLED"},
            {"id": "snap1", "type": "snapshot",
             "expect_fields": {"active_gen": 1}},
            {"id": "retry", "type": "publish", "token": "$refs.p",
             "expected_active_gen": None, "old_valid_ms": 0,
             "expect_fields": {"gen": 1, "replayed": True}},
            {"id": "s", "type": "sign", "request_id": "req-c1",
             "event": "ops:commit", "expect_fields": {"gen": 1}},
        ],
    })

    # 05 同一代两写者竞争：文件系统层不可变保护 + 数据库唯一性
    cases.append({
        "case_id": "05_same_gen_two_writers",
        "group_id": "grp_race",
        "steps": [
            {"id": "g", "type": "create_group"},
            {"id": "p1", "type": "prepare", "seed": "seed-race-1",
             "expect_fields": {"gen": 1}},
            {"id": "p2", "type": "prepare", "seed": "seed-race-2",
             "expect_error": "E_STAGING_EXISTS"},
            {"id": "p3", "type": "prepare", "seed": "seed-race-3",
             "replace": True, "expect_fields": {"gen": 2}},
            {"id": "snap", "type": "snapshot"},
            {"id": "pub_orphan", "type": "publish", "token": "$refs.p1",
             "expected_active_gen": None, "old_valid_ms": 0,
             "expect_error": "E_TOKEN_SUPERSEDED"},
            {"id": "pub2", "type": "publish", "token": "$refs.p3",
             "expected_active_gen": None, "old_valid_ms": 0,
             "expect_fields": {"gen": 2}},
        ],
    })

    # 06 预发布完成后基准被另一进程替换：旧令牌发布被拒，新基准成功
    cases.append({
        "case_id": "06_staging_baseline_replaced",
        "group_id": "grp_base",
        "steps": [
            {"id": "g", "type": "create_group"},
            {"id": "p1", "type": "prepare", "seed": "seed-base-1",
             "expect_fields": {"gen": 1}},
            {"id": "pub1", "type": "publish", "token": "$refs.p1",
             "expected_active_gen": None, "old_valid_ms": 0,
             "expect_fields": {"gen": 1}},
            {"id": "p2", "type": "prepare", "seed": "seed-base-2",
             "expect_fields": {"gen": 2}},
            {"id": "p3", "type": "prepare", "seed": "seed-base-3",
             "replace": True, "expect_fields": {"gen": 3}},
            {"id": "pub_stale", "type": "publish", "token": "$refs.p2",
             "expected_active_gen": 1, "old_valid_ms": 0,
             "expect_error": "E_TOKEN_SUPERSEDED"},
            {"id": "pub3", "type": "publish", "token": "$refs.p3",
             "expected_active_gen": 1, "old_valid_ms": 5_000,
             "expect_fields": {"gen": 3, "old_gen": 1}},
            {"id": "s", "type": "sign", "request_id": "req-base",
             "event": "ops:base", "expect_fields": {"gen": 3}},
        ],
    })

    # 07 单副本损坏：另一副本仍可服务；双副本损坏失败关闭，不回退旧代
    cases.append({
        "case_id": "07_single_copy_corruption",
        "group_id": "grp_corrupt",
        "steps": [
            {"id": "g", "type": "create_group"},
            {"id": "p1", "type": "prepare", "seed": "seed-corr-1",
             "expect_fields": {"gen": 1}},
            {"id": "pub1", "type": "publish", "token": "$refs.p1",
             "expected_active_gen": None, "old_valid_ms": 0,
             "expect_fields": {"gen": 1}},
            {"id": "s1", "type": "sign", "request_id": "req-corr-1",
             "event": "ops:corr", "expect_fields": {"gen": 1}},
            {"id": "p2", "type": "prepare", "seed": "seed-corr-2",
             "expect_fields": {"gen": 2}},
            {"id": "pub2", "type": "publish", "token": "$refs.p2",
             "expected_active_gen": 1, "old_valid_ms": 100_000,
             "expect_fields": {"gen": 2, "old_gen": 1}},
            # 活动代代 2 的 A 副本损坏：B 副本经摘要检查后继续服务
            {"id": "bad_a", "type": "corrupt_copy", "gen": 2, "slot": "a",
             "mode": "garbage"},
            {"id": "s2", "type": "sign", "request_id": "req-corr-2",
             "event": "ops:corr2", "expect_fields": {"gen": 2}},
            {"id": "bad_b", "type": "corrupt_copy", "gen": 2, "slot": "b",
             "mode": "delete"},
            {"id": "s3_fail", "type": "sign", "request_id": "req-corr-3",
             "event": "ops:corr3", "expect_error": "E_MATERIAL_UNAVAILABLE"},
            # 不得静默回到旧代：旧代材料虽完好，签名仍必须失败
            {"id": "v_old", "type": "verify", "gen": 1, "mac": "$refs.s1",
             "event": "ops:corr", "expect_valid": True},
            {"id": "snap", "type": "snapshot",
             "expect_fields": {"active_gen": 2}},
        ],
    })

    # 08 恰到旧代截止：截止时刻仍可验签，越过一毫秒即拒绝
    cases.append({
        "case_id": "08_old_gen_deadline_boundary",
        "group_id": "grp_deadline",
        "steps": [
            {"id": "g", "type": "create_group"},
            {"id": "p1", "type": "prepare", "seed": "seed-dl-1",
             "expect_fields": {"gen": 1}},
            {"id": "pub1", "type": "publish", "token": "$refs.p1",
             "expected_active_gen": None, "old_valid_ms": 0,
             "expect_fields": {"gen": 1}},
            {"id": "s1", "type": "sign", "request_id": "req-dl-1",
             "event": "ops:dl", "expect_fields": {"gen": 1}},
            {"id": "p2", "type": "prepare", "seed": "seed-dl-2",
             "expect_fields": {"gen": 2}},
            {"id": "pub2", "type": "publish", "token": "$refs.p2",
             "expected_active_gen": 1, "old_valid_ms": 1_000,
             "expect_fields": {"gen": 2, "old_deadline_ms": CLOCK_T + 1_000}},
            # now == deadline：边界包含，允许
            {"id": "adv_eq", "type": "clock_advance", "delta_ms": 1_000},
            {"id": "v_eq", "type": "verify", "gen": 1, "mac": "$refs.s1",
             "event": "ops:dl", "expect_valid": True},
            # now = deadline + 1：拒绝
            {"id": "adv_over", "type": "clock_advance", "delta_ms": 1},
            {"id": "v_over", "type": "verify", "gen": 1, "mac": "$refs.s1",
             "event": "ops:dl", "expect_error": "E_OLD_GEN_EXPIRED"},
        ],
    })

    # 09 吊销不可重新发行：代数单调，吊销代验签永久拒绝
    cases.append({
        "case_id": "09_revoked_never_reissued",
        "group_id": "grp_revoke",
        "steps": [
            {"id": "g", "type": "create_group"},
            {"id": "p1", "type": "prepare", "seed": "seed-rv-1",
             "expect_fields": {"gen": 1}},
            {"id": "pub1", "type": "publish", "token": "$refs.p1",
             "expected_active_gen": None, "old_valid_ms": 0,
             "expect_fields": {"gen": 1}},
            {"id": "s1", "type": "sign", "request_id": "req-rv",
             "event": "ops:rv", "expect_fields": {"gen": 1}},
            {"id": "p2", "type": "prepare", "seed": "seed-rv-2",
             "expect_fields": {"gen": 2}},
            {"id": "pub2", "type": "publish", "token": "$refs.p2",
             "expected_active_gen": 1, "old_valid_ms": 10_000,
             "expect_fields": {"gen": 2}},
            {"id": "rev", "type": "revoke", "gen": 1,
             "expect_fields": {"status": "revoked"}},
            {"id": "v_rev", "type": "verify", "gen": 1, "mac": "$refs.s1",
             "event": "ops:rv", "expect_error": "E_REVOKED_GEN"},
            {"id": "p3", "type": "prepare", "seed": "seed-rv-3",
             "expect_fields": {"gen": 3}},
            {"id": "snap", "type": "snapshot"},
        ],
    })

    # 10 清理安全：外来文件绝不被恢复逻辑触碰；本系统 tmp/孤儿才会被清理
    cases.append({
        "case_id": "10_recover_safety_foreign_files",
        "group_id": "grp_safe",
        "steps": [
            {"id": "g", "type": "create_group"},
            {"id": "p1", "type": "prepare", "seed": "seed-safe",
             "expect_fields": {"gen": 1}},
            {"id": "pub1", "type": "publish", "token": "$refs.p1",
             "expected_active_gen": None, "old_valid_ms": 0,
             "expect_fields": {"gen": 1}},
            {"id": "plant", "type": "plant_foreign",
             "name": "READ_NOTES.txt", "content": "not owned by key rotation"},
            {"id": "plant_bin", "type": "plant_foreign",
             "name": "random-blob.bin", "content": "random"},
            {"id": "rec", "type": "recover",
             "expect_fields": {"orphan_files_removed.__len__": 0,
                               "tmp_files_removed.__len__": 0}},
            {"id": "keep1", "type": "assert_file",
             "name": "READ_NOTES.txt", "exists": True},
            {"id": "keep2", "type": "assert_file",
             "name": "random-blob.bin", "exists": True},
            {"id": "keep3", "type": "assert_file",
             "name": "gen1.a.bin", "exists": True},
            {"id": "keep4", "type": "assert_file",
             "name": "gen1.b.bin", "exists": True},
            {"id": "snap", "type": "snapshot",
             "expect_fields": {"active_gen": 1}},
        ],
    })

    # 11 同内容不同代数：相同种子生成不同代密钥，代数绝不复用
    cases.append({
        "case_id": "11_same_material_distinct_generation",
        "group_id": "grp_same",
        "steps": [
            {"id": "g", "type": "create_group"},
            {"id": "p1", "type": "prepare", "seed": "seed-same",
             "expect_fields": {"gen": 1}},
            {"id": "pub1", "type": "publish", "token": "$refs.p1",
             "expected_active_gen": None, "old_valid_ms": 0,
             "expect_fields": {"gen": 1}},
            {"id": "s1", "type": "sign", "request_id": "req-same-1",
             "event": "ops:same", "expect_fields": {"gen": 1}},
            {"id": "p2", "type": "prepare", "seed": "seed-same",
             "expect_fields": {"gen": 2}},
            {"id": "pub2", "type": "publish", "token": "$refs.p2",
             "expected_active_gen": 1, "old_valid_ms": 10_000,
             "expect_fields": {"gen": 2}},
            {"id": "s2", "type": "sign", "request_id": "req-same-2",
             "event": "ops:same", "expect_fields": {"gen": 2}},
            {"id": "snap", "type": "snapshot"},
        ],
    })

    # 12 签名幂等与冲突：同 request_id 重放同请求；冲突请求体被拒
    cases.append({
        "case_id": "12_sign_idempotency",
        "group_id": "grp_idem",
        "steps": [
            {"id": "g", "type": "create_group"},
            {"id": "p1", "type": "prepare", "seed": "seed-idem",
             "expect_fields": {"gen": 1}},
            {"id": "pub1", "type": "publish", "token": "$refs.p1",
             "expected_active_gen": None, "old_valid_ms": 0,
             "expect_fields": {"gen": 1}},
            {"id": "s1", "type": "sign", "request_id": "req-idem",
             "event": "ops:idem", "expect_fields": {"replayed": False}},
            {"id": "s1b", "type": "sign", "request_id": "req-idem",
             "event": "ops:idem",
             "expect_fields": {"replayed": True},
             "expect_refs": {"mac": "$refs.s1"}},
            {"id": "s1c", "type": "sign", "request_id": "req-idem",
             "event": "ops:different", "expect_error": "E_REQUEST_CONFLICT"},
            {"id": "snap", "type": "snapshot"},
        ],
    })

    return cases


def main():
    cases = build_cases()
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    out = os.path.join(root, "cases.json")
    with open(out, "w", encoding="utf-8") as fh:
        json.dump(
            {
                "schema": "key-rotation-cases/v1",
                "description": "本地服务签名密钥轮换验证器可重放用例（全部输入为合成测试数据）",
                "clock_start_ms": CLOCK_T,
                "cases": cases,
            },
            fh, ensure_ascii=False, indent=2,
        )
    print("wrote %s (%d cases)" % (out, len(cases)))


if __name__ == "__main__":
    main()
