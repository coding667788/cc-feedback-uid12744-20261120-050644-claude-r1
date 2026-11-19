# -*- coding: utf-8 -*-
"""可重放用例编排器。

``cases.json`` 中每个 case 是一串确定性步骤；编排器持有虚拟时钟与服务实例，
既可跑进程内步骤，也可通过 :mod:`solution.worker` 拉起独立工作进程，
用文件同步点制造真实终止与竞争。

每一步可带：
- ``expect_error``：断言该步必须返回指定错误码；
- ``expect_fields``：断言结果 JSON 包含指定键值（支持 "$refs.<id>.<path>" 引用前序结果）；
- ``expect_true``：对结果取布尔字段断言。

case 结束后对整个运行目录做**密钥泄漏扫描**：任何派生密钥的原始字节或其十六进制
形式都不得出现在数据库、审计日志、回执 JSON 或任何落盘元数据中。
"""

import json
import os
import shutil

from .clock import VirtualClock
from .errors import ServiceError
from .keystore import copy_paths, group_dir
from .kdf import derive_key
from .service import KeyRotationService
from .syncpoint import SyncPoint
from .worker import read_worker_result, spawn_worker

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


class CaseFailure(AssertionError):
    pass


def _resolve(value, refs):
    if isinstance(value, str) and value.startswith("$refs."):
        cur = refs
        for part in value[len("$refs."):].split("."):
            cur = cur[part]
        return cur
    return value


def _digest_field(obj, dotted):
    """按 a.b.c 路径取值，返回 (父节点处的值, 最后一段键名)；纯数字段按下标处理。"""
    parts = dotted.split(".")
    cur = obj
    for part in parts[:-1]:
        cur = cur[int(part)] if part.isdigit() else cur[part]
    return cur, parts[-1]


def _field_value(result, dotted, refs):
    """支持普通路径、列表下标与操作符 ``x.__ref__``。

    ``x.__ref__`` 表示：取本结果中字段 x 的值（形如 ``$refs.<id>``），
    再到前序记录 <id> 中读取同名字段 x，用于断言两个步骤产出的字段相等。
    """
    if dotted.endswith(".__len__"):
        target = dotted[: -len(".__len__")]
        parent, leaf = _digest_field(result, target)
        return len(parent[leaf])
    if dotted.endswith(".__ref__"):
        target_path = dotted[: -len(".__ref__")]
        parent, leaf = _digest_field(result, target_path)
        ref_record = _resolve(parent[leaf], refs)
        return _field_value(ref_record["result"], target_path, refs)
    parent, leaf = _digest_field(result, dotted)
    return parent[int(leaf)] if leaf.isdigit() else parent[leaf]


def _walk_files(path):
    for base, _dirs, names in os.walk(path):
        for name in names:
            yield os.path.join(base, name)


def scan_key_leak(root, group_id, seeds):
    """扫描运行目录，断言任何密钥字节/十六进制都未泄漏到元数据中。

    返回发现的泄漏列表（空列表表示通过）。
    """
    leaks = []
    needles = []
    for seed in seeds:
        # 扫描覆盖该 case 中所有可能派生的代数（1..32 足够覆盖测试场景）
        for gen in range(1, 33):
            key = derive_key(seed, group_id, gen)
            needles.append((gen, "raw", key))
            needles.append((gen, "hex", key.hex().encode("ascii")))
            needles.append((gen, "HEX", key.hex().upper().encode("ascii")))

    for path in _walk_files(root):
        # 两个正式密钥副本是本题授权持有密钥字节的文件，跳过
        norm = path.replace("\\", "/")
        if norm.endswith(".a.bin") or norm.endswith(".b.bin"):
            continue
        try:
            with open(path, "rb") as fh:
                blob = fh.read()
        except OSError:
            continue
        for gen, kind, needle in needles:
            if needle and needle in blob:
                leaks.append({"file": path, "gen": gen, "form": kind})
    return leaks


class Runner:
    def __init__(self, work_root, sync_root):
        self.work_root = os.path.abspath(work_root)
        self.sync_root = os.path.abspath(sync_root)
        os.makedirs(self.work_root, exist_ok=True)
        os.makedirs(self.sync_root, exist_ok=True)
        self.clock = VirtualClock()
        self.svc = KeyRotationService(self.work_root)
        self.refs = {}
        self.procs = {}
        self.events = []

    # ------------------------------------------------------------------
    def _record(self, step_id, record):
        self.refs[step_id] = record
        self.events.append({"step": step_id, **record})

    def _expect(self, step, record):
        step_id = step["id"]
        if "expect_error" in step:
            if record.get("ok") or record.get("code") != step["expect_error"]:
                raise CaseFailure(
                    "step %s expected error %s, got %s"
                    % (step_id, step["expect_error"], record)
                )
            return
        if not record.get("ok", False):
            raise CaseFailure("step %s unexpectedly failed: %s" % (step_id, record))
        result = record.get("result", {})
        for key, want in step.get("expect_fields", {}).items():
            want = _resolve(want, self.refs)
            got = _field_value(result, key, self.refs)
            if got != want:
                raise CaseFailure(
                    "step %s field %s expected %r got %r"
                    % (step_id, key, want, got)
                )
        for key, want in step.get("expect_true", {}).items():
            got = _field_value(result, key, self.refs)
            if bool(got) != bool(want):
                raise CaseFailure(
                    "step %s field %s expected truth=%s got %r"
                    % (step_id, key, want, got)
                )
        # expect_refs: {"本步字段": "$refs.<前序步骤id>"} 断言两者同名字段相等
        for key, ref in step.get("expect_refs", {}).items():
            other = _resolve(ref, self.refs)["result"]
            if _field_value(result, key, self.refs) != _field_value(other, key, self.refs):
                raise CaseFailure(
                    "step %s field %s differs from %s" % (step_id, key, ref)
                )

    # ------------------------------------------------------------------
    def run(self, case):
        group_id = case["group_id"]
        seeds = set()
        for step in case["steps"]:
            sid = step["id"]
            try:
                record = self._run_step(step, group_id, seeds)
            except CaseFailure:
                raise
            except ServiceError as exc:
                record = {"ok": False, "code": exc.code, "message": str(exc),
                          "details": exc.details}
            except Exception as exc:  # noqa: BLE001
                record = {"ok": False, "code": "E_RUNNER", "message": repr(exc)}
            self._record(sid, record)
            self._expect(step, record)

        leaks = scan_key_leak(self.work_root, group_id, sorted(seeds))
        return {
            "case_id": case["case_id"],
            "group_id": group_id,
            "steps": self.events,
            "leak_scan": {"leaks": leaks, "passed": not leaks},
        }

    # ------------------------------------------------------------------
    def _run_step(self, step, group_id, seeds):
        t = step["type"]
        now = self.clock.now_ms()

        if t == "create_group":
            return {"ok": True, "result": self.svc.create_group(group_id, now)}

        if t == "clock_advance":
            return {"ok": True, "result": {"now_ms": self.clock.advance(step["delta_ms"])}}

        if t == "prepare":
            seed = step["seed"]
            seeds.add(seed)
            return {
                "ok": True,
                "result": self.svc.prepare(
                    group_id, seed, now, replace=step.get("replace", False)
                ),
            }

        if t == "publish":
            token = self._resolve_token(step)
            return {
                "ok": True,
                "result": self.svc.publish(
                    group_id, token, step.get("expected_active_gen"),
                    int(step.get("old_valid_ms", 0)), now,
                ),
            }

        if t == "sign":
            event = step.get("event", "ops:event").encode("utf-8")
            return {
                "ok": True,
                "result": self.svc.sign(group_id, step["request_id"], event, now),
            }

        if t == "verify":
            event = step.get("event", "ops:event").encode("utf-8")
            mac = _resolve(step["mac"], self.refs)["result"]["mac"]
            result = self.svc.verify(group_id, step["gen"], event, mac, now)
            if "expect_valid" in step:
                if result["valid"] != step["expect_valid"]:
                    raise CaseFailure(
                        "step %s verify valid expected %s got %s"
                        % (step["id"], step["expect_valid"], result["valid"])
                    )
            return {"ok": True, "result": result}

        if t == "revoke":
            return {"ok": True, "result": self.svc.revoke(group_id, step["gen"], now)}

        if t == "recover":
            return {"ok": True, "result": self.svc.recover(group_id)}

        if t == "snapshot":
            return {"ok": True, "result": self.svc.snapshot(group_id)}

        if t == "worker_spawn":
            return self._worker_spawn(step, group_id, seeds, now)

        if t == "worker_gate":
            return self._worker_gate(step)

        if t == "worker_result":
            proc = self.procs.pop(step["proc"])
            record = read_worker_result(proc)
            os.remove(self.proc_jobs.pop(step["proc"]))
            return record

        if t == "corrupt_copy":
            return self._corrupt_copy(step, group_id)

        if t == "list_files":
            gdir = group_dir(self.svc.key_root, group_id)
            names = sorted(os.listdir(gdir)) if os.path.isdir(gdir) else []
            return {"ok": True, "result": {"files": names}}

        if t == "plant_foreign":
            # 在组目录放置本题之外的外来文件，恢复逻辑必须原样保留
            gdir = group_dir(self.svc.key_root, group_id, create=True)
            path = os.path.join(gdir, step["name"])
            payload = step.get("content", "foreign").encode("utf-8")
            with open(path, "wb") as fh:
                fh.write(payload)
            return {"ok": True, "result": {"path": path, "size": len(payload)}}

        if t == "assert_file":
            gdir = group_dir(self.svc.key_root, group_id)
            path = os.path.join(gdir, step["name"])
            exists = os.path.exists(path)
            if exists != bool(step.get("exists", True)):
                raise CaseFailure(
                    "step %s file %s exists=%s expected %s"
                    % (step["id"], step["name"], exists, step.get("exists", True))
                )
            return {"ok": True, "result": {"name": step["name"], "exists": exists}}

        raise CaseFailure("unknown step type: %s" % t)

    def _resolve_token(self, step):
        """支持 prepare 结果令牌或 recover 报告 staging_pending[0].token。"""
        if "token_path" in step:
            return _field_value(self.refs, step["token_path"], self.refs)
        return _resolve(step["token"], self.refs)["result"]["token"]

    # ------------------------------------------------------------------
    def _worker_spawn(self, step, group_id, seeds, now):
        sync_dir = os.path.join(self.sync_root, step["id"])
        os.makedirs(sync_dir, exist_ok=True)
        job = {
            "root": self.work_root,
            "sync_dir": sync_dir,
            "op": step["op"],
            "group_id": group_id,
            "now_ms": now,
            "hook": step.get("hook"),
        }
        if step["op"] == "prepare":
            job["seed"] = step["seed"]
            seeds.add(step["seed"])
            job["replace"] = step.get("replace", False)
        else:
            token_ref = step["token"]
            job["token"] = _resolve(token_ref, self.refs)["result"]["token"]
            job["expected_active_gen"] = step.get("expected_active_gen")
            job["old_valid_ms"] = int(step.get("old_valid_ms", 0))
        proc, job_path = spawn_worker(job, _REPO_ROOT)
        self.procs[step["proc"]] = proc
        self.proc_jobs = getattr(self, "proc_jobs", {})
        self.proc_jobs[step["proc"]] = job_path
        return {"ok": True, "result": {"proc": step["proc"], "pid": proc.pid}}

    def _worker_gate(self, step):
        proc = self.procs[step["proc"]]
        sp = SyncPoint(os.path.join(self.sync_root, step["spawn_step"]))
        action = step.get("action", "go")
        sp.gate(step["hook"], proc=proc, action=action)
        return {"ok": True, "result": {"action": action, "hook": step["hook"]}}

    def _corrupt_copy(self, step, group_id):
        gen = step["gen"]
        slot = step["slot"]
        path = copy_paths(self.svc.key_root, group_id, gen)[slot]
        mode = step["mode"]
        if mode == "delete":
            os.remove(path)
        elif mode == "truncate":
            with open(path, "r+b") as fh:
                fh.truncate(4)
        elif mode == "garbage":
            with open(path, "r+b") as fh:
                fh.seek(0)
                fh.write(b"\x00" * min(8, fh.seek(0, os.SEEK_END)))
        else:
            raise CaseFailure("unknown corrupt mode: %s" % mode)
        return {"ok": True, "result": {"path": path, "mode": mode}}


def run_cases(cases, base_dir):
    """在 base_dir 下为每个 case 建独立目录并顺序执行，返回汇总结果。"""
    results = []
    for case in cases:
        work_root = os.path.join(base_dir, case["case_id"], "data")
        sync_root = os.path.join(base_dir, case["case_id"], "sync")
        shutil.rmtree(os.path.join(base_dir, case["case_id"]), ignore_errors=True)
        runner = Runner(work_root, sync_root)
        results.append(runner.run(case))
    return {"case_count": len(results), "results": results}
