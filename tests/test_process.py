# -*- coding: utf-8 -*-
"""真实独立工作进程测试：同步点终止、同代竞争、跨进程并发发布。

这些测试通过 ``subprocess`` 拉起第二个 OS 进程（``solution.worker``），
在精确阶段用 ``terminate()`` 制造真实终止，再由主进程恢复/重试，
覆盖“写一半文件 / 两副本落盘指针未提交 / 指针已提交未响应”三类崩溃。
"""

import os

from solution import keystore
from solution.errors import E_MATERIAL_UNAVAILABLE, E_UNSAFE_PATH, ServiceError
from solution.syncpoint import SyncPoint
from solution.worker import read_worker_result, spawn_worker
from tests._base import REPO_ROOT, BaseCase

T0 = 1_700_000_000_000


class ProcessCrashTest(BaseCase):
    def _job(self, sync_name, **overrides):
        job = {
            "root": self.root,
            "sync_dir": os.path.join(self.sync_root, sync_name),
            "now_ms": T0,
        }
        job.update(overrides)
        os.makedirs(job["sync_dir"], exist_ok=True)
        return job

    def test_01_kill_mid_first_write_leaves_only_tmp(self):
        svc = self.service()
        svc.create_group("g1", T0)
        job = self._job("s1", op="prepare", group_id="g1", seed="seed-half",
                        hook="prepare.mid_first_write")
        proc, job_path = spawn_worker(job, REPO_ROOT)
        SyncPoint(job["sync_dir"]).gate("prepare.mid_first_write", proc, "kill")
        result = read_worker_result(proc)
        os.remove(job_path)
        self.assertEqual(result["code"], "E_WORKER_KILLED")
        self.assertNotEqual(result["returncode"], 0)

        gdir = keystore.group_dir(svc.key_root, "g1")
        names = os.listdir(gdir)
        # 没有正式副本，只有写一半的 .tmp
        self.assertTrue(any(n.endswith(".tmp") for n in names))
        self.assertFalse(any(keystore._DURABLE_RE.match(n) for n in names))

        # 恢复：临时文件被清理，代数 1 标记 orphan 且永不复用
        report = svc.recover("g1")
        self.assertGreaterEqual(len(report["tmp_files_removed"]), 1)
        self.assertEqual(os.listdir(gdir), [])
        prep = svc.prepare("g1", "seed-half-2", T0)
        self.assertEqual(prep["gen"], 2)

    def test_02_kill_after_both_written_keeps_recoverable_staging(self):
        svc = self.service()
        svc.create_group("g2", T0)
        job = self._job("s2", op="prepare", group_id="g2", seed="seed-both",
                        hook="prepare.after_both_written")
        proc, job_path = spawn_worker(job, REPO_ROOT)
        SyncPoint(job["sync_dir"]).gate("prepare.after_both_written", proc, "kill")
        result = read_worker_result(proc)
        os.remove(job_path)
        self.assertEqual(result["code"], "E_WORKER_KILLED")

        report = svc.recover("g2")
        self.assertEqual(report["orphan_files_removed"], [])
        self.assertEqual(len(report["staging_pending"]), 1)
        token = report["staging_pending"][0]["token"]

        # 恢复后可正常发布并签名，代数仍是 1（未重新发行）
        pub = svc.publish("g2", token, None, 0, T0)
        self.assertEqual(pub["gen"], 1)
        self.assertFalse(pub["replayed"])
        sig = svc.sign("g2", "r1", b"ev", T0)
        self.assertEqual(sig["gen"], 1)

    def test_03_kill_after_commit_retry_is_idempotent(self):
        svc = self.service()
        svc.create_group("g3", T0)
        prep = svc.prepare("g3", "seed-c", T0)
        job = self._job("s3", op="publish", group_id="g3", token=prep["token"],
                        expected_active_gen=None, old_valid_ms=0,
                        hook="publish.after_commit")
        proc, job_path = spawn_worker(job, REPO_ROOT)
        SyncPoint(job["sync_dir"]).gate("publish.after_commit", proc, "kill")
        result = read_worker_result(proc)
        os.remove(job_path)
        self.assertEqual(result["code"], "E_WORKER_KILLED")

        # 指针已落库
        self.assertEqual(svc.snapshot("g3")["active_gen"], 1)
        # 客户端重试：幂等重放，不发新代、不报错
        retry = svc.publish("g3", prep["token"], None, 0, T0)
        self.assertTrue(retry["replayed"])
        self.assertEqual(retry["gen"], 1)
        sig = svc.sign("g3", "r1", b"ev", T0)
        self.assertEqual(sig["gen"], 1)

    def test_04_two_workers_same_gen_race_serialized(self):
        """两个独立进程并发准备：数据库 IMMEDIATE 事务串行化，第二个拿不到同代。"""
        svc = self.service()
        svc.create_group("g4", T0)
        sync_dir = os.path.join(self.sync_root, "s4")
        os.makedirs(sync_dir, exist_ok=True)
        sp = SyncPoint(sync_dir)
        base = {"root": self.root, "sync_dir": sync_dir, "op": "prepare",
                "group_id": "g4", "now_ms": T0,
                "hook": "prepare.after_both_written"}
        p1, path1 = spawn_worker(dict(base, seed="seed-w1"), REPO_ROOT)
        # 等 worker1 两副本落盘（尚未提交 ledger），再启动 worker2
        sp.wait("prepare.after_both_written")
        p2, path2 = spawn_worker(dict(base, seed="seed-w2"), REPO_ROOT)
        # 放行两者（worker2 若被 IMMEDIATE 事务阻塞，会在 worker1 提交后拿到冲突错误）
        go_path = os.path.join(sync_dir, "prepare.after_both_written.go")
        with open(go_path, "xb"):
            pass
        r1 = read_worker_result(p1)
        r2 = read_worker_result(p2)
        os.remove(path1)
        os.remove(path2)

        codes = sorted([r1.get("code", "OK"), r2.get("code", "OK")])
        self.assertTrue(r1["ok"] or r2["ok"])
        # 第二个准备者必须被 staging 占用拒绝；绝不产生同代双份
        if r1["ok"] and r2["ok"]:
            self.fail("two concurrent prepares must not both succeed without replace")
        self.assertIn("E_STAGING_EXISTS", codes)
        snap = svc.snapshot("g4")
        staging = [g for g in snap["generations"] if g["status"] == "staging"]
        self.assertEqual(len(staging), 1)

    def test_05_concurrent_publish_only_one_active_gen(self):
        """两个独立进程无同步点并发发布同一令牌：SQLite 写锁串行化，
        一个全新提交、另一个幂等重放，最终只有唯一活动代，无新代发行。"""
        svc = self.service()
        svc.create_group("g5", T0)
        prep = svc.prepare("g5", "seed-p", T0)
        sync_dir = os.path.join(self.sync_root, "s5")
        os.makedirs(sync_dir, exist_ok=True)
        base = {"root": self.root, "sync_dir": sync_dir, "op": "publish",
                "group_id": "g5", "token": prep["token"], "now_ms": T0,
                "expected_active_gen": None, "old_valid_ms": 0}
        p1, path1 = spawn_worker(dict(base), REPO_ROOT)
        p2, path2 = spawn_worker(dict(base), REPO_ROOT)
        r1 = read_worker_result(p1)
        r2 = read_worker_result(p2)
        os.remove(path1)
        os.remove(path2)

        # 两者都成功解析到唯一活动代 1；恰好一个是幂等重放
        self.assertTrue(r1["ok"] and r2["ok"], (r1, r2))
        self.assertEqual(r1["result"]["gen"], 1)
        self.assertEqual(r2["result"]["gen"], 1)
        self.assertEqual(bool(r1["result"]["replayed"]) +
                         bool(r2["result"]["replayed"]), 1)
        snap = svc.snapshot("g5")
        self.assertEqual(snap["active_gen"], 1)
        self.assertEqual(len([g for g in snap["generations"]
                              if g["status"] == "active"]), 1)
        self.assertEqual(snap["next_gen"], 2)  # 没有发行代 2

    def test_06_recover_never_touches_foreign_files(self):
        svc = self.service()
        svc.create_group("g6", T0)
        svc.prepare("g6", "seed-x", T0)
        gdir = keystore.group_dir(svc.key_root, "g6")
        foreign = os.path.join(gdir, "OWNER_NOTES.txt")
        with open(foreign, "wb") as fh:
            fh.write(b"not owned by key rotation")
        report = svc.recover("g6")
        self.assertEqual(report["orphan_files_removed"], [])
        self.assertTrue(os.path.exists(foreign))
        # safe_unlink 对越权路径直接拒绝
        outside = os.path.join(self.tmp, "outside.txt")
        with open(outside, "wb") as fh:
            fh.write(b"x")
        with self.assertRaises(ServiceError) as ctx:
            keystore.safe_unlink(outside, gdir)
        self.assertEqual(ctx.exception.code, E_UNSAFE_PATH)
        self.assertTrue(os.path.exists(outside))

    def test_07_double_corruption_after_recover_still_fails_closed(self):
        svc = self.service()
        svc.create_group("g7", T0)
        prep = svc.prepare("g7", "seed-z", T0)
        svc.publish("g7", prep["token"], None, 0, T0)
        for slot in ("a", "b"):
            os.remove(keystore.copy_paths(svc.key_root, "g7", 1)[slot])
        with self.assertServiceError(E_MATERIAL_UNAVAILABLE):
            svc.sign("g7", "r1", b"ev", T0)
        # 恢复不会凭空重建材料：签名仍失败
        svc.recover("g7")
        with self.assertServiceError(E_MATERIAL_UNAVAILABLE):
            svc.sign("g7", "r2", b"ev2", T0)
