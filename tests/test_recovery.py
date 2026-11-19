# -*- coding: utf-8 -*-
"""恢复分类与密钥泄漏防护测试。"""

import json
import os
import sqlite3

from solution import keystore
from solution.kdf import derive_key
from solution.orchestrator import Runner, scan_key_leak
from tests._base import BaseCase

T0 = 1_700_000_000_000


class RecoveryAndLeakTest(BaseCase):
    def test_01_recover_classifies_three_states(self):
        """已提交代保留；回执绑定的完整 staging 保留；未确认孤立准备物清理。"""
        svc = self.service()
        svc.create_group("g1", T0)
        # 已提交活动代
        p1 = svc.prepare("g1", "seed-a", T0)
        svc.publish("g1", p1["token"], None, 0, T0)
        # 孤立准备物：手工构造“数据库有代数但双副本缺失”
        p2 = svc.prepare("g1", "seed-b", T0)
        gdir = keystore.group_dir(svc.key_root, "g1")
        for slot in ("a", "b"):
            os.remove(keystore.copy_paths(svc.key_root, "g1", p2["gen"])[slot])

        report = svc.recover("g1")
        kept_gens = {k["gen"]: k["status"] for k in report["kept"]}
        self.assertEqual(kept_gens.get(1), "active")
        abandoned = {a["gen"] for a in report["abandoned_prepares"]}
        self.assertIn(2, abandoned)

        snap = svc.snapshot("g1")
        statuses = {g["gen"]: g["status"] for g in snap["generations"]}
        self.assertEqual(statuses[2], "orphan")
        # 孤立代数不再占用 ledger，且后续准备使用代 3，不复用 2
        self.assertEqual(snap["prep_ledger"], [])
        p3 = svc.prepare("g1", "seed-c", T0)
        self.assertEqual(p3["gen"], 3)

    def test_02_orphan_disk_files_without_db_row_are_removed(self):
        svc = self.service()
        svc.create_group("g2", T0)
        svc.prepare("g2", "seed-a", T0)
        gdir = keystore.group_dir(svc.key_root, "g2")
        # 数据库完全不知道的代 9 文件：可证明未被授权引用，必须清理
        for slot in ("a", "b"):
            with open(os.path.join(gdir, "gen9.%s.bin" % slot), "wb") as fh:
                fh.write(b"unauthorized-bytes")
        report = svc.recover("g2")
        removed = sorted(os.path.basename(p) for p in report["orphan_files_removed"])
        self.assertEqual(removed, ["gen9.a.bin", "gen9.b.bin"])
        self.assertFalse(any("gen9" in n for n in os.listdir(gdir)))
        # 授权的代 1 双副本保留
        self.assertIn("gen1.a.bin", os.listdir(gdir))
        self.assertIn("gen1.b.bin", os.listdir(gdir))

    def test_03_no_key_leak_in_db_audit_or_receipts(self):
        svc = self.service()
        svc.create_group("g3", T0)
        seed = "seed-leak"
        prep = svc.prepare("g3", seed, T0)
        svc.publish("g3", prep["token"], None, 10_000, T0)
        svc.sign("g3", "req-1", b"ops:event", T0)
        svc.recover("g3")
        key = derive_key(seed, "g3", 1)

        conn = sqlite3.connect(svc.store.db_path)
        for table in ("groups_meta", "generations", "prep_ledger",
                      "receipts", "audit_log"):
            rows = conn.execute("SELECT * FROM %s" % table).fetchall()
            blob = json.dumps(rows).encode()
            self.assertNotIn(key, blob, "raw key leaked in %s" % table)
            self.assertNotIn(key.hex().encode(), blob, "hex key leaked in %s" % table)
        conn.close()

        # 全盘扫描：除两个 .bin 副本外任何文件都不得含密钥
        leaks = scan_key_leak(self.root, "g3", [seed])
        self.assertEqual(leaks, [])

    def test_04_audit_log_rejects_sensitive_fields(self):
        from solution.store import Store
        conn = Store(self._db_path()).conn()
        try:
            Store.begin_immediate(conn)
            with self.assertRaises(ValueError):
                Store.audit(conn, T0, "bad", detail={"key": b"x"})
            Store.rollback(conn)
        finally:
            conn.close()

    def _db_path(self):
        return os.path.join(self.root, "rotation.db")

    def test_05_runner_case_outputs_concrete_results(self):
        """用 cases.json 的截止边界用例跑编排器，断言逐步具体结果。"""
        from tests._base import case_by_id
        case = case_by_id("08_old_gen_deadline_boundary")
        runner = Runner(self.root, self.sync_root)
        out = runner.run(case)
        self.assertTrue(out["leak_scan"]["passed"])
        by_step = {e["step"]: e for e in out["steps"]}
        self.assertTrue(by_step["v_eq"]["result"]["valid"])
        self.assertEqual(by_step["v_over"]["code"], "E_OLD_GEN_EXPIRED")
        self.assertEqual(by_step["pub2"]["result"]["old_deadline_ms"],
                         T0 + 1_000)
