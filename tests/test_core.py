# -*- coding: utf-8 -*-
"""核心规则单元测试：代数单调、双副本冗余、失败关闭、截止边界、吊销、幂等。"""

import os

from solution.errors import (
    E_BASELINE_STALE,
    E_DIGEST_MISMATCH,
    E_FILE_ALREADY_EXISTS,
    E_MATERIAL_UNAVAILABLE,
    E_OLD_GEN_EXPIRED,
    E_REQUEST_CONFLICT,
    E_REVOKED_GEN,
    E_STAGING_EXISTS,
    E_TOKEN_SUPERSEDED,
)
from solution.kdf import derive_key, hmac_sha256_hex, sha256_hex
from solution import keystore
from tests._base import BaseCase

T0 = 1_700_000_000_000


class CoreRulesTest(BaseCase):
    def test_01_full_rotation_and_redundant_read(self):
        svc = self.service()
        svc.create_group("g1", T0)
        prep1 = svc.prepare("g1", "seed-A", T0)
        self.assertEqual(prep1["gen"], 1)
        self.assertTrue(prep1["committed"])

        pub1 = svc.publish("g1", prep1["token"], None, 10_000, T0)
        self.assertEqual(pub1["gen"], 1)
        self.assertFalse(pub1["replayed"])

        event = b"ops:disk-full"
        sign1 = svc.sign("g1", "req-1", event, T0)
        self.assertEqual(sign1["gen"], 1)
        # 独立重算 HMAC 断言具体签名值，而不是只比较自引用
        key1 = derive_key("seed-A", "g1", 1)
        self.assertEqual(sign1["mac"], hmac_sha256_hex(key1, event))
        self.assertEqual(sign1["event_digest"], sha256_hex(event))

        prep2 = svc.prepare("g1", "seed-B", T0)
        self.assertEqual(prep2["gen"], 2)
        pub2 = svc.publish("g1", prep2["token"], 1, 10_000, T0 + 1)
        self.assertEqual(pub2["old_gen"], 1)
        self.assertEqual(pub2["old_deadline_ms"], T0 + 1 + 10_000)

        # 新代签名；旧代在截止内仍可验签
        sign2 = svc.sign("g1", "req-2", b"ops:other", T0 + 1)
        self.assertEqual(sign2["gen"], 2)
        ok = svc.verify("g1", 1, event, sign1["mac"], T0 + 1)
        self.assertTrue(ok["valid"])
        # 跨事件验签必失败，证明没有混用材料
        bad = svc.verify("g1", 1, b"ops:other", sign2["mac"], T0 + 1)
        self.assertFalse(bad["valid"])

    def test_02_generation_monotonic_even_same_material(self):
        svc = self.service()
        svc.create_group("g2", T0)
        p1 = svc.prepare("g2", "same-seed", T0)
        svc.publish("g2", p1["token"], None, 0, T0)
        p2 = svc.prepare("g2", "same-seed", T0)
        self.assertEqual(p2["gen"], 2)
        self.assertNotEqual(p1["digest"], p2["digest"])
        # 同种子不同代派生出不同密钥字节
        self.assertNotEqual(derive_key("same-seed", "g2", 1),
                            derive_key("same-seed", "g2", 2))

    def test_03_staging_conflict_and_replace_supersede(self):
        svc = self.service()
        svc.create_group("g3", T0)
        p1 = svc.prepare("g3", "s1", T0)
        with self.assertServiceError(E_STAGING_EXISTS):
            svc.prepare("g3", "s2", T0)
        p2 = svc.prepare("g3", "s2", T0, replace=True)
        self.assertEqual(p2["gen"], 2)
        # 被替换的预发布令牌不得再发布
        with self.assertServiceError(E_TOKEN_SUPERSEDED):
            svc.publish("g3", p1["token"], None, 0, T0)
        pub = svc.publish("g3", p2["token"], None, 0, T0)
        self.assertEqual(pub["gen"], 2)

    def test_04_baseline_stale_after_other_publisher(self):
        svc = self.service()
        svc.create_group("g4", T0)
        p1 = svc.prepare("g4", "s1", T0)
        svc.publish("g4", p1["token"], None, 0, T0)
        p2 = svc.prepare("g4", "s2", T0)
        p3 = svc.prepare("g4", "s3", T0, replace=True)
        # p2 已被替换，先确认其令牌作废；p3 以真实基准 1 发布成功
        with self.assertServiceError(E_TOKEN_SUPERSEDED):
            svc.publish("g4", p2["token"], 1, 0, T0)
        self.assertEqual(svc.publish("g4", p3["token"], 1, 0, T0)["gen"], 3)
        # 若调用方携带错误基准，显式 E_BASELINE_STALE
        p4 = svc.prepare("g4", "s4", T0)
        with self.assertServiceError(E_BASELINE_STALE):
            svc.publish("g4", p4["token"], 1, 0, T0)

    def test_05_single_copy_corruption_then_double_failure_closed(self):
        svc = self.service()
        svc.create_group("g5", T0)
        p1 = svc.prepare("g5", "s1", T0)
        svc.publish("g5", p1["token"], None, 0, T0)
        s1 = svc.sign("g5", "r1", b"ev", T0)
        p2 = svc.prepare("g5", "s2", T0)
        svc.publish("g5", p2["token"], 1, 100_000, T0)

        # 活动代 A 副本损坏：B 副本通过摘要检查继续服务
        path_a = keystore.copy_paths(svc.key_root, "g5", 2)["a"]
        with open(path_a, "r+b") as fh:
            fh.seek(0)
            fh.write(b"\x00" * 8)
        s2 = svc.sign("g5", "r2", b"ev2", T0)
        self.assertEqual(s2["gen"], 2)

        # B 副本删除：双副本不可用 -> 失败关闭，不回退旧代
        os.remove(keystore.copy_paths(svc.key_root, "g5", 2)["b"])
        with self.assertServiceError(E_MATERIAL_UNAVAILABLE):
            svc.sign("g5", "r3", b"ev3", T0)
        # 旧代材料仍完好且在截止内，显式验签可用（但签名绝不静默回退）
        self.assertTrue(svc.verify("g5", 1, b"ev", s1["mac"], T0)["valid"])
        self.assertEqual(svc.snapshot("g5")["active_gen"], 2)

    def test_06_deadline_boundary_inclusive_then_expired(self):
        svc = self.service()
        svc.create_group("g6", T0)
        p1 = svc.prepare("g6", "s1", T0)
        svc.publish("g6", p1["token"], None, 0, T0)
        mac = svc.sign("g6", "r1", b"ev", T0)["mac"]
        p2 = svc.prepare("g6", "s2", T0)
        svc.publish("g6", p2["token"], 1, 1_000, T0)
        # now == deadline：允许
        self.assertTrue(svc.verify("g6", 1, b"ev", mac, T0 + 1_000)["valid"])
        # now = deadline + 1：拒绝
        with self.assertServiceError(E_OLD_GEN_EXPIRED):
            svc.verify("g6", 1, b"ev", mac, T0 + 1_001)

    def test_07_revoked_never_reissued(self):
        svc = self.service()
        svc.create_group("g7", T0)
        p1 = svc.prepare("g7", "s1", T0)
        svc.publish("g7", p1["token"], None, 0, T0)
        mac = svc.sign("g7", "r1", b"ev", T0)["mac"]
        p2 = svc.prepare("g7", "s2", T0)
        svc.publish("g7", p2["token"], 1, 10_000, T0)
        svc.revoke("g7", 1, T0)
        with self.assertServiceError(E_REVOKED_GEN):
            svc.verify("g7", 1, b"ev", mac, T0)
        p3 = svc.prepare("g7", "s3", T0)
        self.assertEqual(p3["gen"], 3)  # 代数 1 永不复用
        snap = svc.snapshot("g7")
        self.assertEqual({g["gen"]: g["status"] for g in snap["generations"]}[1],
                         "revoked")

    def test_08_sign_idempotency_and_conflict(self):
        svc = self.service()
        svc.create_group("g8", T0)
        p1 = svc.prepare("g8", "s1", T0)
        svc.publish("g8", p1["token"], None, 0, T0)
        first = svc.sign("g8", "rid", b"ev", T0)
        again = svc.sign("g8", "rid", b"ev", T0)
        self.assertTrue(again["replayed"])
        self.assertEqual(again["mac"], first["mac"])
        with self.assertServiceError(E_REQUEST_CONFLICT):
            svc.sign("g8", "rid", b"different", T0)

    def test_09_immutable_copy_never_overwritten(self):
        svc = self.service()
        svc.create_group("g9", T0)
        svc.prepare("g9", "s1", T0)
        # 同代正式文件已存在，再次落盘必须被拒
        path = keystore.copy_paths(svc.key_root, "g9", 1)["a"]
        with self.assertServiceError(E_FILE_ALREADY_EXISTS):
            keystore.atomic_write(path, b"anything")

    def test_10_digest_mismatch_is_surfaced(self):
        svc = self.service()
        svc.create_group("g10", T0)
        prep = svc.prepare("g10", "s1", T0)
        svc.publish("g10", prep["token"], None, 0, T0)
        path_b = keystore.copy_paths(svc.key_root, "g10", 1)["b"]
        with open(path_b, "r+b") as fh:
            fh.truncate(4)
        # A 仍可读；直接读 B 必须报摘要不符
        self.assertIsNotNone(
            keystore.read_verified_copy(svc.key_root, "g10", 1, "a", prep["digest"])
        )
        with self.assertServiceError(E_DIGEST_MISMATCH):
            keystore.read_verified_copy(svc.key_root, "g10", 1, "b", prep["digest"])

    def test_11_no_key_material_in_db_or_receipts(self):
        svc = self.service()
        svc.create_group("g11", T0)
        prep = svc.prepare("g11", "secret-seed", T0)
        svc.publish("g11", prep["token"], None, 0, T0)
        svc.sign("g11", "r1", b"ev", T0)
        key = derive_key("secret-seed", "g11", 1)
        with open(svc.store.db_path, "rb") as fh:
            db_blob = fh.read()
        self.assertNotIn(key, db_blob)
        self.assertNotIn(key.hex().encode(), db_blob)
        snap = svc.snapshot("g11")
        import json
        snap_blob = json.dumps(snap).encode()
        self.assertNotIn(key, snap_blob)
        self.assertNotIn(key.hex().encode(), snap_blob)

    def test_12_copies_identical_and_never_mixed_across_gens(self):
        """同代两个副本字节完全一致且都匹配摘要；读者绝不拿到跨代混合材料。"""
        svc = self.service()
        svc.create_group("g12", T0)
        p1 = svc.prepare("g12", "seed-mix", T0)
        svc.publish("g12", p1["token"], None, 0, T0)
        p2 = svc.prepare("g12", "seed-mix-2", T0)
        svc.publish("g12", p2["token"], 1, 100_000, T0)

        # 每代 A/B 副本逐字节相同，且与该代期望摘要一致
        for gen, prep in ((1, p1), (2, p2)):
            data_a = keystore.read_verified_copy(
                svc.key_root, "g12", gen, "a", prep["digest"])
            data_b = keystore.read_verified_copy(
                svc.key_root, "g12", gen, "b", prep["digest"])
            self.assertEqual(data_a, data_b)
            self.assertEqual(sha256_hex(data_a), prep["digest"])

        # 冗余读取只在指定代数内进行：用代 1 的摘要读代 2 的副本必须判摘要不符，
        # 证明不会把代 1 的期望套到代 2 上，杜绝混合材料
        with self.assertServiceError(E_DIGEST_MISMATCH):
            keystore.read_verified_copy(
                svc.key_root, "g12", 2, "a", p1["digest"])

        # 活动代签名密钥就是代 2 的派生密钥，与代 1 不同
        sig = svc.sign("g12", "r", b"ev", T0)
        key2 = derive_key("seed-mix-2", "g12", 2)
        self.assertEqual(sig["mac"], hmac_sha256_hex(key2, b"ev"))
        self.assertNotEqual(derive_key("seed-mix", "g12", 1), key2)
