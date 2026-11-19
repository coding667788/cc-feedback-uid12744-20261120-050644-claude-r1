# -*- coding: utf-8 -*-
"""密钥轮换核心服务。

不变量：
1. 一个设备组任一时刻只有唯一活动代（``groups_meta.active_gen``），
   另有至多一个预发布代（staging）与有限期验签旧代（retired）。
2. 活动代由 SQLite 事务决定；密钥材料只落在两个独立本地不可变文件中，
   数据库仅保存确切代数与两个副本的期望摘要。
3. 文件先安全落盘并逐副本重读校验，之后才允许提交“材料已就绪”标记；
   活动指针的移动在全部材料校验通过之后。
4. 代数单调递增、绝不复用（即使新旧代密钥内容相同）；吊销代永久保留记录。
5. 持久签名在同一 IMMEDIATE 事务内重读活动代、校验材料、登记结果与请求回执；
   材料不可用即失败关闭，绝不静默回退旧代。
"""

import hashlib
import hmac as hmac_mod
import json
import os

from . import keystore
from .errors import ServiceError
from .errors import (
    E_BASELINE_STALE,
    E_GEN_NOT_STAGING,
    E_GROUP_EXISTS,
    E_GROUP_UNKNOWN,
    E_MATERIAL_UNAVAILABLE,
    E_OLD_GEN_EXPIRED,
    E_REQUEST_CONFLICT,
    E_REVOKED_GEN,
    E_STAGING_EXISTS,
    E_TOKEN_SUPERSEDED,
    E_TOKEN_UNKNOWN,
)
from .kdf import derive_key, hmac_sha256_hex, sha256_hex
from .store import Store

# 代生命周期
STAGING = "staging"        # 预发布：材料已就绪，等待发布
ACTIVE = "active"          # 活动代：唯一可签名代
RETIRED = "retired"        # 有限期验签旧代
REVOKED = "revoked"        # 已吊销旧代，永久不可再用
SUPERSEDED = "superseded"  # 被 replace 准备作废的预发布代
ORPHAN = "orphan"          # 准备失败/未确认且不可恢复的孤立代


class KeyRotationService:
    def __init__(self, root):
        self.root = os.path.abspath(root)
        os.makedirs(self.root, exist_ok=True)
        self.key_root = os.path.join(self.root, "keystore")
        os.makedirs(self.key_root, exist_ok=True)
        self.store = Store(os.path.join(self.root, "rotation.db"))

    # ------------------------------------------------------------------
    # 内部工具
    # ------------------------------------------------------------------
    @staticmethod
    def _hook(hook, stage, tmp_path=None):
        if hook is not None:
            hook(stage, tmp_path)

    def _get_group(self, conn, group_id, lock=False):
        row = conn.execute(
            "SELECT * FROM groups_meta WHERE group_id=?", (group_id,)
        ).fetchone()
        if row is None:
            raise ServiceError(E_GROUP_UNKNOWN, "unknown group: %s" % group_id)
        return row

    def _gen_row(self, conn, gen):
        return conn.execute("SELECT * FROM generations WHERE gen=?", (gen,)).fetchone()

    # ------------------------------------------------------------------
    # 设备组
    # ------------------------------------------------------------------
    def create_group(self, group_id, now_ms):
        keystore.safe_group_name(group_id)
        conn = self.store.conn()
        try:
            Store.begin_immediate(conn)
            exists = conn.execute(
                "SELECT 1 FROM groups_meta WHERE group_id=?", (group_id,)
            ).fetchone()
            if exists is not None:
                raise ServiceError(E_GROUP_EXISTS, "group already exists: %s" % group_id)
            conn.execute(
                "INSERT INTO groups_meta(group_id, created_ms, next_gen) VALUES (?,?,?)",
                (group_id, int(now_ms), 1),
            )
            Store.audit(conn, now_ms, "group_created", group_id=group_id)
            Store.commit(conn)
        except Exception:
            Store.rollback(conn)
            raise
        finally:
            conn.close()
        keystore.group_dir(self.key_root, group_id, create=True)
        return {"group_id": group_id, "created_ms": int(now_ms)}

    # ------------------------------------------------------------------
    # 准备（prepare）：分配代数 -> 落盘双副本并校验 -> 提交就绪标记
    # ------------------------------------------------------------------
    def prepare(self, group_id, seed, now_ms, replace=False, hook=None):
        conn = self.store.conn()
        gen = None
        token = None
        try:
            Store.begin_immediate(conn)
            self._get_group(conn, group_id)
            staging_row = conn.execute(
                "SELECT gen FROM generations WHERE group_id=? AND status=?",
                (group_id, STAGING),
            ).fetchone()
            if staging_row is not None and not replace:
                raise ServiceError(
                    E_STAGING_EXISTS,
                    "staging gen %d already prepared" % staging_row["gen"],
                    gen=staging_row["gen"],
                )
            if staging_row is not None:
                # 显式替换：旧预发布代作废（代数绝不复用），其就绪绑定解除
                conn.execute(
                    "UPDATE generations SET status=?, superseded_ms=? WHERE gen=?",
                    (SUPERSEDED, int(now_ms), staging_row["gen"]),
                )
                conn.execute("DELETE FROM prep_ledger WHERE gen=?", (staging_row["gen"],))
                Store.audit(
                    conn, now_ms, "staging_superseded",
                    group_id=group_id, gen=staging_row["gen"],
                    detail={"by": "replace_prepare"},
                )

            row = conn.execute(
                "SELECT next_gen FROM groups_meta WHERE group_id=?", (group_id,)
            ).fetchone()
            gen = int(row["next_gen"])
            conn.execute(
                "UPDATE groups_meta SET next_gen=? WHERE group_id=?",
                (gen + 1, group_id),
            )

            # 密钥材料只在进程内存中出现，数据库不保存
            material = derive_key(seed, group_id, gen)
            digest = sha256_hex(material)
            token = hashlib.sha256(
                ("token|%s|%d|%s" % (group_id, gen, digest)).encode("utf-8")
            ).hexdigest()

            conn.execute(
                "INSERT INTO generations(gen, group_id, status, token, digest_a,"
                " digest_b, created_ms, seed_tag) VALUES (?,?,?,?,?,?,?,?)",
                (gen, group_id, STAGING, token, digest, digest, int(now_ms), str(seed)),
            )
            conn.execute(
                "INSERT INTO prep_ledger(token, gen, group_id, committed, created_ms)"
                " VALUES (?,?,?,?,?)",
                (token, gen, group_id, 0, int(now_ms)),
            )
            Store.audit(
                conn, now_ms, "prepare_allocated", group_id=group_id, gen=gen,
                detail={"digest": digest},
            )
            Store.commit(conn)
        except Exception:
            Store.rollback(conn)
            raise
        finally:
            conn.close()

        # 事务外安全落盘：两个独立不可变副本，逐个重读校验
        try:
            paths = keystore.write_gen_copies(
                self.key_root, group_id, gen, material, digest,
                hooks=lambda stage, tmp_path=None: self._hook(hook, stage, tmp_path),
            )
        except ServiceError:
            self._abandon_prepare(group_id, gen, now_ms)
            raise

        # 落盘校验通过后，才在新事务里提交“材料已就绪”绑定
        conn = self.store.conn()
        try:
            Store.begin_immediate(conn)
            ledger = conn.execute(
                "SELECT committed FROM prep_ledger WHERE token=?", (token,)
            ).fetchone()
            if ledger is None:
                # 已被并发 replace 准备作废
                raise ServiceError(
                    E_TOKEN_SUPERSEDED,
                    "prepare token for gen %d was superseded" % gen, gen=gen,
                )
            for slot in ("a", "b"):
                data = keystore.read_verified_copy(
                    self.key_root, group_id, gen, slot, digest
                )
                if data is None:
                    raise ServiceError(
                        E_MATERIAL_UNAVAILABLE,
                        "copy %s missing before ledger commit" % slot, gen=gen,
                    )
            conn.execute(
                "UPDATE prep_ledger SET committed=1 WHERE token=?", (token,)
            )
            Store.audit(
                conn, now_ms, "prepare_committed", group_id=group_id, gen=gen,
                detail={"digest": digest, "copies": ["a", "b"]},
            )
            Store.commit(conn)
        except Exception:
            Store.rollback(conn)
            self._abandon_prepare(group_id, gen, now_ms, only_if_uncommitted=True)
            raise
        finally:
            conn.close()

        return {
            "token": token,
            "gen": gen,
            "digest": digest,
            "paths": paths,
            "committed": True,
        }

    def _abandon_prepare(self, group_id, gen, now_ms, only_if_uncommitted=False):
        """准备失败：解除绑定并把代标记为 orphan（代数不复用）。"""
        if gen is None:
            return
        conn = self.store.conn()
        try:
            Store.begin_immediate(conn)
            row = conn.execute(
                "SELECT status FROM generations WHERE gen=?", (gen,)
            ).fetchone()
            if row is None or row["status"] != STAGING:
                Store.rollback(conn)
                return
            if only_if_uncommitted:
                ledger = conn.execute(
                    "SELECT committed FROM prep_ledger WHERE gen=?", (gen,)
                ).fetchone()
                if ledger is not None and ledger["committed"]:
                    Store.rollback(conn)
                    return
            conn.execute("DELETE FROM prep_ledger WHERE gen=?", (gen,))
            conn.execute(
                "UPDATE generations SET status=? WHERE gen=?", (ORPHAN, gen)
            )
            Store.audit(conn, now_ms, "prepare_abandoned", group_id=group_id, gen=gen)
            Store.commit(conn)
        except Exception:
            Store.rollback(conn)
        finally:
            conn.close()

    # ------------------------------------------------------------------
    # 发布（publish）：材料校验通过后原子移动活动指针
    # ------------------------------------------------------------------
    def publish(self, group_id, token, expected_active_gen, old_valid_ms,
                now_ms, hook=None):
        conn = self.store.conn()
        replayed = False
        try:
            Store.begin_immediate(conn)
            group = self._get_group(conn, group_id)
            ledger = conn.execute(
                "SELECT * FROM prep_ledger WHERE token=?", (token,)
            ).fetchone()
            gen = None
            if ledger is None:
                # 幂等重放：“指针已提交未响应”后客户端重试
                grow = conn.execute(
                    "SELECT * FROM generations WHERE token=?", (token,)
                ).fetchone()
                if grow is None:
                    raise ServiceError(E_TOKEN_UNKNOWN, "unknown prepare token")
                if grow["status"] == SUPERSEDED:
                    raise ServiceError(
                        E_TOKEN_SUPERSEDED,
                        "token gen %d was superseded before publish" % grow["gen"],
                        gen=grow["gen"],
                    )
                if grow["status"] != ACTIVE:
                    raise ServiceError(
                        E_GEN_NOT_STAGING,
                        "token gen %d is not publishable (status=%s)"
                        % (grow["gen"], grow["status"]),
                        gen=grow["gen"],
                    )
                replayed = True
                gen = grow["gen"]
                old_active = group["active_gen"]
                old_deadline = group["old_deadline_ms"]
            else:
                gen = ledger["gen"]
                grow = self._gen_row(conn, gen)
                if grow is None or grow["status"] != STAGING:
                    raise ServiceError(
                        E_GEN_NOT_STAGING,
                        "gen %s is not a staging generation" % gen, gen=gen,
                    )
                current_active = group["active_gen"]
                if (
                    expected_active_gen is not None
                    and int(expected_active_gen) != int(current_active)
                ):
                    raise ServiceError(
                        E_BASELINE_STALE,
                        "expected active gen %s but current is %s"
                        % (expected_active_gen, current_active),
                        expected=expected_active_gen,
                        current=current_active,
                    )

                # 提交前再次确认两个副本均可用且摘要正确——失败关闭
                for slot in ("a", "b"):
                    data = keystore.read_verified_copy(
                        self.key_root, group_id, gen, slot, grow["digest_a"]
                    )
                    if data is None:
                        raise ServiceError(
                            E_MATERIAL_UNAVAILABLE,
                            "copy %s missing at publish" % slot, gen=gen,
                        )

                self._hook(hook, "publish.before_commit")

                old_active = current_active
                old_deadline = None
                if old_active is not None:
                    old_deadline = int(now_ms) + int(old_valid_ms)
                    conn.execute(
                        "UPDATE generations SET status=?, deadline_ms=? WHERE gen=?",
                        (RETIRED, old_deadline, old_active),
                    )
                    conn.execute(
                        "UPDATE groups_meta SET old_gen=?, old_deadline_ms=? "
                        "WHERE group_id=?",
                        (old_active, old_deadline, group_id),
                    )
                    Store.audit(
                        conn, now_ms, "gen_retired", group_id=group_id,
                        gen=old_active, detail={"deadline_ms": old_deadline},
                    )

                conn.execute(
                    "UPDATE generations SET status=?, published_ms=? WHERE gen=?",
                    (ACTIVE, int(now_ms), gen),
                )
                conn.execute(
                    "UPDATE groups_meta SET active_gen=? WHERE group_id=?",
                    (gen, group_id),
                )
                conn.execute("DELETE FROM prep_ledger WHERE token=?", (token,))
                Store.audit(
                    conn, now_ms, "gen_published", group_id=group_id, gen=gen,
                    detail={"old_gen": old_active, "old_deadline_ms": old_deadline},
                )

            Store.commit(conn)
        except Exception:
            Store.rollback(conn)
            raise
        finally:
            conn.close()

        # 提交成功、响应返回前的同步点：模拟“指针已提交未响应”的真实终止
        self._hook(hook, "publish.after_commit")
        return {
            "gen": gen,
            "active_gen": gen,
            "old_gen": old_active,
            "old_deadline_ms": old_deadline,
            "replayed": replayed,
        }

    # ------------------------------------------------------------------
    # 持久签名：同事务重读活动代 + 校验材料 + 原子登记回执
    # ------------------------------------------------------------------
    def sign(self, group_id, request_id, event_bytes, now_ms):
        event_digest = sha256_hex(event_bytes)
        conn = self.store.conn()
        try:
            Store.begin_immediate(conn)
            group = self._get_group(conn, group_id)

            existing = conn.execute(
                "SELECT * FROM receipts WHERE request_id=?", (request_id,)
            ).fetchone()
            if existing is not None:
                if existing["event_digest"] != event_digest or existing["kind"] != "sign":
                    raise ServiceError(
                        E_REQUEST_CONFLICT,
                        "request_id %s reused with different payload" % request_id,
                    )
                # 幂等重放：仍须在本事务内重读活动代并确认材料可用
                active_gen = group["active_gen"]
                grow = self._gen_row(conn, active_gen)
                if grow is None or grow["status"] != ACTIVE:
                    raise ServiceError(
                        E_MATERIAL_UNAVAILABLE, "no active generation", gen=active_gen
                    )
                _, material = keystore.read_best_copy(
                    self.key_root, group_id, active_gen, grow["digest_a"]
                )
                Store.audit(
                    conn, now_ms, "sign_replayed", group_id=group_id, gen=active_gen,
                    detail={"request_id": request_id, "event_digest": event_digest},
                )
                Store.commit(conn)
                return {
                    "request_id": request_id,
                    "gen": active_gen,
                    "event_digest": event_digest,
                    "mac": existing["mac"],
                    "replayed": True,
                }

            active_gen = group["active_gen"]
            if active_gen is None:
                raise ServiceError(E_MATERIAL_UNAVAILABLE, "no active generation yet")
            grow = self._gen_row(conn, active_gen)
            if grow is None or grow["status"] != ACTIVE:
                raise ServiceError(
                    E_MATERIAL_UNAVAILABLE,
                    "active gen %s not usable" % active_gen, gen=active_gen,
                )

            # 提交前发现材料不可用 -> 失败关闭，不写回执
            slot, material = keystore.read_best_copy(
                self.key_root, group_id, active_gen, grow["digest_a"]
            )
            mac = hmac_sha256_hex(material, event_bytes)

            conn.execute(
                "INSERT INTO receipts(request_id, group_id, kind, gen, event_digest,"
                " mac, created_ms) VALUES (?,?,?,?,?,?,?)",
                (request_id, group_id, "sign", active_gen, event_digest, mac,
                 int(now_ms)),
            )
            Store.audit(
                conn, now_ms, "signed", group_id=group_id, gen=active_gen,
                detail={
                    "request_id": request_id,
                    "event_digest": event_digest,
                    "copy_slot": slot,
                },
            )
            Store.commit(conn)
        except Exception:
            Store.rollback(conn)
            raise
        finally:
            conn.close()

        return {
            "request_id": request_id,
            "gen": active_gen,
            "event_digest": event_digest,
            "mac": mac,
            "replayed": False,
        }

    # ------------------------------------------------------------------
    # 验签：活动代或未截止/未吊销的旧代；绝不跨代混用材料
    # ------------------------------------------------------------------
    def verify(self, group_id, gen, event_bytes, mac_hex, now_ms):
        conn = self.store.conn()
        try:
            Store.begin_immediate(conn)
            self._get_group(conn, group_id)
            grow = self._gen_row(conn, gen)
            if grow is None:
                raise ServiceError(E_GEN_NOT_STAGING, "unknown gen %s" % gen, gen=gen)
            status = grow["status"]
            if status == REVOKED:
                raise ServiceError(E_REVOKED_GEN, "gen %d revoked" % gen, gen=gen)
            if status == RETIRED:
                if int(now_ms) > int(grow["deadline_ms"]):
                    raise ServiceError(
                        E_OLD_GEN_EXPIRED,
                        "retired gen %d past verify deadline" % gen, gen=gen,
                        deadline_ms=grow["deadline_ms"],
                    )
            elif status != ACTIVE:
                # staging / superseded / orphan 均未授权
                raise ServiceError(
                    E_GEN_NOT_STAGING,
                    "gen %d not authorized for verify (status=%s)" % (gen, status),
                    gen=gen,
                )

            _, material = keystore.read_best_copy(
                self.key_root, group_id, gen, grow["digest_a"]
            )
            expected = hmac_sha256_hex(material, event_bytes)
            valid = hmac_mod.compare_digest(expected, mac_hex)
            Store.audit(
                conn, now_ms, "verified", group_id=group_id, gen=gen,
                detail={"valid": bool(valid), "status": status},
            )
            Store.commit(conn)
        except Exception:
            Store.rollback(conn)
            raise
        finally:
            conn.close()
        return {"gen": gen, "status": status, "valid": bool(valid)}

    # ------------------------------------------------------------------
    # 吊销旧代：永久作废，代数与记录均不复用
    # ------------------------------------------------------------------
    def revoke(self, group_id, gen, now_ms):
        conn = self.store.conn()
        try:
            Store.begin_immediate(conn)
            self._get_group(conn, group_id)
            grow = self._gen_row(conn, gen)
            if grow is None or grow["status"] != RETIRED:
                raise ServiceError(
                    E_GEN_NOT_STAGING,
                    "only retired generations can be revoked (gen=%s)" % gen, gen=gen,
                )
            conn.execute(
                "UPDATE generations SET status=?, revoked_ms=? WHERE gen=?",
                (REVOKED, int(now_ms), gen),
            )
            conn.execute(
                "UPDATE groups_meta SET old_gen=NULL, old_deadline_ms=NULL "
                "WHERE group_id=? AND old_gen=?",
                (group_id, gen),
            )
            Store.audit(conn, now_ms, "gen_revoked", group_id=group_id, gen=gen)
            Store.commit(conn)
        except Exception:
            Store.rollback(conn)
            raise
        finally:
            conn.close()
        return {"gen": gen, "status": REVOKED}

    # ------------------------------------------------------------------
    # 恢复：区分已提交代 / 回执绑定阶段 / 未确认孤立准备物
    # ------------------------------------------------------------------
    def recover(self, group_id):
        gdir = keystore.group_dir(self.key_root, group_id)
        on_disk = keystore.list_gen_files(gdir)
        report = {
            "group_id": group_id,
            "kept": [],
            "orphan_files_removed": [],
            "tmp_files_removed": [],
            "abandoned_prepares": [],
            "staging_pending": [],
        }
        conn = self.store.conn()
        try:
            Store.begin_immediate(conn)
            self._get_group(conn, group_id)
            db_gens = {
                r["gen"]: r
                for r in conn.execute(
                    "SELECT * FROM generations WHERE group_id=?", (group_id,)
                ).fetchall()
            }

            # 1) 磁盘有、数据库无代数记录：可证明未被授权引用 -> 清理
            for gen, items in sorted(on_disk.items()):
                if gen not in db_gens:
                    for path in sorted(items["durable"].values()):
                        keystore.safe_unlink(path, gdir)
                        report["orphan_files_removed"].append(path)
                    for path in items["tmp"]:
                        keystore.safe_unlink(path, gdir)
                        report["tmp_files_removed"].append(path)
                    continue

                # 2) 任何代数遗留的写一半临时文件都不是授权引用 -> 清理
                for path in items["tmp"]:
                    keystore.safe_unlink(path, gdir)
                    report["tmp_files_removed"].append(path)

                grow = db_gens[gen]
                if grow["status"] == STAGING:
                    ledger = conn.execute(
                        "SELECT * FROM prep_ledger WHERE gen=?", (gen,)
                    ).fetchone()
                    complete = True
                    copy_slots = {}
                    for slot in ("a", "b"):
                        try:
                            data = keystore.read_verified_copy(
                                self.key_root, group_id, gen, slot, grow["digest_a"]
                            )
                        except ServiceError:
                            data = None
                        copy_slots[slot] = data is not None
                        if data is None:
                            complete = False
                    if complete:
                        # 双副本均通过摘要校验：属于可恢复的预发布准备物。
                        # 若就绪令牌绑定随进程终止丢失，则补登一个恢复令牌，
                        # 仍由数据库代数记录授权（代数不重用、不新发）。
                        if ledger is None:
                            token = hashlib.sha256(
                                ("recover|%s|%d|%s"
                                 % (group_id, gen, grow["digest_a"])).encode("utf-8")
                            ).hexdigest()
                            conn.execute(
                                "INSERT INTO prep_ledger(token, gen, group_id,"
                                " committed, created_ms) VALUES (?,?,?,?,?)",
                                (token, gen, group_id, 1, grow["created_ms"]),
                            )
                            conn.execute(
                                "UPDATE generations SET token=? WHERE gen=?",
                                (token, gen),
                            )
                            Store.audit(
                                conn, grow["created_ms"], "prepare_recovered_staging",
                                group_id=group_id, gen=gen,
                                detail={"copies": copy_slots},
                            )
                            ledger = conn.execute(
                                "SELECT * FROM prep_ledger WHERE gen=?", (gen,)
                            ).fetchone()
                        report["staging_pending"].append(
                            {"gen": gen, "token": ledger["token"],
                             "committed": bool(ledger["committed"])}
                        )
                    else:
                        # 未确认且无法通过材料校验的孤立准备物：解除绑定后清理
                        conn.execute("DELETE FROM prep_ledger WHERE gen=?", (gen,))
                        conn.execute(
                            "UPDATE generations SET status=? WHERE gen=?",
                            (ORPHAN, gen),
                        )
                        Store.audit(conn, grow["created_ms"], "prepare_recovered_orphan",
                                    group_id=group_id, gen=gen,
                                    detail={"copies": copy_slots})
                        for path in items["durable"].values():
                            if os.path.exists(path):
                                keystore.safe_unlink(path, gdir)
                                report["orphan_files_removed"].append(path)
                        report["abandoned_prepares"].append(
                            {"gen": gen, "copies": copy_slots}
                        )
                else:
                    # active/retired/revoked/superseded/orphan：已提交或已定性，保留
                    report["kept"].append({"gen": gen, "status": grow["status"]})

            # 3) 数据库有 staging 记录但磁盘整个代数目录缺失：登记为孤立准备
            for gen, grow in sorted(db_gens.items()):
                if grow["status"] == STAGING and gen not in on_disk:
                    conn.execute("DELETE FROM prep_ledger WHERE gen=?", (gen,))
                    conn.execute(
                        "UPDATE generations SET status=? WHERE gen=?", (ORPHAN, gen)
                    )
                    report["abandoned_prepares"].append(
                        {"gen": gen, "copies": {"a": False, "b": False}}
                    )
            Store.commit(conn)
        except Exception:
            Store.rollback(conn)
            raise
        finally:
            conn.close()
        return report

    # ------------------------------------------------------------------
    # 只读快照（测试与编排断言用；不含任何密钥材料）
    # ------------------------------------------------------------------
    def snapshot(self, group_id):
        conn = self.store.conn()
        try:
            group = self._get_group(conn, group_id)
            gens = [
                dict(r)
                for r in conn.execute(
                    "SELECT gen, group_id, status, digest_a, digest_b, created_ms,"
                    " published_ms, revoked_ms, deadline_ms, superseded_ms, seed_tag"
                    " FROM generations WHERE group_id=? ORDER BY gen",
                    (group_id,),
                ).fetchall()
            ]
            ledgers = [
                dict(r)
                for r in conn.execute(
                    "SELECT token, gen, committed FROM prep_ledger WHERE group_id=?",
                    (group_id,),
                ).fetchall()
            ]
            receipts = [
                dict(r)
                for r in conn.execute(
                    "SELECT request_id, kind, gen, event_digest, mac, created_ms"
                    " FROM receipts WHERE group_id=? ORDER BY created_ms, request_id",
                    (group_id,),
                ).fetchall()
            ]
            audits = [
                dict(r)
                for r in conn.execute(
                    "SELECT id, event_ms, gen, action, detail FROM audit_log"
                    " WHERE group_id=? ORDER BY id",
                    (group_id,),
                ).fetchall()
            ]
        finally:
            conn.close()
        return {
            "group_id": group_id,
            "next_gen": group["next_gen"],
            "active_gen": group["active_gen"],
            "old_gen": group["old_gen"],
            "old_deadline_ms": group["old_deadline_ms"],
            "generations": gens,
            "prep_ledger": ledgers,
            "receipts": receipts,
            "audit_log": audits,
        }

    @staticmethod
    def dump_json(obj):
        return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
