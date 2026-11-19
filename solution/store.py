# -*- coding: utf-8 -*-
"""SQLite 元数据存储。

数据库只保存代数、状态与两个副本的期望 SHA-256 摘要，**绝不保存任何密钥字节**。
写事务一律使用 BEGIN IMMEDIATE，配合 WAL 与 busy_timeout，
保证两个以上独立工作进程并发准备/发布时的串行化与可恢复性。
"""

import os
import sqlite3

SCHEMA = """
CREATE TABLE IF NOT EXISTS groups_meta (
    group_id        TEXT PRIMARY KEY,
    created_ms      INTEGER NOT NULL,
    next_gen        INTEGER NOT NULL,
    active_gen      INTEGER,
    old_gen         INTEGER,
    old_deadline_ms INTEGER
);

CREATE TABLE IF NOT EXISTS generations (
    gen            INTEGER PRIMARY KEY,
    group_id       TEXT NOT NULL,
    status         TEXT NOT NULL,
    token          TEXT,
    digest_a       TEXT NOT NULL,
    digest_b       TEXT NOT NULL,
    created_ms     INTEGER NOT NULL,
    published_ms   INTEGER,
    revoked_ms     INTEGER,
    deadline_ms    INTEGER,
    superseded_ms  INTEGER,
    seed_tag       TEXT NOT NULL,
    FOREIGN KEY(group_id) REFERENCES groups_meta(group_id)
);

CREATE TABLE IF NOT EXISTS prep_ledger (
    token          TEXT PRIMARY KEY,
    gen            INTEGER NOT NULL UNIQUE,
    group_id       TEXT NOT NULL,
    committed      INTEGER NOT NULL,
    created_ms     INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS receipts (
    request_id   TEXT PRIMARY KEY,
    group_id     TEXT NOT NULL,
    kind         TEXT NOT NULL,
    gen          INTEGER NOT NULL,
    event_digest TEXT NOT NULL,
    mac          TEXT NOT NULL,
    created_ms   INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS audit_log (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    event_ms   INTEGER NOT NULL,
    group_id   TEXT,
    gen        INTEGER,
    action     TEXT NOT NULL,
    detail     TEXT NOT NULL
);
"""

BUSY_TIMEOUT_MS = 10_000


def connect(db_path):
    os.makedirs(os.path.dirname(os.path.abspath(db_path)), exist_ok=True)
    conn = sqlite3.connect(db_path, timeout=BUSY_TIMEOUT_MS / 1000.0, isolation_level=None)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    conn.execute("PRAGMA synchronous=FULL")
    conn.execute("PRAGMA busy_timeout=%d" % BUSY_TIMEOUT_MS)
    conn.executescript(SCHEMA)
    return conn


class Store:
    """每个方法使用短连接；写操作在 IMMEDIATE 事务内完成并提交。"""

    def __init__(self, db_path):
        self.db_path = db_path

    def conn(self):
        return connect(self.db_path)

    @staticmethod
    def begin_immediate(conn):
        conn.execute("BEGIN IMMEDIATE")

    @staticmethod
    def commit(conn):
        conn.execute("COMMIT")

    @staticmethod
    def rollback(conn):
        try:
            conn.execute("ROLLBACK")
        except sqlite3.Error:
            pass

    @staticmethod
    def audit(conn, now_ms, action, group_id=None, gen=None, detail=None):
        """审计日志只允许记录非敏感元数据。"""
        import json

        payload = detail or {}
        # 双保险：拒绝把明显的密钥材料写进日志
        banned = {"key", "material", "secret", "mac_key", "raw"}
        if any(k in payload for k in banned):
            raise ValueError("refuse to log sensitive key material")
        conn.execute(
            "INSERT INTO audit_log(event_ms, group_id, gen, action, detail) VALUES (?,?,?,?,?)",
            (int(now_ms), group_id, gen, action, json.dumps(payload, sort_keys=True, separators=(",", ":"))),
        )
