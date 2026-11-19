# -*- coding: utf-8 -*-
"""本地不可变密钥库：每个代数两个独立冗余副本。

目录布局（本题专用，全部文件由本模块创建）::

    <root>/groups/<安全组名>/gen<代数>.a.bin
    <root>/groups/<安全组名>/gen<代数>.b.bin
    写一半的临时文件：gen<代数>.<a|b>.bin.<pid>.<seq>.tmp

规则：
- 正式副本一经原子替换落盘即为不可变文件，任何流程都不会再以写模式打开；
- 每次落盘后立即重读并做 SHA-256 摘要校验，校验不过即失败关闭并清理；
- 读者只接受摘要与数据库期望一致的同代副本，绝不跨代回退；
- 正式文件已存在时拒绝覆盖（同代两写者的文件系统层防护）。
"""

import os
import re
import threading

from .errors import ServiceError
from .errors import (
    E_DIGEST_MISMATCH,
    E_FILE_ALREADY_EXISTS,
    E_MATERIAL_UNAVAILABLE,
    E_UNSAFE_PATH,
)
from .kdf import sha256_hex

_DURABLE_RE = re.compile(r"^gen(\d+)\.([ab])\.bin$")
_TMP_RE = re.compile(r"^gen(\d+)\.([ab])\.bin\..+\.tmp$")
_GROUP_RE = re.compile(r"^[A-Za-z0-9_-]{1,64}$")

_tmp_seq_lock = threading.Lock()
_tmp_seq = 0


def _next_tmp_seq():
    global _tmp_seq
    with _tmp_seq_lock:
        _tmp_seq += 1
        return _tmp_seq


def safe_group_name(group_id):
    if not isinstance(group_id, str) or not _GROUP_RE.match(group_id):
        raise ServiceError(E_UNSAFE_PATH, "unsafe group id: %r" % (group_id,))
    return group_id


def group_dir(root, group_id, create=False):
    safe_group_name(group_id)
    base = os.path.abspath(root)
    path = os.path.abspath(os.path.join(base, "groups", group_id))
    # 目录穿越 containment 校验
    if os.path.commonpath([base, path]) != base:
        raise ServiceError(E_UNSAFE_PATH, "path escapes keystore root")
    if create:
        os.makedirs(path, exist_ok=True)
    return path


def copy_paths(root, group_id, gen):
    gdir = group_dir(root, group_id)
    return {
        "a": os.path.join(gdir, "gen%d.a.bin" % gen),
        "b": os.path.join(gdir, "gen%d.b.bin" % gen),
    }


def _fsync_dir(path):
    # Windows 上目录句柄 fsync 支持有限，best-effort；os.replace 在 NTFS 同目录内为原子操作
    try:
        flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
        fd = os.open(path, flags)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
    except (OSError, AttributeError):
        pass


def atomic_write(path, data, mid_write_hook=None):
    """安全落盘：独占临时文件 -> 写全量并 fsync -> 原子替换 -> 目录 fsync。

    ``mid_write_hook(tmp_path)`` 在写入前半段并 flush/fsync 之后、
    关闭文件之前触发，用于在真实独立进程中制造“写一半文件”终止。
    返回正式文件路径。
    """
    if os.path.exists(path):
        raise ServiceError(E_FILE_ALREADY_EXISTS, "immutable target already exists: %s" % os.path.basename(path))

    tmp = "%s.%d.%d.tmp" % (path, os.getpid(), _next_tmp_seq())
    try:
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_BINARY)
        try:
            half = max(1, len(data) // 2)
            os.write(fd, data[:half])
            os.fsync(fd)
            if mid_write_hook is not None:
                mid_write_hook(tmp)
            os.write(fd, data[half:])
            os.fsync(fd)
        finally:
            os.close(fd)
        os.replace(tmp, path)  # 同目录 NTFS 原子重命名
        _fsync_dir(os.path.dirname(path))
    except ServiceError:
        raise
    except Exception:
        if os.path.exists(tmp):
            try:
                os.remove(tmp)
            except OSError:
                pass
        raise
    return path


def write_gen_copies(root, group_id, gen, material, expected_digest, hooks=None):
    """写两个独立不可变副本并逐个重读校验。

    hooks: 可选 callable(stage: str, tmp_path: str|None)，阶段：
      ``prepare.mid_first_write`` / ``prepare.after_first_write`` /
      ``prepare.after_both_written``。
    全部成功后返回两个正式路径；任一失败失败关闭并清理本次产物。
    """
    hooks = hooks or (lambda stage, tmp_path=None: None)
    paths = copy_paths(root, group_id, gen)
    gdir = group_dir(root, group_id, create=True)
    created = []
    try:
        for slot in ("a", "b"):
            target = paths[slot]
            if os.path.exists(target):
                raise ServiceError(
                    E_FILE_ALREADY_EXISTS,
                    "copy %s of gen %d already exists" % (slot, gen),
                )

            def mid_hook(tmp_path, _slot=slot):
                if _slot == "a":
                    hooks("prepare.mid_first_write", tmp_path)

            atomic_write(target, material, mid_write_hook=mid_hook)
            created.append(target)
            # 落盘后立即重读校验，确认磁盘字节与期望摘要一致
            with open(target, "rb") as fh:
                on_disk = fh.read()
            if sha256_hex(on_disk) != expected_digest:
                raise ServiceError(E_DIGEST_MISMATCH, "post-write digest mismatch on copy %s" % slot)
            if slot == "a":
                hooks("prepare.after_first_write", None)
        hooks("prepare.after_both_written", None)
        return paths
    except Exception:
        # 失败关闭：只清理本次已创建的正式副本与本代临时文件
        for p in created:
            if os.path.exists(p):
                try:
                    os.remove(p)
                except OSError:
                    pass
        for name in os.listdir(gdir):
            m = _TMP_RE.match(name)
            if m and int(m.group(1)) == gen:
                try:
                    os.remove(os.path.join(gdir, name))
                except OSError:
                    pass
        raise


def read_verified_copy(root, group_id, gen, slot, expected_digest):
    """读取单个副本并校验摘要。

    返回 bytes；文件不存在返回 None；存在但摘要不符抛 E_DIGEST_MISMATCH。
    """
    path = copy_paths(root, group_id, gen)[slot]
    if not os.path.exists(path):
        return None
    with open(path, "rb") as fh:
        data = fh.read()
    if sha256_hex(data) != expected_digest:
        raise ServiceError(
            E_DIGEST_MISMATCH,
            "copy %s of gen %d failed digest check" % (slot, gen),
            slot=slot,
            gen=gen,
        )
    return data


def read_best_copy(root, group_id, gen, expected_digest):
    """同代冗余读取：A 坏了可用 B；两个都缺失/损坏则失败关闭。

    绝不回退到其他代数，保证不会返回混合材料。
    返回 (slot, material)。
    """
    problems = {}
    for slot in ("a", "b"):
        try:
            data = read_verified_copy(root, group_id, gen, slot, expected_digest)
        except ServiceError as exc:
            problems[slot] = exc.code
            continue
        if data is not None:
            return slot, data
        problems[slot] = "missing"
    raise ServiceError(
        E_MATERIAL_UNAVAILABLE,
        "no verified copy for gen %d" % gen,
        gen=gen,
        copies=problems,
    )


def list_gen_files(gdir):
    """扫描组目录，返回 {gen: {"durable": {slot: path}, "tmp": [path]}}。"""
    result = {}
    if not os.path.isdir(gdir):
        return result
    for name in os.listdir(gdir):
        m = _DURABLE_RE.match(name)
        if m:
            gen, slot = int(m.group(1)), m.group(2)
            result.setdefault(gen, {"durable": {}, "tmp": []})["durable"][slot] = os.path.join(gdir, name)
            continue
        m = _TMP_RE.match(name)
        if m:
            gen = int(m.group(1))
            result.setdefault(gen, {"durable": {}, "tmp": []})["tmp"].append(os.path.join(gdir, name))
    return result


def safe_unlink(path, gdir):
    """只允许删除组目录内、且文件名符合本模块命名规则的文件。"""
    gdir_abs = os.path.abspath(gdir)
    target = os.path.abspath(path)
    if os.path.commonpath([gdir_abs, target]) != gdir_abs:
        raise ServiceError(E_UNSAFE_PATH, "refuse to unlink outside group dir")
    name = os.path.basename(target)
    if not (_DURABLE_RE.match(name) or _TMP_RE.match(name)):
        raise ServiceError(E_UNSAFE_PATH, "refuse to unlink unrecognized file: %s" % name)
    if os.path.exists(target):
        os.remove(target)
