# -*- coding: utf-8 -*-
"""测试密钥材料的确定性派生。

全部密钥均为自行生成的测试字节，不接入任何外部密钥源。
使用标准库 PBKDF2-HMAC-SHA256 从合成种子派生固定长度密钥，
同参数派生结果恒定（离线可重放），不同代数派生结果不同。
"""

import hashlib

_MAGIC = b"local-key-rotation/v1"
_PBKDF2_ITERS = 2000
_KEY_LEN = 32


def derive_key(seed, group_id, gen):
    """根据合成种子、设备组与代数派生 32 字节测试密钥。"""
    if isinstance(seed, str):
        seed = seed.encode("utf-8")
    label = "{}|g{}".format(group_id, gen).encode("utf-8")
    salt = _MAGIC + b"|" + label
    return hashlib.pbkdf2_hmac("sha256", seed, salt, _PBKDF2_ITERS, dklen=_KEY_LEN)


def sha256_hex(data):
    return hashlib.sha256(data).hexdigest()


def hmac_sha256_hex(key, data):
    import hmac

    return hmac.new(key, data, hashlib.sha256).hexdigest()
