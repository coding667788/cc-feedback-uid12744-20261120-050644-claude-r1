# -*- coding: utf-8 -*-
"""统一错误码定义。

服务层所有可预期失败都抛出 :class:`ServiceError`，其 ``code`` 为稳定错误码，
便于 ``cases.json`` 与自动化测试断言具体结果。
"""


class ServiceError(Exception):
    """带稳定错误码的业务异常。"""

    def __init__(self, code, message="", **details):
        self.code = code
        self.details = details
        super().__init__(message or code)

    def to_dict(self):
        return {"code": self.code, "message": str(self), "details": self.details}


# 设备组不存在
E_GROUP_UNKNOWN = "E_GROUP_UNKNOWN"
# 设备组已存在
E_GROUP_EXISTS = "E_GROUP_EXISTS"
# 密钥材料不可用（两个副本均缺失/损坏，或提交前校验失败）——失败关闭
E_MATERIAL_UNAVAILABLE = "E_MATERIAL_UNAVAILABLE"
# 旧代已超过验签截止时间
E_OLD_GEN_EXPIRED = "E_OLD_GEN_EXPIRED"
# 旧代已吊销，不得再用于验签
E_REVOKED_GEN = "E_REVOKED_GEN"
# 代数已吊销/已发布，不能重新发行
E_GEN_NOT_STAGING = "E_GEN_NOT_STAGING"
# 摘要与数据库记录不一致（副本损坏或被篡改）
E_DIGEST_MISMATCH = "E_DIGEST_MISMATCH"
# 已存在预发布代且未允许替换
E_STAGING_EXISTS = "E_STAGING_EXISTS"
# 预发布令牌已被另一进程的替换准备作废
E_TOKEN_SUPERSEDED = "E_TOKEN_SUPERSEDED"
# 未知预发布令牌
E_TOKEN_UNKNOWN = "E_TOKEN_UNKNOWN"
# 发布基准与当前活动代不一致（基准已被其他进程替换）
E_BASELINE_STALE = "E_BASELINE_STALE"
# 同一 request_id 携带了不同请求体
E_REQUEST_CONFLICT = "E_REQUEST_CONFLICT"
# 目标文件已存在（同代两写者的文件系统层防护）
E_FILE_ALREADY_EXISTS = "E_FILE_ALREADY_EXISTS"
# 非法/越权路径
E_UNSAFE_PATH = "E_UNSAFE_PATH"
# 等待进程同步点超时
E_SYNC_TIMEOUT = "E_SYNC_TIMEOUT"
# 十六进制密钥参数非法
E_BAD_KEY_HEX = "E_BAD_KEY_HEX"
