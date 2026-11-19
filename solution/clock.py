# -*- coding: utf-8 -*-
"""确定性虚拟时钟。

测试需要精确控制“旧代验签截止”等时间边界，因此服务层不直接读取系统时钟，
所有时间戳由调用方显式传入（epoch 毫秒）。编排器持有本虚拟时钟，
子进程在任务派发时获得时间快照，时钟只在编排器中前进，保证可重放。
"""


class VirtualClock:
    def __init__(self, start_ms=1_700_000_000_000):
        self._now = int(start_ms)

    def now_ms(self):
        return self._now

    def advance(self, delta_ms):
        if delta_ms < 0:
            raise ValueError("clock cannot move backwards")
        self._now += int(delta_ms)
        return self._now
