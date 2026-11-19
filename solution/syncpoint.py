# -*- coding: utf-8 -*-
"""Windows 进程同步点（仅标准库，基于目录中的哨兵文件）。

两个以上独立工作进程通过文件系统哨兵完成“到达/放行”握手，
用于在 prepare/publish 的精确阶段制造真实进程终止。

约定：
- ``arrive`` ：工作进程写出 ``<name>.arrived`` 后原地等待 ``<name>.go``；
- ``gate``   ：编排进程等待对方到达，随后选择放行（写 go）或终止；
- ``wait``   ：等待某事件哨兵出现（不写 go）。
"""

import os
import time

from .errors import ServiceError, E_SYNC_TIMEOUT, E_UNSAFE_PATH

_POLL_SECONDS = 0.05
_DEFAULT_TIMEOUT = 30.0


class SyncPoint:
    def __init__(self, dir_path, timeout=_DEFAULT_TIMEOUT):
        self.dir = os.path.abspath(dir_path)
        self.timeout = timeout
        os.makedirs(self.dir, exist_ok=True)

    def _path(self, name, suffix):
        # 名称仅允许字母数字与下划线，杜绝路径穿越
        safe = "".join(ch for ch in name if ch.isalnum() or ch in "._-")
        if not safe or safe != name:
            raise ServiceError(E_UNSAFE_PATH, "bad sync name: %r" % name)
        return os.path.join(self.dir, safe + suffix)

    @staticmethod
    def _touch(path):
        with open(path, "xb"):
            pass

    def _wait_for(self, path, timeout=None):
        deadline = time.monotonic() + (self.timeout if timeout is None else timeout)
        while not os.path.exists(path):
            if time.monotonic() > deadline:
                raise ServiceError(E_SYNC_TIMEOUT, "timeout waiting for %s" % os.path.basename(path))
            time.sleep(_POLL_SECONDS)

    def arrive(self, name):
        """工作进程：报告到达并阻塞，直到编排方放行。"""
        arrived = self._path(name, ".arrived")
        if not os.path.exists(arrived):
            self._touch(arrived)
        self._wait_for(self._path(name, ".go"))

    def gate(self, name, proc=None, action="go"):
        """编排方：等待工作进程到达。

        action:
          - ``go``   ：放行；
          - ``kill`` ：先终止进程，再写 go（进程已终止，go 仅用于清理状态）。
        """
        self._wait_for(self._path(name, ".arrived"))
        if action == "kill" and proc is not None:
            proc.terminate()
            proc.wait(timeout=self.timeout)
        self._touch(self._path(name, ".go"))

    def wait(self, name, timeout=None):
        """只等待哨兵出现，不放行。"""
        self._wait_for(self._path(name, ".arrived"), timeout=timeout)

    def event(self, name):
        """主动写一个事件哨兵。"""
        self._touch(self._path(name, ".arrived"))

    def reset(self, name):
        for suffix in (".arrived", ".go"):
            p = self._path(name, suffix)
            if os.path.exists(p):
                os.remove(p)
