# -*- coding: utf-8 -*-
"""独立工作进程入口与进程拉起工具。

用 ``sys.executable -m solution.worker <job.json>`` 在**独立 OS 进程**中执行
prepare/publish 任务，通过 :class:`~solution.syncpoint.SyncPoint` 与编排进程握手，
从而在精确阶段制造真实进程终止（terminate）。

job.json 结构::

    {
      "root": "...", "sync_dir": "...", "op": "prepare|publish",
      "group_id": "...", "seed": "...", "now_ms": 123,
      "replace": false, "token": "...", "expected_active_gen": null,
      "old_valid_ms": 0, "hook": "prepare.mid_first_write"
    }

进程把结果写成单行 JSON 打印到 stdout；若被终止则不会有结果行，由编排方判定。
"""

import json
import os
import subprocess
import sys

from .errors import ServiceError
from .service import KeyRotationService
from .syncpoint import SyncPoint


def make_hook(sync_dir, hook_stage):
    """生成只在指定阶段阻塞的同步钩子。"""
    sp = SyncPoint(sync_dir)

    def hook(stage, tmp_path=None):
        if stage == hook_stage:
            sp.arrive(stage)

    return hook


def run_job(job):
    svc = KeyRotationService(job["root"])
    hook = make_hook(job["sync_dir"], job["hook"]) if job.get("hook") else None
    op = job["op"]
    if op == "prepare":
        return svc.prepare(
            job["group_id"], job["seed"], job["now_ms"],
            replace=bool(job.get("replace", False)), hook=hook,
        )
    if op == "publish":
        return svc.publish(
            job["group_id"], job["token"],
            job.get("expected_active_gen"), int(job.get("old_valid_ms", 0)),
            job["now_ms"], hook=hook,
        )
    raise ValueError("unknown op: %s" % op)


def main(argv=None):
    argv = argv or sys.argv[1:]
    if len(argv) != 1:
        print(json.dumps({"fatal": "usage: python -m solution.worker <job.json>"}))
        return 2
    with open(argv[0], "r", encoding="utf-8") as fh:
        job = json.load(fh)
    try:
        result = run_job(job)
        sys.stdout.write(json.dumps({"ok": True, "result": result}, ensure_ascii=False))
        return 0
    except ServiceError as exc:
        sys.stdout.write(json.dumps(
            {"ok": False, "code": exc.code, "message": str(exc), "details": exc.details},
            ensure_ascii=False,
        ))
        return 1
    except Exception as exc:  # noqa: BLE001 - 子进程需要把任何异常回传编排方
        sys.stdout.write(json.dumps({"ok": False, "code": "E_WORKER_CRASH",
                                     "message": repr(exc)}, ensure_ascii=False))
        return 3


def spawn_worker(job, repo_root):
    """拉起独立工作进程，返回 (Popen, job_path)。"""
    import tempfile

    fd, job_path = tempfile.mkstemp(prefix="worker_job_", suffix=".json",
                                    dir=job.get("sync_dir"))
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(job, fh, ensure_ascii=False)
        # cwd 设为仓库根，保证 `solution` 包可被导入；不依赖 PYTHONPATH 注入
        proc = subprocess.Popen(
            [sys.executable, "-m", "solution.worker", job_path],
            cwd=repo_root,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
    except Exception:
        os.remove(job_path)
        raise
    return proc, job_path


def read_worker_result(proc):
    out, err = proc.communicate(timeout=60)
    text = out.decode("utf-8", errors="replace").strip()
    parsed = json.loads(text) if text else {"ok": False, "code": "E_WORKER_KILLED",
                                            "message": "no output (terminated)"}
    parsed["returncode"] = proc.returncode
    if err:
        parsed["stderr_tail"] = err.decode("utf-8", errors="replace")[-500:]
    return parsed


if __name__ == "__main__":
    sys.exit(main())
