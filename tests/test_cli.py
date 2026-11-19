# -*- coding: utf-8 -*-
"""CLI 端到端测试：python -m solution --input cases.json --output result.json"""

import json
import os
import subprocess
import sys

from tests._base import REPO_ROOT, BaseCase


class CliTest(BaseCase):
    def test_cli_runs_all_cases_and_writes_result(self):
        """以仓库根为 cwd 运行 -m，工作目录受本题控制，无第三方输入目录。"""
        out_path = os.path.join(self.tmp, "result.json")
        workdir = os.path.join(self.tmp, "runs")
        proc = subprocess.run(
            [sys.executable, "-m", "solution",
             "--input", os.path.join(REPO_ROOT, "cases.json"),
             "--output", out_path, "--workdir", workdir],
            cwd=REPO_ROOT, capture_output=True, text=True, timeout=300,
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertTrue(os.path.exists(out_path))
        with open(out_path, "r", encoding="utf-8") as fh:
            doc = json.load(fh)
        self.assertEqual(doc["schema"], "key-rotation-result/v1")
        self.assertTrue(doc["all_passed"])
        self.assertEqual(doc["case_count"], len(doc["results"]))
        # 每个用例都无泄漏，且都实际执行了步骤
        for result in doc["results"]:
            self.assertTrue(result["leak_scan"]["passed"])
            self.assertGreater(len(result["steps"]), 1)

    def test_cli_worker_subprocess_is_importable(self):
        """worker 模块可独立启动并对缺参作业返回稳定错误码。"""
        bad_job = os.path.join(self.tmp, "bad.json")
        with open(bad_job, "w", encoding="utf-8") as fh:
            json.dump({"op": "prepare"}, fh)
        proc = subprocess.run(
            [sys.executable, "-m", "solution.worker", bad_job],
            cwd=REPO_ROOT, capture_output=True, text=True, timeout=60,
        )
        self.assertNotEqual(proc.returncode, 0)
        payload = json.loads(proc.stdout.strip())
        self.assertFalse(payload["ok"])

    def test_cases_file_is_self_contained_and_deterministic(self):
        """cases.json 结构自洽：每个 case 都有 group_id 与步骤，ID 唯一。"""
        with open(os.path.join(REPO_ROOT, "cases.json"), "r", encoding="utf-8") as fh:
            doc = json.load(fh)
        ids = [c["case_id"] for c in doc["cases"]]
        self.assertEqual(len(ids), len(set(ids)))
        required = {"case_id", "group_id", "steps"}
        for case in doc["cases"]:
            self.assertTrue(required.issubset(case.keys()))
            step_ids = [s["id"] for s in case["steps"]]
            self.assertEqual(len(step_ids), len(set(step_ids)))
