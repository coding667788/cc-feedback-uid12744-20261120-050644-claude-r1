# -*- coding: utf-8 -*-
"""命令行入口：python -m solution --input cases.json --output result.json"""

import argparse
import json
import os
import sys

from .orchestrator import run_cases


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="本地服务签名密钥轮换验证器（离线、标准库、合成输入）"
    )
    parser.add_argument("--input", required=True, help="可重放用例 cases.json 路径")
    parser.add_argument("--output", required=True, help="结果 result.json 输出路径")
    parser.add_argument(
        "--workdir",
        default=None,
        help="运行数据根目录（默认：<输出目录>/runs/<input文件名去后缀>）",
    )
    args = parser.parse_args(argv)

    with open(args.input, "r", encoding="utf-8") as fh:
        payload = json.load(fh)
    cases = payload["cases"] if isinstance(payload, dict) else payload

    out_path = os.path.abspath(args.output)
    os.makedirs(os.path.dirname(out_path) or ".", exist_ok=True)
    if args.workdir:
        base_dir = os.path.abspath(args.workdir)
    else:
        stem = os.path.splitext(os.path.basename(args.input))[0]
        base_dir = os.path.join(os.path.dirname(out_path), "runs", stem)
    os.makedirs(base_dir, exist_ok=True)

    summary = run_cases(cases, base_dir)
    all_passed = all(r["leak_scan"]["passed"] for r in summary["results"])
    doc = {
        "schema": "key-rotation-result/v1",
        "input": os.path.abspath(args.input),
        "workdir": base_dir,
        "all_passed": all_passed,
        "case_count": summary["case_count"],
        "results": summary["results"],
    }
    with open(out_path, "w", encoding="utf-8") as fh:
        json.dump(doc, fh, ensure_ascii=False, indent=2)
    print(json.dumps(
        {"all_passed": all_passed, "case_count": summary["case_count"],
         "output": out_path},
        ensure_ascii=False,
    ))
    return 0 if all_passed else 1


if __name__ == "__main__":
    sys.exit(main())
