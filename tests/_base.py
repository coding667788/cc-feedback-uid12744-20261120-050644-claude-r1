# -*- coding: utf-8 -*-
"""测试公共夹具：独立临时根目录、合成常量、用例加载。"""

import json
import os
import shutil
import tempfile
import unittest

from solution.errors import ServiceError

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


class _ServiceErrorCtx:
    def __init__(self, case, code):
        self.case = case
        self.code = code

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        if exc is None:
            self.case.fail("expected ServiceError %s but nothing raised" % self.code)
        self.case.assertIsInstance(exc, ServiceError)
        self.case.assertEqual(exc.code, self.code)
        return True


class BaseCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="keyrot-test-",
                                    dir=os.path.join(REPO_ROOT, ".runtime-tmp"))
        self.root = os.path.join(self.tmp, "data")
        self.sync_root = os.path.join(self.tmp, "sync")
        os.makedirs(self.root, exist_ok=True)
        os.makedirs(self.sync_root, exist_ok=True)

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def assertServiceError(self, code):
        return _ServiceErrorCtx(self, code)

    def service(self):
        from solution.service import KeyRotationService
        return KeyRotationService(self.root)

    def sync(self, name):
        from solution.syncpoint import SyncPoint
        path = os.path.join(self.sync_root, name)
        os.makedirs(path, exist_ok=True)
        return SyncPoint(path)


def load_cases():
    with open(os.path.join(REPO_ROOT, "cases.json"), "r", encoding="utf-8") as fh:
        return json.load(fh)["cases"]


def case_by_id(case_id):
    for case in load_cases():
        if case["case_id"] == case_id:
            return case
    raise KeyError(case_id)
