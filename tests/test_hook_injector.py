"""Tests for hook_injector process selection."""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from pyweixin import hook_injector


class _Proc:
    def __init__(self, info):
        self.info = info


def test_find_wechat_pid_prefers_active_main(monkeypatch):
    procs = [
        _Proc({"pid": 101, "name": "Weixin.exe", "cmdline": ["Weixin.exe", "--type=renderer"], "status": "running", "create_time": 1.0}),
        _Proc({"pid": 102, "name": "Weixin.exe", "cmdline": ["Weixin.exe"], "status": "stopped", "create_time": 2.0}),
        _Proc({"pid": 103, "name": "Weixin.exe", "cmdline": ["Weixin.exe"], "status": "running", "create_time": 3.0}),
    ]
    monkeypatch.setattr(hook_injector.psutil, "process_iter", lambda *_: iter(procs))
    assert hook_injector.find_wechat_pid() == 103


def test_find_wechat_pid_falls_back_when_all_stopped(monkeypatch):
    procs = [
        _Proc({"pid": 201, "name": "Weixin.exe", "cmdline": ["Weixin.exe"], "status": "stopped", "create_time": 1.0}),
        _Proc({"pid": 202, "name": "Weixin.exe", "cmdline": ["Weixin.exe"], "status": "stopped", "create_time": 2.0}),
    ]
    monkeypatch.setattr(hook_injector.psutil, "process_iter", lambda *_: iter(procs))
    assert hook_injector.find_wechat_pid() == 202

