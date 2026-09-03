"""X-Device-Token 提供器（Python 侧）。

复用本机 WorkBuddy 桌面端自带的 Turing Shield SDK（原生模块）取得设备风控 Token，
供 workbuddy2api 的全部后端请求注入 `X-Device-Token` 头，避免被上游风控识别为异常客户端。

实现：调用项目根目录的 `turing_helper.js`（Node 脚本），该脚本 require 桌面端的
TuringShieldSDK 原生桥接并返回 token。token 带进程内缓存（默认 10 分钟），避免每次
请求都 fork 一个 Node 进程。

失败（桌面端未安装 / SDK 不支持 / 超时）时返回 None，调用方应优雅降级（不注入该头），
绝不影响主流程。
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import threading
import time
from pathlib import Path

# 项目根目录（admin/ 的上一级）
_ROOT = Path(__file__).resolve().parent.parent
_HELPER = _ROOT / "turing_helper.js"

# token 缓存 TTL（秒）。Turing SDK 自身也有缓存，这里再兜一层避免频繁 fork node。
_CACHE_TTL = 600
_cache: dict = {"token": None, "ts": 0.0}
_lock = threading.Lock()


def _node_bin() -> str | None:
    return shutil.which("node") or shutil.which("node.exe")


def get_device_token(force: bool = False) -> str | None:
    """返回本机设备风控 Token；取不到返回 None。

    force=True 时忽略缓存，重新向 SDK 索取（用于排查 / 测试）。
    """
    now = time.time()
    if not force:
        with _lock:
            if _cache["token"] and now - _cache["ts"] < _CACHE_TTL:
                return _cache["token"]

    node = _node_bin()
    if not node or not _HELPER.is_file():
        raise Exception(f'not found node or helper')


    out = subprocess.run(
        [node, str(_HELPER)],
        capture_output=True, text=True, timeout=25, env=dict(os.environ),
    )

    if out.returncode != 0:
        raise Exception(f'subprocess exit code：{out.returncode} stdout: {out.stdout} stderr: {out.stderr}')

    token: str | None = None
    try:
        result = out.stdout
        data = json.loads(result)
        token = (data.get("token") or "").strip() or None
    except Exception:
        raise Exception(f'parse subprocess stdout error: {result}')

    if token:
        with _lock:
            _cache["token"] = token
            _cache["ts"] = time.time()
    return token


def clear_cache() -> None:
    """清除缓存（进程内）。调试用。"""
    with _lock:
        _cache["token"] = None
        _cache["ts"] = 0.0
