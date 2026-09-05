#!/usr/bin/env python3
"""
workbuddy2api — 把 CodeBuddy / WorkBuddy 的订阅暴露成标准 OpenAI 兼容 API。

原理（直连后端，原生 function calling）：
  - 读取本机已登录的 CodeBuddy 桌面端凭据（auth 文件里的 token / uid / enterpriseId）。
  - 直接转发到 CodeBuddy 后端 `https://copilot.tencent.com/v2/chat/completions`。
    该后端本身就是标准 OpenAI chat/completions 协议（含原生 tools / tool_calls / SSE 流式）。
  - 转换器只做两件事：①注入鉴权 header（Authorization / X-User-Id 等）
    ②在本地 /v1/* 与后端 /v2/* 之间做路径映射与透传（含 Anthropic / Chat / Responses 三种协议）。
  - token 过期时自动调 `/v2/plugin/auth/token/refresh` 刷新，并回写 auth 文件。

跨平台：自动定位 auth 目录（macOS / Windows / Linux）。
依赖：fastapi + uvicorn + httpx（pip install fastapi "uvicorn[standard]" httpx）。

用法：
  python3 converter.py                       # 默认 127.0.0.1:8787
  python3 converter.py --port 9000
  python3 converter.py --api-key mysecret    # 启用客户端鉴权
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import threading
import time
from pathlib import Path
from typing import Optional

import httpx
from fastapi import FastAPI, Header, HTTPException, Request
from fastapi.responses import JSONResponse, StreamingResponse
import uvicorn

# 连接池：减少重复 TLS 握手； MaxIdleConnsPerHost=20 设计。
_HTTP_LIMITS = httpx.Limits(max_connections=100, max_keepalive_connections=20)


def _client_ip_headers(request: Request, purpose: str = "conversation") -> dict:
    """提取真实客户端 IP 与用途/产品头，透传给上游，避免请求用量里 client/agentPurpose 为空。

    真实 WorkBuddy 桌面端：
      - X-Agent-Purpose: "conversation" 用于普通对话
      - X-IDE-Name / X-IDE-Type / X-Product: "WorkBuddy" 用于上游识别 client
    """
    ip = None
    xff = request.headers.get("X-Forwarded-For")
    if xff:
        ip = xff.split(",")[0].strip()
    else:
        real = request.headers.get("X-Real-IP")
        if real:
            ip = real.strip()
        elif request.client:
            ip = request.client.host
    client_name = os.environ.get("ADMIN_UPSTREAM_CLIENT_NAME", "WorkBuddy").strip() or "WorkBuddy"
    h = {
        "X-Agent-Purpose": purpose or "conversation",
        "X-IDE-Name": client_name,
        "X-IDE-Type": client_name,
        "X-Product": client_name,
    }
    if ip:
        h["X-Forwarded-For"] = ip
        h["X-Real-IP"] = ip
        h["X-Client-IP"] = ip
        custom = os.environ.get("ADMIN_UPSTREAM_CLIENT_HEADER", "").strip()
        if custom:
            h[custom] = ip
    return h

try:
    from desensitize import desensitize_body
except ImportError:  # 模块缺失时降级为不脱敏
    def desensitize_body(body, roles=("system",), desensitize_harness_user=False,
                         desensitize_tools=False, compact_harness=False,
                         strip_tool_metadata=False):
        return body

from responses_adapter import (
    responses_request_to_chat,
    ResponsesStreamConverter,
)
from responses_projection import project_responses_chat_body
from anthropic_adapter import (
    anthropic_request_to_chat,
    AnthropicStreamConverter,
)

# ---------------------------------------------------------------------------
# 常量
# ---------------------------------------------------------------------------

BACKEND = "https://copilot.tencent.com"
DEFAULT_DOMAIN = "www.codebuddy.cn"
USER_AGENT = "codebuddy2openai/2.0"

# ---------------------------------------------------------------------------
# 平台相关：定位 auth 目录
# ---------------------------------------------------------------------------

def auth_dirs() -> list[Path]:
    env_dir = os.environ.get("CODEBUDDY_AUTH_DIR")
    if env_dir:
        return [Path(env_dir)]
    home = Path.home()
    plat = sys.platform
    if plat == "darwin":
        return [home / "Library" / "Application Support" / "CodeBuddyExtension" / "Data" / "Public" / "auth"]
    if plat == "win32":
        local = Path(os.environ.get("LOCALAPPDATA", home / "AppData" / "Local"))
        return [local / "CodeBuddyExtension" / "Data" / "Public" / "auth"]
    xdg = Path(os.environ.get("XDG_DATA_HOME", home / ".local" / "share"))
    return [xdg / "CodeBuddyExtension" / "Data" / "Public" / "auth"]


def find_auth_file() -> Path | None:
    for d in auth_dirs():
        if not d.is_dir():
            continue
        # 优先用桌面端实时登录文件（无时间戳后缀），避免被历史备份按字典序抢走
        live = d / "workbuddy-desktop.info"
        if live.is_file():
            return live
        files = sorted(d.glob("*.info"))
        if files:
            return files[0]
    return None


# ---------------------------------------------------------------------------
# Auth 凭据管理（读 + 自动刷新 + 回写）
# ---------------------------------------------------------------------------

def _get_turing_device_token() -> str | None:
    """延迟取本机设备风控 Token；失败返回 None（不影响主流程）。

    放在模块级做懒加载：converter.py 既可作为 admin 的子模块被挂载，也可独立
    `python converter.py` 运行。admin 包不可用时（极少数情况）直接降级为不带该头。
    """
    try:
        from admin.turing_token import get_device_token
        return get_device_token()
    except Exception as error:
        _log(f'获取device token错误： {error}')
        return None


class CredentialManager:
    """从 auth 文件读取凭据；token 临近过期时自动刷新并回写。"""

    def __init__(self, path: Path):
        self.path = path
        self._lock = threading.Lock()
        self._cached: dict | None = None
        self._mtime: float = 0.0

    def _read_raw(self) -> dict:
        with open(self.path, "r", encoding="utf-8") as f:
            return json.load(f)

    def _load_if_stale(self):
        """若文件 mtime 变了（外部刷新过），重新加载缓存。"""
        try:
            mt = self.path.stat().st_mtime
        except OSError:
            return
        if self._cached is None or mt != self._mtime:
            self._cached = self._read_raw()
            self._mtime = mt

    def _session(self) -> dict:
        self._load_if_stale()
        if self._cached is None:
            raise RuntimeError(f"无法读取 auth 文件：{self.path}")
        return self._cached

    def _is_expired(self) -> bool:
        s = self._session()
        expires_at = (s.get("auth") or {}).get("expiresAt") or 0
        # 提前 60s 判定过期
        return time.time() * 1000 >= (expires_at - 60_000)

    def _refresh(self):
        """调后端刷新 token，写回 auth 文件与缓存。"""
        s = self._session()
        auth = s.get("auth") or {}
        headers = self._build_headers_from(auth, s.get("account") or {})
        headers["X-Refresh-Token"] = auth.get("refreshToken", "")
        headers["X-Auth-Refresh-Source"] = "plugin"
        url = f"{BACKEND}/v2/plugin/auth/token/refresh"
        try:
            with httpx.Client(timeout=15, limits=_HTTP_LIMITS) as c:
                r = c.post(url, headers=headers, json={})
            data = r.json()
        except Exception as e:
            raise RuntimeError(f"刷新 token 网络失败：{e}")
        if data.get("code") != 0 or not data.get("data"):
            raise RuntimeError(f"刷新 token 失败：{data.get('msg', data)}")
        new_auth = data["data"]
        # 继承部分字段
        new_auth["domain"] = new_auth.get("domain") or auth.get("domain")
        new_auth["lastRefreshTime"] = int(time.time() * 1000)
        # 计算 expiresAt（若后端没直接给）
        if not new_auth.get("expiresAt") and new_auth.get("expiresIn"):
            new_auth["expiresAt"] = int(time.time() * 1000) + new_auth["expiresIn"] * 1000
        if not new_auth.get("refreshExpiresAt") and new_auth.get("refreshExpiresIn"):
            new_auth["refreshExpiresAt"] = int(time.time() * 1000) + new_auth["refreshExpiresIn"] * 1000
        s["auth"] = new_auth
        # 原子写回
        tmp = self.path.with_suffix(self.path.suffix + ".tmp")
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(s, f, ensure_ascii=False, indent=2)
        os.replace(tmp, self.path)
        self._cached = s
        self._mtime = self.path.stat().st_mtime

    def _build_headers_from(self, auth: dict, account: dict) -> dict:
        domain = auth.get("domain") or DEFAULT_DOMAIN
        h = {
            "Content-Type": "application/json",
            "Accept": "application/json",
            "Authorization": f"Bearer {auth.get('accessToken','')}",
            "X-User-Id": account.get("uid", ""),
            "X-Enterprise-Id": account.get("enterpriseId", ""),
            "X-Tenant-Id": account.get("enterpriseId", ""),
            "X-Domain": domain,
            "User-Agent": USER_AGENT,
        }
        # 风控设备头：与桌面端 Turing Shield 一致，缺失会被上游识别为异常客户端。
        # 取不到（桌面端未安装 / SDK 不支持）时优雅降级为不带该头，不影响主流程。
        tok = _get_turing_device_token()
        if tok:
            _log(f'获取到device token：{tok}')
            h["X-Device-Token"] = tok
        return h

    def get_headers(self, extra: dict | None = None) -> dict:
        """返回带最新 token 的后端请求 header；必要时先刷新。

        extra: 调用方（如 proxy.py）可注入的风控/审计头，例如真实客户端 IP、
               用途标识 X-Agent-Purpose 等。这些头会被 merge 到基础鉴权头之后，
               确保上游请求用量能正确显示 client 与 agentPurpose，降低被风控概率。
        """
        with self._lock:
            if self._is_expired():
                self._refresh()
            s = self._session()
            h = self._build_headers_from(s.get("auth") or {}, s.get("account") or {})
            if extra:
                h.update(extra)
            return h

    def summary(self) -> dict:
        s = self._session()
        auth = s.get("auth") or {}
        acct = s.get("account") or {}
        exp = auth.get("expiresAt", 0)
        return {
            "uid": acct.get("uid"),
            "nickname": acct.get("nickname"),
            "enterpriseName": acct.get("enterpriseName"),
            "token_expires_at": exp,
            "token_expired": self._is_expired(),
        }

    # -----------------------------------------------------------------------
    # 后端资源查询（模型列表、额度）
    # -----------------------------------------------------------------------

    def _request_backend(self, method: str, path: str, json_body: dict | None = None) -> dict:
        """向后端发一个同步请求，返回 {code, msg, requestId, data} 或抛异常。"""
        headers = self.get_headers()
        url = f"{BACKEND}{path}"
        try:
            with httpx.Client(timeout=15, limits=_HTTP_LIMITS) as c:
                if method.upper() == "GET":
                    r = c.get(url, headers=headers)
                else:
                    r = c.post(url, headers=headers, json=json_body or {})
        except Exception as e:
            raise RuntimeError(f"后端请求网络失败 {method} {path}: {e}")
        try:
            data = r.json()
        except Exception as e:
            raise RuntimeError(f"后端返回非 JSON {method} {path} HTTP {r.status_code}: {r.text[:200]}")
        if r.status_code != 200 or data.get("code") != 0:
            raise RuntimeError(f"后端请求失败 {method} {path}: HTTP {r.status_code} / {data.get('msg', data)}")
        return data

    def _request_backend_soft(self, method: str, path: str, json_body: dict | None = None) -> dict:
        """同 `_request_backend`，但后端返回业务 code!=0 时**不抛异常**，原样返回解析后的 dict。

        用于签到领取等场景：领取接口的 1001(已领)/1002(无资格)/1003(活动结束) 等业务码
        属于正常业务结果，需要由调用方根据 code 区分处理，而非当作错误抛掉。
        """
        headers = self.get_headers()
        url = f"{BACKEND}{path}"
        try:
            with httpx.Client(timeout=15, limits=_HTTP_LIMITS) as c:
                if method.upper() == "GET":
                    r = c.get(url, headers=headers)
                else:
                    r = c.post(url, headers=headers, json=json_body or {})
        except Exception as e:
            raise RuntimeError(f"后端请求网络失败 {method} {path}: {e}")
        try:
            return r.json()
        except Exception as e:
            raise RuntimeError(f"后端返回非 JSON {method} {path} HTTP {r.status_code}: {r.text[:200]}")

    def _enterprise_path_key(self) -> str:
        """返回模型列表 endpoint 里的 enterprise 段：personal 或 enterpriseId。"""
        s = self._session()
        acct = s.get("account") or {}
        if acct.get("type") == "personal":
            return "personal"
        eid = acct.get("enterpriseId")
        return eid if eid else "personal"

    @staticmethod
    def _parse_credit_multiplier(credits) -> float | None:
        """把 'x0.05' / 'x0.00 credits' 解析成浮点倍率，解析不出返回 None。"""
        if not credits:
            return None
        m = re.search(r"x\s*([0-9]+(?:\.[0-9]+)?)", str(credits))
        return float(m.group(1)) if m else None

    def fetch_models(self) -> list[dict]:
        """获取后端真实模型列表（含 id/name/credits 等元信息）。

        兼容两种返回结构：
          - 顶层 data.models 为对象数组（每项含 id/name/credits...）；
          - 仅 data.agents[].models 为字符串数组时，回退收集并去重。
        """
        eid = self._enterprise_path_key()
        data = self._request_backend("GET", f"/v2/enterprises/{eid}/models")
        payload = data.get("data", {})
        models = payload.get("models")
        if isinstance(models, list) and models:
            return models
        # 兜底：从 agents 里收集模型名
        collected: list[dict] = []
        for a in payload.get("agents", []) or []:
            for m in a.get("models", []) or []:
                if isinstance(m, dict) and m.get("id"):
                    collected.append(m)
                elif isinstance(m, str) and m:
                    collected.append({"id": m})
        seen = set()
        result: list[dict] = []
        for m in collected:
            mid = m.get("id")
            if mid and mid not in seen:
                seen.add(mid)
                result.append(m)
        if not result:
            raise RuntimeError("后端模型列表格式异常：缺少 data.models 且 agents 中无模型")
        return result

    def fetch_balance(self) -> dict:
        """获取当前账号积分汇总，仅返回总量与剩余（可用积分）。"""
        data = self._request_backend("POST", "/v2/billing/meter/get-user-resource", {})
        resp = data.get("data", {}).get("Response", {}).get("Data", {}) or {}
        total = 0
        total_size = 0
        for a in resp.get("Accounts") or []:
            if a.get("CapacityUnit") != "credits":
                continue
            total += a.get("CapacityRemain") or 0
            total_size += a.get("CapacitySize") or 0
        return {
            "total": total_size,    # 总积分
            "remain": total,        # 可用积分（剩余额度）
        }


# ---------------------------------------------------------------------------
# 模型列表
# ---------------------------------------------------------------------------

DEFAULT_MODELS = [
    "glm-5.2", "glm-5.1", "glm-5v-turbo",
    "kimi-k2.7", "kimi-k2.6", "kimi-k2.5",
    "deepseek-v4-pro", "deepseek-v4-flash",
    "minimax-m3-pay", "hy3-preview-agent", "auto",
]

# 后端资源缓存（TTL，秒）
_RESOURCE_CACHE_TTL = 60.0
_MODELS_CACHE = {"ts": 0.0, "data": None, "error": None}
_BALANCE_CACHE = {"ts": 0.0, "data": None, "error": None}

# 后端请求体里出现过的额外字段（透传时若客户端给了就保留）
PASSTHROUGH_BODY_KEYS = {
    "model", "messages", "tools", "tool_choice", "temperature",
    "max_tokens", "max_completion_tokens", "top_p", "stream",
    "stream_options", "stop", "presence_penalty", "frequency_penalty",
    "n", "response_format", "seed", "user", "reasoning_effort",
    "verbosity", "reasoning_summary",
}

# ---------------------------------------------------------------------------
# FastAPI 应用
# ---------------------------------------------------------------------------

app = FastAPI(title="codebuddy2openai", version="2.0")
CONFIG: dict = {"api_key": "", "cred": None, "log_path": None,
                "desensitize": False, "no_compact": False,
                # 去掉流式 delta 里的空 content:""（GLM 等模型的 reasoning 周期
                # 会被 AI SDK 当成"文本开始"，提前掐断 Thought 周期，产生上百个
                # "Thought for 2ms"。默认开，可用环境变量 WORKBUDDY_STRIP_EMPTY_DELTA=0 关闭）
                "strip_empty_delta": os.environ.get("WORKBUDDY_STRIP_EMPTY_DELTA", "1") not in ("0", "false", "no"),
                # 把流式 reasoning_content 零散分片在网关层合并成"一整段"，统一在首个
                # content/tool_calls/finish delta 之前释放，并从 tool_calls 的 arguments
                # 流中彻底剔除任何混入的 reasoning 字符。解决两类问题：
                #   1) 客户端把每个零散 reasoning 分片渲染成独立 Thought 块 → 几百个
                #      "Thought for 2ms"（上面 strip_empty_delta 只挡空 content，不够）；
                #   2) reasoning token 与 tool_call arguments 互相穿插 → 工具参数 JSON
                #      被截断/污染（Expected '}' / Unterminated string / Expected 'id'...）。
                # 默认开，可用环境变量 WORKBUDDY_COALESCE_REASONING=0 关闭（关闭=原样逐事件转发）。
                "coalesce_reasoning": os.environ.get("WORKBUDDY_COALESCE_REASONING", "1") not in ("0", "false", "no")}
                # cred: CredentialManager | None


# ---------------------------------------------------------------------------
# 日志（写文件）
# ---------------------------------------------------------------------------

_LOG_LOCK = threading.Lock()


def _log(msg: str):
    """写一行日志到 CONFIG['log_path'] 指定的文件（追加，带时间戳）。未设置则丢弃。"""
    path = CONFIG.get("log_path")
    if not path:
        return
    line = f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] {msg}\n"
    try:
        with _LOG_LOCK:
            with open(path, "a", encoding="utf-8") as f:
                f.write(line)
    except OSError:
        pass  # 日志失败不应影响主流程

_LOG_OK_LOCK = threading.Lock()
_LOG_BAD_LOCK = threading.Lock()

def _log_ok(msg: str):
    line = f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] {msg}\n"
    try:
        with _LOG_OK_LOCK:
            with open('ok.log', "a", encoding="utf-8") as f:
                f.write(line)
    except OSError:
        pass  # 日志失败不应影响主流程

def _log_bad(msg: str):
    line = f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] {msg}\n"
    try:
        with _LOG_BAD_LOCK:
            with open('bad.log', "a", encoding="utf-8") as f:
                f.write(line)
    except OSError:
        pass  # 日志失败不应影响主流程

def _truncate(s: str, n: int = 80) -> str:
    s = str(s).replace("\n", " ").strip()
    return s[:n] + ("…" if len(s) > n else "")


def _check_auth(authorization: Optional[str], x_api_key: Optional[str]):
    key = CONFIG["api_key"]
    if not key:
        return
    token = ""
    if authorization and authorization.startswith("Bearer "):
        token = authorization[7:].strip()
    if not token and x_api_key:
        token = x_api_key
    if token != key:
        raise HTTPException(status_code=401, detail={"error": {"message": "invalid api key", "type": "auth_error"}})


def _cred() -> CredentialManager:
    if CONFIG["cred"] is None:
        raise HTTPException(status_code=503, detail={"error": {"message": "未找到登录凭据，请先在桌面端登录 CodeBuddy/WorkBuddy", "type": "auth_error"}})
    return CONFIG["cred"]


def _cached_models(cred) -> list[dict]:
    """带 TTL 缓存的真实模型列表；失败时抛异常由调用方回退。"""
    global _MODELS_CACHE
    now = time.time()
    if _MODELS_CACHE["data"] is not None and now - _MODELS_CACHE["ts"] < _RESOURCE_CACHE_TTL:
        return _MODELS_CACHE["data"]
    try:
        models = cred.fetch_models()
    except Exception as e:
        _MODELS_CACHE["error"] = str(e)
        raise
    _MODELS_CACHE = {"ts": now, "data": models, "error": None}
    return models


def _cached_balance(cred) -> dict:
    """带 TTL 缓存的真实积分额度；失败时抛异常由调用方回退。"""
    global _BALANCE_CACHE
    now = time.time()
    if _BALANCE_CACHE["data"] is not None and now - _BALANCE_CACHE["ts"] < _RESOURCE_CACHE_TTL:
        return _BALANCE_CACHE["data"]
    try:
        balance = cred.fetch_balance()
    except Exception as e:
        _BALANCE_CACHE["error"] = str(e)
        raise
    _BALANCE_CACHE = {"ts": now, "data": balance, "error": None}
    return balance


@app.get("/health")
def health():
    cred = CONFIG["cred"]
    info: dict = {"status": "ok", "platform": sys.platform, "python": sys.version.split()[0],
                  "auth_file": str(find_auth_file() or "(未找到)"), "mode": "direct-proxy (native function calling)"}
    if cred is not None:
        try:
            info["credential"] = cred.summary()
        except Exception as e:
            info["credential_error"] = str(e)
        try:
            info["balance"] = _cached_balance(cred)
        except Exception as e:
            info["balance_error"] = str(e)
    return info


@app.get("/v1/models")
def list_models(authorization: Optional[str] = Header(default=None),
                x_api_key: Optional[str] = Header(default=None, alias="X-Api-Key")):
    _check_auth(authorization, x_api_key)
    cred = CONFIG["cred"]
    if cred is not None:
        try:
            models = _cached_models(cred)
            data = [{
                "id": m.get("id"),
                "object": "model",
                "created": 1700000000,
                "owned_by": "codebuddy",
                "name": m.get("name") or m.get("id"),
                "credits": m.get("credits"),
                "credit_multiplier": cred._parse_credit_multiplier(m.get("credits")),
                "description": m.get("descriptionZh") or m.get("descriptionEn"),
                "supports_images": m.get("supportsImages"),
                "supports_reasoning": m.get("supportsReasoning"),
                "supports_tool_call": m.get("supportsToolCall"),
                "max_input_tokens": m.get("maxInputTokens"),
                "max_output_tokens": m.get("maxOutputTokens"),
                "vendor": m.get("vendor"),
            } for m in models if m.get("id")]
            return {"object": "list", "data": data, "source": "backend"}
        except Exception as e:
            _log(f"获取真实模型列表失败，回退到 DEFAULT_MODELS: {e}")
    data = [{"id": m, "object": "model", "created": 1700000000, "owned_by": "codebuddy"}
            for m in DEFAULT_MODELS]
    return {"object": "list", "data": data, "source": "fallback"}


@app.get("/v1/balance")
def get_balance(authorization: Optional[str] = Header(default=None),
                x_api_key: Optional[str] = Header(default=None, alias="X-Api-Key")):
    _check_auth(authorization, x_api_key)
    cred = _cred()
    try:
        return {"object": "balance", "source": "backend", **_cached_balance(cred)}
    except Exception as e:
        raise HTTPException(status_code=502, detail={"error": {"message": f"获取额度失败：{e}", "type": "upstream_error"}})


@app.post("/v1/chat/completions")
async def chat_completions(request: Request,
                           authorization: Optional[str] = Header(default=None),
                           x_api_key: Optional[str] = Header(default=None, alias="X-Api-Key")):
    _check_auth(authorization, x_api_key)
    cred = _cred()

    try:
        payload = await request.json()
    except Exception as e:
        raise HTTPException(status_code=400, detail={"error": {"message": f"bad json: {e}", "type": "invalid_request_error"}})

    messages = payload.get("messages") or []
    if not messages:
        raise HTTPException(status_code=400, detail={"error": {"message": "messages is required", "type": "invalid_request_error"}})

    # 构造后端 body：只透传已知的合法字段
    client_wants_stream = bool(payload.get("stream"))
    body = {k: payload[k] for k in PASSTHROUGH_BODY_KEYS if k in payload}
    body.setdefault("model", "auto")
    # 后端只支持流式：始终以 stream=True 调后端，非流式由转换器聚合
    body["stream"] = True
    if "stream_options" not in body:
        body["stream_options"] = {"include_usage": True}

    # 可选：脱敏。缓解客户端合规模板（如 Codex CLI / ZCode 注入的说明文字）被后端误判为敏感词。
    # 处理 system / developer 消息、Codex 注入的上下文 user 消息，以及 tools 的 description。
    if CONFIG.get("desensitize"):
        body = desensitize_body(body, roles=("system", "assistant"),
                                desensitize_harness_user=True,
                                desensitize_tools=True,
                                compact_harness=not CONFIG.get("no_compact"),
                                strip_tool_metadata=True)

    # 日志：请求摘要
    model_name = payload.get("model", "auto")
    tool_names = [t.get("function", {}).get("name") for t in (payload.get("tools") or [])
                  if isinstance(t, dict)]
    last_user = _last_user_text(messages)
    rid = os.urandom(4).hex()
    _log(f"[{rid}] ▶ REQUEST {model_name} | stream={client_wants_stream} | msgs={len(messages)}"
         + (f" | tools={tool_names}" if tool_names else "")
         + (f" | last_user={_truncate(last_user, 60)!r}" if last_user else ""))
    # 完整请求体（发往后端的实际内容；若启用脱敏，这里已是脱敏后）
    _log(f"[{rid}] ── REQUEST BODY (发往后端) ──\n{json.dumps(body, ensure_ascii=False, indent=2)}")

    headers = cred.get_headers()
    headers.update(_client_ip_headers(request))
    url = f"{BACKEND}/v2/chat/completions"
    t0 = time.time()

    if client_wants_stream:
        return StreamingResponse(
            _stream_upstream(url, headers, body, model_name, t0, rid),
            media_type="text/event-stream",
            headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
        )

    # 非流式：后端只支持流式，这里把后端 SSE 聚合成单个 chat.completion 响应
    try:
        async with httpx.AsyncClient(timeout=300, limits=_HTTP_LIMITS) as c:
            async with c.stream("POST", url, headers=headers, json=body) as r:
                if r.status_code != 200:
                    raw = await r.aread()
                    _log(f"[{rid}] ✗ HTTP {r.status_code} | {model_name} | {_truncate(raw.decode('utf-8','replace'),200)}")
                    _log(f"[{rid}] ── ERROR BODY ──\n{raw.decode('utf-8','replace')}")
                    raise HTTPException(status_code=r.status_code, detail=_safe_err_raw(raw, r.status_code))
                collected = await _collect_stream(r)
    except HTTPException:
        raise
    except httpx.HTTPError as e:
        _log(f"[{rid}] ✗ 网络错误 | {model_name} | {e}")
        raise HTTPException(status_code=502, detail={"error": {"message": f"upstream error: {e}", "type": "upstream_error"}})
    _log_finish(model_name, t0, collected, rid)
    return JSONResponse(content=collected)


def _last_user_text(messages: list) -> str:
    """取最后一条 user 消息的文本，用于日志预览。"""
    for m in reversed(messages):
        if m.get("role") != "user":
            continue
        content = m.get("content", "")
        if isinstance(content, list):
            for blk in content:
                if isinstance(blk, dict) and blk.get("type") == "text":
                    return str(blk.get("text", ""))
            return ""
        return str(content)
    return ""


def _log_finish(model_name: str, t0: float, result: dict, rid: str = ""):
    """记录一次完成的请求：耗时 / finish_reason / usage / 工具调用 / 审核拦截 + 完整响应。"""
    elapsed = time.time() - t0
    prefix = f"[{rid}] " if rid else ""
    choice = (result.get("choices") or [{}])[0]
    finish = choice.get("finish_reason")
    msg = choice.get("message") or {}
    tcs = msg.get("tool_calls") or []
    usage = result.get("usage") or {}
    tag = ""
    if finish == "content-filter":
        tag = " ⚠️内容审核拦截"
    tc_names = [t.get("function", {}).get("name") for t in tcs]
    _log(f"{prefix}◀ RESPONSE {model_name} | {elapsed:.1f}s | finish={finish}{tag}"
         + (f" | tool_calls={tc_names}" if tc_names else "")
         + f" | tokens={usage.get('total_tokens', '?')}")
    # 完整响应体
    _log(f"{prefix}── RESPONSE BODY ──\n{json.dumps(result, ensure_ascii=False, indent=2)}")


async def _collect_stream(response: httpx.Response) -> dict:
    """消费后端的 OpenAI SSE 流，聚合成单个非流式 chat.completion 对象。

    合并所有 chunk 的 delta（content / tool_calls），并取 usage / finish_reason。
    """
    content_parts: list[str] = []
    # tool_calls: index -> {id, name, arguments(分片拼接)}
    tool_calls: dict[int, dict] = {}
    model: str | None = None
    finish_reason: str | None = None
    usage: dict | None = None

    async for line in response.aiter_lines():
        line = line.strip()
        if not line or not line.startswith("data:"):
            continue
        data = line[5:].strip()
        if data == "[DONE]":
            break
        try:
            chunk = json.loads(data)
        except json.JSONDecodeError:
            continue
        model = chunk.get("model") or model
        if chunk.get("usage"):
            usage = chunk["usage"]
        for choice in chunk.get("choices") or []:
            if choice.get("finish_reason"):
                finish_reason = choice["finish_reason"]
            delta = choice.get("delta") or {}
            if delta.get("content"):
                content_parts.append(delta["content"])
            for tc in delta.get("tool_calls") or []:
                idx = tc.get("index", 0)
                slot = tool_calls.setdefault(idx, {"id": None, "name": None, "arguments": ""})
                if tc.get("id"):
                    slot["id"] = tc["id"]
                fn = tc.get("function") or {}
                if fn.get("name"):
                    slot["name"] = fn["name"]
                if fn.get("arguments"):
                    slot["arguments"] += fn["arguments"]

    tcs = None
    if tool_calls:
        tcs = [
            {"id": v["id"], "type": "function",
             "function": {"name": v["name"], "arguments": v["arguments"]}}
            for _, v in sorted(tool_calls.items())
        ]
        finish_reason = finish_reason or "tool_calls"

    message = {"role": "assistant", "content": "".join(content_parts) or None}
    if tcs:
        message["tool_calls"] = tcs
    return {
        "id": "chatcmpl-" + os.urandom(12).hex(),
        "object": "chat.completion",
        "created": int(time.time()),
        "model": model or "unknown",
        "choices": [{"index": 0, "message": message,
                     "finish_reason": finish_reason or "stop"}],
        "usage": usage or {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0},
    }


def _safe_err_raw(raw: bytes, status: int) -> dict:
    try:
        return json.loads(raw.decode("utf-8", "replace"))
    except Exception:
        return {"error": {"message": raw.decode("utf-8", "replace")[:500], "type": "upstream_error", "code": status}}


async def _stream_upstream(url: str, headers: dict, body: dict,
                           model_name: str = "?", t0: float = 0.0, rid: str = ""):
    """把后端 SSE 原样转发给客户端（后端已是标准 OpenAI SSE，含 tool_calls）。

    同时轻量解析流，统计 finish_reason / tool_calls / usage 用于日志，不阻塞转发。
    完整原始 SSE 累积后落盘到日志（调试用）。

    当 CONFIG['strip_empty_delta'] 开启时，对每个完整 SSE event 做 delta 清洗：
    去掉 `delta.content == ""` / `delta.reasoning_content == ""` 这类"空字段"，
    避免 AI SDK 把空 content 当成"文本已开始"而提前结束 reasoning 周期。

    当 CONFIG['coalesce_reasoning'] 开启时，把所有转发事件再过一遍 _ReasoningCoalescer：
    把零散 reasoning 分片合并成"一整段"再释放，并从 tool_calls 参数流里剔除混入的
    reasoning，避免几百个 "Thought for Xms" 与工具参数 JSON 被截断/污染。
    """
    finish_reason = None
    tool_names: list[str] = []
    usage: dict = {}
    saw_filter = False
    line_buf = _SseLineBuffer()
    raw_parts: list[bytes] = []     # 累积完整原始 SSE
    forwarded_parts: list[bytes] = []  # 累积转发给客户端的 SSE（已清洗）
    prefix = f"[{rid}] " if rid else ""
    strip = bool(CONFIG.get("strip_empty_delta"))
    coal = _ReasoningCoalescer()

    def _process_event_lines(lines: list[bytes]) -> bytes | None:
        """处理一个完整 SSE event（以 \\n\\n 结尾的若干行）。
        返回要转发给客户端的字节；返回 None 表示该 event 应被丢弃。
        """
        if not lines:
            return None
        new_lines: list[bytes] = []
        for ln in lines:
            stripped = ln.lstrip()
            if strip and stripped.startswith(b"data:"):
                payload = stripped[5:].lstrip()
                try:
                    obj = json.loads(payload)
                except (json.JSONDecodeError, ValueError):
                    new_lines.append(ln)
                    continue
                _, new_obj = _sanitize_delta_obj(obj)
                if obj is not new_obj:
                    new_lines.append(b"data: " + json.dumps(
                        new_obj, ensure_ascii=False, separators=(",", ":")
                    ).encode("utf-8"))
                else:
                    new_lines.append(ln)
                continue
            new_lines.append(ln)
        if not new_lines:
            return None
        return b"\n".join(new_lines) + b"\n\n"

    # —— 关键修复：SSE 事件分组状态必须跨 chunk 持久，绝不能每个 aiter_bytes chunk
    #    都重建 sink。此前 `out, feed_line = _make_sink()` 放在 chunk 循环内，每次
    #    chunk 都新建，导致"一个 SSE event 的行没在本 chunk 看到结尾空行就被丢弃"。
    #    当后端一个事件跨多个 TCP chunk（GLM/深度推理模型很常见）时，会随机整段丢掉
    #    data 事件 → tool_call 的 arguments 缺字符/缺字段、reasoning 缺片段，且随网络
    #    时序时好时坏。现在 sink 全局只建一次，靠 _drain() 消费后就清空。
    def _make_sink() -> tuple[list[bytes], callable]:
        """返回 (out_lines, feed_line)。feed_line(line) 累积当前事件的若干行，
        遇到空行表示事件结束，把整事件（清洗后）推入 out_lines。状态跨 chunk 存活。
        """
        out: list[bytes] = []
        evt: list[bytes] = []

        def feed_line(ln: bytes):
            if ln == b"":
                if evt:
                    out.append(_process_event_lines(evt))
                    evt.clear()
            else:
                evt.append(ln)

        def feed_all(lis: list[bytes]):
            for ln in lis:
                feed_line(ln)

        return out, feed_all

    # 全局唯一 sink（out_buf 累积所有已完整、待消费的事件）
    out_buf, feed_all = _make_sink()

    def _emit_sink() -> list[bytes] | None:
        """非阻塞：若 out_buf 非空则记录统计并清空，返回待 yield 的事件列表。"""
        if not out_buf:
            return None
        batch = list(out_buf)   # 快照后清空共享缓冲（不能直接引用再 clear，会清掉 batch）
        out_buf.clear()
        _record_stats(batch)
        return batch

    def _drain() -> list[bytes]:
        """把 out_buf 里所有事件经 reasoning 合并器后转成待转发列表。"""
        out: list[bytes] = []
        for evt in _emit_sink() or []:
            if evt is not None:
                for e in coal.feed(evt):
                    if e is not None:
                        forwarded_parts.append(e)
                        out.append(e)
        return out

    def _record_stats(events: list[bytes | None]):
        nonlocal finish_reason, saw_filter
        for cleaned in events:
            if not cleaned:
                continue
            text_repr = cleaned.decode("utf-8", "replace")
            # 统计用：从清洗后的 event 里解析（finish / tool_calls / usage）
            for el in cleaned.split(b"\n"):
                s = el.lstrip()
                if not s.startswith(b"data:"):
                    continue
                d = s[5:].lstrip()
                if d == b"[DONE]":
                    continue
                try:
                    o = json.loads(d)
                except Exception:
                    continue
                if o.get("usage"):
                    usage.update(o["usage"])
                for ch in o.get("choices") or []:
                    if ch.get("finish_reason"):
                        finish_reason = ch["finish_reason"]
                    for tc in (ch.get("delta") or {}).get("tool_calls") or []:
                        nm = (tc.get("function") or {}).get("name")
                        if nm:
                            tool_names.append(nm)
            # 内容审核拦截常以 content-filter 或特殊中文文案返回
            if "content-filter" in text_repr or "敏感" in text_repr or "审核" in text_repr:
                saw_filter = True

    try:
        async with httpx.AsyncClient(timeout=None, limits=_HTTP_LIMITS) as c:
            async with c.stream("POST", url, headers=headers, json=body) as r:
                if r.status_code != 200:
                    err = await r.aread()
                    _log_bad(f'url: {url} headers: {json.dumps(headers)} json: {json.dumps(body)}')
                    _log_bad(f"status: {r.status_code} error: {err.decode('utf-8','replace')}")
                    _log(f"{prefix}✗ HTTP {r.status_code} | {model_name} | {_truncate(err.decode('utf-8','replace'),200)}")
                    _log(f"{prefix}── ERROR BODY ──\n{err.decode('utf-8','replace')}")
                    yield _err_event(err, r.status_code)
                    return

                _log_ok(f'url: {url} headers: {json.dumps(headers)} json: {json.dumps(body)}')
                async for chunk in r.aiter_bytes():
                    if not chunk:
                        continue
                    raw_parts.append(chunk)
                    lines = line_buf.feed(chunk)
                    feed_all(lines)          # 喂进唯一的持久 sink，不重建
                    for e in _drain():
                        yield e
        # flush：把 line_buf 里残留的完整行喂进 sink，消费最后一个事件
        tail_lines = line_buf.flush()
        if tail_lines:
            feed_all(tail_lines)
            for e in _drain():
                yield e
        # 流提前结束（无结尾空行）：把 line_buf 残余再 flush 一次兜底
        tail2 = line_buf.flush()
        if tail2:
            feed_all(tail2)
            for e in _drain():
                yield e
        # 释放流尾残余 reasoning（若整段 reasoning 后直接 [DONE] 而没有任何推进 delta，
        # 会在上面 [DONE] 事件里触发 flush；这里兜底处理在无 [DONE] 帧就结束的异常流）
        for e in coal.flush():
            if e is not None:
                forwarded_parts.append(e)
                yield e
    except httpx.HTTPError as e:
        _log(f"{prefix}✗ 网络错误 | {model_name} | {e}")
        yield _err_event(str(e).encode(), 502)

    # 流结束：输出完成日志
    elapsed = time.time() - t0 if t0 else 0
    tag = " ⚠️内容审核拦截" if (saw_filter or finish_reason == "content-filter") else ""
    _log(f"{prefix}◀ RESPONSE {model_name} | {elapsed:.1f}s | stream finish={finish_reason}{tag}"
         + (f" | tool_calls={tool_names}" if tool_names else "")
         + f" | tokens={usage.get('total_tokens', '?')}")
    # 完整原始 SSE（后端返回的全部内容）
    _log(f"{prefix}── RESPONSE RAW SSE ──\n{b''.join(raw_parts).decode('utf-8','replace')}")
    if strip:
        _log(f"{prefix}── RESPONSE FORWARDED SSE (sanitized) ──\n{b''.join(forwarded_parts).decode('utf-8','replace')}")


def _safe_err(r: httpx.Response) -> dict:
    try:
        return {"error": r.json()}
    except Exception:
        return {"error": {"message": r.text[:500], "type": "upstream_error", "code": r.status_code}}


def _err_event(msg: bytes, status: int) -> bytes:
    # 以 OpenAI SSE 错误 chunk 形式返回
    import json as _json, time as _time
    chunk = {
        "error": {"message": msg.decode("utf-8", "replace")[:500], "type": "upstream_error", "code": status},
    }
    return f"data: {_json.dumps(chunk, ensure_ascii=False)}\n\n".encode("utf-8")


def _looks_like_content_filter_text(text: str) -> bool:
    text = (text or "").lower()
    return (
        "content-filter" in text
        or "content_filter" in text
        or "敏感内容" in text
        or "内容审核" in text
        or "无法响应您的请求" in text
    )


# ---------------------------------------------------------------------------
# 流式 delta 净化：去掉空 content / 空 reasoning_content 段
# ---------------------------------------------------------------------------
# GLM 等模型的 SSE 经常出现 `{"delta":{"content":"","reasoning_content":"..."}}`。
# AI SDK（Codex CLI / Claude Agent SDK / Vercel AI SDK）只要看到 delta 里出现
# `content` 字段就认为"文本输出已开始"，会立刻结束当前 reasoning 周期；下一
# 个只有 reasoning_content 的 delta 又开启新周期，导致一次回答里出现几百个
# "Thought for 2ms" 块，每块 1 个 token。这里在网关层把"空的 content"和"空
# 的 reasoning_content"都剥掉，让 AI SDK 把它当成纯 reasoning delta。
# ---------------------------------------------------------------------------

# 单个 SSE data 行的 content/reasoning_content 是否空且无其他可见字段
_EMPTY_DELTA_KEYS = ("content", "reasoning_content")


def _is_empty_delta_content(value: str) -> bool:
    return value is None or (isinstance(value, str) and value == "")


def _sanitize_delta_obj(obj: Any) -> tuple[bool, Any]:
    """尝试清洗 SSE data JSON；返回 (changed, new_obj)。

    - 若不是 Chat delta 形状（choices/delta 都在），原样返回 (False, obj)
    - 清洗规则：遍历每个 choice.delta
        * 若 content == "" 且 reasoning_content 非空 → 删 content
        * 若 content == "" 且 reasoning_content 也空 → 整个 delta 若仍含
          tool_calls/role 等"非空"字段就保留，但若 delta 完全空（只两个空字段）→ 整 choice 删
        * reasoning_content == "" 同样处理
    """
    if not isinstance(obj, dict):
        return False, obj
    choices = obj.get("choices")
    if not isinstance(choices, list) or not choices:
        return False, obj
    changed = False
    new_choices: list = []
    for ch in choices:
        if not isinstance(ch, dict):
            new_choices.append(ch)
            continue
        delta = ch.get("delta")
        if not isinstance(delta, dict):
            new_choices.append(ch)
            continue

        # 复制 delta 用于清洗
        new_delta = dict(delta)
        delta_changed = False

        for k in _EMPTY_DELTA_KEYS:
            v = new_delta.get(k)
            if _is_empty_delta_content(v):
                # 仅当存在"非空兄弟字段"时删除这个空字段；
                # 若 delta 里只有这一个空字段，则把整个 choice 也丢掉
                if len(new_delta) == 1:
                    delta = None  # 标记整 choice 删除
                    delta_changed = True
                    break
                del new_delta[k]
                delta_changed = True

        if delta is None:
            # 整个 choice 没有任何有效 delta 字段
            # 但若 choice 仍带 finish_reason（典型收尾 chunk），就保留 finish_reason
            if ch.get("finish_reason"):
                new_choices.append({"index": ch.get("index", 0),
                                    "delta": {},
                                    "finish_reason": ch["finish_reason"]})
                changed = True
            else:
                # 整 choice 丢弃
                changed = True
                continue
        elif delta_changed:
            new_ch = dict(ch)
            new_ch["delta"] = new_delta
            new_choices.append(new_ch)
            changed = True
        else:
            new_choices.append(ch)

    if not changed:
        return False, obj
    new_obj = dict(obj)
    new_obj["choices"] = new_choices
    return True, new_obj


def _sanitize_sse_data(data: str) -> str:
    """清洗单个 SSE data 行（去掉 'data:' 前缀后的 payload）。
    非 JSON / 非 Chat delta 形状 → 原样返回。
    """
    if data == "[DONE]":
        return data
    try:
        obj = json.loads(data)
    except (json.JSONDecodeError, ValueError):
        return data
    changed, new_obj = _sanitize_delta_obj(obj)
    if not changed:
        return data
    # ensure_ascii=False 保留中文，separators 紧凑减少字节
    return json.dumps(new_obj, ensure_ascii=False, separators=(",", ":"))


def _maybe_sanitize_line(line: str) -> str:
    """对单条 SSE 行做"按行"清洗：保留 event:/id:/retry: 等控制行；
    data: 行解析 payload 并清洗后重新拼回 data: 前缀。
    关闭时（CONFIG['strip_empty_delta'] = False）原样返回。
    """
    if not CONFIG.get("strip_empty_delta"):
        return line
    if not line or not line.startswith("data:"):
        return line
    payload = line[5:].lstrip()
    if not payload or payload == "[DONE]":
        return line
    try:
        obj = json.loads(payload)
    except (json.JSONDecodeError, ValueError):
        return line
    _, new_obj = _sanitize_delta_obj(obj)
    if obj is new_obj:
        return line
    return "data: " + json.dumps(new_obj, ensure_ascii=False, separators=(",", ":"))


def _reasoning_text(obj: Any) -> str:
    """从 SSE data JSON 里取第一个 choice.delta 的 reasoning_content（若有）。"""
    try:
        ch = (obj.get("choices") or [{}])[0]
        delta = ch.get("delta") or {}
        r = delta.get("reasoning_content")
        return r if isinstance(r, str) else ""
    except Exception:
        return ""


def _has_non_reasoning_delta(obj: Any) -> bool:
    """该 SSE data 是否携带"会推进对话/工具"的可见内容（content / tool_calls /
    finish_reason / error）。纯 reasoning（或只有 role 收尾）不算。
    """
    if not isinstance(obj, dict):
        return True
    if obj.get("error"):
        return True
    try:
        ch = (obj.get("choices") or [{}])[0]
    except Exception:
        return True
    if not isinstance(ch, dict):
        return True
    delta = ch.get("delta") or {}
    if not isinstance(delta, dict):
        return True
    if ch.get("finish_reason"):
        return True
    # 只要 delta 里出现非空 content / tool_calls，就算"可见推进"
    c = delta.get("content")
    if isinstance(c, str) and c:
        return True
    if delta.get("tool_calls"):
        return True
    if delta.get("refusal"):
        return True
    return False


def _remove_reasoning_from_delta(obj: Any) -> Any:
    """把某个推进 delta 里夹带的 reasoning_content 整段剥掉，返回新对象。

    用于 content 起笔帧或 tool_calls 帧与 reasoning 同帧的情形：推理 token 若混在
    tool_calls 的 arguments 里会让参数 JSON 截断/坏掉；若混在 content 起笔帧里会让
    客户端误判"文本已开始"而提前结束 Thought 周期。剥走后，调用方负责把这段
    reasoning 单独以纯 reasoning delta 释放。无 reasoning 时原样返回同一对象。
    """
    if not isinstance(obj, dict):
        return obj
    choices = obj.get("choices")
    if not isinstance(choices, list) or not choices:
        return obj
    changed = False
    new_choices: list = []
    for ch in choices:
        if not isinstance(ch, dict):
            new_choices.append(ch)
            continue
        delta = ch.get("delta")
        if not isinstance(delta, dict):
            new_choices.append(ch)
            continue
        rc = delta.get("reasoning_content")
        if not isinstance(rc, str) or not rc:
            new_choices.append(ch)
            continue
        new_delta = dict(delta)
        new_delta.pop("reasoning_content", None)
        new_ch = dict(ch)
        new_ch["delta"] = new_delta
        new_choices.append(new_ch)
        changed = True
    if not changed:
        return obj
    new_obj = dict(obj)
    new_obj["choices"] = new_choices
    return new_obj


def _encode_sse_chunk(obj: Any) -> bytes:
    return b"data: " + json.dumps(obj, ensure_ascii=False, separators=(",", ":")).encode("utf-8") + b"\n\n"


def _parse_sse_data_objects(evt: bytes) -> list[Any]:
    """把一个完整 SSE 帧（可能含多行 data:）解析成 payload 对象列表。非 data 行忽略。"""
    out: list[Any] = []
    for ln in evt.split(b"\n"):
        s = ln.lstrip()
        if not s.startswith(b"data:"):
            continue
        payload = s[5:].strip()
        if not payload or payload in (b"[DONE]", b"[done]"):
            out.append(None)  # 占位表示 [DONE]
            continue
        try:
            out.append(json.loads(payload))
        except (json.JSONDecodeError, ValueError):
            # 无法解析的数据行原样透传，不参与合并（交给客户端容错）
            out.append(payload)
    return out


class _ReasoningCoalescer:
    """网关层"推理合并器"：把流式 reasoning 零散分片攒成一段，在首个真正推进对话
    （content / tool_calls / finish_reason / [DONE]）的 delta 之前整段释放，并从
    tool_calls 的参数流里剔除混入的 reasoning。用法：

        c = _ReasoningCoalescer()
        for evt_bytes in c.feed(one_cleaned_event_bytes):  yield evt_bytes
        for evt_bytes in c.flush():                          yield evt_bytes

    feed 每来一个事件返回"应当转发给客户端"的事件列表；flush 在流结束时调用以清空
    残余 reasoning。注意合并只在同一个 choice 的 reasoning 连续段内发生，遇到
    content / tool_calls 会先 flush 当前 reasoning，因此不会把不同用途的内容拼错。
    """

    __slots__ = ("_rbuf", "_rcount")

    def __init__(self) -> None:
        self._rbuf: list[str] = []
        self._rcount = 0  # 已攒的 reasoning 分片数（用于判断是否真的发生过穿插）

    def _flush_reasoning(self) -> list[bytes]:
        if not self._rbuf:
            return []
        text = "".join(self._rbuf)
        self._rbuf = []
        self._rcount = 0
        if not text:
            return []
        chunk = {"choices": [{"index": 0, "delta": {"reasoning_content": text}}]}
        return [_encode_sse_chunk(chunk)]

    def feed(self, evt: bytes) -> list[bytes]:
        if not evt:
            return []
        if not CONFIG.get("coalesce_reasoning"):
            # 关闭：原样透传（不合并、不重组）
            return [evt]

        objs = _parse_sse_data_objects(evt)
        if not objs:
            return [evt]

        merged: list[bytes] = []
        for o in objs:
            if o is None:
                # [DONE]：先 flush 残余 reasoning，再原样放 [DONE]
                merged += self._flush_reasoning()
                merged.append(b"data: [DONE]\n\n")
                continue
            if not isinstance(o, dict):
                # 无法 JSON 解析的原样行：合并推理时保守忽略该行内容，避免错乱
                merged += self._flush_reasoning()
                merged.append(evt)  # 整帧原样补发一次（很少触发）
                continue

            rc = _reasoning_text(o)                 # 本 delta 的 reasoning（若有）
            advancing = _has_non_reasoning_delta(o)  # 是否带 content/tool_calls/finish

            # 纯 reasoning（不带任何推进内容）→ 入缓冲，攒成一段
            if rc and not advancing:
                self._rbuf.append(rc)
                self._rcount += 1
                continue

            if advancing:
                # content / tool_calls / finish 到来：先把已攒 reasoning 整段释放。
                merged += self._flush_reasoning()
                if rc:
                    # 该推进 delta 自身还夹带 reasoning（如 tool_calls 与 reasoning 同帧，
                    # 或 content 起笔帧带 reasoning）：剥走，避免污染参数流或让客户端把
                    # "推理继续"误判成"文本已开始"而再次开启 Thought 块。
                    self._rbuf.append(rc)
                    self._rcount += 1
                    merged += self._flush_reasoning()
                    o = _remove_reasoning_from_delta(o)
                merged.append(_encode_sse_chunk(o))
                continue

            # 其余（如 role:"assistant" 收尾等无可见推进、无 reasoning 的标记 delta）
            # 原样转发，不参与合并，保持协议帧完整。
            merged.append(_encode_sse_chunk(o))
        return merged

    def flush(self) -> list[bytes]:
        return self._flush_reasoning()


class _SseLineBuffer:
    """字节级 SSE 行缓冲解析器。

    上游可能把一行 SSE 拆到多个 TCP chunk 里发（GLM 流经常出现），所以不能
    假设每次 aiter_bytes 拿到的是完整行。每调一次 feed(chunk) 就把内部
    缓冲里能切的完整行（以 \n 分隔）切出来，返回行列表（不含换行符）。
    """

    __slots__ = ("_buf",)

    def __init__(self) -> None:
        self._buf = bytearray()

    def feed(self, chunk: bytes) -> list[bytes]:
        if not chunk:
            return []
        self._buf.extend(chunk)
        out: list[bytes] = []
        while True:
            idx = self._buf.find(b"\n")
            if idx < 0:
                break
            line = bytes(self._buf[:idx])
            del self._buf[:idx + 1]
            if line.endswith(b"\r"):
                line = line[:-1]
            out.append(line)
        return out

    def flush(self) -> list[bytes]:
        if not self._buf:
            return []
        line = bytes(self._buf)
        self._buf.clear()
        if line.endswith(b"\r"):
            line = line[:-1]
        return [line]


def _chat_body_desensitize(body: dict, *, force_compact: bool = False) -> dict:
    if not CONFIG.get("desensitize"):
        return body
    return desensitize_body(
        body,
        roles=("system", "developer"),
        desensitize_harness_user=True,
        desensitize_tools=True,
        compact_harness=(force_compact or not CONFIG.get("no_compact")),
        strip_tool_metadata=True,
    )


async def _post_backend_once(url: str, headers: dict, body: dict) -> tuple[int, bytes]:
    async with httpx.AsyncClient(timeout=120, limits=_HTTP_LIMITS) as c:
        async with c.stream("POST", url, headers=headers, json=body) as r:
            chunks: list[bytes] = []
            async for chunk in r.aiter_bytes():
                if chunk:
                    chunks.append(chunk)
            return r.status_code, b"".join(chunks)


async def _post_backend_with_filter_retry(url: str, headers: dict, body: dict,
                                          rid: str = "", model_name: str = "?") -> tuple[int, bytes, dict]:
    prefix = f"[{rid}] " if rid else ""
    status, raw = await _post_backend_once(url, headers, body)
    text = raw.decode("utf-8", "replace")
    if status == 200 and _looks_like_content_filter_text(text) and CONFIG.get("desensitize") and CONFIG.get("no_compact"):
        retry_body = _chat_body_desensitize(body, force_compact=True)
        _log(f"{prefix}↻ RESPONSES {model_name} | content filter detected, retry with compact harness")
        _log(f"{prefix}── RESPONSES RETRY CHAT BODY ──\n{json.dumps(retry_body, ensure_ascii=False, indent=2)}")
        retry_status, retry_raw = await _post_backend_once(url, headers, retry_body)
        retry_text = retry_raw.decode("utf-8", "replace")
        if retry_status == 200 and not _looks_like_content_filter_text(retry_text):
            return retry_status, retry_raw, retry_body
    return status, raw, body


# ---------------------------------------------------------------------------
# Responses API 端点（Codex CLI 兼容）
# ---------------------------------------------------------------------------

@app.post("/v1/responses")
async def create_response(request: Request,
                          authorization: Optional[str] = Header(default=None),
                          x_api_key: Optional[str] = Header(default=None, alias="X-Api-Key")):
    """OpenAI Responses API 兼容端点。

    Codex CLI 使用 Responses API（wire_api = "responses"）而非 Chat Completions。
    本端点接收 Responses 格式请求，转换为 Chat 格式发往后端，再将后端的 Chat SSE
    转换为 Responses 语义事件流返回。
    """
    _check_auth(authorization, x_api_key)
    cred = _cred()

    try:
        payload = await request.json()
    except Exception as e:
        raise HTTPException(status_code=400, detail={"error": {"message": f"bad json: {e}", "type": "invalid_request_error"}})

    # 转换请求：Responses → Chat
    try:
        chat_body = responses_request_to_chat(payload)
    except Exception as e:
        raise HTTPException(status_code=400, detail={"error": {"message": f"request conversion error: {e}", "type": "invalid_request_error"}})

    chat_body, projection_stats = project_responses_chat_body(chat_body)
    chat_body.setdefault("model", "auto")
    chat_body["stream"] = True
    if "stream_options" not in chat_body:
        chat_body["stream_options"] = {"include_usage": True}

    chat_body = _chat_body_desensitize(chat_body)

    client_wants_stream = payload.get("stream", True)  # Codex CLI 默认 stream
    model_name = payload.get("model", "auto")
    rid = os.urandom(4).hex()
    _log(f"[{rid}] ▶ RESPONSES {model_name} | stream={client_wants_stream} | input_items={len(payload.get('input', []))}")
    _log(
        f"[{rid}] ── RESPONSES PROJECTION ── "
        f"mode={projection_stats.get('mode')} "
        f"| msgs {projection_stats.get('original_messages')}→{projection_stats.get('projected_messages')} "
        f"| chars {projection_stats.get('original_message_chars')}→{projection_stats.get('projected_message_chars')} "
        f"| tools {projection_stats.get('original_tools')}→{projection_stats.get('projected_tools')} "
        f"| tool_chars {projection_stats.get('original_tool_chars')}→{projection_stats.get('projected_tool_chars')} "
        f"| summarized_history={projection_stats.get('summarized_history_messages', 0)} "
        f"| dropped_harness={projection_stats.get('dropped_harness_messages', 0)} "
        f"| anchor_user={projection_stats.get('anchor_user_preserved', False)}"
    )
    _log(f"[{rid}] ── RESPONSES → CHAT BODY ──\n{json.dumps(chat_body, ensure_ascii=False, indent=2)}")

    headers = cred.get_headers()
    headers.update(_client_ip_headers(request))
    url = f"{BACKEND}/v2/chat/completions"
    t0 = time.time()

    if client_wants_stream:
        return StreamingResponse(
            _stream_responses(url, headers, chat_body, model_name, t0, rid),
            media_type="text/event-stream",
            headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
        )

    # 非流式：聚合后端 SSE → 非流式 Response 对象
    try:
        status_code, raw, final_body = await _post_backend_with_filter_retry(url, headers, chat_body, rid, model_name)
        if status_code != 200:
            _log(f"[{rid}] ✗ HTTP {status_code} | {model_name} | {_truncate(raw.decode('utf-8','replace'),200)}")
            raise HTTPException(status_code=status_code, detail=_safe_err_raw(raw, status_code))
        converter = ResponsesStreamConverter(model=model_name)
        for line in raw.decode("utf-8", "replace").splitlines():
            line = _maybe_sanitize_line(line)
            converter.feed_line(line)
        chat_body = final_body
    except HTTPException:
        raise
    except httpx.HTTPError as e:
        _log(f"[{rid}] ✗ 网络错误 | {model_name} | {e}")
        raise HTTPException(status_code=502, detail={"error": {"message": f"upstream error: {e}", "type": "upstream_error"}})

    result = converter.get_nonstream_response()
    elapsed = time.time() - t0
    _log(f"[{rid}] ◀ RESPONSES {model_name} | {elapsed:.1f}s")
    _log(f"[{rid}] ── RESPONSE OBJ ──\n{json.dumps(result, ensure_ascii=False, indent=2)}")
    return JSONResponse(content=result)


async def _stream_responses(url: str, headers: dict, body: dict,
                            model_name: str = "?", t0: float = 0.0, rid: str = ""):
    """消费后端 Chat SSE，实时转换为 Responses API 事件流输出。"""
    converter = ResponsesStreamConverter(model=model_name)
    prefix = f"[{rid}] " if rid else ""

    try:
        status_code, raw, _ = await _post_backend_with_filter_retry(url, headers, body, rid, model_name)
        if status_code != 200:
            _log(f"{prefix}✗ HTTP {status_code} | {model_name} | {_truncate(raw.decode('utf-8','replace'),200)}")
            error_evt = {"type": "error", "error": {"message": raw.decode('utf-8','replace')[:500], "code": status_code}}
            yield f"data: {json.dumps(error_evt, ensure_ascii=False)}\n\n".encode("utf-8")
            return
        raw_sse_lines = []
        for line in raw.decode("utf-8", "replace").splitlines():
            if line.strip():
                raw_sse_lines.append(line)
            line = _maybe_sanitize_line(line)
            events = converter.feed_line(line)
            if events:
                yield events.encode("utf-8")
    except httpx.HTTPError as e:
        _log(f"{prefix}✗ 网络错误 | {model_name} | {e}")
        error_evt = {"type": "error", "error": {"message": str(e)[:500], "code": 502}}
        yield f"data: {json.dumps(error_evt, ensure_ascii=False)}\n\n".encode("utf-8")
        return

    # 发送收尾事件
    finish_events = converter.finish()
    if finish_events:
        yield finish_events.encode("utf-8")

    elapsed = time.time() - t0 if t0 else 0
    _log(f"{prefix}◀ RESPONSES {model_name} | {elapsed:.1f}s | stream done")
    _log(f"{prefix}── RESPONSES RAW SSE ──\n" + "\n".join(raw_sse_lines[-30:]))


# ---------------------------------------------------------------------------
# Anthropic Messages API 端点（Claude Code / CC Switch 兼容）
# ---------------------------------------------------------------------------

@app.post("/v1/messages")
async def create_message(request: Request,
                         authorization: Optional[str] = Header(default=None),
                         x_api_key: Optional[str] = Header(default=None, alias="X-Api-Key")):
    """Anthropic Messages API 兼容端点。

    Claude Code / CC Switch 使用 Anthropic Messages API（POST /v1/messages）。
    本端点接收 Anthropic 格式请求，转换为 Chat 格式发往后端，再将后端的 Chat SSE
    转换为 Anthropic SSE 事件流返回。
    """
    _check_auth(authorization, x_api_key)
    cred = _cred()

    try:
        payload = await request.json()
    except Exception as e:
        raise HTTPException(status_code=400, detail={"error": {"message": f"bad json: {e}", "type": "invalid_request_error"}})

    # 将 Anthropic 格式消息、工具规范在进入后端前统一转换为 OpenAI Chat 格式。
    messages = payload.get("messages") or []
    if not messages:
        raise HTTPException(status_code=400, detail={"error": {"message": "messages is required", "type": "invalid_request_error"}})

    try:
        chat_body = anthropic_request_to_chat(payload)
    except Exception as e:
        raise HTTPException(status_code=400, detail={"error": {"message": f"request conversion error: {e}", "type": "invalid_request_error"}})

    chat_body.setdefault("model", "auto")
    chat_body["stream"] = True
    if "stream_options" not in chat_body:
        chat_body["stream_options"] = {"include_usage": True}

    if CONFIG.get("desensitize"):
        chat_body = desensitize_body(chat_body, roles=("system", "developer"),
                                     desensitize_harness_user=True,
                                     desensitize_tools=True,
                                     compact_harness=not CONFIG.get("no_compact"),
                                     strip_tool_metadata=True)

    model_name = payload.get("model", "auto")
    chat_messages = chat_body.get("messages", [])
    rid = os.urandom(4).hex()
    _log(f"[{rid}] ▶ ANTHROPIC {model_name} | msgs={len(chat_messages)} | anthropic_msgs={len(messages)}")
    _log(f"[{rid}] ── ANTHROPIC → CHAT BODY ──\n{json.dumps(chat_body, ensure_ascii=False, indent=2)}")

    headers = cred.get_headers()
    headers.update(_client_ip_headers(request))
    url = f"{BACKEND}/v2/chat/completions"
    t0 = time.time()

    return StreamingResponse(
        _stream_anthropic(url, headers, chat_body, model_name, t0, rid),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


async def _stream_anthropic(url: str, headers: dict, body: dict,
                            model_name: str = "?", t0: float = 0.0, rid: str = ""):
    """消费后端 OpenAI Chat SSE，实时转换为 Anthropic Messages SSE 事件流。"""
    converter = AnthropicStreamConverter(model=model_name)
    prefix = f"[{rid}] " if rid else ""

    try:
        async with httpx.AsyncClient(timeout=None, limits=_HTTP_LIMITS) as c:
            async with c.stream("POST", url, headers=headers, json=body) as r:
                if r.status_code != 200:
                    err = await r.aread()
                    _log(f"{prefix}✗ HTTP {r.status_code} | {model_name} | {_truncate(err.decode('utf-8','replace'),200)}")
                    error_evt = {"type": "error", "error": {"message": err.decode('utf-8','replace')[:500], "type": "api_error", "code": r.status_code}}
                    yield f"event: error\ndata: {json.dumps(error_evt, ensure_ascii=False)}\n\n".encode("utf-8")
                    return
                async for line in r.aiter_lines():
                    line = _maybe_sanitize_line(line)
                    events = converter.feed_line(line)
                    if events:
                        yield events.encode("utf-8")
    except httpx.HTTPError as e:
        _log(f"{prefix}✗ 网络错误 | {model_name} | {e}")
        error_evt = {"type": "error", "error": {"message": str(e)[:500], "type": "api_error", "code": 502}}
        yield f"event: error\ndata: {json.dumps(error_evt, ensure_ascii=False)}\n\n".encode("utf-8")
        return

    finish_events = converter.finish()
    if finish_events:
        yield finish_events.encode("utf-8")

    elapsed = time.time() - t0 if t0 else 0
    _log(f"{prefix}◀ ANTHROPIC {model_name} | {elapsed:.1f}s | stream done")


@app.post("/v1/messages/count_tokens")
async def count_tokens(request: Request,
                       authorization: Optional[str] = Header(default=None),
                       x_api_key: Optional[str] = Header(default=None, alias="X-Api-Key")):
    """Anthropic token 计数端点（stub）。

    Claude Code 可能在发送消息前调用此端点。
    返回一个简单估算值，不做实际 token 计数。
    """
    _check_auth(authorization, x_api_key)
    return {"input_tokens": 0}


# ---------------------------------------------------------------------------
# 启动
# ---------------------------------------------------------------------------

def preflight() -> bool:
    af = find_auth_file()
    sys.stderr.write("==== 预检 ====\n")
    sys.stderr.write(f"平台      : {sys.platform}\n")
    sys.stderr.write(f"Python    : {sys.version.split()[0]}\n")
    sys.stderr.write(f"后端      : {BACKEND} (直连，原生 function calling)\n")
    sys.stderr.write(f"登录文件  : {af or '(未找到)'}\n")
    if auth_dirs():
        sys.stderr.write(f"已查目录  : {', '.join(str(d) for d in auth_dirs())}\n")
    ok = True
    if af is None:
        sys.stderr.write("\n[警告] 未找到登录文件。请在桌面端完成登录（CodeBuddy/WorkBuddy）。\n")
        ok = False
    else:
        try:
            cm = CredentialManager(af)
            info = cm.summary()
            sys.stderr.write(f"账号      : {info.get('nickname')} / {info.get('enterpriseName')}\n")
            sys.stderr.write(f"token过期 : {'是(将自动刷新)' if info['token_expired'] else '否'}\n")
        except Exception as e:
            sys.stderr.write(f"[警告] 读取凭据失败：{e}\n")
            ok = False
    sys.stderr.write("================\n")
    return ok


def main():
    ap = argparse.ArgumentParser(description="CodeBuddy -> OpenAI 兼容转换器（直连后端）")
    ap.add_argument("--host", default="0.0.0.0")
    ap.add_argument("--port", type=int, default=8787)
    ap.add_argument("--api-key", default=os.environ.get("CODEBUDDY2OPENAI_KEY", ""),
                    help="可选：要求客户端携带的 API key（默认不校验）")
    ap.add_argument("--log", default=None, metavar="PATH",
                    help="开启日志并写到该文件（如 --log converter.log 或 --log /tmp/cb.log）。"
                         "不传则不记日志。")
    ap.add_argument("--desensitize", action="store_true",
                    help="启用脱敏：对 system 消息里的合规模板敏感词（DoS/exploit/credential 等）"
                         "插入零宽空格，缓解被后端内容审核误拦。默认关闭。")
    ap.add_argument("--no-compact", action="store_true",
                    help="配合 --desensitize 使用：跳过 system/harness 压缩，仅做零宽脱敏。"
                         "保留原始 system prompt 完整内容（如 Claude Code 的行为指令），"
                         "但审核误拦风险略高于默认压缩模式。")
    ap.add_argument("--skip-check", action="store_true", help="跳过启动预检")
    args = ap.parse_args()
    CONFIG["api_key"] = args.api_key
    CONFIG["desensitize"] = args.desensitize
    CONFIG["no_compact"] = args.no_compact
    # --log 直接指定文件路径即开启；不传则不记
    CONFIG["log_path"] = args.log if args.log else os.environ.get("CODEBUDDY2OPENAI_LOG")
    af = find_auth_file()
    CONFIG["cred"] = CredentialManager(af) if af else None

    if not args.skip_check:
        preflight()

    sys.stderr.write(f"\n✅ 监听 http://{args.host}:{args.port}（直连后端，原生 function calling）\n")
    sys.stderr.write("   GET  /v1/models\n")
    sys.stderr.write("   GET  /v1/balance            (当前账号可用积分额度)\n")
    sys.stderr.write("   POST /v1/chat/completions   (原生 tools/tool_calls，支持流式)\n")
    sys.stderr.write("   POST /v1/responses          (Responses API，Codex CLI 兼容)\n")
    sys.stderr.write("   POST /v1/messages           (Anthropic API，Claude Code / CC Switch 兼容)\n")
    sys.stderr.write("   GET  /health\n")
    if args.api_key:
        sys.stderr.write("   鉴权已启用（API key 已设置）\n")
    if CONFIG["log_path"]:
        sys.stderr.write(f"   日志      : {CONFIG['log_path']}\n")
    if args.desensitize:
        mode = "零宽脱敏 + 保留全文" if args.no_compact else "零宽脱敏 + 压缩摘要"
        sys.stderr.write(f"   脱敏      : 已启用（{mode}）\n")
    sys.stderr.write("按 Ctrl+C 退出。\n\n")

    # 启动时写一条标记
    _log(f"==== converter 启动 ====")

    uvicorn.run(app, host=args.host, port=args.port, log_level="warning")


if __name__ == "__main__":
    main()
