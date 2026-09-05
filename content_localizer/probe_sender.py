#!/usr/bin/env python3
"""
content_localizer / probe_sender.py —— 把 localize.py 生成的探测 payload 逐条发给网关。

安全约定
--------
- 不带 --send 时：只做“本地回放”，打印每条 payload，**不发任何网络请求**。
- 带 --send 时才真正 POST（url/model/key 默认取自 plan.json，由 localize.py 从日志解析）。

关键：后端（copilot.tencent.com）**只支持流式**。本脚本发送前会强制给每个 body 加
    stream=True, stream_options={"include_usage": True}
并按 SSE 逐行读取，用流里的错误块 / [DONE] / choices 判定 PASS / BLOCK。因此不要再手动
给探测文件里的 stream 传 False——会被这里强制改成 True。

判定口径
--------
- HTTP != 200 且响应体 JSON 带业务 code=11128        -> BLOCK（安全策略拦截）
- HTTP != 200 其它                                  -> ERR(status)
- HTTP 200 的 SSE 流里出现 error 块（code=11128 等）  -> BLOCK（安全策略拦截，走流内错误）
- HTTP 200 的 SSE 流里有 choices(内容/finish_reason) 或正常 [DONE] -> PASS

用法
----
本地回放（默认，不联网）：
    python probe_sender.py probes/plan.json
真正发送（url/model/key 均已写在 plan.json，取自日志，无需再传参）：
    python probe_sender.py probes/plan.json --send
需要覆盖（例如改发到本地网关而非日志里的后端）：
    python probe_sender.py probes/plan.json --send --url http://127.0.0.1:8787/v1/chat/completions --key ...

输出
----
逐条打印探测名 -> PASS / BLOCK / ERR；并汇总到 --result result.json。
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

try:
    import httpx
except ImportError:
    httpx = None

# 后端只支持流式，这是被强制加上的（与 converter.py 一致）
_FORCE_STREAM = True


def load_plan(plan_path: str) -> tuple[dict, dict, dict]:
    with open(plan_path, "r", encoding="utf-8") as f:
        plan = json.load(f)
    base_dir = Path(plan_path).parent
    probes = {}
    for name in sorted(plan.get("probes", [])):
        p = base_dir / f"{name}.json"
        if p.exists():
            probes[name] = json.loads(p.read_text(encoding="utf-8"))
        else:
            probes[name] = {"model": plan.get("model") or plan.get("meta", {}).get("model", ""),
                            "messages": [{"role": "user", "content": f"<missing {name}>"}]}
    # 连接信息优先取 plan.json 顶层；旧版可能只放 meta.conn
    meta = plan.get("meta", {})
    conn = {
        "url": plan.get("url") or meta.get("conn", {}).get("url", ""),
        "model": plan.get("model") or meta.get("model", ""),
        "key": plan.get("key", "") or meta.get("conn", {}).get("key", ""),
    }
    return plan, probes, conn


def _parse_error_payload(obj: dict) -> tuple[int, str]:
    """从 JSON 里提取业务 code 与 msg。兼容两种形态：
       {"code": 11128, "msg": "..."}          （顶层）
       {"error": {"code": 11128, "message": "..."}}（OpenAI 包装）
    """
    if isinstance(obj, dict) and obj.get("error"):
        e = obj["error"]
        code = e.get("code")
        msg = e.get("message") or e.get("msg") or ""
        return (int(code) if isinstance(code, (int, float)) or str(code).isdigit() else 0), str(msg)
    code = obj.get("code")
    msg = obj.get("msg") or obj.get("message") or ""
    return (int(code) if isinstance(code, (int, float)) or str(code).isdigit() else 0), str(msg)


def _http_error_verdict(status: int, text: str) -> tuple[str, str, dict]:
    """HTTP 非 200：把响应体当 JSON 解析，给出 BLOCK / ERR 判定。"""
    code = status
    summary = ""
    extra = {"http": status}
    try:
        obj = json.loads(text)
        bcode, msg = _parse_error_payload(obj)
        if bcode:
            code = bcode
        summary = (f"code={bcode} msg={msg[:120]}") if bcode else text[:120]
        extra["code"] = bcode
        extra["msg"] = msg[:300]
    except Exception:
        summary = text[:160]
    verdict = "BLOCK" if code == 11128 else f"ERR({status})"
    return verdict, summary, extra


def _consume_sse(lines) -> tuple[str, str, dict]:
    """HTTP 200 的 SSE 流：逐行解析 data 块，判定 PASS / BLOCK。

    返回 (verdict, summary, extra)。
    - 流内出现 error 块(带业务 code)      -> BLOCK
    - 出现 choices(含 delta 内容/finish_reason) -> 记为“见内容”，正常 [DONE] 后 PASS
    - 只有干净 [DONE]                    -> PASS
    - 既无 error 也无任何 data            -> ERR(empty)
    """
    saw_content = False
    saw_done = False
    error_code = 0
    error_msg = ""
    n_data = 0
    for raw in lines:
        line = (raw or "").strip()
        if not line.startswith("data:"):
            continue
        payload = line[len("data:"):].strip()
        if not payload:
            continue
        if payload == "[DONE]":
            saw_done = True
            continue
        n_data += 1
        try:
            o = json.loads(payload)
        except Exception:
            continue
        if isinstance(o, dict):
            # 流内错误块
            if o.get("error"):
                bcode, msg = _parse_error_payload(o)
                if bcode:
                    error_code = bcode
                error_msg = msg or error_msg
                continue
            # choices → 有内容或 finish_reason
            chs = o.get("choices")
            if isinstance(chs, list) and chs:
                for ch in chs:
                    if not isinstance(ch, dict):
                        continue
                    delta = ch.get("delta") or {}
                    if isinstance(delta, dict) and (
                        delta.get("content") or delta.get("reasoning_content")
                        or delta.get("tool_calls") or ch.get("finish_reason")
                    ):
                        saw_content = True
            if o.get("usage") is not None and saw_content is False and n_data >= 0:
                # usage 块也算“正常收到响应”，不 panic
                pass
    if error_code:
        verdict = "BLOCK" if error_code == 11128 else f"ERR({error_code})"
        return verdict, f"code={error_code} msg={error_msg[:120]}", {"http": 200, "code": error_code, "msg": error_msg[:300]}
    if saw_content or saw_done or n_data > 0:
        # 有内容或到达 [DONE] → 通过
        return "PASS", f"stream_ok data_events={n_data}", {"http": 200, "data_events": n_data}
    return "ERR(empty)", "no data in SSE", {"http": 200}


def send_one(client, url: str, key: str, body: dict, timeout: float = 60,
             scheme: str = "Bearer") -> tuple[str, str, dict]:
    headers = {"Content-Type": "application/json"}
    if key:
        headers["Authorization"] = f"{scheme} {key}" if scheme else key

    # 后端只支持流式：强制 stream=True，并补上 include_usage
    payload = dict(body)
    if _FORCE_STREAM:
        payload["stream"] = True
        payload.setdefault("stream_options", {"include_usage": True})

    try:
        with client.stream("POST", url, json=payload, headers=headers,
                           timeout=timeout) as r:
            if r.status_code != 200:
                text = r.read().decode("utf-8", "replace")
                return _http_error_verdict(r.status_code, text)
            # 200 -> 按 SSE 逐行读
            return _consume_sse(r.iter_lines())
    except Exception as e:  # noqa: BLE001
        return f"ERR(net)", f"{type(e).__name__}: {e}", {}


def main() -> int:
    ap = argparse.ArgumentParser(description="发送 localize.py 生成的探测（自动流式）；url/model/key 默认取 plan.json，--send 才联网")
    ap.add_argument("plan", help="plan.json 路径（由 localize.py 生成，内含 url/model/key）")
    ap.add_argument("--send", action="store_true", help="真正发起 POST；不带则只打印 payload")
    ap.add_argument("--url", default="", help="覆盖 plan.json 里的 url（例如改发本地网关）")
    ap.add_argument("--key", default="", help="覆盖 plan.json 里的 key")
    ap.add_argument("--model", default="", help="覆盖 plan.json 里的 model")
    ap.add_argument("--only", nargs="*", default=[], help="只发指定探测名（可多个）")
    ap.add_argument("--result", default="", help="把 PASS/BLOCK/ERR 汇总写到该 json")
    ap.add_argument("--timeout", type=float, default=90)
    args = ap.parse_args()

    plan, probes, conn = load_plan(args.plan)
    names = [n for n in probes if (not args.only or n in args.only)]
    if not names:
        print("没有可用的探测。")
        return 1

    # 目标地址/model/key：优先命令行覆盖，否则用 plan.json（取自日志）
    url = args.url or conn["url"]
    model = args.model or conn["model"] or plan.get("meta", {}).get("model", "")
    key = args.key or conn["key"]
    if model:
        for b in probes.values():
            b["model"] = model

    if not args.send or not url:
        print("=== 本地回放模式（不联网）：以下探测本可发送（发送时会被强制 stream=True）===")
        for n in names:
            body = probes[n]
            text = body["messages"][-1].get("content", "") if body.get("messages") else ""
            print(f"  {n}  [model={body.get('model')}] user_len={len(text)}")
            print(f"      messages={len(body.get('messages', []))} tools={'yes' if body.get('tools') else 'no'}")
        print("\n要真正发送，请加 --send；目标 url 默认取 plan.json（已从日志解析）。见文件头。")
        return 0

    if httpx is None:
        print("缺少 httpx，无法发送。先: pip install httpx")
        return 2

    scheme = (conn.get("auth_scheme") or plan.get("meta", {}).get("conn", {}).get("auth_scheme") or "Bearer")
    results = {}
    with httpx.Client(http2=False) as client:
        for n in names:
            body = probes[n]
            print(f"▶ {n} ...", end=" ", flush=True)
            try:
                verdict, summary, extra = send_one(client, url, key, body, args.timeout, scheme=scheme)
                results[n] = {"verdict": verdict, **extra, "summary": summary}
                print(f"{verdict}  {summary}")
            except Exception as e:  # noqa: BLE001
                results[n] = {"verdict": "ERR", "summary": f"{type(e).__name__}: {e}"}
                print(f"ERR  {type(e).__name__}: {e}")
            time.sleep(0.3)

    print("\n===== 汇总 =====")
    for n, r in results.items():
        print(f"  {r['verdict']:<8} {n}")

    if args.result:
        Path(args.result).write_text(json.dumps(results, ensure_ascii=False, indent=2), encoding="utf-8")
        print(f"\n已写入 {args.result}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
