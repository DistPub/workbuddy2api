#!/usr/bin/env python3
"""
content_localizer / localize.py  —— 本地二分定位：哪段请求内容触发了后端审查拦截

背景
----
workbuddy2api 网关把请求转发到 copilot.tencent.com，后端有时返回
HTTP 400 code 11128（“Illegal API invocation from an unapproved channel /
请求被安全策略拦截”）。这份工具**只读日志、生成候选探测 payload**，
本身不发任何外呼。你用它把“坏请求”切成最小片段，逐个交给网关去试，
从而定位到底是【整条通道被风控】还是【请求里某段内容触发了关键词审查】。

用法
----
1) 生成探测 payload（默认动作，不联网）：
       python localize.py --log ../bad.log --req 23 --out probes/
   → 生成 control / system / per-message / halve 等探测 JSON + plan.json + plan.md
   plan.json 顶层会写入该请求的 url（日志里的后端地址）、model、key（Authorization: Bearer），
   发送时无需再手动传参。

2) 真正逐条发送（可选；url/model/key 已在 plan.json 里）：
       python probe_sender.py probes/plan.json --send
   想改发本地网关而非日志后端时再覆盖：--url http://127.0.0.1:8787/v1/chat/completions --key ...
   probe_sender 是**独立**脚本，本地化工具本身不做任何外呼（不加 --send 只本地回放）。

退出码/输出目录
---------------
默认把 payload 写到 --out（缺省 ./probes），每条一个 .json，外加：
  - plan.json    含 url/model/key + 探测清单（给 probe_sender.py 用）
  - plan.md      建议探测顺序与判定逻辑
  - report.txt   该坏请求的文本结构摘要（每条消息 id / 角色 / 长度 / 命中词提示）
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from pathlib import Path

# 触发审查的“风险语义”候选取样（仅用于 report 高亮提示，不是定位依据）
RISK_HINTS = [
    "delete from", "truncate", "drop ", "grant ", "mysqldump", "dump ",
    "password", "root123", "DB_PASSWORD", "superadmin", "sudo", "chmod",
    "/bin/", "bash", "sh -c", "curl ", "wget ", "nc ", "frida", "inject",
    "payload", "credential", "sandbox", "proxy", "bypass", "escalat",
    "exploit", "malware", "illegal", "attack", "hack", "kill", "hook",
    "raw sql", "delete", "恢复", "删除", "清理", "脚本", "脱敏", "绕过",
]

# 若单条消息文本超过该长度，额外生成“对半切”子探测，便于手工二分
HALVE_THRESHOLD = 8_000


def parse_request(log_path: str, req_idx: int) -> tuple[dict, str, dict]:
    """从 bad.log 里取第 req_idx 条被拒请求。bad.log 每 2 行一组：REQ 行 + RESP 行。

    返回 (body, 行首预览, conn)。conn 从 REQ 行头里解析出发起连接所需的信息：
      url   —— 后端地址（copilot.tencent.com/v2/chat/completions）
      model —— 请求体里的 model
      key   —— Authorization: Bearer <token>（若存在），或 X-Api-Key
      这样 probe_sender 可直接用 plan.json 里的 conn，无需手动传 --url/--model/--key。
    """
    with open(log_path, "r", encoding="utf-8", errors="replace") as f:
        lines = f.readlines()
    line_no = req_idx * 2
    if line_no >= len(lines):
        raise SystemExit(f"bad.log 只有 {len(lines)//2} 条被拒请求，--req 超出范围。")
    line = lines[line_no]
    if not (line.startswith("[") and "url:" in line[:200]):
        raise SystemExit(f"第 {req_idx} 行不是请求行，可能日志结构不是每 2 行一组。")
    m = re.search(r" json: (.*)\n$", line, re.S)
    if not m:
        raise SystemExit("未能在该行定位到 ' json: {...}' 请求体。")
    body = json.loads(m.group(1))

    head = line[: line.find(" json: ")]
    url = re.search(r"url: (\S+)", head)
    key = ""
    if re.search(r'"Authorization": "Bearer ([^"]+)"', head):
        key = re.search(r'"Authorization": "Bearer ([^"]+)"', head).group(1)
    elif re.search(r'"X-Api-Key": "([^"]+)"', head):
        key = re.search(r'"X-Api-Key": "([^"]+)"', head).group(1)
    conn = {
        "url": url.group(1) if url else "",
        "key": key,
        "auth_scheme": "Bearer",  # 发送时拼成 Authorization: Bearer <key>
    }
    return body, line[:200], conn


def text_of(msg: dict) -> str:
    c = msg.get("content")
    if isinstance(c, str):
        return c
    if isinstance(c, list):
        out = []
        for p in c:
            if isinstance(p, dict) and p.get("type") == "text":
                out.append(str(p.get("text", "")))
        return "\n".join(out)
    return ""


def hint_hits(text: str) -> list[str]:
    low = text.lower()
    return [h for h in RISK_HINTS if h.lower() in low]


def message_texts(req: dict) -> list[dict]:
    """返回所有消息的轻量描述列表：{i, role, len, hint}（含 system）。"""
    rows = []
    for i, mm in enumerate(req.get("messages", [])):
        t = text_of(mm)
        hits = hint_hits(t)
        rows.append({
            "i": i, "role": mm.get("role", "?"),
            "len": len(t),
            "tool_call_id": mm.get("tool_call_id", ""),
            "hints": hits[:6],
            "preview": t[:80].replace("\n", " "),
        })
    return rows


def _deepcopy_msgs(msgs: list) -> list:
    """深度拷贝消息列表（content 为 str，其它字段直接复制，避免改坏原对象）。"""
    return [dict(m) for m in msgs]


def _turn_prefixes(msgs: list) -> list[tuple[list, int]]:
    """把原始消息序列切成“完整回合”前缀。

    回合边界规则（保持 assistant tool_calls 与 tool 响应对齐全）：
      - 新回合从 system 或 user 消息开始；
      - 回合内允许任意条 assistant(tool_calls) / tool；
      - 直到遇到下一条 system / user 才算回合结束。
    返回 [(该回合结束后的完整消息前缀, 结尾消息下标), ...]，
    每项都是一条可发送的、结构完整的历史前缀。首项固定含 system(msg0)。
    """
    prefixes: list[tuple[list, int]] = []
    # 起始：只含 system（msg0），保证“什么都不带历史”也能发
    start = 0
    if msgs and msgs[0].get("role") == "system":
        prefixes.append((_deepcopy_msgs(msgs[:1]), 0))
        start = 1
    cur: list[dict] = _deepcopy_msgs(msgs[:start])
    for i in range(start, len(msgs)):
        r = msgs[i].get("role")
        if r in ("system", "user") and cur:
            # 上一个回合结束
            prefixes.append((_deepcopy_msgs(cur), i - 1))
            cur.append(dict(msgs[i]))
        else:
            cur.append(dict(msgs[i]))
    if cur:
        prefixes.append((_deepcopy_msgs(cur), len(msgs) - 1))
    return prefixes


def build_probes(req: dict, req_idx: int, max_msgs: int = 200, conn: dict | None = None) -> dict:
    """构造一套“二分定位”探测集。

    判定模型（内容触发假设下）：内容审查作用于整个请求文本。我们通过
    缩小 payload 看“哪一条/哪一段消息缺席后就不再被拦”，从而锁定触发点。
    """
    model = req.get("model", "deepseek-v4-flash")
    sys_text = ""
    msgs = req.get("messages", [])
    # system 消息（一般 msg0）
    if msgs and msgs[0].get("role") == "system":
        sys_text = text_of(msgs[0])
        non_sys = msgs[1:]
    else:
        non_sys = msgs
    # 工具定义（用于“system+tools”探测）
    tools = req.get("tools", [])

    probes = {}  # name -> body(dict)

    # 0) 干净对照：只发“hi”。若这也被拦 → 大概率通道/账号级风控。
    probes["00_control_hi"] = {
        "model": model, "stream": True, "stream_options": {"include_usage": True}, "max_tokens": 32,
        "messages": [{"role": "user", "content": "hi"}],
    }
    # 0b) 空白对照（空 user，测最小长度是否触发）
    probes["00b_control_blank"] = {
        "model": model, "stream": True, "stream_options": {"include_usage": True}, "max_tokens": 32,
        "messages": [{"role": "user", "content": "ok"}],
    }
    # 1) 仅 system 文本
    if sys_text:
        probes["01_system_only"] = {
            "model": model, "stream": True, "stream_options": {"include_usage": True}, "max_tokens": 32,
            "messages": [{"role": "user", "content": _cap(sys_text)}],
        }
        # 1b) system + 工具定义（接近真实请求的最小形态）
        if tools:
            probes["02_system_plus_tools"] = {
                "model": model, "stream": True, "stream_options": {"include_usage": True}, "max_tokens": 32,
                "tools": tools,
                "messages": [{"role": "user", "content": "hi"}],
            }
        # 1c) 隔离探测：把 system 内容放进真正的 system 角色（+/- tools）
        #     判定“是 system 角色本身，还是 system+tools 的 agent 形态”触发
        probes["03_system_role_no_tools"] = {
            "model": model, "stream": True, "stream_options": {"include_usage": True}, "max_tokens": 32,
            "messages": [{"role": "system", "content": _cap(sys_text)}],
        }
        if tools:
            probes["04_system_hi_plus_tools"] = {
                "model": model, "stream": True, "stream_options": {"include_usage": True}, "max_tokens": 32,
                "tools": tools,
                "messages": [{"role": "system", "content": "hi"}],
            }
            probes["05_system_content_plus_tools"] = {
                "model": model, "stream": True, "stream_options": {"include_usage": True}, "max_tokens": 32,
                "tools": tools,
                "messages": [{"role": "system", "content": _cap(sys_text)}],
            }

    # 2) 逐条消息切片：把每条消息文本单独作为 user content 探测（内容触发假设）
    #    命中风险词的消息优先放前面（更可能是触发点）。
    candidates = []
    for r in message_texts(req):
        if r["role"] == "system":
            continue
        if not r["hints"] and r["len"] < 400 and r["role"] in ("user",):
            continue  # 短且无风险词的真实小输入先跳过，保留大的
        candidates.append(r)
    # 排序：有风险词优先，其次按长度降序
    candidates.sort(key=lambda r: (not bool(r["hints"]), -(r["len"])))
    for n, r in enumerate(candidates[:max_msgs]):
        tag = "T" if r["hints"] else "M"
        name = f"10_{tag}{n:02d}_msg{r['i']:03d}_{r['role']}"
        probes[name] = {
            "model": model, "stream": True, "stream_options": {"include_usage": True}, "max_tokens": 32,
            "messages": [{"role": "user", "content": _cap(text_of(req["messages"][r["i"]]))}],
        }
        # 超大消息额外生成“对半切”探测，便于手工二分
        if r["len"] > HALVE_THRESHOLD:
            t = text_of(req["messages"][r["i"]])
            probes[f"{name}__halfA"] = {
                "model": model, "stream": True, "stream_options": {"include_usage": True}, "max_tokens": 32,
                "messages": [{"role": "user", "content": t[: len(t) // 2]}],
            }
            probes[f"{name}__halfB"] = {
                "model": model, "stream": True, "stream_options": {"include_usage": True}, "max_tokens": 32,
                "messages": [{"role": "user", "content": t[len(t) // 2:]}],
            }

    # ------------------------------------------------------------------
    # 3) 结构保留探测：原始顺序、按“完整回合”切割，逐段累加历史。
    #    —— 若“单条都不拦、完整请求拦”，触发通常是多轮/组合/意图语义的，
    #       这种只能在保留原始 role 顺序与 tool_calls 线程的前提下定位。
    # ------------------------------------------------------------------
    tools = req.get("tools", [])
    cum = _turn_prefixes(msgs)          # 每个“完整回合”结束后一条前缀
    for k, (cut_msgs, boundary) in enumerate(cum):
        name = f"20_cum{k:02d}_upto{boundary:03d}"
        probes[name] = {
            "model": model, "stream": True, "stream_options": {"include_usage": True}, "max_tokens": 32,
            "tools": tools,
            "messages": cut_msgs,
        }
    # 逐回合二分：只保留“中间某一段”多轮历史（结构性内容最可能在中间某些轮）。
    # 取 25% / 50% / 75% 三个中段，供与前缀对照判断“哪一段”触发。
    if len(cum) >= 4:
        for frac in (0.25, 0.5, 0.75):
            idx = min(len(cum) - 1, int((len(cum) - 1) * frac))
            name = f"21_mid{int(frac*100):03d}"
            probes[name] = {
                "model": model, "stream": True, "stream_options": {"include_usage": True}, "max_tokens": 32,
                "tools": tools,
                "messages": cum[idx][0],
            }
    # 4) 完整请求复刻（唯一能确认“仍在拦”的对照，应当 BLOCK）
    full = _deepcopy_msgs(msgs)
    probes["30_full_request"] = {
        "model": model, "stream": True, "stream_options": {"include_usage": True}, "max_tokens": 32,
        "tools": tools,
        "messages": full,
    }

    return {
        "meta": {
            "source_log": str(req_idx),
            "model": model,
            "num_messages": len(msgs),
            "conn": conn or {"url": "", "key": "", "auth_scheme": "Bearer"},
            "note": "00 干净、10 单条切片、20/21 结构累积、30 完整复刻。若单条全过而 30 仍拦→多轮/组合/意图语义触发。",
        },
        "probes": probes,
    }


def _cap(s: str, n: int = 200_000) -> str:
    return s if len(s) <= n else s[:n]


def write_report(req: dict, req_idx: int, out_dir: Path) -> str:
    lines = [f"请求 #{req_idx} 文本结构（用于挑探测对象）", "=" * 50]
    for r in message_texts(req):
        mark = "  <<< 命中候选词: " + ",".join(r["hints"]) if r["hints"] else ""
        lines.append(
            f"[{r['i']:>3}] {r['role']:<10} len={r['len']:>7}{mark}\n      {r['preview']}"
        )
    path = out_dir / "report.txt"
    path.write_text("\n".join(lines), encoding="utf-8")
    return str(path)


def write_plan(probes: dict, out_dir: Path) -> str:
    names = list(probes["probes"].keys())
    steps = [
        "# 二分定位执行顺序",
        "",
        "0) 先发 00_control_hi 与 00b_control_blank（最干净）。",
        "   - 若这俩也被拦(code 11128) → 基本是【通道/账号级风控】，与内容无关：",
        "     换 token/账号/设备重新登录再试，无需继续逐段定位。",
        "   - 若通过 → 进入内容定位。",
        "1) 发 01_system_only、02_system_plus_tools：判断固定 system 提示/工具定义是否触发。",
        "2) 逐条发 10_* 消息切片。规则：",
        "   - 找到“单独发也会被拦”的消息 → 触发点在该消息内。",
        "   - 若该消息带 __halfA/__halfB → 继续对其中被拦的一半再对半，直到锁定到句子/词。",
        "   - 若单条都不拦 → 不是“词/单条内容”触发，进入 3)。",
        "3) 发 30_full_request（完整请求复刻）：",
        "   - 它也 PASS → 原坏请求现已放行（之前拦截是瞬时的），换最新被拦请求复测。",
        "   - 它 BLOCK 而上面全过 → 【多轮/组合/意图语义】触发（安全分类，非词表）。",
        "     用 20_cum* 逐回合加回，找“加入哪个回合后开始 BLOCK”以定位窗口；",
        "     修复改请求构造层（历史压缩/截断、去掉删库意图+硬编码凭据的整段重放），",
        "     词表/零宽脱敏对此类无效。",
        "",
        "记录方式（发到 gateway 后记下 pass/fail）：",
    ]
    for n in names:
        steps.append(f"   - {n}.json  ->  pass / fail")
    steps += [
        "",
        "发送探测用（独立脚本，不联网默认；url/model/key 已写在 plan.json，无需再传参）：",
        f"   python probe_sender.py {out_dir.as_posix()}/plan.json --send",
        "（如需改目标，可用 --url / --model / --key 覆盖 plan.json 里的值。）",
    ]
    path = out_dir / "plan.md"
    path.write_text("\n".join(steps), encoding="utf-8")
    return str(path)


def main() -> int:
    ap = argparse.ArgumentParser(description="把坏请求切成候选探测 payload（只读日志，不联网）")
    ap.add_argument("--log", default="bad.log", help="bad.log 路径")
    ap.add_argument("--req", type=int, default=23, help="取第几条被拒请求(0 起)")
    ap.add_argument("--out", default="probes", help="输出目录")
    ap.add_argument("--max-msgs", type=int, default=200, help="最多生成多少条消息切片探测")
    args = ap.parse_args()

    log_path = Path(args.log)
    if not log_path.exists():
        raise SystemExit(f"找不到 {log_path}")

    req, head, conn = parse_request(str(log_path), args.req)
    probes = build_probes(req, args.req, max_msgs=args.max_msgs, conn=conn)

    out_dir = Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)
    written = 0
    for name, body in probes["probes"].items():
        (out_dir / f"{name}.json").write_text(
            json.dumps(body, ensure_ascii=False, indent=2), encoding="utf-8"
        )
        written += 1

    report = write_report(req, args.req, out_dir)
    plan = write_plan(probes, out_dir)

    # 汇总清单（plan.json 供 probe_sender.py 读取；manifest.json 供人看）
    # plan.json 顶层直接带 url / model / key —— 来自日志行，发送时无需再手动传参。
    conn = probes["meta"].get("conn") or {}
    manifest = {
        "source_line": head,
        "url": conn.get("url", ""),
        "model": probes["meta"]["model"],
        "num_messages": probes["meta"]["num_messages"],
        "probe_count": written,
        "probes": sorted(probes["probes"].keys()),
    }
    payload = {
        "meta": probes["meta"],
        "url": conn.get("url", ""),
        "model": probes["meta"]["model"],
        "key": conn.get("key", ""),
        "probes": manifest["probes"],
    }
    (out_dir / "plan.json").write_text(
        json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    (out_dir / "manifest.json").write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2), encoding="utf-8"
    )

    print(f"已从 {log_path} 取第 {args.req} 条被拒请求，生成 {written} 个探测 payload 到 {out_dir}/")
    print(f"  report:    {report}")
    print(f"  plan:      {plan}")
    print(f"  manifest:  {out_dir / 'manifest.json'}")
    if payload["url"] and payload["key"]:
        print("  连接信息已写入 plan.json：url/model/key 均取自日志，发送时无需再传参。")
    print("\n提示：本工具只生成候选，不联网。真正发送用 probe_sender.py（默认就用 plan.json 里的 url/key）。")
    return 0


if __name__ == "__main__":
    sys.exit(main())
