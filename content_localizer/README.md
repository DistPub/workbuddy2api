# content_localizer —— 本地二分定位：哪段请求触发了 11128 审查拦截

两份脚本都**默认不联网**：`localize.py` 只读 bad.log、把“坏请求”切成候选探测 payload；
`probe_sender.py` 只有你显式 `--send` 才会真正 POST。

**连接信息自动带出**：生成时会把该请求的 `url`（日志里的后端地址）、`model`、`key`
（`Authorization: Bearer`）写进 `plan.json` 顶层 → 发送时无需再手动传参。

## 1. 生成探测（取 bad.log 第 N 条被拒请求）
```
python localize.py --log ../bad.log --req 23 --out probes
```
产物（都在 `--out` 下）：
- `00_control_hi.json` … 干净对照（先发它判断是不是通道级风控）
- `00b_control_blank.json` 空白对照
- `01_system_only.json` / `02_system_plus_tools.json`  判断固定 system/工具定义是否触发
- `10_*.json`  每条非 system 消息的切片探测（命中风险词优先，超大消息附 `__halfA/B`）
- `20_cum*.json`  保留原始 role 顺序的“完整回合”历史前缀（每加一个回合一条）
- `21_mid*.json`  25%/50%/75% 处的中段历史窗口
- `30_full_request.json`  完整请求复刻（唯一确认“仍在拦”的对照）
- `plan.json`（含 url/model/key + 探测清单）`plan.md`（执行顺序）`report.txt`（命中词提示）

> **探测体已带 `stream: true` + `stream_options: {"include_usage": true}`**
> （后端 copilot.tencent.com **只支持流式**，非流式会回 11101）。发送脚本也会再次强制
> 覆盖为流式，所以无需、也不要在探测文件里把它改回 false。

## 2. 发送并记录 pass/fail（默认用 plan.json 里的 url/model/key）
```
python probe_sender.py probes/plan.json --send
```
只发某几个：`--only 00_control_hi 01_system_only`
改发本地网关而非日志后端：`--url http://127.0.0.1:8787/v1/chat/completions --key 你的key`
不加 `--send` 时只本地回放、不发网络。

## 3. 如何判读
实测（req1，106 条消息，DB 恢复场景）**115 条探测全部 PASS**：00 干净、01 system、02 工具定义、
每条 10_* 单独内容（含 `DELETE FROM/TRUNCATE/root123` 的 tool 切片）**单发都不拦**。据此判读：

- **00 也 fail(11128)** → 通道/账号级风控，与内容无关：换 token/账号/设备登录。
- **00 过、某条 10_* fail** → 触发点在该消息文本内；有 `__halfA/B` 继续对半。
- **单条全过、但 30_full_request 仍 fail** → **非“词”触发**。这类是**多轮/组合/意图语义**的
  安全分类（如：整段 agent 轨迹在指示对带硬编码口令的库执行删/清库）。词表/零宽脱敏**治不了**，
  方向要改：
  - 先确认 `30_full_request` 现在是否**仍然**被拦（用 `--only 30_full_request` 单独发一次）；
  - 若仍拦 → 用 `20_cum*` 逐回合加回，找“加入哪个回合后开始 fail”（定位到多轮触发的窗口）；
  - 修复只能从**请求构造层**入手：别把“删库意图 + 硬编码凭据 + 长历史”整段上送，改成
    历史压缩/截断、给工具结果打摘要、避免把敏感操作指令完整保留在重放历史里。
- **30_full_request 也 PASS** → 说明原坏请求现在已放行（之前的拦截是瞬时的 / 已恢复），
  可换最新一条被拦请求再复测。

## 注意
- 本工具只生成本地候选，不做任何外呼；是否发送、发给谁，全由你自己控制。
- 若要“只改网关行为、不破坏代码”，优先考虑**历史压缩/截断**（别把 750KB 整段重放），
  而不是往 tool 里的代码/SQL 塞不可见字符（会破坏 agent 读取内容）。
