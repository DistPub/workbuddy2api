/**
 * turing_helper.js — 从本机 WorkBuddy 桌面端自带的 Turing Shield SDK 取得设备风控 Token。
 *
 * 用途：workbuddy2api（Python 网关）需要给后端请求注入 `X-Device-Token` 头，
 * 否则敏感请求（签到 / 对话）会被上游风控识别为「非真实客户端」。设备 Token 由桌面端
 * 的 TuringShieldSDK 原生桥接生成，本脚本是 Python 侧调用该原生模块的桥梁。
 *
 * 输出（stdout，单行 JSON）：{"token": "v3:AAAA..."}；失败仅向 stderr 写错误并返回非 0。
 *
 * 路径可通过环境变量覆盖（默认指向常见安装位置）：
 *   WORKBUDDY_TURING_SDK_DIR   SDK 目录（含 index.cjs / TuringShieldSDK.dll / turing_sdk.node）
 *   WORKBUDDY_TURING_CHANNEL_ID  channelId（桌面端 product.json 中 turingSdk.channelId，默认 109144）
 *   WORKBUDDY_PRODUCT_NAME      产品名（默认 WorkBuddy）
 *   WORKBUDDY_VERSION           产品版本（默认 2.0.0）
 *
 * ---------------------------------------------------------------------------
 * 稳定性修复（2026-09：根治“有时能拿到、有时超时”）
 * ---------------------------------------------------------------------------
 * 根因（反汇编 macos-turing-sdk/build/Release/turing_sdk.node 确认）：
 *   联网取风险消息链路中的 +[turing_HIreYaasq8lbjBASE rootFlag]（0x61d52）会执行
 *     dispatch_sync(_dispatch_main_queue, ^{ result = ...; })   // call @ 0x61de2
 *   并阻塞在栈上信号量等结果。SDK 假设宿主是 GUI App（主线程 runloop 会排空主队列）；
 *   而普通 Node 进程的主线程停在 libuv 的 kevent 里，永远不排空主队列
 *   → dispatch_sync 死等 → FPQueryQueue 卡死 → "device token request timed out"。
 *   缓存命中时 rootFlag 走另一条不碰主队列的分支，所以「有时」能成功。
 *
 * 修复：fetchDeviceToken 是异步调用（返回 Promise，主线程空闲）。等待期间在 JS 主线程
 *   上反复调用伴生模块 mainq_drain.node 的 drainMain(ms)（即 CFRunLoopRunInMode），
 *   主队列被正常排空，rootFlag 的 dispatch_sync 立即返回 —— 与 GUI App 行为一致。
 *
 * 辅助稳定性措施（均可通过环境变量调整）：
 *   TURING_ATTEMPTS=2                进程内重试次数
 *   TURING_ATTEMPT_TIMEOUT_MS=9000   单次尝试看门狗（SDK 自身超时会设为该值 +2s）
 *   TURING_TOTAL_BUDGET_MS=20000     总预算（Python 侧 subprocess timeout=25s，必须留余量）
 *   TURING_TOKEN_CACHE_TTL_MS=600000 磁盘缓存有效期（默认 10 分钟，与 Python 侧 TTL 一致）
 *   TURING_TOKEN_STALE_MS=86400000   失败兜底：超过 TTL 但小于该窗口的旧 token 也可用
 *   TURING_NO_CACHE=1                跳过磁盘缓存（强制真实拉取，排障用）
 */
"use strict";
const fs = require("fs");
const path = require("path");
let DEFAULT_TURING_SDK = './turing-sdk';
if (process.platform === 'darwin') {
  DEFAULT_TURING_SDK = './macos-turing-sdk';
}

const sdkDir = process.env.WORKBUDDY_TURING_SDK_DIR || DEFAULT_TURING_SDK;

let turing;
try {
  turing = require(sdkDir);
} catch (e) {
  process.stderr.write("require turing sdk failed: " + (e && e.message ? e.message : String(e)) + "\n");
  process.stderr.write("SDK dir tried: " + sdkDir + "\n");
  process.exit(1);
}

const channelId = parseInt(process.env.WORKBUDDY_TURING_CHANNEL_ID || "109144", 10);
const productName = process.env.WORKBUDDY_PRODUCT_NAME || "WorkBuddy";
const productVersion = process.env.WORKBUDDY_VERSION || "2.0.0";

// ===== 伴生模块：主队列排空（仅 darwin 加载；失败则退回旧行为） =====================
const DRAIN = (function () {
  if (process.platform !== "darwin") return null;
  try {
    return require(path.join(__dirname, "mainq_drain.node"));
  } catch (e) {
    process.stderr.write(
      "[turing_helper] mainq_drain.node unavailable (deadlock workaround inactive): " +
      (e && e.message ? e.message : String(e)) + "\n");
    return null;
  }
})();

// ===== 可调参数 =====================================================================
function numEnv(name, def) {
  const v = parseInt(process.env[name] || "", 10);
  return Number.isFinite(v) ? v : def;
}
const ATTEMPTS = Math.max(1, numEnv("TURING_ATTEMPTS", 2));
const ATTEMPT_TIMEOUT_MS = Math.max(500, numEnv("TURING_ATTEMPT_TIMEOUT_MS", 9000));
const TOTAL_BUDGET_MS = Math.max(ATTEMPT_TIMEOUT_MS, numEnv("TURING_TOTAL_BUDGET_MS", 20000));
const CACHE_FILE = process.env.TURING_TOKEN_CACHE || path.join(__dirname, ".turing_token_cache.json");
const CACHE_TTL_MS = numEnv("TURING_TOKEN_CACHE_TTL_MS", 10 * 60 * 1000);
const CACHE_STALE_MS = numEnv("TURING_TOKEN_STALE_MS", 24 * 60 * 60 * 1000);
const NO_CACHE = process.env.TURING_NO_CACHE === "1";

function readCachedToken(maxAgeMs) {
  if (NO_CACHE || !Number.isFinite(maxAgeMs) || maxAgeMs <= 0) return null;
  try {
    const c = JSON.parse(fs.readFileSync(CACHE_FILE, "utf8"));
    if (c && typeof c.token === "string" && c.token &&
        Number.isFinite(c.ts) && Date.now() - c.ts <= maxAgeMs) {
      return c.token;
    }
  } catch (_) { /* 无缓存或损坏：忽略 */ }
  return null;
}

function writeCachedToken(token) {
  if (NO_CACHE) return;
  try {
    fs.writeFileSync(CACHE_FILE, JSON.stringify({ token: token, ts: Date.now() }));
  } catch (_) { /* 磁盘缓存写失败不影响主流程 */ }
}

// 收尾：优先自然退出（保证 stdout/stderr 冲刷）；若 SDK 残留句柄导致进程赖着不走，
// 3 秒后强杀（unref：仅当事件循环仍被别的东西撑着时才会触发）。
function finish(code) {
  process.exitCode = code;
  const killer = setTimeout(function () { process.exit(code); }, 3000);
  if (typeof killer.unref === "function") killer.unref();
}

// ===== 核心：带主 runloop 泵的单次取 token ============================================
async function fetchTokenOnce(attemptTimeoutMs) {
  const pending = Promise.resolve(turing.fetchDeviceToken({
    usingCachedMessage: true,
    includesOutdatedMessage: true,
    includesDeviceInfo: true,
    timeoutMs: Math.min(60000, attemptTimeoutMs + 2000), // SDK 自身超时略晚于我们的看门狗
  }));

  if (!DRAIN || process.platform !== "darwin") {
    return await pending; // 无伴生模块：维持旧行为
  }

  let state = 0; // 0=进行中 1=成功 2=失败
  let value, error;
  pending.then(
    function (v) { value = v; state = 1; },
    function (e) { error = e; state = 2; }
  );

  const deadline = Date.now() + attemptTimeoutMs;
  while (state === 0) {
    if (Date.now() >= deadline) {
      throw new Error("watchdog: fetchDeviceToken not settled within " + attemptTimeoutMs + "ms");
    }
    try { DRAIN.drainMain(50); } catch (_) { /* 单次泵失败不致命 */ }
    // 转一圈事件循环：SDK 的 Promise 回调（线程安全函数投递到主线程）得以执行
    await new Promise(function (resolve) { setImmediate(resolve); });
  }
  if (state === 2) throw error;
  return value;
}

async function fetchTokenWithRetry() {
  const totalDeadline = Date.now() + TOTAL_BUDGET_MS;
  let lastErr = new Error("unknown fetch failure");
  for (let i = 1; i <= ATTEMPTS; i++) {
    const remain = totalDeadline - Date.now();
    if (remain < 1500) break; // 剩余预算不足以再来一次
    const per = Math.min(ATTEMPT_TIMEOUT_MS, remain);
    try {
      const token = await fetchTokenOnce(per);
      const t = (token || "").toString().trim();
      if (t) return t;
      lastErr = new Error("turing sdk returned empty token");
    } catch (e) {
      lastErr = e;
    }
    process.stderr.write("[turing_helper] attempt " + i + "/" + ATTEMPTS + " failed: " +
      (lastErr && lastErr.message ? lastErr.message : String(lastErr)) + "\n");
  }
  throw lastErr;
}

// ===== 主流程 ========================================================================
function isSupported() {
  try {
    return !turing.isSupported || turing.isSupported();
  } catch (e) {
    return false;
  }
}

(async () => {
  if (!isSupported()) {
    process.stderr.write("turing sdk not supported on this platform\n");
    finish(1);
    return;
  }

  // 1) 新鲜的磁盘缓存：直接用（fork node 进程的开销远大于命中判断）
  const cached = readCachedToken(CACHE_TTL_MS);
  if (cached) {
    process.stdout.write(JSON.stringify({ token: cached }));
    finish(0);
    return;
  }

  try {
    turing.configure(channelId, productName, productVersion);
    // configure 后先泵一小会儿：冲掉 SDK 初始化阶段可能投递到主队列的 block
    if (DRAIN) { try { DRAIN.drainMain(100); } catch (_) {} }

    const t = await fetchTokenWithRetry();
    writeCachedToken(t);
    process.stdout.write(JSON.stringify({ token: t }));
    finish(0);
  } catch (e) {
    // 2) 兜底：取不到新 token 时，过期时间窗内的旧设备 token 依然可用（设备 token 长期有效）
    const stale = readCachedToken(CACHE_STALE_MS);
    if (stale) {
      process.stderr.write("[turing_helper] fetch failed, serving stale cached token\n");
      process.stdout.write(JSON.stringify({ token: stale }));
      finish(0);
      return;
    }
    process.stderr.write(`sdk dir: ${sdkDir} fetch device token failed: ` + (e && e.message ? e.message : String(e)) + "\n");
    finish(1);
  }
})();
