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
 */
"use strict";
const path = require("path");

const sdkDir = process.env.WORKBUDDY_TURING_SDK_DIR
  || "D:\\workbuddy\\resources\\app.asar.unpacked\\native\\turing-sdk";

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
    process.exit(1);
  }
  try {
    turing.configure(channelId, productName, productVersion);
    const token = await turing.fetchDeviceToken({
      usingCachedMessage: true,
      includesOutdatedMessage: true,
      includesDeviceInfo: true,
      timeoutMs: 15000,
    });
    const t = (token || "").toString().trim();
    if (!t) {
      process.stderr.write("turing sdk returned empty token\n");
      process.exit(1);
    }
    process.stdout.write(JSON.stringify({ token: t }));
  } catch (e) {
    process.stderr.write("fetch device token failed: " + (e && e.message ? e.message : String(e)) + "\n");
    process.exit(1);
  }
})();
