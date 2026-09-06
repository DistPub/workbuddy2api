/**
 * mainq_drain.m — 极小的 N-API 伴生模块：在调用线程上泵 macOS 主 runloop。
 *
 * 为什么需要它：
 *   Turing Shield SDK (turing_sdk.node) 在联网获取风险消息的链路里，
 *   +[turing_HIreYaasq8lbjBASE rootFlag] 会执行：
 *
 *       dispatch_sync(_dispatch_main_queue, ^{ result = compute(); });
 *       （0x61de2: call _dispatch_sync；队列参数来自 GOT 槽 0x7f1b8 → __dispatch_main_q）
 *
 *   SDK 假设宿主是 GUI App：主线程的 NSRunLoop 会排空主队列，block 得以执行。
 *   普通 Node 进程的主线程停在 libuv 的 kevent 循环里，永远不排空主队列
 *   → dispatch_sync 死等 → FPQueryQueue 卡死 → "device token request timed out"。
 *
 * 修复方式：
 *   fetchDeviceToken 是异步调用（返回 Promise，主线程空闲）。JS 主线程在等待
 *   期间反复调用 drainMain(ms) —— 即 CFRunLoopRunInMode —— 主队列被正常排空，
 *   rootFlag 的 dispatch_sync 立刻返回，链路恢复，与 GUI App 行为一致。
 *
 * 编译（x86_64，需与 node 架构一致）：
 *   ./build_mainq_drain.sh
 */
#include <node_api.h>
#import <Foundation/Foundation.h>

/* 在当前线程上跑主 runloop（限定 darwin；本模块只在 darwin 下会被 require）。
 * ms：本次泵多久（毫秒），1..2000，默认 50。 */
static napi_value DrainMain(napi_env env, napi_callback_info info) {
  size_t argc = 1;
  napi_value argv[1];
  double ms = 50.0;
  if (napi_get_cb_info(env, info, &argc, argv, NULL, NULL) == napi_ok && argc >= 1) {
    if (napi_get_value_double(env, argv[0], &ms) != napi_ok || ms <= 0.0) ms = 50.0;
  }
  if (ms < 1.0) ms = 1.0;
  if (ms > 2000.0) ms = 2000.0;

  @autoreleasepool {
    /* returnAfterSourceHandled = false：跑满时长，期间持续执行主队列 block */
    CFRunLoopRunInMode(kCFRunLoopDefaultMode, (CFTimeInterval)(ms / 1000.0), false);
  }

  napi_value undefined;
  napi_get_undefined(env, &undefined);
  return undefined;
}

static napi_value Init(napi_env env, napi_value exports) {
  napi_value fn;
  if (napi_create_function(env, "drainMain", NAPI_AUTO_LENGTH, DrainMain, NULL, &fn) != napi_ok) {
    return NULL;
  }
  napi_set_named_property(env, exports, "drainMain", fn);
  return exports;
}

NAPI_MODULE(NODE_GYP_MODULE_NAME, Init)
