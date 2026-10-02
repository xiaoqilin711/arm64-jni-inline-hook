# arm64-jni-inline-hook

一个**极简、零依赖的 arm64 JNI 免修复 inline hook 框架**。用于在 Android 加固 App 的 JNI native 方法入口处无痕落地参数与返回值——不开 frida-server、不注入 frida-agent，因此不触发"检测 `/proc/self/maps` 里 `/memfd:frida-agent` 特征"这类反 Frida 自毁。

A minimal, dependency-free **ARM64 JNI fixup-free inline hook**. It lets you transparently dump the arguments and return value of a JNI native method in a hardened Android app — without running frida-server or injecting a frida-agent, so anti-Frida self-destructs that scan `/proc/self/maps` for `/memfd:frida-agent` never fire.

---

## 一句话定位

> 不是又一个"hook 引擎"，而是只解决一个真实、高杠杆的场景：**目标函数是 JNI native 方法、且其 prologue 前 16 字节无 PC 相对寻址**时，用 32 字节免修复 trampoline 把它重定向到你的 handler，handler 里 `GetStringUTFChars` 直接读明文参数。

## 为什么这么做

常规 hook 方案在这个场景下的硬伤，是这套代码存在的原因：

| 方案 | 问题 |
|------|------|
| Frida (spawn/attach) | agent 以 memfd 映射进进程，`/proc/self/maps` 留下 `/memfd:frida-agent-64.so (deleted)`，被壳的 maps 扫描命中即 `abort()` 自毁 |
| eCapture / eBPF uprobe | 只能挂系统 libssl/conscrypt；目标登录流量走 **Go 纯 crypto/tls**，根本不进系统库 |
| 内核 HWBP | Go 1.15 栈式 ABI：明文 slice 指针在**栈**上，断点命中那刻寄存器里没有指针 |

唯一能稳定活下来的路：**换注入载体**——用定制 ROM 的"任意 so 注入"，让目标进程 `dlopen` 一个普通的、你自己写的 so（不产生 memfd 映射），在 so 的 constructor 里对目标 JNI 方法下 inline hook。

## 特性

- **免修复 trampoline**：prologue 前 16 字节无 PC 相对指令即可原样搬运，无需指令重定位。
- **可验证的 PIC 预检**：`jnihook_prologue_is_pic()` 用 AArch64 硬件级判据（bit 26 = 所有分支指令；`ADR/ADRP`；`LDR-literal` 的 `bits[28:26]==110`）在打补丁前拒绝不可重定位的 prologue，避免"搬过去就跑飞"。
- **零依赖**：只链 `log`，不依赖 Dobby/Substrate 等任何 hook 框架。
- **普通 C dispatcher**：不手写 naked 汇编，控制流清晰、寄存器保存由编译器 ABI 保证。
- **纯逻辑有单测**：PIC 预检是纯位运算，带主机端单元测试。

## 快速开始

### 1. 交叉编译

```bash
NDK=/path/to/android-ndk ./build.sh        # 产出 build/libjnihook.so
```

或手动：

```bash
$NDK/toolchains/llvm/prebuilt/*/bin/aarch64-linux-android24-clang \
    -shared -fPIC -O2 -Iinclude src/jnihook.c -o libjnihook.so -llog
```

### 2. 写你的 handler

参考 [examples/resource_api_dump.c](examples/resource_api_dump.c)。核心三步：

```c
#include "jnihook.h"

static void* on_api(void* env, void* thiz, void* a1, void* a2,
                    void* a3, void* a4, void* a5, void** orig) {
    JNIEnv* e = (JNIEnv*)env;
    jstring url = (jstring)a1;                 // 参数按 JNI 寄存器序落位
    const char* s = (*e)->GetStringUTFChars(e, url, NULL);
    /* ... 落地 s ... */
    return *orig;                              // 或调用原函数后返回其结果
}

/* 在 constructor 里轮询找到目标 so 基址后： */
jnihook_install((void*)(base + TARGET_OFF), on_api, &orig);
```

### 3. 注入目标进程

用你手上 ROM 的"任意 so 注入"路径（**不是 Frida**），把编译出的 so 放进加载目录，App 下次启动即自动 `dlopen`，constructor 触发 hook。

## 架构

```
原始调用
  │
  ├─ target(0xXXXX)  ── patch ──▶  ldr x16,#8; br x16; .quad jnihook_dispatch
  │                                        │
  │                                        ▼
  │                            jnihook_dispatch (普通 C 函数)
  │                                        │
  │                              ┌─────────┴─────────┐
  │                              │                   │
  │                        你的 handler ──▶ orig() = trampoline
  │                              │             └─ 原 prologue 16B
  │                              │                └─ 原函数体 (只执行一次)
  │                              │
  │                              └── handler 返回值 ──▶ 原始调用者
```

- `Trampoline`：`[原 16 字节] + ldr x16,#8 + br x16 + .quad target+16`（32B，RWX mmap）。
- `Patch`：`ldr x16,#8 + br x16 + .quad jnihook_dispatch`（16B，覆盖 prologue）。
- `jnihook_dispatch` 是普通 C 函数，编译器生成 ABI 兼容的 prologue/epilogue，自动保存/恢复 callee-saved 寄存器与返回地址。

## 诚实边界

**这里不写"能 X 却没验证"的能力。** 明确以下几点：

1. **只支持 ARM64**。32 位 ARM / x86 未实现、未验证。
2. **只支持 JNI 方法且 ≤5 个整型/指针参数**（`this` + x2..x6）。第 6 个参数（x7）与浮点参数（d0-d7）不保存、不转发。
3. **prologue 必须 PIC**。含 `ADR/ADRP/B/BL/B.cond/CBZ/TBZ/BR/LDR-literal` 的函数会被拒绝（返回 `-1`）。
4. **未做 .text CRC 对抗**。若目标 so 有 `.text` 完整性自校验，改 16 字节可能触发二次自毁。本框架只保证"注入不产生 frida-agent memfd 特征"，不保证绕过所有完整性校验。
5. **单元测试未在真机执行**：`tests/test_pic.c` 已交叉编译为 arm64 可执行文件，但仓库作者的 Windows 环境无主机编译器、无连接设备，故 PIC 判据经**反汇编逐条核对** + 交叉编译验证，未在设备上运行。推设备后 `adb shell /data/local/tmp/test_pic` 即可跑。
6. 抓包位置是 **JNI 业务层参数**，不是网卡线缆级字节；Go `net/http` 发出时追加的底层头不在此层可见。

## 实战复盘

完整过程（走通的与撞墙的）见 [docs/case-study.md](docs/case-study.md)：一条"抓某加固 App 登录请求"的授权测试，从 eCapture / Frida / HWBP 三条死路，到最终锁定 JNI 业务入口用本框架落地的全过程。

## License

[MIT](LICENSE)
