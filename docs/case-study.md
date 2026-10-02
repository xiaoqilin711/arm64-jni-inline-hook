# 案例复盘：一次加固金融 App 的 JNI 业务层抓包

> **目标（脱敏）**：某银行移动端 App（v1.0.4，包名 `com.xxx.xxx`）。授权测试，抓取**登录请求**的 URL / method / headers / body / response。
> **成果**：在 JNI 业务入口 `resourceApi` 处无痕落地登录请求全量业务层参数与响应头。
> **本文已做公开级脱敏**：包名、接口路径、channel/bank 编码、token/sid/verifyToken、流水号、精确时间戳、目标 so 名均打码或泛化。仅保留技术过程与可复用的方法论。

---

## 0. 起因与结论先行

一次授权测试，目标是某银行 App，要抓登录请求四件套。这个 App 同时踩了四块硬骨头：

1. **梆梆加固（DexHelper 抽取式壳）**——dex 被抽取加密，jadx 只能看到壳加载器；
2. **反 Frida 主动自毁**——检测到 frida-server 就在 constructor 期 `abort()`；
3. **登录流量走 Go 纯 crypto/tls**——不经过系统 conscrypt，eBPF 抓不到；
4. **业务逻辑是加密 JS bundle**——静态无明文可读。

三条常规路线（eCapture / Frida / 内核 HWBP）全部撞墙后，最终靠**"换注入载体"**——用定制 ROM 的任意 so 注入 + 自写 arm64 免修复 inline hook，在 JNI 业务入口把登录请求落地。本文把走通的、走不通的、以及中途自己犯的错，一五一十写出来。

---

## 1. 第一个异常：App 一开就无限回退

还没开始抓包，先撞上一个更麻烦的现象：**App 正常安装启动后，每过几秒自动退回初始页，无限循环**，根本点不到登录。

做了对照实验后锁定：

| 条件 | App 行为 |
|------|----------|
| frida-server 活跃 | 约 18s 后 SIGSEGV 崩溃，退回 Splash 循环 |
| 停掉 frida-server | 完全稳定，可正常操作 |

崩溃现场特征：`Fatal signal 11 (SIGSEGV), fault addr 0x97c`，`pc=0x97c lr=0x0 sp=0x0`，backtrace 仅两帧全 `<unknown>`。`fault addr` 和 `pc` 都落在比任何合法映射小得多的低地址——**不是野指针，是控制流被强劫持跳到一个未映射低地址**，是壳主动自毁的典型手法（把 sp/lr 清零再 `br` 到低地址，让崩溃现场"干净"到没法回溯）。

> **教训（贯穿全程）**：*"App 能稳定运行" ≠ "绕过了反 Frida"，只是"没开 frida-server"。* 我一度把这两件事搞混，做对照实验时又手贱拉起 frida-server，把"已稳定"的环境亲手打回原形。**做对照实验，一次只变一个变量。**

---

## 2. 第一回合：eCapture 抓不到登录包

既然不能开 frida，先用 eCapture（eBPF 内核态，uprobe 挂系统 TLS 库，不注入进程、不触发自毁）。

`tls -m text` 模式只 hook 系统 conscrypt 的 `SSL_write/read`。抓到了 App 的**遥测**流量（走系统栈），但登录请求始终不见。

中间还踩了个坑：用 `-p <pid>` 锁死进程，结果 App 在登录流程里自己重启，`-p` 一直盯一个已死的 PID。改成全量抓包后复测，目标进程一条登录明文都没有——**只抓到别的进程的流量**（某手机厂商系统联网探测 `GET /generate_204`）。

这个对比很有信息量：eCapture 能抓到系统进程的 conscrypt 流量、也能抓到目标 App 自己的遥测，说明**工具本身是好的**；偏偏抓不到登录，只能说明**登录根本不走系统 TLS 库**。

再试 eCapture 针对 Go 的 `gotls` 模式，直接报 `not a Go executable`——因为 TLS 逻辑在**动态库**里（gomobile 生成的 c-shared JNI 库），不是独立 Go 可执行文件，`gotls` 要解析的 Go build info 段不存在。**两条 eCapture 路子都死。**

---

## 3. 中途一次"自证"：32 位 / 64 位的坑

为了搞清目标 so 里是什么，导出 so 做静态分析。这里犯了个实打实的错：**第一次导出的是 32 位 ARM 版本（ELFCLASS32），而设备跑的是 arm64**，同一函数的偏移完全错位，得出一整轮错误地址。

> **教训**：*分析 so 前先 `file` 一下架构。* 32/64 位搞错会浪费一整轮分析。此后每一步都强调"导出时确认 arm64-v8a"。

重新导出 64 位后，才确认登录网络栈是 **Go 纯 crypto/tls**（go1.15，栈式 ABI），`crypto/tls.(*Conn).Write` 是明文写入口。prologue 先是一段 Go 栈检查：

```asm
.text:0047F800  LDR   X1, [X28,#0x10]     ; g.stackguard0
.text:0047F804  SUB   X2, SP, #0x60
.text:0047F808  CMP   X2, X1
.text:0047F80C  B.LS  loc_47FDD4          ; 栈不足 → morestack
.text:0047F810  STR   X30, [SP,#-0xE0]!   ; 建帧
```

注意第 4 条 `B.LS`——这是一个分支，也是后来"为什么 HWBP 抓不到、为什么免修复 hook 要拒绝这类 prologue"的关键伏笔。

---

## 4. 内核 HWBP：撞上 Go 栈式 ABI 死穴

不能开 frida，就想到内核硬件断点（HWBP）方案：不开 frida-server、不触发自毁，在内核下断点打 `Write` 明文。但这方案撞上一个 go1.15 栈式 ABI 死穴：

1. **Go 1.15 是栈式 ABI**——参数放栈上，不放 X0-X7；
2. 内核断点 handler **只保存 X0-X7 寄存器、只 dump 寄存器指向内存（≤128B）、不 dump SP 栈内存**；
3. 结果：`Write` 裸入口下断点，X0-X7 里根本没有明文指针（在栈上），读不到。

结论：**HWBP 抓 Go 栈式明文，原理上就别扭**——不是"找对指令"能救的，而是"断点那一下寄存器里压根没有指针"。这条路放弃。

> 反向价值：它点明了 Frida 恰恰能读 SP 栈——但 Frida 又被反 Frida 挡在门外，一个死循环。

---

## 5. 第二回合：Frida spawn 早注入，定位自毁点

决定正面解决反 Frida，用 **spawn 早注入**（在 App 主逻辑跑起来前布防），而不是 attach（attach 时检测早已跑完）。

写了绕过脚本（libc 兜底 strstr/strcmp/fopen/readlink + dlopen/线程/自毁观察探针）。中间踩了 Frida 17 的版本坑：`Module.findExportByName(null, ...)` 静态全局查找已移除，一崩导致排在后面的自毁观察器根本没装上，第一轮白白浪费（观察到自毁但没抓到 backtrace）。修掉后拿到决定性 backtrace：

```
SUICIDE abort
  0x…24450  libc.so!fdopendir
  0x…43b14  libc.so!0x80b14
  0x…135d4  libDexHelper.so!0x35d4
  0x…14944  libDexHelper.so!0x4944
  0x…7b684  linker64!call_constructors+0x2c4
```

翻译：**自毁点不在业务层，而在梆梆壳（libDexHelper.so）的 constructor 加载期**——`call_constructors → 壳 init → 子函数 → libc fdopendir 遍历目录 → 命中 frida 特征 → abort()`。

再做了 OBSERVE_ONLY 纯观察对照（只打印、不篡改），App 仍自毁 → 排除"是我们的篡改打断了加载器"。而观察探针抓到了**检测真面目**：`strcmp` 反复命中，被比较串赫然是

```
/memfd:frida-agent-64.so (deleted)
```

**全链串起来了**：壳检测 = 反复 `fopen`/`open` 读 `/proc/self/maps`，逐行 `strcmp` 比对，命中 frida-agent 的 memfd 映射这一行就 `abort()`。这正是 Frida 17 用 `memfd_create` 注入 agent 留下的铁证特征。

> 曾想过"对症下药"：hook read 把 maps 里含 frida/memfd 的行擦掉。真去试才发现此路不通——**壳的 ELF 加载器自己也合法读 `/proc/self/maps` 做重定位**，粗暴拦/改内容会打断加载器。这也是转向 route(c) 的直接原因。

---

## 6. 换一条思路：登录逻辑不在 Java dex 里

另一条线在推进：登录逻辑到底在哪一层。整体脱壳 + 抽取式脱壳跑完，jadx 看产物——**只有壳加载器类，没有任何业务类**。再查运行时文件与 APK assets，全是高熵加密 `.dat`（无 gzip 魔数、无 PK、无明文 JS）。

结论：这是 **MADP/Weex 框架 App**，登录页逻辑以加密 JS bundle 存在，运行时解密喂给 Weex JS 引擎执行。**静态读明文 JS 彻底死路**，登录逻辑只可能在运行时内存里。

---

## 7. 路线切换：native 注册监听 → 锁定总入口

三条常规路线都有硬伤，转向定制 ROM 自带能力。方法论上还有一道刹车：**同一检测链连续动态测试失败累计 3 次就停**，转静态——Frida 路线已撞墙多次，继续叠加 hook 只会越陷越深。

用定制 ROM 的 **native 函数注册监听**（logcat 输出 `RegisterNative`）冷启动采集了一次注册过程。几千条注册里，唯二非系统 so 是 Weex 渲染引擎和业务核心库。业务核心库里出现一组决定性方法：

```
funcName: byte[] worker.ApiResponse.getBody()        @offset=…
funcName: java.lang.String worker.ApiResponse.getCode()
funcName: worker.ServiceWorker.resourceApi(String,String,String,String,boolean) → worker.ApiResponse
funcName: worker.Worker.aesEncrypt(String) → String
```

**这是决定性突破**：业务核心库不是单纯的 TLS 库，而是一个 Go 写的完整 **ServiceWorker 引擎**（方法签名里的 `go.Seq`/`go.Universe` 是 gomobile bind 铁证）。`resourceApi` 是**网络请求总入口**（4 个 String + 1 bool，返回 ApiResponse），所有 API——包括登录——都从这过；`ApiResponse.getBody/getCode/getHeader` 是响应明文出口。

这比 hook `crypto/tls Write` 高了整整一层：**不用碰 Go 栈式 ABI 的 TLS 内部，直接在 JNI 边界读业务层看到的原始 url/method/body/header**。

而且地址换算能对上（`base + offset == 日志里的 funcAddr`），证明 offset 就是 IDA 文件偏移，可直接跳转。

---

## 8. 最后一步：换注入载体 + 自写 inline hook

定制 ROM 只提供"让 App 加载任意 so"的机制，**没有现成 hook 框架**，所以要自己写。核心是 arm64 免修复 inline hook——也就是本仓库的 [src/jnihook.c](../src/jnihook.c)。

**为什么这条路能活**：检测的是"frida-agent 以 memfd 映射进进程"这个特征。换成"定制 ROM 把普通 so 直接 `dlopen` 进进程"——**不经过 frida-agent、不产生 memfd 映射**，maps 检测天然命中不到，全程不开 frida-server。这正是整个 case 最核心的洞察：

> **检测和抓包是两个正交的问题。反 Frida 自毁针对"frida-agent 的 memfd 特征"，那换一种不产生该特征的注入方式，自毁就天然不触发。**

关键实现点（详见库注释）：

1. **参数语义坐实**：`resourceApi` 4 个 String 的顺序（url/method/body/header）靠两步坐实——静态（Go 实现里的 debug 日志拼接串 `"Receive :url:"+a2+",method:"+a3…` 写死了顺序）+ 动态（注入后打印与真实业务 100% 吻合）。
2. **免修复 trampoline**：先确认目标 prologue 前 16 字节无 PC 相对指令（这正是本库 `jnihook_prologue_is_pic` 干的事），原样搬进 trampoline 无需重定位。
3. **选改 prologue 的 inline hook，而不是换 RegisterNatives 表指针**：后者要 `FindClass("worker/ServiceWorker")` 重拿类，而该类由系统 classloader 持有，注入 so 的 native 线程找不到——经典 classloader 阻塞。inline hook 完全不用 FindClass，X0 直接就是 `JNIEnv*`。

**生效验证**靠三条 logcat 证据（值已脱敏）：

```
libcdbhook loaded, pid=<redacted>
libtarget base=0x… target=0x…
inline hook resourceApi ret=0 orig=0x…
```

关键是第三点：改了 `.text` 前 16 字节后 **App 持续存活、无二次自毁** → 证明目标 so 无 `.text` CRC 自校验（此前一直悬着的风险点，实测排除）。

---

## 9. 结果：登录请求落地

注入后启动 App，人工完成登录。`resourceApi` 被调，明文落地。筛出登录主请求（字段已全部脱敏）：

```http
POST /pweb/app***.do HTTP/1.1
Host: 127.0.0.1:<redacted>        # 本地 weex 代理
Accept: application/json
stage-type: weex
X-AuthToken: <redacted>
user-agent: Pixel 6(Android/15) (com.xxx.xxx/1.0.4) Weex/0.28.0.1
Content-Length: <redacted>

{"loginId":"<三段 | 分隔密文>","loginIdType":"C","loginType":"R",
 "password":"<base64，前缀 MDAw…>","_macAddr":"<redacted>",
 "token":"<redacted>","sid":"<redacted>","verifyToken":"<redacted>",
 "_terminalType":"ANDROID","_channelId":"PM**","_bankId":"1***",
 "_deviceId":"<redacted>","_accessNo":"<redacted>"}
```

响应：

```http
HTTP/1.1 200
Server: nginx
Content-Type: application/json
Content-Length: 138
Set-Cookie: X-LB=<redacted>; HttpOnly
_traceid: <redacted>
```

几个有意思的点：

- **Host 是本地 loopback 代理**：App 资源与 API 统一走本地 weex 代理，由代理转发到真实后端（响应 `Server: nginx` 说明后端是 nginx）。
- **loginId 是三段 `|` 分隔密文、password 是 base64**：在这个 JNI 边界，账号密码**已经是密文**——明文在更上层的 Weex/JS 层就完成了加密。想还原加密算法，得逆 `Worker.aesEncrypt`，那是另一个任务。

---

## 10. 诚实边界（没做到 / 做不完全的地方）

1. **响应体明文缺失**：hook 的 `dump_response` 对 `getBody()` 只在文件分支落字节，logcat 分支只打长度。这次捞的 logcat，138 字节响应体没落地。改 hook 把 body 也 `LOGI`（或确保读文件）重登一次即得。
2. **非线缆级字节流**：hook 抓的是 JNI 业务层参数，不是网卡真实 HTTP 字节。Go `net/http` 发出时追加的 `Connection`、`Accept-Encoding`、真实 `Cookie: SESSION=…` 等在业务层看不到。
3. **加密算法未逆向**：loginId/password 的加密过程（`aesEncrypt`）本次没逆。给的登录包可直接接口重放，但不是明文凭证。
4. **反 Frida 只绕过、未根治**：route(c) 成在"绕开" memfd 检测，不是"干掉"它。壳的 OLLVM 自毁逻辑还在，只是没被触发。

---

## 11. 复盘：整条路的取舍

真正的转折点有三个：

1. **eCapture 抓不到 → 确认登录走 Go crypto/tls 而非系统库**——排除了最省事的方案；
2. **Frida spawn 拿到 abort backtrace → 确认自毁点在壳 constructor，检测的是 memfd 特征**——同时知道了"检测的是什么"；
3. **native 注册监听锁定 `resourceApi` 是网络请求总入口**——把抓包从"TLS 底层硬抠明文"拉高到"JNI 业务边界直接读参数"，干净得多。

贯穿全程的主线：**检测与抓包是两个正交的问题**。很多时候**换注入载体，比硬刚检测代码更划算**。

给同行的提醒：金融 App 防护是分层的（壳自毁、Go 栈式 ABI、加密 JS bundle、业务层加密），别指望一条路走到黑。**每一层死路都会告诉你下一层该看哪里**——eCapture 的死路指向 Go tls，HWBP 的死路指向栈 ABI，Frida 的死路指向 memfd 检测，静态 JS 的死路指向运行时入口。把死路串起来，路就通了。

---

## 附：可复用成果 vs 一次性资产

| 类型 | 内容 | 落地 |
|------|------|------|
| **可复用** | arm64 免修复 inline hook 框架、PIC 预检、trampoline/patch 布局 | 本仓库 [src/](..) |
| **可复用方法论** | "换注入载体绕 memfd 检测"、native 注册监听锁入口、Go 栈 ABI 认知 | 本文 §5–§8 |
| **一次性（未开源）** | 目标 APK、壳 IDA 导出、真实登录包、Frida 绕过脚本 | 不在本仓库 |
