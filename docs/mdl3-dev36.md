# MDL3 3.0.0-dev.36 逆向分析、业务路径与版本差异报告

分析日期：2026-11-06　|　对象：`ref/MDL3-3.0.0-dev.36-preview-Data-Hub-0.3.0.zip`
基线：`ref/MDL3-3.0.0-dev.28-preview-Data-Hub-0.3.0.zip` + `docs/mdl3.md`（前期逆向结果，含 dev.33 补记）
约定：与 `docs/mdl3.md` 一致，**只记录协议与结构，解出的 MDL3 源码不随仓库分发**；本次解包/解密产物全部落在系统临时目录 `C:\Users\madma\AppData\Local\Temp\mdl3-re\`，未入库（`ref/` 与 `.workbuddy/` 已在 `.gitignore` [W8]）。

---

## 0. 结论

1. **原生桥与 Data Hub 两版字节级完全相同**：`Native/mdl_native_bridge.dll`（9,304,424 B，sha256 `99877159…c08d`，v0.4.5）与 `Addon/9ba626afa44a3aa3.patch_0`（224,240 B，HD2 Data Hub 0.3.0）在 dev.28 / dev.36 中 sha256 一致 [S1][R5]。前期针对 DLL 的全部结论继续有效 [P6]。
2. **差异集中在 boot 与包外壳**：`MDL3/patch_0` 中唯一的 `boot` Lua 资源由 2,311,658 B 增至 2,574,946 B；解混淆后明文由 **802,105** 字符增至 **893,431** 字符（+91,326）[S2][S3]。dev.28 的 802,105 与前期记录精确吻合，构成本次解密算法的校验锚点 [P2]。
3. **dev.36 的两条主线变更**：① 新增「游戏内自部署原生组件 + EAC 证书诊断」；② **整套移除 Chef Shared Loader（CSL）兼容层**及与之绑定的 boot 分类/计划系统、引擎 API 代理白名单 [S4]。
4. **对本仓库 BML 的影响**：`coordinator` 独占注册表、`package.loaded` 去重、`init` 内安装设置服务、`ui.experimental_takeover` 开关等协议**两版一致**，README 的路由规则仍成立 [W1][P7][S8]；但 dev.36 移除了 `-- @loader mdl` 与 `HD2-Requires` 的解析，BML 侧以这两者为判定条件的规则需重新评估 [S4][W1 L70]。
5. **前期结果需修正一处**：前期只记录了 `luaopen_mdlbridge_call` [P6]；实测 Lua 侧共调用 **4 个**入口，`start` / `step` / `stop` 负责原生会话生命周期，`call` 负责握手与命令分发 [S8][R1]。
6. `docs/mdl3.md` 第 10 节记录的 dev.33 设置界面开关，在 dev.36 中仍为 `f = ui.experimental_takeover ~= false and not safe_mode` 的同构实现 [S9][P10]。

---

## 1. 分析范围、方法与证据编号

### 1.1 仓库结构（导览地图）

| 顺序 | 路径 | 角色 | 为什么先看 | 依据 / 置信度 |
|---|---|---|---|---|
| 1 | `docs/mdl3.md` | **前期逆向结果**（dev.28 主体 + dev.33 补记，10 节） | 本次比对的唯一基线，且给出了解密算法与 DLL 结论 | 已确认（文件 110 行）[W2] |
| 2 | `README.md` | BML 0.14.9 的对外行为契约，L63–156 是「哪个加载器跑哪些 mod」的路由表 | 判断 MDL3 变更对本项目的影响面 | 已确认 [W1] |
| 3 | `src/boot_mod_loader.lua` | 本仓库唯一业务源码（2,582 行），实现 chef 模式路由 | 所有"影响 BML"的结论要回到这里 | 已确认（骨架扫描 `src` 2,582 行）[W3] |
| 4 | `build.py` / `tools/extract_boot.py` | Arsenal `patch_0` 容器格式（`0xF0000011` + `0x48+types*32` + `rows*80`）的可执行说明 | 解析 MDL3 的 `patch_0` / `.stream` 必须用它 | 已确认 [W4] |
| 5 | `tests/test_loader.py` | 1,140 行 PUC Lua 5.1 行为测试，含 chef 模式与 MDL3 标记用例 | "最好的使用说明书"，验证路由假设 | 已确认（README L363–402）[W5] |
| 6 | `ref/` | 5 个 zip + 1 个已解出的 DLL：`dev.28`、`dev.36`、ChefBridge 0.2.1、Squad Ping MDL3 1.0.2、BFV v1.17.0 | 本次分析对象与旁证 | 已确认 [W6] |
| 7 | `dist/Boot Mod Loader v0.14.9/` | 构建产物，patch_0 仅 1 个 `boot` 资源 | 对照 MDL3 的单资源布局 | 已确认 [W7] |

骨架扫描结论：9 个文本文件 / 约 4,003 行，`.py×3 + .lua×1`，无依赖清单；`src` 为最热目录。二进制 8 个被排除（含 `boot.luac`、5 个 zip）——这是该文件级结论的可信边界。

### 1.2 前期逆向基线（`docs/mdl3.md` 逐节）

| 节 | 前期结论 | 本次用途 |
|---|---|---|
| §1 | 两包为 Arsenal 布局；`patch_0` 资源表格式 | 复用解析器 [P1] |
| §2 | boot 是 Prometheus 风格自解密壳，末尾 `loadstring(J,"@MDL3/boot")`；dev.28 明文 802,105 字符 | 解密算法与校验锚点 [P2] |
| §3 | `u.classify` 按 7 类特征给 boot 定性；`u.plan_boots` 跳过别的加载器但不中止 | 判定 dev.36 是否保留 [P3] |
| §4 | addon 启动 `require` 优先，仅 `module not found` 且 `package.loaded[name]==nil` 才取源码 | 路由核心依据 [P4] |
| §5 | 内置 CSL 模拟层 `u.version=0.1.0 / emulates=1.4.1 / [csl]`；全源码 0 处 `@loader` | 最重要的删除项 [P5] |
| §6 | DLL 10 个 `MDLB_*` 导出；导入 KERNEL32(143)/bcrypt(3)/ADVAPI32(1)；无 lua51 依赖；`luaopen_mdlbridge_call` + `"hello"→"MDL3OK"` | 需修正/扩充 [P6] |
| §7 | 对 BML 0.14 的 6 条含义（含 registry 唯一主人、Chef 不写 `package.loaded`） | 影响面基线 [P7] |
| §8 | 3 项只能进游戏验证 | 保留为未验证项 [P8] |
| §9 | ChefBridge = Chef 核 1.5.1 原样 + 首帧补 init | 旁证 [P9] |
| §10 | dev.33：`f = ui.experimental_takeover ~= false and not safe_mode`；0.14.9 起回填菜单要等 MDL3 的 `init` 返回 | 设置服务开关基线 [P10] |

### 1.3 证据编号

| 码 | 含义 |
|---|---|
| W1–W8 | 仓库内文件（见 1.1） |
| P1–P10 | `docs/mdl3.md` 对应小节 |
| R1–R7 | rea mcp 观察 / 本地 DLL 静态提取 |
| S1–S9 | 本次解包、解密、差异与流程取证产物（临时目录） |

- **R1** `rea:inspect_native_exports` → 191 个导出，含 10 × `MDLB_*`、4 × `luaopen_mdlbridge_*`、177 个 CRT。
- **R2** `rea:inspect_pe_imports` → 147 个导入（KERNEL32 143 / bcrypt 3 / ADVAPI32 1），imphash `c2cbfe93879194a6aca31989ecef4ee3`。
- **R3** `rea:inspect_pe_certificates` → WIN_CERTIFICATE 10,600 B，PKCS#7 signedData，证书链 Certum Code Signing 2021 CA → CHIEI INTERNET TECHNOLOGY LLC。
- **R4** `rea:inspect_pe_load_config` → TLS callbacks **空**，`IMAGE_GUARD_CF_INSTRUMENTED`。
- **R5** `rea:open_binary` → PE32+ / x86_64 / sha256 `99877159…c08d`。
- **R6** `rea:binary_overview` → Ghidra 12.1.4 导入分析超过 330,000 ms 启动时限，**函数级反编译未取得**。
- **R7** 本地对 DLL 的 ASCII 字符串提取（172,100 条，96 条 MDL3 相关）。
- **S1** 两版 zip 逐文件 sha256 比对；**S2** `patch_0` 资源表解析；**S3** 混淆壳静态复现；**S4** 明文字符串集合差异；**S5** 内嵌大字面量 hash；**S6** 授权清单 JSON；**S7** `.stream` 头 + Adler-32；**S8** `flow_v36.txt` 代码锚点；**S9** `final_probe.out`。

### 1.4 方法边界

- 解密采用**静态复现自写 PRNG + 字节表算法**，替换 `loadstring` 的思路一致但**不执行载荷**；dev.28 解出 802,105 字符与 [P2] 吻合，算法可复核 [S3]。
- Lua 侧结论来自静态字符串与代码锚点，**未进游戏运行**；DLL 侧结论来自 PE 结构与字符串，**未做函数级反编译** [R6]。动态派发、反射式调用、运行时行为不在本次覆盖内。

---

## 2. MDL3 dev.36 业务路径

### 2.1 交付包与部署入口

| 路径 | 大小 | 作用 | 依据 |
|---|---|---|---|
| `MDL3/9ba626afa44a3aa3.patch_0` | 2,575,152 B | 含唯一 Lua 资源 `boot`（fid `0xf476df93691895fa`，`flag=2` 源码，正文 2,574,946 B） | [S2] |
| `MDL3/9ba626afa44a3aa3.patch_0.stream` | 9,304,680 B | **新增**：256 B 头 + 完整 `mdl_native_bridge.dll` | [S1][S7] |
| `Native/mdl_native_bridge.dll` | 9,304,424 B | 供 `INSTALL.bat` 手动安装的同一份 DLL | [S1][R5] |
| `Addon/9ba626afa44a3aa3.patch_0` | 224,240 B | HD2 Data Hub 0.3.0，唯一资源 `mods/codex/hd2_data_hub`（224,032 B，**明文**） | [S2][S9] |
| `BUILD.json` | 344 B | `native_sha256`、`native_thumbprint`、`patch_sha256`、`requires_signature:false`、`native_version:0.4.5` | [S1] |
| `manifest.json` | 445 B | Arsenal 包：两个 Option（MDL3 / HD2 Data Hub） | [S1] |
| `install.ps1` | 18,461 B | 手工安装；新增 ANSI 代码页检测与 `%ProgramData%` 迁移 | [S1] |
| `INSTALL.bat` | 482 B | 两版相同 | [S1] |
| `README_zh.md` | 5,264 B | 玩家文档 | [S1] |
| `For Modder/hd2data_field_reference_v0_3_0.md` | 22,177 B | **打包方式变化**：dev.28 为 `For Modder.zip`（内含同名文件），内容 sha256 完全相同 `820b011c…6a90` | [S1] |
| `MDL3-EAC-Fix-Kit-1.0.2.zip` | 10,465 B | 8 文件；相对 1.0.1 改 4 个 bat/README，`tools/` 下 3 个文件不变 | [S1] |

**部署入口**：Arsenal 导入 → 勾选 MDL3 / HD2 Data Hub → Deploy → 要求 MDL3 处于**最高优先级**（游戏只跑最高优先级的 `boot`）→ Steam 启动 → 引擎以纯源码加载 `boot` 并调用 `init/update/render/shutdown` [W1 L13, L37][S1]。

### 2.2 启动链（分层）

```
Steam → helldivers2.exe (PUC Lua 5.1.4, 无 LuaJIT)
  └─ 最高优先级 patch 的 `boot` 资源（纯源码，flag=2）
       └─ 混淆壳 [-- MDL3 3.0.0-dev.36 game boot (PUC Lua 5.1, protected preview)]
            ├─ 自有 PRNG：seed 1735127，LCG e=(e*48271)%2147483647
            ├─ dev.36 常量：inc=24219315416723、X 乘数=48、滚动初值=213、key=32116962947227
            ├─ 置换表 h[l]=string.char(l-1)；逐字节 r=(byte+o()+r)%256
            └─ loadstring(明文,"@MDL3/boot") → setfenv(明文,getfenv(1)) → return 明文(...)
                 └─ 明文 boot（893,431 字符）
                      ├─ init,update,render,shutdown = 空函数（先占位）
                      ├─ 非 release 构建 require("debug")
                      ├─ 顶层常量 I="3.0.0-dev.36" + 授权清单 manifest(JSON)
                      ├─ f.coordinator / f.mdl_library / f.panel_renderer ... 模块装配
                      ├─ 原生桥 attach → 会话 start → step/frame 循环
                      ├─ 游戏内自部署检查（.stream 载荷）
                      ├─ 诊断模式（EAC 证书）
                      └─ init 内安装设置服务（ModOptionsMenu / ModBindingsMenu）
```
依据：[S3][S8 `init,update,render,shutdown` @77][P2][W1 L14–15]。

**dev.36 壳常量对照 dev.28**（前期 dev.28 未记录常量，dev.33 记录了 PRNG 221/9264981147793、字节流 238、滚动初值 73、key 1124343134926 [P10]）：

| 常量 | dev.28 | dev.36 |
|---|---|---|
| PRNG 增量 | `9273321088925` | `24219315416723` |
| X 乘数 | `172` | `48` |
| 滚动初值 | `16` | `213` |
| 解密 key | `11974645562315` | `32116962947227` |
| 密文长度 / 明文长度 | 802,105 | 893,431 |

### 2.3 关键流程

| # | 阶段 | 入口 / 节点 | 动作 | 依据 |
|---|---|---|---|---|
| F1 | 入口 | 引擎 `boot` | 解壳后先置 4 个空回调；非 release 时 `require("debug")` | [S8 @77] |
| F2 | 授权清单 | 顶层 `manifest` 常量 | `{"issued":"2026-11-02T11:05:05Z","modules":[sys,watch,esc_ui,audio],"publisher":"MDL3","schema":1}`，每模块带 sha256 与 `tier:"base"` | [S6] |
| F3 | 注册表独占 | `f.coordinator` @723202 | `rawget(_G,"CowboyBingusModLoader")` 非空 → 记 `coordinator: <provider> owns the addon registry` 并 `return nil`；否则新建 `{version=17,api=1,modules={},provider="MDL",mdl3=true}` 并 `rawset` | [S8][P7-5] |
| F4 | 配置读取 | `E.base_dir.."/MDL.cfg"` | `loadstring(...,"=MDL.cfg")` + `setfenv(chunk,{})` 沙箱执行；`safe_mode==true` → 标记 `R="config"`；键含 `bindings,boot_disabled,dll,enabled,game_dir,memory_mb,performance,rva_cache,safe_mode,ui`，`ui.incremental_draw` | [S8][S9] |
| F5 | 原生桥握手 | `d.attach(I)` @38677 | `package.loadlib(dll,"luaopen_mdlbridge_call")` → `pcall(l, MAGIC,"hello","MDL3HELLO")`，期望 `"MDL3OK"`，否则 `E_HOST_ABI`；成功后 `B={call=l,ack=0,transport="memory"}` | [S8][P6][R7] |
| F6 | 原生会话 | @60299 | 写 `start.cfg` → `loadlib(...,"luaopen_mdlbridge_start")` → `pcall(z)` → `status()` 必须为 `READY`，否则 `session handshake missing (another client...)`；再取 `luaopen_mdlbridge_step` / `luaopen_mdlbridge_stop` | [S9][R7] |
| F7 | 帧循环 | `B.frame` / `frame_fast` / `pump` / `submit` | 全部经 `luaopen_mdlbridge_call` + MAGIC + 命令字符串分发；`frame_fast` 走 `frame_fast`，否则 `frame`；结果用 `d.unpack`（batch 协议，kind 1..5） | [S8] |
| F8 | 组件自部署 | `z()` @755787 | 扫描 `..` / `.` 两根下 `data/9ba626afa44a3aa3.patch_<n>.stream`（连续 16 个缺失停止）；读 256 B 头匹配 `^MDL3PAYLOAD1 (%d+) (%d+) (%x+)`，校验 size / **Adler-32** / sha256 后读回 DLL | [S7][S8] |
| F9 | 组件落地 | `O(d)` @757112 | Adler-32 不符 → `component file damaged`；与现有不同 → `rename 旧 → .old`、写新、复读校验 `written file differs`；更新 `config.json`(`schema=1`,`dll=路径`)；写 `install-state.json`(`schema=2`,`installed_by="MDL3 in-game deployment"`,`native_version="0.4.5"`) | [S8] |
| F10 | 自部署状态机 | `s()` | DLL 缺失 → `payload_missing`/`installing`；hash 不同 → `installing`+`updated`；否则 `blocked`；结果 `installed` / `install_failed` | [S8] |
| F11 | 诊断模式 | `e.activate` @759208 | 记 `DIAG_MODE …` → `pcall(s)`；`update(dt)` 中 ESC 显隐，状态 `blocked→checking`（每 0.3 s 查 `certutil -store CA`），30 s 无应答 → `cert_unknown` | [S8] |
| F12 | 证书修复 | `update` @759801 | `cert_missing`/`cert_failed` 时 **F1** 写并提权运行 `mdl3_ingame_install_cert.bat`（`certutil -addstore -f CA`）；**F2** 打开 `/fix`；状态 `cert_installing→cert_done`/`cert_failed`/`declined` | [S8][S1 README L34–45] |
| F13 | addon 启动 | `require` / `package.loaded` | 沿用「require 优先 + `package.loaded` 去重」协议（两版各 12 处引用） | [P4][S4] |
| F14 | 设置服务 | `init` 内 | `experimental_takeover ~= false and not safe_mode` 时才安装 `ModOptionsMenu` / `ModBindingsMenu`；UI 文案 `实验性接管：MOM / MBM / HUD+ 设置并入 MDL` | [P10][S8][S9] |

### 2.4 调用关系

| 调用方 | 被调 / 媒介 | 关系 | 依据 |
|---|---|---|---|
| 引擎 | `boot` chunk → `init/update/render/shutdown` | 引擎回调契约 | [W1 L14–15][S8 @77] |
| 混淆壳 | `loadstring(明文,"@MDL3/boot")` → `setfenv` → `return 明文(...)` | 单层包装，不执行载荷可截获 | [P2][S3] |
| `f.coordinator` | `rawget/rawset(_G,"CowboyBingusModLoader")` | 与 BML / Chef 的注册表互斥 | [S8][P7-5][W1 L94–101] |
| `d.attach` | `package.loadlib` → `luaopen_mdlbridge_call` → MAGIC/`"hello"`/`"MDL3HELLO"` → `"MDL3OK"` | C 模块握手 | [S8][R1][R7] |
| 会话层 | `luaopen_mdlbridge_start` → `status()==READY` → `step` / `stop` | 生命周期三入口 | [S9][R1] |
| 帧层 | `luaopen_mdlbridge_call` + `"submit"/"frame"/"frame_fast"/"pump"` | **单入口命令分发** | [S8] |
| 原生 VM | `@bridge_codec` / `@bridge_platform` / `@bridge_runtime` / `@bridge_selftest`（DLL 内部） | 内部模块，Lua 侧无对应注册 | [R7] |
| 原生 VM | `MDLHOSTAPI1 %lx %lx %lx` host API 缓存协议；`trusted bootstrap required before hello` | 握手前置条件 | [R7] |
| Data Hub addon | `HOST` 表 7 个原生模块 `hdh_profile/hdh_catalog/hdh_events/hdh_player/hdh_tactical/hdh_strikes/hdh_main` → `host.memory.region`、`host.modules.info` | 原生 owner `'hd2data'` 供数 | [S9][S2 Addon L20] |
| 游戏 Lua mod | `_G.HD2Data`（`D.version/api/state/ready/player/.../set_option`） | 唯一对外公开 API | [S1 field reference] |
| 自部署 | `os.execute("mkdir ...")`、`os.rename`、`os.remove`、`io.open` | 游戏内落盘 | [S8] |

### 2.5 数据流转

| 数据 | 产生 | 载体 / 格式 | 消费 | 依据 |
|---|---|---|---|---|
| 加密源码 | 构建期 | `boot` 资源内 `\ddd` 转义长字符串 + 数值 key | 壳解密 → `loadstring` | [S3] |
| 授权清单 | 构建期 | 顶层 686 B JSON，含模块 sha256 / exports / tier | 原生 VM `trust_*` 校验器（DLL 内 `trust schema fields`、`trust hex`、`trust UTC date`） | [S6][R7] |
| 原生组件 DLL | 构建期签名 | `.stream`：256 B 头 `MDL3PAYLOAD1 <size> <adler32> <sha256> <version>` + 原样 PE | 游戏内 `z()` → `O()` 写入 `%LOCALAPPDATA%\MDL3\`（非 ANSI 用户名时 `%ProgramData%\MDL3`） | [S7][S8][S1 install.ps1] |
| 帧数据 | 原生桥 | batch 协议：`u32 len` 前缀 + kind 1..5 + id(≤128) + body(≤1 MiB)，上限 2 MiB | `d.unpack` → Lua 侧 | [S8 `d.unpack`] |
| 设置 | 玩家 / mod | `MDL.cfg`（Lua 表，空环境沙箱）、`config.json`、`install-state.json` | `coordinator`、UI、自部署 | [S8][S9] |
| 游戏数据 | 原生 owner 读进程内存 | `host.memory.region` 校验可读区（`READABLE` 保护位掩码）→ 烘焙的 chain profile | `HD2Data` 全局表 → mod | [S9 Addon L47–70][R2] |
| 证书诊断 | `certutil -store CA` | `cert_check.txt` / `cert_check_done.txt` / `cert_result.txt` | 诊断窗口状态机 | [S8] |
| 路径授权 | `install.ps1` | `%LOCALAPPDATA%\MDL3\sys-paths.txt` 的 `mkdir=` 行 | 原生 host 的额外根目录（DLL 同时支持 `read=` / `mkdir=`） | [S1 install.ps1 diff][R7] |

**关键校验值**：`.stream` 头第二字段 `767505348` = 整份 DLL 的 **Adler-32**（本地实测 `zlib.adler32 = 767505348`），**不是 CRC32**（CRC32 为 `2981284469`）[S7]；第三字段 `99877159…c08d` 与 `BUILD.json.native_sha256`、rea 的 PE 摘要三者一致 [R5][S1]。

### 2.6 重要分支

| 条件 | 走向 | 依据 |
|---|---|---|
| `stingray.Application.build() ~= "release"` | `require("debug")` | [S8 @77] |
| `_G.CowboyBingusModLoader` 已存在 | coordinator 返回 nil，一个 addon 都不启动 | [S8][P7-5] |
| `MDL.cfg` 中 `safe_mode == true` | 标记来源 `config`；`mod 启动` 分支整批跳过，仅记录 `safe mode: N remembered mod(s) not started` | [S8][S9 `v.start`] |
| `ui.experimental_takeover ~= false and not safe_mode` | 才安装 `ModOptionsMenu` / `ModBindingsMenu` | [P10][S9] |
| `package.loaded[name] ~= nil` | addon 不二次执行 | [P4][S4] |
| `.stream` 头 size / adler / sha256 任一不符 | `component file damaged` / `not found in the deployed patches` / `incomplete` | [S8] |
| 已安装 DLL 与载荷不同 | 备份 `.old` → 写新 → `install-state.json` 标 `updated` | [S8] |
| 用户名不在系统 ANSI 代码页 | 根切换到 `%ProgramData%`，`sys-paths.txt` 授权 `MDL3` 与 `MDL\Helldivers2`，并复制旧设置/散装 mod | [S1 install.ps1 diff][S1 README L25] |
| 证书缺失 / 已装 / 未知 / 安装中 | 诊断窗口 F1 装证书、F2 开目录、30 s 超时、提权被拒 `declined` | [S8][S1 README L34–45] |
| 原生时间片 `E_BUDGET` 耗尽 | 批次重发；`SYS_SLICE_RAISED native slice 30 ms for 4 s after E_BUDGET` | [S4][R7][S5] |
| patch 数超过上限 | `Many mods: {count} startup patches deployed (over {limit})`，但 `); all are read` | [S4] |
| `ui.incremental_draw == false` | 菜单改整页重画（两版一致） | [S9][S1 README L28] |

---

## 3. 与前期逆向结果逐项比照

判定：**保留** = 实测一致；**修正** = 前期不完整/不准确；**失效** = dev.36 已不存在；**验证** = 前期标"未验证"，本次静态可见但仍需实机。

| # | 前期结论（依据） | dev.36 实测（依据） | 判定 |
|---|---|---|---|
| 1 | Arsenal 布局、`0xF0000011` 资源表格式 [P1] | 两版各 1 个 `boot` 资源，fid/偏移/flag 一致；新增 `.stream` 为独立文件 [S2] | **保留** |
| 2 | 壳 = 自写解密器 + `loadstring(J,"@MDL3/boot")`；dev.28 明文 802,105 [P2] | 壳结构相同，4 个常量全变；dev.28 复现得 802,105（校验通过），dev.36 得 893,431 [S3] | **保留 + 修正**（常量随版本轮换，dev.33 记录亦印证 [P10]） |
| 3 | `u.classify` 7 类 boot 特征、`u.plan_boots` 跳过其他加载器但不中止 [P3] | `Chef Shared Loader`、`--@@LOADER@@`、`Bingus Shared Loader v`、`Boot Mod Loader`、`local MARKER = "boot-mod-loader-…"`、`revision = "loader-vN"`、`@MDL3/boot`、`"HD2"…"-Addon"` 等**全部字符串消失**；`csl`/`Chef`/`emulates` 命中数 21/20/6 → 0 [S4] | **失效**（整套分类/计划系统移除） |
| 4 | addon `require` 优先、`package.loaded` 去重 [P4] | 两版 `package.loaded` 均 12 处、`loading` 均 13 处、HD2Data 均 2 处 [S4] | **保留** |
| 5 | 内置 CSL 模拟层 `version=0.1.0 / emulates=1.4.1 / [csl]`；全源码 0 处 `@loader` [P5] | `[csl]`、`/CSL`、`Chef Shared Loader addon (run by MDL3)`、`chef.capabilities is read-only`、`needs Chef Shared Loader %s or newer`、Chef mod 检测模式、`SAFE MODE: other mods' boot scripts are not run` 全部删除；`@loader` 命中 1 → 0 [S4] | **失效**（CSL 兼容层整体移除）；"0 处 @loader" 在 dev.36 仍成立但已无意义 |
| 6 | DLL 10 个 `MDLB_*` 导出、导入 143/3/1、无 lua51 依赖 [P6] | rea 复核：191 导出（10 MDLB + 4 luaopen + 177 CRT）、147 导入、imphash `c2cbfe…` [R1][R2] | **保留 + 补充** |
| 7 | Lua 侧用 `luaopen_mdlbridge_call` + `"hello"→"MDL3OK"` [P6] | 实测 4 个入口：`start`（写 `start.cfg`/起会话/查 READY）、`step`、`stop`、`call`（`MAGIC,"hello","MDL3HELLO"` → `MDL3OK` 并分发命令）[S8][S9] | **修正**（前期漏记 3 个；握手指令为 `MDL3HELLO` 而非仅 `"hello"`） |
| 8 | 二进制无 `helldivers2`/`EasyAntiCheat` 字样，无宿主检查 [P6] | DLL 两版字节相同，故仍成立；但**包与 boot 侧**现在含大量 EAC 证书逻辑与内嵌 `find_eac_setup.ps1` [S4][R7] | **保留（DLL）/ 修正（整包）** |
| 9 | `install.ps1` 只放 DLL + 写配置，不改 patch [P6] | dev.36 的 `install.ps1` 仍不改 patch，但新增 ANSI 检测、`%ProgramData%` 迁移、`sys-paths.txt` 写入；另有**游戏内**自部署链路（不经 install.ps1）[S1][S8] | **修正** |
| 10 | registry 唯一主人，托管前须移走 BML 的表 [P7-5] | `f.coordinator` 逻辑逐字保留 [S8] | **保留** |
| 11 | Chef 不写 `package.loaded`，BML 需代写 [P7-6] | 协议未变；但 dev.36 已不直接跑 Chef mod，此工作流前提变为「Chef 本体是否仍部署」[S4][W1 L63–121] | **保留（协议）/ 需重评（适用性）** |
| 12 | `HD2-Requires:` / `-- @loader mdl` 是 BML 的判定规则 [W1 L70][P7-3] | MDL3 侧 `HD2-Requires` 解析模式、`@loader` 字符串均已移除；BML 的判定表仍按旧规则 [S4][W1] | **失效（MDL3 侧）/ 保留（BML 侧，需复核）** |
| 13 | dev.33 设置开关 `experimental_takeover ~= false and not safe_mode` [P10] | dev.36 `experimental_takeover` 11 处、`safe_mode` 35 处、`MDL.cfg` 18 处与 dev.28 完全相同 [S4] | **保留** |
| 14 | 设置服务装在 `init` 内，回填菜单须等 init 返回 [P10] | `ModOptionsMenu` 6→4、`ModBindingsMenu` 5→3 处（接入点减少），开关逻辑保留 [S4][S9] | **保留 + 补充** |
| 15 | §8 三项未验证（菜单 ON 状态、非 boot 位置桥/ESC、Chef 对未知 requirement 的处理）[P8] | 第 3 项因 CSL 移除而**不再适用**；前 2 项仍只能进游戏验证 | **部分失效** |
| 16 | `For Modder` 接口文档 [S1] | dev.28 为 `For Modder.zip`（9,777 B 压缩包），dev.36 为文件夹内同名 md（22,177 B）；**解压后内容 sha256 完全相同** `820b011c…6a90` [S1] | **保留（内容）/ 修改（打包）** |

---

## 4. 变更分类

### 4.1 新增（NEW）

| 路径 / 节点 | 依赖 | 行为差异 | 依据 |
|---|---|---|---|
| `MDL3/9ba626afa44a3aa3.patch_0.stream` | `BUILD.json.native_sha256`、已签名 DLL | 256 B `MDL3PAYLOAD1 <size> <adler32> <sha256> <version>` 头 + 完整 PE；供游戏内自部署 | [S1][S7] |
| `z()` / `O()` / `s()` 自部署状态机 | `os.execute`、`os.rename`、`io.open`、Adler-32 | 扫描 `patch_<n>.stream`（连续 16 缺失停止）→ 三重校验 → 备份 `.old` → 写 DLL → 更新 `config.json` / 写 `install-state.json`(schema=2) | [S8] |
| `install-state.json` | — | `{schema=2,product="MDL3",version,native_version="0.4.5",data,files[{path,sha256}],installed_by="MDL3 in-game deployment"}` | [S8] |
| 诊断模式 `DIAG_MODE` + `e.activate/e.update` | ESC/F1/F2、`certutil` | 状态机 `blocked→checking→cert_present/cert_missing/cert_unknown→cert_installing→cert_done/cert_failed/declined`；30 s 超时 | [S8] |
| 内嵌修复包（8 个大字面量） | `os.execute` 提权 | boot 明文内嵌 3 个 `.bat`、`README_FIRST.txt`、2× 证书 DER(1,664 B)、`MDL3-EAC-TrustCheck.ps1`(6,085)、`find_eac_setup.ps1`(1,399) | [S4][S5] |
| 非 ANSI 用户名路径迁移 | `GetACP` / `EncoderFallback` | `AnsiSafe()` 检测 → 根切到 `%ProgramData%` → `sys-paths.txt` 写 `mkdir=` 两行 → 复制旧 `MDL\Helldivers2` / `HD2Runtime\mod_data` | [S1 install.ps1 diff][S1 README L25] |
| 原生预算自适应 | `E_BUDGET` / `slice_ms` / `tick_budget_ms` | `SYS_SLICE_RAISED native slice 30 ms for 4 s after E_BUDGET`、批次重发、`SYS_BUSY`、`SYS_WATCH_*` | [S4][R7] |
| 多 patch 上限提示 | `flash.many_patches` / `note.many_patches` | `Many mods: {count} startup patches deployed (over {limit})` + `); all are read` | [S4] |
| `(refused: …)` 拒绝原因日志 | — | addon 被拒时给出具体原因 | [S4] |
| `For Modder/` 直出文件夹 | — | 由 zip 改为文件夹（内容不变） | [S1] |
| `README_zh.md` 新增章节 | — | 诊断模式、ProgramData、F1/F2 修复流程；删除 Chef mod 说明 | [S1] |

### 4.2 删除（REMOVED）

| 路径 / 节点 | 依赖 | 行为差异 | 依据 |
|---|---|---|---|
| **整套 CSL 兼容层** | `emulates=1.4.1` | `[csl]` 日志前缀、`/CSL`、`u.claims`/`u.requirements`/`u.requires_ok`、`chef.capabilities`、`chef.%s` 绘制缺失提示、Chef 版本检查全部消失；Chef mod 不再由 MDL3 直接运行 | [S4][P5][S1 manifest/README 描述亦删] |
| **boot 分类 / 计划系统** | `u.classify` / `u.plan_boots` | 7 类特征（BML / Bingus / Chef / MDL3 / HD2 Lua Runtime / 其它加载器 / 普通 boot）、`skipped` / `not run` / `Keep MDL3 deployed last` 提示、重复 boot 检测、`could not compile the boot script in` 全部移除 | [S4][P3] |
| `-- HD2-Requires:` 解析 | 头 1200 字节扫描 | 模式 `\n%-%- HD2%-Requires: (…)` 消失；`chef-shared-loader`/`chef-loader`/`mods/...` 需求判定一并消失 | [S4][P5] |
| `-- @loader mdl` 支持 | — | `@loader` 命中 1 → 0 | [S4][W1 L70] |
| 引擎 API 代理白名单 | `chef` 模拟层 | `Application.*` / `Camera.*` / `Unit.*` / `World.*` / `Network.*` / `GameSession.*` / `Light.*` / `Keyboard.*` / `Mouse.*` / `Steam.*` / `Vector3.*` / `Quaternion.*` / `IdString64.*` 等约 60 个名字与 `is not available to mods`、`not an engine call` 等沙箱提示消失 | [S4] |
| 旧 UI 控件/能力标签 | CSL 绘制层 | `bitmap/bitmap_uv/circle/rect/ring/sprite/sprite_sheet/triangle/text_wrap/slider_choice`、`\|draw\|button\|color\|save\|timers\|wait\|refused`、Apple 配色常量、`timers: 512 running already`、`20 errors` 熔断 | [S4] |
| `MAX_LUA` / 4 MB 检查 | Chef 核常量 | 命中 2 → 0（`4 MB` 文案仍存 1 处） | [S4] |
| `MDL3/ui-rva-cache.txt` 路径 | — | 改为 `/ui-rva-cache.txt` | [S4] |
| 旧公钥 / 旧版本串 | — | 128 hex `7efd860b…` 删除，换为 `ea04b77b…`；`3.0.0-dev.28` → `3.0.0-dev.36` | [S4] |
| `For Modder.zip` / `MDL3-EAC-Fix-Kit-1.0.1.zip` | — | 被 `For Modder/` 与 `1.0.2.zip` 取代 | [S1] |

### 4.3 修改（MODIFIED）

| 路径 / 节点 | 变更 | 依据 |
|---|---|---|
| `MDL3/patch_0` → `boot` 资源 | 2,311,658 B → 2,574,946 B（+263,288）；明文 802,105 → 893,431 字符 | [S2][S3] |
| 混淆壳常量 | PRNG 增量 / X 乘数 / 滚动初值 / key 四项全换（见 2.2 表） | [S3] |
| `BUILD.json` | 仅 `version` 与 `patch_sha256` 变：`00f88df3…400` → `81af7e7e…84b`；`native_sha256`/`thumbprint`/`native_version`/`requires_signature` 不变 | [S1] |
| 授权清单 `manifest` | `issued` 2026-10-31T18:14:22Z → 2026-11-02T11:05:05Z；`sys` 库 sha256 `76b30161…f2` → `160f7a01…c6`；`watch`/`esc_ui`/`audio` 三项 sha256 与 exports 不变 | [S6] |
| 内嵌 `sys` 服务库（`__mdl3_ffi=ffi`，native LuaJIT VM） | 35,708 → 36,043 字符（+335）；唯一改动是 `plat()` 改为「先在局部变量构建完整、再一次性赋值」，修复 dev.32 起 `E_BUDGET` 中途打断导致 `platform` 已设但 `images=nil`、整个会话图标全失败的问题 | [S5] |
| 内嵌 `audio`(20,269) / `UI`(71,161) / `sys watcher`(3,502) 三库 | sha256 逐字节相同 | [S5] |
| `install.ps1` | 15,705 → 18,461 B；新增 `PlainAscii`/`AnsiSafe`/`RootMoved` 分支与 `sys-paths.txt` 写入；目录创建由 `Join-Path $env:LOCALAPPDATA` 改为 `Join-Path $Root` | [S1 diff] |
| `README_zh.md` | 3,963 → 5,264 B；安装步骤由「先退出游戏跑 INSTALL.bat」改为「Arsenal Deploy 优先 + 游戏内自装」 | [S1] |
| `manifest.json`（Arsenal） | 511 → 445 B；Description 删去「支持 Chef Shared Loader 的 mod（绘制部分暂不支持）」 | [S1] |
| EAC Fix Kit | 1.0.1 → 1.0.2；`1_CHECK.bat` 932→1,071、`2_FIX_CERT_ADMIN.bat` 1,401→1,390、`3_REPAIR_EAC_ADMIN.bat` 1,688→1,798、`README_FIRST.txt` 1,661→1,827；`9_UNDO` 与 `tools/` 三文件不变 | [S1] |
| 设置菜单接入点 | `ModOptionsMenu` 6→4、`ModBindingsMenu` 5→3 处引用；开关逻辑不变 | [S4][S9] |
| `CowboyBingusModLoader` 交互 | 9→7 处引用；`coordinator` 仍 8 处 | [S4] |

### 4.4 未变（UNCHANGED，作为稳定性锚点）

`Native/mdl_native_bridge.dll` [S1][R5]、HD2 Data Hub `Addon/patch_0` 与 For Modder 文档内容 [S1]、`INSTALL.bat` [S1]、`coordinator` 注册表协议 [S8]、`package.loaded` 去重 [S4]、4 个 `luaopen_mdlbridge_*` + `MDL3OK` 握手 [S4]、10 个 `MDLB_*` 导出与 147 个导入 [R1][R2]、TLS callbacks 空 [R4]、`experimental_takeover`/`safe_mode`/`MDL.cfg` [S4]、内嵌 audio/UI/watcher 三库 [S5]、`ui.incremental_draw` [S9]。

---

## 5. 简明变更点清单

| 编号 | 类型 | 路径 / 节点 | 一句话变更 | 依据 |
|---|---|---|---|---|
| D01 | 新增 | `MDL3/…patch_0.stream` | 内嵌已签名 DLL（头 `MDL3PAYLOAD1`，Adler-32 校验） | [S1][S7] |
| D02 | 新增 | boot → `z()/O()/s()` | 游戏内自部署/更新组件，旧文件备份 `.old` | [S8] |
| D03 | 新增 | `install-state.json` | 记录自部署来源与版本（schema=2） | [S8] |
| D04 | 新增 | boot → 诊断模式 | EAC 证书检测 + F1 提权装证书 / F2 开目录 | [S8] |
| D05 | 新增 | boot 内嵌字面量 | 8 个修复包文件（bat/cer/ps1/txt）随 boot 下发 | [S4][S5] |
| D06 | 新增 | `install.ps1` | 非 ANSI 用户名 → `%ProgramData%` + `sys-paths.txt` | [S1 diff] |
| D07 | 新增 | 原生预算 | `E_BUDGET` 临时提额 30 ms/4 s、批次重发 | [S4][R7] |
| D08 | 新增 | patch 数量 | 超上限告警 `many_patches`，但全部仍读 | [S4] |
| D09 | 删除 | CSL 兼容层 | Chef mod 不再由 MDL3 直接运行 | [S4][P5] |
| D10 | 删除 | `u.classify`/`u.plan_boots` | boot 分类与跳过逻辑整体移除 | [S4][P3] |
| D11 | 删除 | `HD2-Requires` / `@loader` | MDL3 侧不再解析这两类声明 | [S4] |
| D12 | 删除 | 引擎 API 代理白名单 | 约 60 个 `Unit.*`/`World.*` 等名字与沙箱提示消失 | [S4] |
| D13 | 删除 | 旧 UI 控件/配色/熔断 | `bitmap…triangle`、Apple 配色、20-error 熔断 | [S4] |
| D14 | 删除 | `MAX_LUA`、`MDL3/ui-rva-cache.txt` | 路径/限制节点变更 | [S4] |
| D15 | 修改 | `boot` 资源 | +263,288 B；明文 802,105 → 893,431 | [S2][S3] |
| D16 | 修改 | 壳常量 | 4 项全部轮换 | [S3] |
| D17 | 修改 | `BUILD.json` | `version` 与 `patch_sha256`，native 字段不动 | [S1] |
| D18 | 修改 | 授权清单 | `issued` 改 11-02；`sys` 库 sha256 改，余 3 模块不变 | [S6] |
| D19 | 修改 | `sys` 服务库 `plat()` | 原子化初始化，修 E_BUDGET 打断导致图标全失效 | [S5] |
| D20 | 修改 | `install.ps1` / `README_zh.md` / Arsenal manifest | 安装主路径改为 Arsenal + 游戏内自装；删 Chef 宣传语 | [S1] |
| D21 | 修改 | EAC Fix Kit | 1.0.1 → 1.0.2，4 个文件改写，`tools/` 不变 | [S1] |
| D22 | 修改 | 菜单接入点 | `ModOptionsMenu` 6→4、`ModBindingsMenu` 5→3；开关不变 | [S4] |
| D23 | 修正 | 前期 §6 | 原生桥实为 4 个 `luaopen_*`，握手指令 `MDL3HELLO` | [S8][S9][R1] |
| D24 | 未变 | DLL / Data Hub / 文档内容 / coordinator / `package.loaded` / 握手 / TLS | 逐字节或逐命中数一致 | [S1][S4][S5][R4] |

---

## 6. 已存在但未向外开放的接口

「向外开放」的口径：随包提供的 `For Modder/hd2data_field_reference_v0_3_0.md` 明确声明「列出 MOD 通过 `HD2Data` 能拿到的**全部**函数和字段」；`README_zh.md` 只给玩家 3 个配置向开关。除此之外均为未开放面。

### 6.1 分层清单

| 层 | 接口 | 存在证据 | 未开放证据 |
|---|---|---|---|
| **L1 配置层**（已实现、无 UI 或仅隐性开关） | `MDL.cfg` 的 `safe_mode`、`ui.experimental_takeover`、`ui.incremental_draw`、`boot_disabled`、`memory_mb`、`performance`、`rva_cache`、`game_dir`、`dll`、`enabled`、`bindings` | [S8 `coordinator` 读 `MDL.cfg`][S9 配置键枚举][P10] | README 仅公开 `ui.incremental_draw`；`experimental_takeover` 只有界面文案 [S1 README L28][S9]；`boot_disabled`/`memory_mb`/`performance`/`rva_cache` 无玩家文档 |
| **L2 PE 导出层**（导出但无文档/无 Lua 封装） | 10 × `MDLB_*`：`GetABIVersion / GetInfo / GetMemory / GetPerformance / GetPerformanceDefaults / GetTrustInfo / QueueMemory / QueuePerformance / RequestStop / SetHostAPI` | [R1] 导出表 ordinal 1–10 | boot 明文 `MDLB_` 命中 **0** [S4]；无头文件、无签名说明、无调用样例 |
| **L2' C 模块入口**（Lua 侧自用，未暴露给 mod） | `luaopen_mdlbridge_start / step / stop / call`，`MAGIC` + `"hello"` / `"MDL3HELLO"` / `"MDL3OK"`，命令 `submit/frame/frame_fast/pump`，batch 协议（kind 1..5） | [S8][S9][R1] | 只由 boot 内部 `package.loadlib` 调用；`For Modder` 文档未提 [S1] |
| **L3 原生 VM 模块层** | 授权清单 4 模块：`sys`(exports `batch`,`set_watch`)、`watch`/`esc_ui`(service, exports=[])、`audio`(exports `prepare/init/step/describe/shutdown`) | [S6] | 位于 DLL 内 **native LuaJIT VM**（`__mdl3_ffi=ffi`），仅 boot 内部加载；`tier:"base"` 且带 sha256，属于受校验模块 [S5][S6] |
| **L3' DLL 内部模块** | `@bridge_codec` / `@bridge_platform` / `@bridge_runtime` / `@bridge_selftest`、`SELFTEST_PASS GC64 ffi=true bit=true jit_trace=true`、`start.cfg`、`MDLHOSTAPI1 %lx %lx %lx` | [R7] | 无对外注册；`trusted bootstrap required before hello` 表明有前置握手 [R7] |
| **L3'' Data Hub 原生 owner** | `HOST` 表 7 模块 `hdh_profile/hdh_catalog/hdh_events/hdh_player/hdh_tactical/hdh_strikes/hdh_main`；`host.memory.region`、`host.modules.info` | [S9][S2 Addon L20, L47–70] | 仅 addon 内嵌 `ffi` 代码使用；`HD2Data` 公开面只有 18 个函数 [S1 field reference §1] |
| **L4 路径 / 授权策略** | `%LOCALAPPDATA%\MDL3\sys-paths.txt` 的 **`read=`** 指令（与已用的 `mkdir=` 并列）、`sys path outside allowed roots` 根目录白名单 | [R7] `sys-paths.txt requires read= or mkdir=`；[S1 install.ps1] 只写 `mkdir=` | `read=` 未被任何安装脚本或文档使用 |
| **L4' 沙箱预算参数** | `slice_ms`、`tick_budget_ms`、`task_budget=`、`budget_overruns=`、`late_budget=`、`check_budget` / `clear_budget` | [R7] | 无配置入口、无文档 |
| **L4'' 信任链** | `trust_load/trust_call/trust_module/trust_state`、`trust_selftest=`、`trust_test_keys=`、`trust_rejected=`、严格 JSON 解析错误表 | [R7] | 授权清单校验器，非业务 API |

### 6.2 「能否打开这些接口」

分层回答，不代写代码、不改动任何二进制：

| 层 | 能否打开 | 说明 |
|---|---|---|
| **L1 配置键** | **能，且是唯一无需改程序的路径** | 这些键由 `MDL.cfg` 的沙箱 Lua 表读取 [S8]。玩家可直接编辑 `%LOCALAPPDATA%\MDL\Helldivers2\MDL.cfg`（非 ANSI 用户名场景为 `%ProgramData%\MDL\Helldivers2` [S1 README L25]）。本仓库已有先例：BML 0.14.8/0.14.9 在托管 MDL3 前把 `ui.experimental_takeover` 改回 `true` [W1 L103–110][P10]。注意 `safe_mode=true` 会让 mod 整批不启动 [S9]。 |
| **L2 / L2' 导出与 C 模块** | **技术上可调用，但本次不给调用代码** | `package.loadlib` 可直接取导出 [S8]，但 `MDLB_*` 的参数布局/ABI 未知（Ghidra 函数级反编译未取得 [R6]），且 DLL 内有 `trusted bootstrap required before hello`、`another bridge process owns this installation` 等前置状态 [R7]。盲调有游戏崩溃风险。要安全使用，需先补函数级反编译 + 运行时验证。 |
| **L3 / L3' / L3'' 原生 VM 模块** | **不属于"开关"，不能靠配置打开** | 这些模块靠 686 B 授权清单的 `sha256` + `tier` 校验加载 [S6][R7 `trust_*`]，并由 `MDLHOSTAPI1` 握手与单实例锁约束 [R7]。让它们面向游戏 Lua mod 暴露，等于新增桥接/注册代码并改动受签名保护的模块清单。 |
| **L4 / L4' / L4'' 策略与校验** | **不建议，且本会话不做** | `read=` 之类虽在 DLL 里存在 [R7]，但根目录有 `sys path outside allowed roots` 白名单；预算参数与 `trust_*` 校验器属于保护/治理面。改动它们等于绕过第三方闭源预览版（`protected preview`）的授权与完整性约束。 |

**明确边界**：本会话的角色是静态解读，只解释现状、给出位置与依据；**不生成补丁代码、不修改 DLL/patch、不协助绕过签名与授权校验**。若目标是让某个能力对 mod 可用，正确路径是：① 用 L1 配置键；② 依据 `For Modder` 文档与作者沟通新增公开 API；③ 确实需要扩展时，转到开发类工具，由你在自有代码里做实现与实机验证。另外，dev.36 的 DLL 带 Authenticode 签名（Certum → CHIEI INTERNET TECHNOLOGY LLC [R3]），任何对 DLL 的字节改动都会使签名失效并触发 EAC 的"不受信任的系统文件"路径 [S1 README L34–38]；去保护再分发还涉及第三方授权问题。

---

## 7. 风险与盲区

1. **静态检索盲区**：`rea:binary_overview` 在 9.3 MB DLL 上触发 Ghidra 330 s 启动时限 [R6]，函数级反编译、跨引用、动态派发、运行时行为均未取得；DLL 侧结论仅来自导出/导入/证书/加载配置表与字符串 [R1–R4][R7]。导出表行不代表导出在运行时可达或可安全调用 [R1 limitations]。
2. **未实机验证**：`docs/mdl3.md` §8 的「MDL3 是否只启动菜单中 ON 的 addon」「非 boot 位置下桥/ESC 菜单」仍未验证 [P8]；自部署、诊断窗口、ProgramData 迁移、E_BUDGET 提额全部只有静态证据。
3. **混淆与推断**：明文 boot 为 Prometheus 压缩/改名后的源码，变量名无语义；本报告的节点名（`z()`/`O()`/`s()` 等）是按上下文命名，非原始标识符。`@loader` / `HD2-Requires` 判定基于字符串集合差，未做语义级调用追踪。
4. **版本跨度**：前期基线是 dev.28 + dev.33 补记，本次是 dev.36，中间 dev.29–35 未在仓库中留存；`plat()` 注释提到 dev.32，说明部分变更早于 dev.36，本报告按「dev.28 → dev.36 净差异」归类，不推断中间版本。
5. **签名验证边界**：[R3] 只做 PKCS#7 结构解析，**未做密码学验签、链有效性、时间戳与 Authenticode 摘要覆盖校验**。
6. **合规**：MDL3 为第三方闭源 `protected preview`，本报告不含其源码；请勿将解出内容提交仓库或外发。

---

## 8. 下一步

1. 用 `tests/test_loader.py` 的 chef 模式用例复核 BML 判定表：`-- @loader mdl` 与 `HD2-Requires` 在 dev.36 已无 MDL3 侧对应解析，确认是否应改用 README L70–74 的其余 4 条规则 [W1][W5][D11]。
2. 若要推进 L2 导出接口，先提高 rea 的 Ghidra 启动时限或改用其它 provider 完成函数级反编译，再补 `MDLB_*` 的参数布局 [R6]。
3. 进游戏验证 `install-state.json` 是否生成、`.old` 备份是否落地、F1/F2 诊断窗口状态流转，以及非 ANSI 用户名下的 `%ProgramData%` 路径 [D02][D04][D06]。

---

### 附：本次逐站验收问题（费曼闭环）

1. dev.36 的 `.stream` 头三字段分别是什么、第二字段为什么不是 CRC32？
2. 为什么「DLL 两版字节相同」这个结论能让前期 §6 大部分结论直接沿用？
3. CSL 兼容层移除后，BML 的哪条路由判定最需要复核？
