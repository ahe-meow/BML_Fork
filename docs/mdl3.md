# MDL3 3.0.0-dev.28：互操作观察（为 BML 0.14 路由而做）

只记录协议与结构，用来判断 "BML 当 boot、Chef 跑普通 mod、MDL3 只跑声明为 mdl 的 mod" 是否成立。
未复制其代码，解出的源码不随仓库分发；`ref/` 已在 `.gitignore`。

## 1. 参考包与解析方法

| 包 | 内容 |
|---|---|
| `MDL3-3.0.0-dev.28-preview-Data-Hub-0.3.0.zip` | `MDL3/patch_0` 只有一个 Lua 资源：`boot`（id `f476df93691895fa`，2 311 658 B）；另有 `Native/mdl_native_bridge.dll`（9.3 MB，v0.4.5）、`Addon/patch_0`（HD2 Data Hub）、`install.ps1` |
| `Chef兼容MDL3补丁…ChefBridge-0.2.1-核心1.5.1.zip` | 单个 addon `mods/mctimel/chef_bridge`（994 KB），即 Chef Shared Loader 1.5.1 的核 |

两个 zip 都是 Arsenal 布局：`<folder>/9ba626afa44a3aa3.patch_0`。资源表按与 BML 相同的格式读取（`0xF0000011` 头 + `0x48 + types*32` + `rows*80`，行内 murmur64 名 / 偏移 / `u32` 大小，包体 `u32 len` + `u32 kind` + 文本）。

## 2. MDL3 的 boot 是混淆的，但只包了一层

- 首个资源首行：`-- MDL3 3.0.0-dev.28 game boot (PUC Lua 5.1, protected preview)`。
- 壳子是一段自写解密器（自有 PRNG + 字节表），末尾：

  ```lua
  local D,p = loadstring(J,"@MDL3/boot")
  assert(D,p) … return D(...)
  ```

  `J` 是解密出的源码字符串（802 105 字符）。
- 因此"逆向"只需要在 Lua 5.1 宿主里把全局 `loadstring` 换成捕获器，不必执行载荷；本机没有 Lua 运行时，改用 Python 复现同一算法解出（只在内存里分析，未落盘入库）。

## 3. 启动序列：认出别的加载器，但不中止

`u.classify(src)` 按文本特征给每个 boot 资源定性：

| 特征 | 判定 |
|---|---|
| 含 `"@MDL3/boot"` + `loadstring`，或首行 `-- MDL3 … game boot` | `mdl3` |
| `--@@LOADER@@` / `chef_shared_loader` / `ChefSharedLoader` | `Chef Shared Loader` |
| `local MARKER = "boot-mod-loader-x.y.z"` 或 `__boot_mod_loader` | `Boot Mod Loader` |
| `CowboyBingusModLoader` + `revision = "loader-vN"` | Bingus |
| 含 `HD2-Addon` + `9ba626afa44a3aa3` | 其它加载器 |
| 其它 | 普通 boot（当 guest 跑） |

`u.plan_boots(found)`：按 patch 号从高到低，重复副本 `skipped`；`loader` / `starter` 类标成
`not run — "<名字>: a mod loader; MDL3 starts its addons itself"`；只有普通 boot 会被 `run`。
若最高 boot 不是 MDL3，只写一条日志（"Keep MDL3 deployed last…"），**不中止**。

→ **BML 当 boot 时 MDL3 仍能运行**，它只是不会去跑 BML 的 boot。

## 4. addon 启动：`require` 优先，已加载就不再执行

启动一个 addon 的路径（源码里 `start` 一段）：

1. `pcall(require, name)`；
2. 只有失败原因是 `module '<name>' not found` **且** `package.loaded[name] == nil` 时，才从 patch 档案里取源码、`loadstring(src,"@"..name)` 后执行；
3. 成功后写 `package.loaded[name]`。

→ **Chef 先启动的 mod 已经写进 `package.loaded`，MDL3 再启动同名 addon 只会拿到缓存值，不会二次执行。**
这是"Chef 默认 + MDL3 按声明"可行的核心依据。

## 5. 内置 CSL 模拟层（dev.28 的 "CSL 支持"）

- 顶层对象 `u` 带 `version="0.1.0"`、`emulates="1.4.1"`，日志前缀 `[csl]`。
- 每个被它启动的 addon 以 `pcall(chunk, chef_table)` 调用（`u.start` 里 `n(b.chef)`），`chef_table` 是它的模拟层。
- `u.claims(src)` 用 `local chef = ...` 之类特征判断"这是 Chef mod"；`u.requirements(src)` 解析头 1200 字节的 `-- HD2-Requires:`；`u.requires_ok` 只处理 `chef-shared-loader` / `chef-loader`（与 `emulates` 比版本）和 `mods/...`（要求已安装），**其他名字一律忽略**。
- 全源码 **0 处** `@loader`。

→ 若 MDL3 先跑，Chef mod 会被它的 1.4.1 模拟层接走（HUD/绘制缺失）。所以顺序必须是 **Chef 先、MDL3 后**。

## 6. 原生桥

`mdl_native_bridge.dll`（amd64，9 304 424 B，sha256 `99877159…c08d`）：

- 导出：`MDLB_GetABIVersion`、`MDLB_GetInfo`、`MDLB_GetMemory`、`MDLB_GetPerformance`、`MDLB_GetPerformanceDefaults`、`MDLB_GetTrustInfo`、`MDLB_QueueMemory`、`MDLB_QueuePerformance`、`MDLB_RequestStop`、`MDLB_SetHostAPI`，其余是 CRT。
- 导入：`KERNEL32.dll`(143)、`bcrypt.dll`(3)、`ADVAPI32.dll`(1，`RegGetValueW`)。**没有** lua51 依赖。
  KERNEL32 里含 `ReadProcessMemory` / `WriteProcessMemory` / `VirtualProtect` / `LoadLibraryExW` / `GetProcAddress` / `IsDebuggerPresent`——它在宿主进程里读写内存、可再加载模块，与"原生 owner 给 addon 提供内存数据"的定位一致。
- TLS 回调为空；PE 证书表未被验证（`inspect-pe-certificates` 只做结构解析）。
- 二进制里没有 `helldivers2` / `EasyAntiCheat` 字样 → 没有"必须是游戏宿主/必须是 boot"的检查。
- Lua 侧加载方式：`package.loadlib(dll, "luaopen_mdlbridge_call")` 拿到模块入口，再用 MAGIC 握手（`"hello"` → `"MDL3OK"`）；默认路径 `bin/mdl_native_bridge/mdl_native_bridge.dll`，可用环境变量 `MDL_NATIVE_BRIDGE_DATA` 覆盖。
- `install.ps1` 只把 DLL 放进游戏 `data\`、写 `%LOCALAPPDATA%\MDL3` 的配置与安装记录，**不改任何 patch**。

→ 原生桥是普通 Lua C 模块 + 宿主 API，不绑定 boot 槽位。**托管方案没有被原生层否决。**

## 7. 对 BML 0.14 的含义

1. 路由可行：BML 当 boot → 分类 → 先把 mdl 组写进 `CowboyBingusModLoader.modules[name]="loading"` 让 Chef 跳过 → 交接给 Chef → Chef 启动其余 mod 并写 `package.loaded` → 最后托管 MDL3 的 boot chunk，它只会真正启动还没被启动的那些。
2. MDL3 在顶层把 `init/update/render/shutdown` 全设成自己的 → 必须按 guest 方式托管（保存现有链，收编成一条具名 link，调一次它的 `init`）。
3. 判定（0.14.2，实机验证后调整）：`-- HD2-Requires: mdl3` / `-- @loader mdl`；读 `HD2Data`（Data Hub 的全局，数据来自 MDL3 的原生 owner，Squad Ping / Enemy HP / BFV / Data Hub 都读它）；脚本 > 4 MB（Chef 核 `MAX_LUA = 4*1024*1024`，超过直接不读）；头 1200 字节含 `MDL3`；首行 `local context = ...` / `local ctx = ...`。日志按 mod 打印理由。**不再只看声明**：BFV（30.5 MB，头部无声明）与 Squad Ping（121 KB，只在正文里读 HD2Data）实机在 Chef 下不生效。
4. `chef` 模式下 BML 不应再注入自己的 `ModOptionsMenu` / `ModBindingsMenu`，交接前清空这两个全局即可让 Chef 装自己的 F9 菜单。托管 MDL3 前同样要清空一次（Chef 已装了自己的）；若 MDL3 跑完仍未安装（dev.33 实测如此，MDL.log 无 "mod options: MDL provides ..."），就把 BML 的那两份放回去，MDL3 启动的 mod 才有地方注册设置（进 HD2 Mod Setting GUI）。
5. **注册表只能有一个主人**（0.14.3 实机发现）：MDL3 的 `coordinator` 在 `rawget(_G,'CowboyBingusModLoader')` 非空时直接返回 nil，日志写 `coordinator: another loader owns the addon registry`，随后一个 addon 都不启动，界面把 mod 标成"由 BML 运行"。所以托管 MDL3 前必须把 BML 自己的表从 `_G` 里拿掉（失败则放回），让它新建 `{version=17,api=1,modules={},provider='MDL',mdl3=true}`。启动结果不能靠假设：`package.loaded[name]` 有值才算真的跑过（日志 `MDL3 runs N of M`）。
6. **Chef 不写 `package.loaded`**（0.14.4 实机发现）：Chef 1.5.1 在它自己的空间里启动 mod，`package.loaded` 不留条目（它自己的 require 只给 look-alike 打标）。MDL3 判断"已被别人启动"只看 `package.loaded`，于是 Chef 启动过的 mod 会被 MDL3 **再跑一遍**（日志里 `addon mods/alomare/skip_intro_animation: loaded`，而 Chef 已启动它）。所以交接后 BML 要给交给 Chef 的每个 mod 写 `package.loaded[name]=true`（真话：Chef 确实跑过）。

## 8. 仍未验证（只能进游戏）

1. MDL3 是否只启动它界面状态为 ON 的 addon；首次部署默认是否 ON。
2. 非 boot 位置下原生桥与 ESC 菜单是否正常（DLL 路径解析、`%LOCALAPPDATA%\MDL3` 配置）。
3. Chef 对未知 requirement（`mdl3`）的实际处理是否如文档所说"不启动并记录"。

## 9. 附：ChefBridge 说明了什么

`mods/mctimel/chef_bridge` 就是 Chef 核 1.5.1 原样（`LOADER`/`FILES`/`ALLOW` 常量未改），尾部加了一段：
"MDL3 不调用 init，首帧补一次；update 继续交给 CSL"。
它证明两件事：加载器的核可以当普通 addon 跑；反过来（MDL3 当 guest）也可以期待同样的可行性。
它的文件头同时写明"只与 MDL3 一起用；BML/CSL 本体不要同时启用"——那是给最终用户的部署建议，不是协议限制。

## 10. dev.33 的设置界面（2026-11-04）

- 解出 dev.33（同一解密器，常量不同：PRNG 221/9264981147793、字节流 238、滚动初值 73、key 1124343134926）。
- 设置服务的开关：`f = ui.experimental_takeover ~= false and not safe_mode`；只有 f 为真且 `ModOptionsMenu` 为空时才安装，日志 `mod options: MDL provides the Mod Options Menu API`。
- 玩家把它关掉后，任何模式下（包括单独当 boot）都没有设置项；0.14.8 起托管前把 `MDL.cfg` 里的 `experimental_takeover` 改回 true。

- 0.14.9：它把设置服务装在 **init** 里（日志 `starting MDL3 ...` 与 `mod options: ...` 同一段），所以回填 BML 菜单必须等它的 init 返回后再判断；0.14.7/0.14.8 在 init 之前回填，正好挡住了它。
