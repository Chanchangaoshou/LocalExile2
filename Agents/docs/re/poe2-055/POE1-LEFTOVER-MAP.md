# PoE1 残留地图 — LocalExile2 角色/登录层从头审计（2026-11-04）

分类：(a) 已按 0.5.5 证据重导｜(b) 继承自 PoE1 fork 未验证｜(c) 已知是 PoE1 的/错的。
证据出处随项标注；结论分级沿用 已实证/推断/待验假设。

## B. 登录与角色路径

| # | 项 | 类 | 证据与说明 |
|---|---|---|---|
| B1 | `CharacterClass` 枚举（Accounts/Models.cs:8：Scion, Marauder, Ranger, Witch, Duelist, Templar, Shadow） | **(c)** | 纯 PoE1 职业集与编号（Scion 在 PoE2 不存在）。存在每个账号角色记录上；`ClassId=-1` 时 0x15 的职业字段直接由它 cast 而来——枚举 Witch=3 发到客户端是第 3 行 StrDexFour，编号体系错位。 |
| B2 | `ClassOf`（0x12 创角定职业）的兜底链 | 混合 | S78→`StartStateWireIds` 是 (a)（2026-11-04 按 0.5.5 GGPK CharacterStartStates/Characters 重导，12 行编号实证）；`ClassIds`（PoE1 的 `Metadata/Characters/...` 路径→枚举）是 (c)；枚举名 parse 是 (c)；`StartStatePrefixes`（PoE1 属性前缀）是 (b)——"Int" 前缀碰巧也能命中 PoE2 的 "IntFour"，但 "StrFourb"（战士）会被判成 Marauder 枚举；U50/U54 数值 cast 到 PoE1 枚举是 (c)（真实样本里这两 u32 恒 0，走不到，但代码在）。 |
| B3 | `Character.Portrait`（Models.cs，ushort，默认 0） | (b) | 注释自称「角色列表显示它（经 U46）、Gateway 以 set_portrait 回报」——U46 已被 16:16 探针证伪为显示来源（改成 6 头像无变化）；set_portrait 在 0.5.5 的对应流程未验证。`MicrotransactionCharacterPortraitVariations` 表在客户端确实存在（exe PrettyName 实证），但与条目的衔接点未知。 |
| B4 | S→C 0x04 LoginResult | 布局 (a)，语义 (b) | 布局已按 0.5.5 重导（虚表 0x143509ed8，write 0x14214dad0 / read 0x14214dbe0，对象 0x90B）。但「哪个前导整数是登录门槛」未定版；结果码表 = BackendErrors 行号+1 是旧客户端（2026-10-16）实测映射；FlagVerified=0x20 的语义（未验证账号面板/锁聊天）是 PoE1 时代观察，均未在 0.5.5 复核。 |
| B5 | S→C 0x15 报文级字段（Head32、SelB28、SlotsB29、U74、U76、Text30、Pairs、Tail68/Tail6C） | 布局 (a)，语义 (b) | 线格式已按 0.5.5 read 0x14214e210 重导；B28/B29 语义是 2026-10-22 在**旧构建**上实测的（选中下标/角色位）；Pairs/Head/Tail/U74/U76/Text30 语义全未知，fork 全发 0/空。它们是职业显示剩余候选之二（见 CLASS-DISPLAY-NOTES §6.6）。 |
| B6 | `ListEntry15` 条目字段语义 | 线序 (a)，语义 (b)，且**职业来源未定** | 线序与客户端条目读函数 0x142716700 三方互证一致（CLASS-DISPLAY-NOTES §1–2）；全部语义标签（+0x48=Level、+0x4a=Class、+0x44/+0x46=肖像、+0x49 红标）源自 PoE1 客户端探针，fork 注释自承。16:16 实证已排除 +0x40/+0x44/+0x46/+0x48/+0x4a 为职业来源；六字节 +0x4c..+0x51 从未被变过。线上代码仍带着已证伪的判别探针（52de3f8：U44=职业号、U46=职业号+5），须按 §6.6 定案后撤除。 |
| B7 | C→S 0x12 CreateCharacter 解析 | (a) | 布局与客户端拷贝构造 0x14213cb50/0x14213cc30 对照一致；11 个真实创角样本的名字/联赛/S78 均被正确解出（错位必乱码）；职业只走 S78。三 u32 的含义 (b) 未知（样本恒 0）。 |
| B8 | C→S 0x10 CharacterSelected | (b) | u32+byte 的拆分是推断、值被服务端忽略（服务端以 0x0e Play 为准）。无害但未验证；注意控制台版面板有 `SetPlayerIndexIsActive(u64, bool)`，下标宽度是 u64，0x10 的真实布局值得按 0.5.5 read 函数复核一次。 |
| B9 | C→S 0x0e Play 的 Index 基数 | (b)，有反证苗头 | fork 按 **1 基**处理（代码注释自承 "inferred"）。2026-11-04 12:27 观察到疑似错位（选角与分配不一致的嫌疑，未定案）。这是登录路径上风险最高的未验证假设之一：错了会把玩家送进别人的角色/实例。 |
| B10 | U16Message 六个 id（0x0b/0d/0f/0x17/0x1e/0x44） | (a)，待一次活验 | 已按共用虚表 0x143509F18 的 read 0x14214e460 改为 u16+u32（提交 1e3ca9d）；0x0d 删角确认尚待下一次删角顺带实证（此前 4 字节旧模型造成接收流错位，是已实证的真 bug）。 |
| B11 | LeagueEntry（0x1a/0x1b 条目） | 布局 (a)，位语义 (b) | 布局已按 0.5.5 条目读函数 0x142716e10 重导（尾部六字节修正过一次错位）；Flags0/1/2 的位语义源自 2026-10-18 对旧客户端的静态分析；三个 raw64 时间未确认、发 0；StartStateSet=0 对应「DefaultCharacters」标准集 (a，已排除为显示成因）；C1 语义 (b)。 |
| B12 | LeagueCatalog 联赛目录 | **(c)** 部分 | 默认联赛含 **"Allflame"——PoE1 3.29 联赛**（注释自承 LeagueNames.dat Deepwater）；变体命名（"HC SSF R …"等）是 PoE1 惯例；Description 是自编英文（「非空否则创角界面崩溃」这条格式约束是 (a)，2026-10-18 活验）。客户端没有自带联赛表，所以名字错不会崩，但这是目录里最显眼的 PoE1 残留。 |
| B13 | S→C 0x16 未建模 | 缺口 | 本轮新发现：工厂 0x14214fbe0 可构造、fork 从不发。线格式已实证：u32 BE + u16 BE + u16 BE（虚表 0x143509e58，read 0x14214de80）。与职业显示无关（推断），疑与改名结果有关，待定位 handler。 |
| B14 | EnterGame 无分配时的默认区域 | **(c)** | LoginServerSession 的兜底是 Lioneye's Watch 哈希 0x235c——**3.29.3b 的哈希**，且 PoE2 根本没有这张图（PoE2 城镇是 G1_town 0x3f70）。Auth 主流程（Program.cs）已改走 WorldAreas.poe2.json 的城镇表，此兜底是否还可达须核实；可达即活雷。 |
| B15 | 数据表来源 | 分项 | `Characters.json`：(a) 2026-11-04 已从 0.5.5 GGPK characters.datc64 重导出（12 行，IntegerId=行序），Gateway 的 SkillCatalog/AscendancyCatalog/GemSources/OrdinaryPassiveRules/PlayerInventories 在用；`WorldAreas.poe2.json`：(a) 0.5.5 WorldAreas.datc64（442 行，HASH16 为存储列）；Core 的 World 辅助类注释仍引用无后缀的 `WorldAreas.json`（旧代文件），实际运行时加载哪个须在 PC 上核实；`SkillGems.json` 与基底物品表：**(c) 旧代导出**——女巫 StartSkillGem 指向第 3951 行越界崩溃已实证，整表待从 0.5.5 GGPK 重导出；BuffTemplates/BuffDefinitions/Delve* 等：(c) PoE1 玩法系统数据（Delve 在 PoE2 不存在）。 |
| B16 | 仓库文档层 | (c) | 仓库内 AGENTS.md 仍写「Path of Exile 3.29.3b 的本地服务器」及 PoE1 的 Agents/ 文档体系（GitHub 根 README 已按用户令换成 PoE2 版，提交 bed7014）。不影响运行，但新读者/AI 会被误导。 |

## C. 实例层残留速览（深挖由 evening 系列进行，此处只给状态）

**已按 0.5.5 验证 (a)**：29 字节开场包与摘要构造（真哈希 = 前 8 字节，CONST8‖Data8‖时间戳；后 4 字节是 BE 时间戳）；Salsa20 密钥流模型与密钥递交（Frida 逐字节实证）；HNC DeriveKey（掩码 0x142f10980 异或 + 六次交换，与抓包逐字节吻合）；S→C 0x11 尾随字节修复；编号重映射（tick C→S 0x1c、pong S→C 0x1d、区域 S→C 0x1e、C→S 区域已生成 0x9a）；`AreaInstance.Encode` 最小 47 字节形（0x1e 被客户端接受、生成河岸、不再抛 HNC——活验）；S→C 0x28 实例身份（key+wstring 名，setter 置 session+0x2270，16:16 活验干净接受）；InstanceKeyring KDF；ClassId（Characters 行号）自 Auth→票据→控制通道→网关贯通。

**未验证待重导 (b)**：0x23 的合法内容形（空形能触发激活却在区域生成期崩溃，evening4 在逆）；玩家 blob 的组件布局（fork 现有 blob 对 0.5.5 实体构造 0x141e705d0 的逐字有效性——当前最大风险）；类型哈希 0xa7000ea0（fork MurmurHash2 算法自算，客户端类型登记从未被观测查过它）；世界头 stamp 语义（填 0 与 ctor 初值一致，仅此而已）；「实例世界未挂入状态机/对象树」模型（evening3 推断，缺失的可能不是报文而是客户端内部迁移）。

**已知 PoE1/错 (c)**：旧 SendPlayer 世界消息全套（0x22 SetLocalPlayer、0x2b9 CreateObject、0x1a9、0x2ba、0x1f3、0x2a9）在 0.5.5 世界分发器里无对应 case（CreateObject 新编号是 0x2f7），现行流程已禁用、待 0x2f7 路线定案后删除；LeagueStats 与地形块的 0.5.5 编码未逆出，Encode 遇之抛 NotSupportedException（不发猜测格式，姿态正确）；出生装备/宝石挂旧代表（见 B15/R7）。

## 重建清单（可执行，按优先级）

- **R1** 跑 CLASS-DISPLAY-NOTES §6.6 的全字段互异标记实验（第 1 轮条目级）→ 定案职业字段 → 撤除 52de3f8 探针，`CharacterEntries` 按定案发送，语义写回 LoginMessages.cs 注释（注明 0.5.5 证据出处）。
- **R2** 以 0.5.5 Characters 行号（0..11）全面取代 `CharacterClass` 枚举：账号库迁移（PoE1 枚举→行号的一次性映射，Scion 无对应行、标无效待用户处置）；删 `ClassIds`/`StartStatePrefixes`/枚举名兜底；`ClassOf` 只保留 S78→CharacterStartStates 行→其 +16 的 Characters 行号一条链（按 0.5.5 两张 .datc64 表重导）。
- **R3** Play Index 基数判别测试：两个角色、新登录、选第二个进游戏，看 Auth 实际分配的角色——定案后修正 `EnterGame` 的 clamp/基数（对应 B9）。
- **R4** 反汇编 0x04 的 handler，定版「门槛整数」；结果码按 0.5.5 GGPK 的 BackendErrors.datc64 重导；FlagVerified 语义在 0.5.5 复核（对应 B4）。
- **R5** 建模 S→C 0x16（线格式已实证，见 B13），定位其 handler 后决定发/不发。
- **R6** LeagueCatalog 去 PoE1 化：删 Allflame 默认；联赛名与变体命名按 PoE2 0.5.x 官方形态重写；Flags 位语义有余力时按 0x1b handler 复核（对应 B11/B12）。
- **R7** 用 PC 上的 ggpk-extract 从 0.5.5 Content.ggpk 整表重导出 Gateway 实际加载的全部 `data/tables/*.json`（SkillGems、基底物品优先）；Delve 等 PoE2 不存在的系统表删除或停用（对应 B15）。
- **R8** 核实 B14 兜底（Lioneye's Watch 0x235c）是否可达：可达则改为 G1_town(0x3f70）或删兜底；下一次删角顺带活验 B10 的 0x0d 新模型后关闭该项。
- **R9** Portrait（B3）：在 `MicrotransactionCharacterPortraitVariations` 的客户端消费点逆清之前，注释里不得再声称「列表显示它」；保持发 0 语义待定。
