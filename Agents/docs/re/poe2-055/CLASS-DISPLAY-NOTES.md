# 2026-11-04 class display bug （选角界面全显示野蛮人） — from-zero re-investigation

用户实测证伪 5c87704（职业号镜像写入条目 +0x40)后，从零重查。不沿用旧结论；
下列每条都标了证据来源。客户端 = PoE2 0.5.5 原始 exe（raw = va − 0x140000C00)。

## 1. 客户端条目读函数逐指令映射（已实证）

S→C 0x15 的条目向量读函数 **0x142716700**（由 0x15 read 0x14214e210 在 0x14214e24a 调用，
全二进制唯一调用点）。先读 u8 计数，再逐条目（对象大小 **0x58**）按以下**线顺序**读：

| 线序 | 线型 | → 对象偏移 | 读点 |
|---|---|---|---|
| 1 | wstr (0x141cfb540) | +0x00（字符串对象 0x20B) | 0x142716800 |
| 2 | wstr | +0x20 | 0x14271680b |
| 3 | u8 | +0x4d | 0x142716817 |
| 4 | u8 | +0x51 | 0x142716829 |
| 5 | u8 | +0x4c | 0x14271683b |
| 6 | u32 + ntohl | +0x40 | 0x14271684d |
| 7 | u8 | +0x4e | 0x142716868 |
| 8 | u16 + ntohs | +0x44 | 0x142716888 |
| 9 | u16 + ntohs | +0x46 | 0x1427168a7 |
| 10 | u16 + ntohs | +0x48 | 0x1427168c7 |
| 11 | u16 + ntohs | +0x4a | 0x1427168e7 |
| 12 | u8 | +0x4f | 0x142716907 |
| 13 | u8 | +0x50 | 0x14271691d |

三方互证：条目**写镜像** 0x142716570 以同一顺序写出；0x15 消息**拷贝构造** 0x142150360
逐字段 1:1 拷贝（+0x40 u32、+0x44/+0x46/+0x48/+0x4a u16、+0x4c..+0x51 字节，及消息级
+0x28/+0x29、+0x30 串、+0x48 对向量、+0x68/+0x6c/+0x70、+0x74)，无任何重排。

## 2. fork 写出侧（已实证）

`ListEntry15.Write`（LoginMessages.cs:153-154）:
`WStr(Name).WStr(Text).U8(B4d).U8(B51).U8(B4c).U32(U40).U8(B4e).U16(U44).U16(U46).U16(Level).U16(Class).U8(B4f).U8(B50)`
——与客户端读序 **1:1 对齐，无错位**。LoginWriter.U16/U32 为大端（LoginWire.cs:19-20)，与
客户端读后 ntoh 一致。

`CharacterEntries()`（LoginServerSession.cs:279-284）对女巫角色（ClassId=1、Level=1、
Portrait=0）实际发出：

| 字段 | +0x40 | +0x44 | +0x46 | +0x48("Level") | +0x4a("Class") | 字节 +0x4c/4d/4e/4f/50/51 |
|---|---|---|---|---|---|---|
| 值 | 1（5c87704 后） | **0** | **0**（c.Portrait) | 1 | 1 | 全 0 |

`Portrait` 在账号模型里默认 0（Accounts/Models.cs:23)，且从未被 set_portrait 改过 → +0x46 恒 0。

**5c87704 实际改了什么**：仅把 `CharacterEntries()` 里 U40 的实参从 0 改为 ClassId
（LoginServerSession.cs 一行）。U40 是线序第 6 字段、落点确为对象 +0x40。用户实测仍显示
野蛮人 ⇒ **+0x40 不是选角界面的职业来源（实验排除，已实证）**。

## 3. 职业编号本身是对的（已实证，GGPK 原始数据）

从用户客户端 GGPK 抽出的原表解析（datc64：u32 行数、8×0xBB 魔数定行宽、字符串偏移
以魔数位置为基)：

- **Characters.datc64**：12 行 × 640B。行序 Id:0=Str/StrFour（野蛮人）、1=Int/IntFour（女巫）、
  2=Dex/DexFour、3=StrDex、4=DexInt、5=StrInt、6=StrFourb、7=IntFourb、8=DexFourb、
  9=StrDexFourb、10=DexIntFourb、11=StrIntFourb。繁中表行 0 名字 = 野蠻人。
- **CharacterStartStates.datc64**：109 行 × 222B；行 0..11 即 12 个「…Default」起始状态，
  其 +16 处 u32 = Characters 行号 0..11（行 1 = "IntFourDefault" → 1)。两表编号一致，
  **1 在客户端任何一张表里都是女巫**，不存在「编号体系不同」的解释。

## 4. C→S 0x12 创角的职业来源（已实证，任务 4)

- 职业由 **S78 字符串**携带（CharacterStartStates 的 Id，如 "IntFourDefault")，
  不在三个 u32 里——全天 11 个真实创角样本 U50/U54/U58 全为 0、S78 全为 "IntFourDefault"
  （Auth 日志，INSTANCE-RE-NOTES 既有记录）；客户端 0x12 对象拷贝构造 0x14213cb50/
  0x14213cc30 显示其对象布局为双 wstr + u32 组 + S78 wstr + 32B 摘要，与 fork 的
  `CreateCharacter.Read`（WStr, WStr, U32×3, WStr, Fixed(32)）一致；且 11 次创角的
  名字/联赛/S78 都被 fork 正确解出（错位则必然乱码），字段对齐成立。
- fork 的 `ClassWireId`（S78 去 "Default" 后缀查 StartStateWireIds)："IntFour"→1，
  与 §3 的客户端编号一致。`ClassOf` 对 U50/U54 的兜底分支永远走不到（S78 先命中）。
  **结论：创角存下的 ClassId=1 是真女巫，DB 没存错。**

## 5. 选角 UI 的职业来源 — 定位结果

**旧标签的来源（问题根源）**：fork 注释自承 "+0x48=level、+0x4a=class、+0x44/+0x46 改肖像"
来自 **PoE1 客户端**的逐字段探针（LoginServerSession.cs:270-277 原文 "on the PoE1 client")，
是 Ehco 从 PoE1 服务器继承的语义，**从未在 0.5.5 上验证过**。父会话早先的笔记
（INSTANCE-RE-NOTES class 节）标注 (level)/(class) 也只是沿用 fork 命
...[truncated 3297 chars]
（注：上方 §5 尾部在落盘时被截断，仅剩字面 "...[truncated 3297 chars]"，其「U44/U46 二选一」推论已被 16:16 实证证伪，见 §6.1。）

## 6. From-scratch audit（2026-11-04 晚，用户「从头排除 PoE1」令后复查）

### 6.1 前提更新：条目 u16/u32 字段全部排除（已实证）

16:16 会话的 0x15 抓包经程序化解码：yyyyyy 条目 U40=1、U44=1、U46=6、+0x48=1（Level 位）、
+0x4a=1（Class 位），界面仍显示野蛮人（Characters 第 0 行），且头像为 PoE1 样子。
**结论：+0x40/+0x44/+0x46/+0x48/+0x4a 都不是职业来源**（至少在这些取值下不是），
§5 的二选一收窄作废。当前线上代码（52de3f8）仍带着已证伪的探针（U44=职业号、U46=职业号+5），定案后必须撤除。

### 6.2 A4：登录工厂全目录与缺失报文（已实证）

- 工厂 0x14214fbe0 的 switch 已完整解码（id−1 ∈ [0, 0x46]，字节表 0x142150310、双字表 0x14215029c）：
  可构造的 S→C id 共 28 个。fork 的 `LoginCodec.ServerToClient` 与之逐一吻合，**只差一个：0x16**。
  （fork 注释里写的工厂地址 0x14219c350 在 0.5.5 里是某函数中段，不是工厂；真工厂是
  0x14214fbe0，它是类虚表 0x143506400 的 slot 1。）
- **S→C 0x16**：alloc 24 B，虚表 0x143509e58，write 0x14214ddd0 / read 0x14214de80。
  线格式（读写对已实证）：u32 BE→+0x10、u16 BE→+0x14、u16 BE→+0x16，全长 10 字节。
- 判断（推断）：0x16 无字符串/向量/计数，**不可能携带每角色职业/外观细节**，「缺失报文导致面板回退第 0 行」
  假设对 0x16 不成立。它仍是未建模报文（`SelectCharacterState::RenameCharacterResult(session, u32, u16, bool)`
  存在，形状相近，疑与改名流程有关），应补建模，但不是显示 bug 的嫌疑人。

### 6.3 A1/A2：面板侧定位（部分实证，静态路线到此为止）

- RTTI lambda 名实证以下类与方法存在：`CharacterSelectionPanel::Update(u64, const LeagueList&, const LeagueList&)`、
  `SSFButtonClicked(bool)`、`SSFMigration(u64, bool)`；`_Console` 版另有 `SetPlayerIndexIsActive(u64, bool)`；
  每行模板类是 **`CharacterEntryTemplate`**（`FourSimpleControlList<CharacterEntryTemplate>`、`OnNowShowingPopups(u64)`）；
  消费状态是 **`SelectCharacterState`**（`StartGame(bool,bool)`、`RenameCharacterResult(...)`、`GetLeaguesWithProgressWindow`）。
- 但这几个类的独立 TypeDescriptor 在二进制里不存在（名字只出现在 lambda 名内），虚表无法经 RTTI 定位；
  登录侧分发也不是 switch（在 0x1420e0000–0x1420e8000 的 142 个函数里扫 cmp 0x15/0x16/0x1b 零命中，
  是监听者注册式分发，与实例侧同构）。**从面板代码静态反推条目字段消费点，本轮到此为止**，改走 §6.6 的线上判别实验。
- 数据侧锚点：`Data/Balance/Characters.dat` 路径（UTF-16）在 exe 字符串池中；`Loaders::CharacterStartStates` /
  `CharacterStartStateSet` 的 TypeID PrettyName 存在；"DefaultCharacters"（UTF-16）位于 CreateCharacterScreen
  的 UI 字符串池区，是 StartStateSet=0 对应的标准集合名——与父会话已实证的「StartStateSet=0 已排除」一致。

### 6.4 A3：0x04 与 StartStateSet 假设（已实证/排除）

- fork 发的 LeagueEntry.StartStateSet=0（LeagueCatalog.Entry() 位置参数实证），即「DefaultCharacters」标准集，
  与官方一致；父会话已在线排除其为显示成因。0x04 LoginResult 本身不含 league/start-state 字段
  （布局已按 0.5.5 重导：U32、U16、账号 wstr、32B 摘要、+0x88 raw u16 标志、blob 向量），
  「0x04 把面板导向旧集合」不成立。

### 6.5 A5：头像来源（推断）

- 条目读函数无独立头像字段（已实证）；U46 在探针前承载 fork 的 Portrait 值、探针把它改成 6 后头像无变化，
  U46 不是头像来源（弱-中证据）。NPCPortraits 是 NPC 专用；玩家的头像/职业名/吊刑架场景 3D 模型
  最可能同源派生于**同一个 Characters 行号**——用户说的「PoE1 头像」即第 0 行野蛮人的头像
  （野蛮人本就是 PoE1 传承职业，美术观感像 PoE1）。行号定案后三者应同时恢复，不必单独追头像。

### 6.6 剩余候选与下一实验（全字段互异标记法）

剩余候选（按可能性排序，均为待验假设）：
1. **条目六字节 +0x4c/+0x4d/+0x4e/+0x4f/+0x50/+0x51**——历次发送全是 0、从未被判别实验动过；
   其 PoE1 标签（dead 标记/可见性）从未在 0.5.5 验证。若其一是行号/集合索引，恒 0 ⇒ 恒第 0 行，与现象完全吻合。
2. **0x15 报文级字段**：Head32(+0x70)、Text30(+0x30)、Pairs(+0x48 向量）、Tail68/Tail6C(+0x68/+0x6c)、U74/U76(+0x74/+0x76)——fork 全发 0/空，从未变过。
3. 由 Name/League 字符串派生（可能性低）；4. 0x04/0x1b 账号级状态（可能性低）。

**实验方案（一轮登录即可判别，不需新 Frida 探针）**：
- 前置：单独提交、单独部署；用**一次性新角色**做标记载体（避免 +0x4c 若是 dead 标记污染 yyyyyy），账号内其它角色条目保持正常。
- 第 1 轮（条目级）：标记角色条目设 U40=3、U44=4、U46=5、+0x48=6、+0x4a=7、字节 +0x4c=8、+0x4d=1（保可见）、
  +0x4e=9、+0x4f=10、+0x50=11、+0x51=2。看选角界面该角色的**职业名行号**：行号直接指认字段
  （对照：0=StrFour 野蛮人、1=IntFour 女巫、2=DexFour、3=StrDexFour、4=DexIntFour、5=StrIntFour、6=StrFourb 战士、
  7=IntFourb 秘术师、8=DexFourb 猎手、9=StrDexFourb 雇佣兵、10=DexIntFourb 武僧、11=StrIntFourb 德鲁伊）。
  +0x48 若真是等级，等级显示变 6 是预期副现象；+0x4c 若使角色变灰/不可选，本身即证据。
  若仍显示第 0 行 ⇒ 条目级全排除，进第 2 轮。
- 第 2 轮（报文级）：0x15 设 Head32=3、Tail68=4、Tail6C=5、U74=6、U76=7、Pairs=[(0,8),(1,9)]、Text30="x"，其余照旧。
  仍第 0 行 ⇒ 来源在 0x15 之外，第 3 轮改 0x04 的 U32/U16 与 LeagueEntry.StartStateSet=1 做对照。
- 可选同场 Frida（不必单独占一轮）：钩条目读函数 0x142716700 onLeave，记录条目对象地址及 +0x40..+0x51 原始字节
  （确认线上字节未被中间层改写）；钩 0x15 读函数 0x14214e210 onLeave，记录报文对象 +0x68..+0x76 与 Pairs 内容。
- 定案后：撤除 52de3f8 探针，CharacterEntries 按定案字段发送，并把字段语义写回 LoginMessages.cs 注释（注明 0.5.5 证据）。
