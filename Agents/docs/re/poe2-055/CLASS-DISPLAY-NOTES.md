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