# 物品层数据表重导报告(PoE2 0.5.5)

任务:把网关运行时用到的物品层数据表从 PoE1 代际导出换成 0.5.5 客户端 GGPK 的重导。
方法:用仓库自带 schema.min.json(dat-schema v7)的 PoE2 布局(validFor=2,无则 3),
按 GameServer.Data.Dat.DatFile 的解析语义逐字节解码 datc64(行宽校验通过才接受),
再按网关反序列化代码实际读取的字段名补别名(PoE2 改名列 → 网关期望名)。
结论分级:已实证 / 推断 / 待验。

## GGPK 提取时间窗(按协调要求记录)

- 第一批:2026-11-04 约 16:37–16:45 CST,对 E:\poe2-local\Content.ggpk 跑 37 个文件名的
  顺序提取(其中 8 个成功),其后约 16:46 有一次 3 调用的探针运行(取得 skillgems)。
  该窗口与用户 16:45 一次启动失败重叠,疑似提取器短暂占用 GGPK 所致。
- 第二批(剩余 33 个文件):改为一次性批量脚本,等协调通知(用户真机测试结束)后执行,
  时间窗待补。离线解析不碰 GGPK。
- 补提批(尚缺 6 表):2026-11-04 17:18:24–17:20:54 CST 执行完毕。动手前与每一轮
  运行前均在目标机复查 PathOfExile 进程——不在运行,才启动提取器。两个相邻脚本
  一次跑完:先按全名提取 6 个文件名(命中 3 个;BuffDefinitions 另带出 9 个语种
  变体,只取 data/balance 基准版),再以词干 componentattribute / indexableskill /
  disenchant 对 GGPK 全索引补查 3 个未命中表(结论见第三节)。输出目录为目标机
  Temp\ggx055b;disenchant 词干误提的 NPC 语音 .ogg 已当场清理。此后 GGPK 未再触碰,
  解码全程离线(本机 /tmp/ggx + /tmp/ggx/stage,导出器 /tmp/export055.py)。

## 一、盘点:网关加载的物品层表

「当前行数」= PC D:\LocalExile2\data\tables 现有文件;「0.5.5 行数」= 本次从
E:\poe2-local\Content.ggpk 提取的 datc64 行数。(待第二批提取后补全)

| 表 | 主要消费者(代码位置) | 网关需要的关键字段 | 当前行数 | 0.5.5 行数 | 代际 |
|---|---|---|---|---|---|
| BaseItemTypes | ItemCatalog.Load;StartKit 经 catalog.Row/Find | Id,Name,HASH32,Width,Height,ItemVisualIdentity,ItemClassesKey,ItemStance,DropLevel,Implicit_ModsKeys,TagsKeys,ModDomain,Unmodifiable | 5461 | 5496 | 不符(PoE1) |
| SkillGems | ItemCatalog.LoadGems;PlayerInventories.StartKit;GemSources;GemVendorStock | BaseItemTypesKey,IsSupport,IsVaalVariant,GemVariants,GemColour,RegularVariant,ItemExperienceType,三维需求百分比,MtxSlotTypes | 847 | 1191 | 不符(PoE1) |
| GemEffects | LoadGems;SkillCatalog(无情模式映射) | Name,GrantedEffect,GrantedEffect2(PoE2 无此列) | 1292 | 1194 | 不符(PoE1) |
| ItemExperiencePerLevel | LoadGems | ItemExperienceType,ItemCurrentLevel,Experience | 361 | 375 | 待核 |
| ItemExperienceTypes | LoadGems | Id | 28 | 48 | 待核 |
| ItemClasses | ItemCatalog.Load | Id,ItemStance,Unmodifiable,CanBeFractured,__col21(PoE2 为 ItemClassFlags 数组,语义待验) | 103 | 118 | 不符(PoE1) |
| Mods | ModCatalog;ItemCatalog 隐含词缀 | Id,HASH16,Name,Domain,GenerationType,Level,StatsKey1..8,Stat{i}Min/Max,Families,SpawnWeight_*,GenerationWeight_*,TagsKeys,ImplicitTagsKeys,ModTypeKey,IsEssenceOnlyModifier | 40355 | 16784 | 不符(PoE1) |
| Stats | ModCatalog;StatCatalog | Id,IsLocal | 23346 | 27281 | 待核 |
| Tags | ItemCatalog.Load;ModCatalog | Id | 1389 | 1339 | 不符 |
| ModType | ModCatalog | Name | 14554 | 12574 | 待核 |
| ItemVisualIdentity | ItemCatalog.Load/Visual | Id,HASH16 | 15484 | 17227 | 待核 |
| ComponentCharges | ItemCatalog.Load;LoadFlasks;UtilityFlasks | BaseItemTypesKey(字符串=Id),MaxCharges,PerCharge | 51 | 31 | 待核(两代同 schema) |
| ComponentAttributeRequirements | ItemCatalog.LoadRequirements | BaseItemTypesKey(字符串),ReqStr/ReqDex/ReqInt | 862 | 无此表(全索引检索 0 命中) | PoE2 无此表 |
| CurrencyItems | ItemCatalog.Load | BaseItemTypesKey,StackSize,FullStack_BaseItemTypesKey | 1962 | 1537 | 不符 |
| WeaponTypes | ItemCatalog.LoadWeaponCrits;SkillCatalog | BaseItemTypesKey,Critical(PoE2 名 CritChance) | 366 | 407 | 不符(PoE1) |
| ShieldTypes | ItemCatalog.LoadShieldBlocks | BaseItemTypesKey,Block | 98 | 203 | 待核 |
| ArmourTypes | ItemCatalog.LoadDefences | BaseItemTypesKey,ArmourMin/Max,EvasionMin/Max,EnergyShieldMin/Max,WardMin/Max(PoE2 为单值列,见待验) | 481 | 1280 | 结构不符 |
| Flasks | ItemCatalog.LoadFlasks;UtilityFlasks | BaseItemTypesKey,LifePerUse,ManaPerUse,RecoveryTime,RecoveryTime2,BuffDefinitionsKey | 51 | 31 | 待核 |
| BuffDefinitions | UtilityFlasks | Id,StatsKeys(PoE2 名 Stats),GrantedFlags | (2.5MB) | 3218 | 不符(PoE1) |
| BuffTemplates | UtilityFlasks | Buff_StatValues 等 | (199KB) | 665 | 待核 |
| IndexableSkillGems | GemVendorStock | IndexRuthless,SkillGem2 | 有 | 无此表(全索引检索 0 命中) | PoE2 无此表 |
| GrantedEffects | SkillCatalog 多处 | Id,StatSet1(PoE2 名 StatSet),StatSet2(PoE2 为 AdditionalStatSets),ActiveSkill,CastTime,AddedActiveSkillTypes | 12829 | 8349 | 不符(PoE1) |
| GrantedEffectsPerLevel | SkillCatalog.Tables | GrantedEffect,Level,CostAmounts,CostTypes(PoE2 无此列),Cooldown,StoredUses,VaalSouls,AttackSpeedMultiplier,预留类字段(PoE2 缺) | 80600 | 34300 | 部分结构不符 |
| GrantedEffectStatSets | SkillCatalog.Tables | ImplicitStats,ConstantStats,ConstantStatsValues | 12763 | 8283 | 待核 |
| GrantedEffectStatSetsPerLevel | SkillCatalog.Tables | StatSet,GemLevel,FloatStats,BaseResolvedValues,AdditionalStats,AdditionalStatsValues,PlayerLevelReq(PoE2 无此列),DamageEffectiveness(PoE2 无此列) | 79927 | 41557 | 部分结构不符 |
| GrantedEffectQualityStats | SkillCatalog.Tables | GrantedEffectsKey,StatsKeys,StatsValuesPermille | 有 | 429 | 待核 |
| ActiveSkills | SkillCatalog | Id,ActionType,ActiveSkillTypes,WeaponRestriction_ItemClassesKeys(PoE2 无此列) | 1941 | 1147 | 部分结构不符 |
| ActiveSkillType | SkillCatalog.EffectsOfType | Id | 135 | 290 | 待核 |
| ActionTypes | SkillCatalog | Id,HASH16(PoE2 schema 未命名 u16 列 __col1,位置/类型与 PoE1 的 HASH16 一致) | 1351 | 963 | 待核 |
| Words | 暗金命名等 | Text,Text2,HASH32 | 4117 | 3246 | 待核(两代同 schema) |
| UniqueStashLayout | 暗金名/图 | WordsKey,ItemVisualIdentityKey | 1556 | 449 | 不符 |
| Characters | StartKit;GemSources;SkillCatalog.RowOfClass/ClassFor | StartWeapons,StartSkillGem,StartSupportGem,IntegerId,基础属性列 | 12 | 12 | 部分错位(见发现 3) |
| Essences | EssenceCrafting | BaseItemTypesKey,Level,ItemLevelRestriction,Display_*_ModsKey… | 106 | 95(仅盘点) | **网关 schema 为 PoE1 形,不重导(见遗留)** |
| CraftingBenchOptions | BenchCrafting | HideoutNPCsKey,Cost_BaseItemTypes,Name,ItemClasses… | 829 | 85(仅盘点) | **PoE2 schema 多为未命名列,无法忠实映射,不重导(见遗留)** |
| CraftingItemClassCategories | BenchCrafting | Id,ItemClasses,CategoryCode | 22 | 29 | 同上待核 |
| DelveUpgrades / DelveFlares / DelveDynamite | Delve 功能 | — | 387 / 2 / 4 | 387 / 2 / 4 | 行数相同,内容待 diff |
| UniqueMaps | 商店/地图 | ItemVisualIdentityKey,WorldAreasKey,WordsKey,Name | 33 | 0(dat 为空表) | 待核 |
| VillageUniqueDisenchantValues | 暗金分解值 | UniqueName,Value | 1527 | 无此表(已实证) | PoE2 无此表 |
| PassiveJewelSlots | 天赋珠宝槽 | Slot,… | 60 | 31 | 待核 |
| QuestRewardOffers | GemSources 掉落池 | (结构化报价) | 有 | — | **PoE2 schema 多为未命名列,不重导(见遗留)** |

另:data/item-types.json(物品组件表,非 dat 表)当前 5461 条,与 PoE1 的 BaseItemTypes
行数一致,是 PoE1 代际;它决定每个基底的 Components(即 ItemCatalog 的 Supported 判定)。
重导它需要跑 scripts/re/ot_components.py 对 GGPK 的 .it 文件提取,不在本批 datc64 范围,列为后续。

## 二、已实证发现

1. **现有整套表是 PoE1 代际**:字段名是 PoE1 schema 的命名(ItemClassesKey、
   MinionGlobalSkillLevelStat 等),行数与 PoE1 对应(SkillGems 847 行 < 女巫
   StartSkillGem 3951,正是此前越界崩溃的来源)。
2. **StartSkillGem=3951 指的是 BaseItemTypes 行,不是 SkillGems 行**(已实证):
   0.5.5 的 SkillGems 只有 1191 行,3951 根本不可索引;而 BaseItemTypes[3951] =
   `Metadata/Items/Gem/SkillGemUnearth`(Unearth,女巫的起始技能),且 SkillGems
   第 389 行的 BaseItemType 正好 = 3951(GemColour 3 = 智力蓝)。PoE2 schema 对
   Characters.StartSkillGem 的引用标注也是 BaseItemTypes。**网关 StartKit 与
   GemSources 把它当 SkillGems 行号用,是代码层语义不符**——数据层无法修正;
   换上新表后,3951 被边界防护判为无宝石(不再崩,但起始技能宝石仍缺失),需代码侧
   改为经 BaseItemTypes 行 → SkillGems 行(BaseItemType 列)解析。
3. **已部署的 Characters.json 的起始套件字段经复核是真值**(已实证,修正早先的
   错位怀疑):该文件带 PoE1 的列名,但不是用仓库 DatFile 解的(PoE1 schema 宽 612 ≠
   dat 的 640,DatFile 会直接抛错)。本次按 PoE2 schema 独立重解后逐项比对:12 个职业的
   StartSkillGem、StartWeapons 与部署文件全部一致(IntFour:3951→Unearth、
   StartWeapons=[2154]→FourWand1 Withered Wand),StartSupportGem 在两边都是空——
   PoE2 的 Characters 表根本没有其实质对应列(位置候选的两个未命名 foreignrow 在
   12 行全为 null),与 PoE2「起始只有技能宝石、无辅助宝石」的设计一致。本次重导的
   Characters.json 显式补 StartSupportGem=null 以满足网关的 GetProperty 硬读。
4. **SkillGems.IsSupport 的 PoE2 判据是 GemType==1**(已实证):1191 行全量交叉表——
   GemType 1 共 642 行,全部是 SupportGem 基底;GemType 0/2 为技能宝石(含常驻/触发类)。
   唯一按名字会误判的是 ascendancy 技能 "Supporting Fire"(SkillGem 基底、GemType 0,
   实为技能)。重导时按此规则生成 IsSupport 字段。
5. **StartKit 写死的 FlaskLife1 在 PoE2 不存在**(已实证):PoE2 的生命药剂 Id 是
   `Metadata/Items/Flasks/FourFlaskLife1` 等;StartKit 的
   `catalog.Find("Metadata/Items/Flasks/FlaskLife1")` 在新表里查不到,起始药剂会
   静默缺失。属代码层旧代残留,报告项,不改代码。
6. **解析器自洽性**:本次解码的每张表都通过了「schema 列宽总和 == dat 实际行宽」
   校验;UniqueStashLayout 得 449 行 × 83 字节,与此前 ExileDeck2 工具独立提取的
   结果(449 行、rowsize 83)一致,交叉验证通过。

## 三、重导结果

已按 PoE2 schema 解码并通过行宽校验的表(行数见盘点表):BaseItemTypes、SkillGems、
GemEffects、ItemClasses、Mods、Stats、Tags、ModType、ItemVisualIdentity、
ComponentCharges、CurrencyItems、WeaponTypes、ShieldTypes、ArmourTypes、Flasks、
ItemExperiencePerLevel、ItemExperienceTypes、Words、UniqueStashLayout、GrantedEffects、
GrantedEffectsPerLevel、GrantedEffectStatSets、GrantedEffectStatSetsPerLevel、
ActiveSkills、ActiveSkillType、ActionTypes、Characters、CraftingItemClassCategories、
PassiveJewelSlots、DelveUpgrades、DelveFlares、DelveDynamite,共 32 张已生成 staging
文件(+UniqueMaps 按空表生成 []),别名映射按第一节消费者字段逐表补齐(明细在
导出器 ALIASES 表)。SkillGems 另按 GemType==1 注入 IsSupport(与「基底 ItemClass==
19 Support Skill Gem」第二判据 1191/1191 全量一致)。

交叉验证三例(已实证):Words 3246 行与 ExileDeck2 独立提取的繁中/英文行数一致;
Characters 行宽 640 与此前 GGPK 原表核对一致;UniqueStashLayout 449 行 × 83B 与
ExileDeck2 的独立结果一致。

尚缺 6 个 datc64(ComponentAttributeRequirements、BuffDefinitions、BuffTemplates、
IndexableSkillGems、GrantedEffectQualityStats、VillageUniqueDisenchantValues),
已并入一次性补提脚本,待协调窗口(用户真机测试结束)执行后同批部署;
VillageUniqueDisenchantValues 在第一批 37 个文件名中未命中,PoE2 GGPK 或无此表。

部署与测试:待协调窗口执行(备份 *.bak-<时间戳> 后覆盖 D:\LocalExile2\data\tables,
重启 Auth/Gateway 后跑 Core/Data 测试)。

## 四、验证

离线 StartKit 路径检查(按 PlayerInventories.StartKit 的原逻辑对 staging 表复算,已实证):
- 女巫行 StartWeapons[0]=2154 → BaseItemTypes[2154] = FourWand1(Withered Wand),索引自洽;
  但其组件来自 data/item-types.json(PoE1 代际),该 PoE2 独有 Id 不在其中,故
  Supported=false——起始武器要真正构造出来,还需 item-types 按 0.5.5 重导(后续项)。
- StartSkillGem=3951 按网关语义(SkillGems 行号)越界(新表 1191 行)→ 边界防护判无宝石、
  不崩;按客户端真语义(BaseItemTypes 行)的完整链自洽:BaseItemTypes[3951]=Unearth →
  SkillGems[389](IsSupport=false、GemColour=3)→ GemEffects[390] → GrantedEffects[332]
  UnearthPlayer → StatSet 404 存在。
- 药剂链数据自洽:FourFlaskLife1 = 基底 2623 行,Flasks 行 LifePerUse 50/RecoveryTime 30,
  ComponentCharges 按 Id 命中(MaxCharges 60),31/31 药剂全有 charges 行;缺的只是
  StartKit 写死的旧 Id(发现 5)。
- 待协调窗口补:PC 上 Core/Data 测试结果、部署后对部署目录重跑同一检查。

## 五、遗留待验 / 结构性问题(不在本次数据层修复范围)

- StartSkillGem/StartSupportGem 的行号语义(BaseItemTypes 行 vs 网关按 SkillGems 行用)——代码层。
- StartKit 写死的 FlaskLife1 Id ——代码层。
- ArmourTypes 的 Min/Max:PoE2 dat 只有单值列;本次按 Min=Max=单值 生成别名
  (**待验假设**:PoE2 基底防御为固定值,退化区间表示;网关的 31 档插值在 Min=Max 时恒等)。
- Mods 的 Stat{i}Min/Max:PoE2 dat 的 Stat{i}Value 是 interval 列 [min,max](如
  IncreasedLife1 = [10,19]),重导时拆成 Min/Max 标量,已实证不是猜测;Hardmode 的
  Min/Max 对为原生列,原样保留。此项已闭环。
- ItemClasses.__col21:PoE2 该位置是 ItemClassFlags(i32 数组),与 PoE1 的未命名 bool
  不是同一字段;CanBeMirrored 判定在新数据下恒 false,待重新逆向。
- GrantedEffectsPerLevel 的 CostTypes、预留(Reservation)拆分列、GESSPL 的
  PlayerLevelReq/DamageEffectiveness、ActiveSkills 的 WeaponRestriction_ItemClassesKeys
  在 PoE2 dat 中无同名列(部分迁移到 GrantedEffects.CostTypes / StatSets 的
  DamageIncrementalEffectiveness),网关读到空/0,技能成本与武器限制语义待重新对齐。
- Essences / CraftingBenchOptions / QuestRewardOffers:网关侧 schema 是 PoE1 形,
  PoE2 对应表结构已变或 schema 未命名,强行覆盖会打断现有功能;保持旧文件不动,单独立项。
- data/item-types.json 需按 0.5.5 的 .it 文件重跑 ot_components.py,否则 PoE2 独有
  基底没有组件、Supported=false,起始武器/宝石即使数据对齐也构造不出来。
