package main

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

//go:embed commands.json
var commandsJSON []byte

//go:embed catalog.json
var catalogJSON []byte

//go:embed names_zh.json
var namesZhJSON []byte

//go:embed mods.json
var modsJSON []byte

type Command struct {
	Name  string `json:"name"`
	Usage string `json:"usage"`
	Zh    string `json:"zh"`
}

type BaseItem struct {
	Name  string `json:"name"`
	ID    string `json:"id"`
	Class string `json:"class"`
	Zh    string `json:"-"` // filled from names_zh.json by Id
}

type UniqueItem struct {
	Name string
	Zh   string
}

type Catalog struct {
	Bases   []BaseItem `json:"bases"`
	Uniques []string   `json:"uniques"`
}

type Mod struct {
	ID     string `json:"id"`
	Name   string `json:"name"`
	Gen    int    `json:"gen"` // 1 prefix, 2 suffix, 3 special
	Domain int    `json:"domain"`
	Level  int    `json:"level"`
	Stat   string `json:"stat"`
	Min    int    `json:"min"`
	Max    int    `json:"max"`
}

var allCommands []Command
var catalog Catalog
var uniques []UniqueItem
var allMods []Mod

func loadData() error {
	if err := json.Unmarshal(commandsJSON, &allCommands); err != nil {
		return fmt.Errorf("命令目录损坏: %w", err)
	}
	if err := json.Unmarshal(catalogJSON, &catalog); err != nil {
		return fmt.Errorf("物品目录损坏: %w", err)
	}
	var zh struct {
		Bases   map[string]string `json:"bases"`
		Uniques map[string]string `json:"uniques"`
	}
	if err := json.Unmarshal(namesZhJSON, &zh); err != nil {
		return fmt.Errorf("中文名数据损坏: %w", err)
	}
	for i := range catalog.Bases {
		catalog.Bases[i].Zh = zh.Bases[catalog.Bases[i].ID]
	}
	uniques = make([]UniqueItem, 0, len(catalog.Uniques))
	for _, u := range catalog.Uniques {
		uniques = append(uniques, UniqueItem{Name: u, Zh: zh.Uniques[u]})
	}
	if err := json.Unmarshal(modsJSON, &allMods); err != nil {
		return fmt.Errorf("词缀库损坏: %w", err)
	}
	return nil
}

func filterCommands(q string) []Command {
	q = strings.ToLower(strings.TrimSpace(q))
	if q == "" {
		return allCommands
	}
	var out []Command
	for _, c := range allCommands {
		if strings.Contains(strings.ToLower(c.Name), q) || strings.Contains(c.Zh, q) {
			out = append(out, c)
		}
	}
	return out
}

// ---- base categories, from the Metadata path (e.g. Metadata/Items/Weapons/TwoHandWeapons/Bows/...) ----

type catRule struct {
	seg   string
	group string
	sub   string
}

// Ordered most-specific first: the first segment that matches decides.
var catRules = []catRule{
	{"OneHandSwords", "武器", "单手剑"}, {"OneHandAxes", "武器", "单手斧"}, {"OneHandMaces", "武器", "单手锤"},
	{"TwoHandSwords", "武器", "双手剑"}, {"TwoHandAxes", "武器", "双手斧"}, {"TwoHandMaces", "武器", "双手锤"},
	{"Daggers", "武器", "匕首"}, {"Claws", "武器", "爪"}, {"Wands", "武器", "法杖"}, {"Sceptres", "武器", "权杖"},
	{"Spears", "武器", "长矛"}, {"Flails", "武器", "连枷"}, {"Bows", "武器", "弓"}, {"Crossbows", "武器", "十字弓"},
	{"Staves", "武器", "长杖"}, {"Quarterstaves", "武器", "禅杖"}, {"Talismans", "武器", "魔符"},
	{"BodyArmour", "防具", "胸甲"}, {"BodyArmours", "防具", "胸甲"}, {"Helmets", "防具", "头盔"},
	{"Gloves", "防具", "手套"}, {"Boots", "防具", "鞋子"}, {"Shields", "防具", "盾牌"},
	{"Bucklers", "防具", "轻盾"}, {"Foci", "防具", "法器"}, {"Quivers", "防具", "箭袋"},
	{"Amulets", "饰品", "项链"}, {"Rings", "饰品", "戒指"}, {"Belts", "饰品", "腰带"},
	{"LifeFlasks", "药剂", "生命药剂"}, {"ManaFlasks", "药剂", "魔力药剂"}, {"HybridFlasks", "药剂", "复合药剂"},
	{"Flasks", "药剂", "药剂"}, {"Charms", "饰品", "咒符"}, {"Jewels", "珠宝", "珠宝"},
	{"SkillGems", "宝石", "技能宝石"}, {"SupportGems", "宝石", "辅助宝石"}, {"Gems", "宝石", "宝石"},
	{"Currency", "通货", "通货"}, {"Maps", "地图", "地图"}, {"MapFragments", "地图", "碎片"},
	{"DivinationCards", "其他", "命运卡"}, {"QuestItems", "其他", "任务物品"}, {"Relics", "其他", "遗物"},
	{"Weapons", "武器", "武器"}, {"Armour", "防具", "防具"},
}

func categoryOf(b BaseItem) string {
	segs := strings.Split(b.ID, "/")
	for _, r := range catRules {
		for _, s := range segs {
			if s == r.seg {
				return r.group + " · " + r.sub
			}
		}
	}
	return "其他"
}

// baseCategories returns the distinct categories present, sorted by group then name.
func baseCategories() []string {
	seen := map[string]bool{}
	var out []string
	for _, b := range catalog.Bases {
		c := categoryOf(b)
		if !seen[c] {
			seen[c] = true
			out = append(out, c)
		}
	}
	sort.Strings(out)
	return out
}

// filterBases: query matches the English or the Chinese name; category "" = any.
func filterBases(q, category string, limit int) []BaseItem {
	q = strings.ToLower(strings.TrimSpace(q))
	var out []BaseItem
	for _, b := range catalog.Bases {
		if category != "" && categoryOf(b) != category {
			continue
		}
		if q != "" && !strings.Contains(strings.ToLower(b.Name), q) && !strings.Contains(b.Zh, q) {
			continue
		}
		out = append(out, b)
		if len(out) >= limit {
			break
		}
	}
	return out
}

func filterUniques(q string, limit int) []UniqueItem {
	q = strings.ToLower(strings.TrimSpace(q))
	var out []UniqueItem
	for _, u := range uniques {
		if q != "" && !strings.Contains(strings.ToLower(u.Name), q) && !strings.Contains(u.Zh, q) {
			continue
		}
		out = append(out, u)
		if len(out) >= limit {
			break
		}
	}
	return out
}

func genName(gen int) string {
	switch gen {
	case 1:
		return "前缀"
	case 2:
		return "后缀"
	default:
		return "特殊"
	}
}

// filterMods: query matches Id, affix name or stat id; gen 0 = any; itemsOnly limits to item-domain mods.
func filterMods(q string, gen int, itemsOnly bool, limit int) []Mod {
	q = strings.ToLower(strings.TrimSpace(q))
	var out []Mod
	for _, m := range allMods {
		if gen != 0 && m.Gen != gen {
			continue
		}
		if itemsOnly && m.Domain != 1 {
			continue
		}
		if q != "" && !strings.Contains(strings.ToLower(m.ID), q) &&
			!strings.Contains(strings.ToLower(m.Name), q) &&
			!strings.Contains(strings.ToLower(m.Stat), q) {
			continue
		}
		out = append(out, m)
		if len(out) >= limit {
			break
		}
	}
	return out
}
