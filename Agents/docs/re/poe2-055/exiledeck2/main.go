package main

import (
	"fmt"
	"image/color"
	"strings"
	"time"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/canvas"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"
)

var (
	statusDot  *canvas.Circle
	statusText *widget.Label
	addrEntry  *widget.Entry
	logText    *widget.Label
	logScroll  *container.Scroll
	logLines   []string

	cmdShownUI []Command

	itemNamesUI       []string // English names to send, parallel to the item list rows
	itemDispUI        [][2]string
	uniqueMode        bool
	selectedItemIndex = -1

	modShownUI       []Mod
	selectedModIndex = -1
)

func setStatus(kind int, text string) {
	switch kind {
	case 0:
		statusDot.FillColor = color.NRGBA{R: 0xc0, G: 0x39, B: 0x2b, A: 0xff}
	case 1:
		statusDot.FillColor = color.NRGBA{R: 0xd4, G: 0x8b, B: 0x0f, A: 0xff}
	default:
		statusDot.FillColor = color.NRGBA{R: 0x27, G: 0xae, B: 0x60, A: 0xff}
	}
	statusDot.Refresh()
	statusText.SetText(text)
}

func logf(format string, args ...any) {
	logLines = append(logLines, time.Now().Format("15:04:05")+"  "+fmt.Sprintf(format, args...))
	if len(logLines) > 300 {
		logLines = logLines[len(logLines)-300:]
	}
	if logText != nil {
		logText.SetText(strings.Join(logLines, "\n"))
		logScroll.ScrollToBottom()
	}
}

func bridgeAddr() string {
	if addrEntry != nil && strings.TrimSpace(addrEntry.Text) != "" {
		return strings.TrimSpace(addrEntry.Text)
	}
	return "127.0.0.1:7010"
}

func sendCommand(command string) {
	command = strings.TrimSpace(command)
	if command == "" {
		return
	}
	if !strings.HasPrefix(command, "/") {
		command = "/" + command
	}
	logf("→ %s", command)
	go func() {
		resp, err := bridgeCommand(bridgeAddr(), command)
		fyne.Do(func() {
			switch {
			case err != nil:
				logf("✗ 发送失败（网关没开或命令桥没响应）：%v", err)
			case !resp.OK:
				logf("✗ %s", resp.Error)
			case resp.Ran:
				logf("✓ 已执行（角色 %s）— 结果看游戏内聊天框", resp.Character)
			default:
				logf("✗ 服务器不认识这条命令（看游戏内聊天框）")
			}
		})
	}()
}

func pollStatus() {
	for {
		names, err := bridgeWho(bridgeAddr())
		fyne.Do(func() {
			switch {
			case err != nil:
				setStatus(0, "未连接：网关未运行或命令桥未开")
			case len(names) == 0:
				setStatus(1, "已连上命令桥，暂无角色进入地图")
			default:
				setStatus(2, "在线："+strings.Join(names, "、"))
			}
		})
		time.Sleep(3 * time.Second)
	}
}

// twoLineList builds a list whose rows show a bold first line and a muted second line.
func twoLineList(length func() int, get func(i int) (string, string)) *widget.List {
	return widget.NewList(
		length,
		func() fyne.CanvasObject {
			first := widget.NewLabel("")
			first.TextStyle = fyne.TextStyle{Bold: true}
			second := widget.NewLabel("")
			return container.NewVBox(first, second)
		},
		func(i widget.ListItemID, o fyne.CanvasObject) {
			box := o.(*fyne.Container)
			a, b := get(int(i))
			box.Objects[0].(*widget.Label).SetText(a)
			box.Objects[1].(*widget.Label).SetText(b)
		},
	)
}

func main() {
	if err := loadData(); err != nil {
		panic(err)
	}
	a := app.NewWithID("local.exiledeck2")
	a.Settings().SetTheme(&poeTheme{})
	w := a.NewWindow("流放命令台 · PoE2 本地服")
	w.Resize(fyne.NewSize(1020, 740))

	// ---------- header ----------
	title := canvas.NewText("⚔  流放命令台 · PoE2", colGoldBright)
	title.TextSize = 22
	title.TextStyle = fyne.TextStyle{Bold: true}
	statusDot = canvas.NewCircle(color.NRGBA{R: 0xd4, G: 0x8b, B: 0x0f, A: 0xff})
	statusText = widget.NewLabel("正在连接命令桥…")
	addrEntry = widget.NewEntry()
	addrEntry.SetText("127.0.0.1:7010")
	header := container.NewBorder(nil, nil,
		container.NewHBox(title),
		container.NewHBox(
			widget.NewLabel("桥地址"), addrEntry,
			container.NewGridWrap(fyne.NewSize(14, 14), statusDot), statusText,
		),
	)

	// ---------- commands tab ----------
	cmdUsage := widget.NewLabel("")
	cmdUsage.Wrapping = fyne.TextWrapWord
	cmdUsage.TextStyle = fyne.TextStyle{Monospace: true}
	cmdShownUI = allCommands
	cmdSearch := widget.NewEntry()
	cmdSearch.SetPlaceHolder("搜索命令（英文名或中文说明）")
	cmdList := twoLineList(
		func() int { return len(cmdShownUI) },
		func(i int) (string, string) { return "/" + cmdShownUI[i].Name, cmdShownUI[i].Zh },
	)
	cmdEntry := widget.NewEntry()
	cmdEntry.SetPlaceHolder("要发送的命令（可修改参数），回车发送")
	cmdEntry.OnSubmitted = func(string) { sendCommand(cmdEntry.Text) }
	cmdList.OnSelected = func(i widget.ListItemID) {
		c := cmdShownUI[i]
		cmdUsage.SetText(c.Usage)
		cmdEntry.SetText("/" + c.Name + " ")
		cmdEntry.CursorColumn = len(cmdEntry.Text)
	}
	cmdSearch.OnChanged = func(s string) {
		cmdShownUI = filterCommands(s)
		cmdList.Refresh()
		if len(cmdShownUI) > 0 {
			cmdList.Select(0)
		}
	}
	sendBtn := widget.NewButtonWithIcon("发送", theme.MailSendIcon(), func() { sendCommand(cmdEntry.Text) })
	sendBtn.Importance = widget.HighImportance
	quick := container.NewHBox(
		widget.NewLabel("常用："),
		widget.NewButton("无敌 /god", func() { sendCommand("/god") }),
		widget.NewButton("回满 /heal", func() { sendCommand("/heal") }),
		widget.NewButton("金币 +100万", func() { sendCommand("/gold 1000000") }),
		widget.NewButton("升到 100 级", func() { sendCommand("/set_level 100") }),
		widget.NewButton("移速 200%", func() { sendCommand("/set_speed 200") }),
	)
	cmdTab := container.NewBorder(
		container.NewPadded(cmdSearch), nil, nil, nil,
		container.NewHSplit(cmdList, container.NewPadded(container.NewVBox(
			widget.NewLabelWithStyle("语法（英文原文）", fyne.TextAlignLeading, fyne.TextStyle{Bold: true}),
			cmdUsage,
			container.NewBorder(nil, nil, nil, sendBtn, cmdEntry),
			quick,
		))),
	)

	// ---------- items tab ----------
	countEntry := widget.NewEntry()
	countEntry.SetText("1")
	raritySel := widget.NewSelect([]string{"普通", "魔法 magic", "稀有 rare"}, nil)
	raritySel.SetSelected("普通")
	catSel := widget.NewSelect(append([]string{"全部分类"}, baseCategories()...), nil)
	catSel.SetSelected("全部分类")
	itemInfo := widget.NewLabel("")
	itemSearch := widget.NewEntry()
	itemSearch.SetPlaceHolder("搜索中文名或英文名，如 魔血 / Mageblood / 铁戒指")
	itemList := twoLineList(
		func() int { return len(itemDispUI) },
		func(i int) (string, string) { return itemDispUI[i][0], itemDispUI[i][1] },
	)
	itemList.OnSelected = func(i widget.ListItemID) { selectedItemIndex = int(i) }
	itemList.OnUnselected = func(widget.ListItemID) { selectedItemIndex = -1 }
	var refreshItems func()
	refreshItems = func() {
		const limit = 400
		selectedItemIndex = -1
		if uniqueMode {
			found := filterUniques(itemSearch.Text, limit)
			itemNamesUI = itemNamesUI[:0]
			itemDispUI = itemDispUI[:0]
			for _, u := range found {
				itemNamesUI = append(itemNamesUI, u.Name)
				first := u.Name
				if u.Zh != "" {
					first = u.Zh
				}
				itemDispUI = append(itemDispUI, [2]string{first, u.Name})
			}
			itemInfo.SetText(fmt.Sprintf("暗金 %d 件（目录共 %d，带中文名 %d）", len(found), len(uniques), countZhUniques()))
		} else {
			cat := ""
			if catSel.Selected != "" && catSel.Selected != "全部分类" {
				cat = catSel.Selected
			}
			found := filterBases(itemSearch.Text, cat, limit)
			itemNamesUI = itemNamesUI[:0]
			itemDispUI = itemDispUI[:0]
			for _, b := range found {
				itemNamesUI = append(itemNamesUI, b.Name)
				first := b.Name
				if b.Zh != "" {
					first = b.Zh
				}
				second := b.Name
				if b.Class != "" {
					second += "  ·  " + categoryOf(b)
				}
				itemDispUI = append(itemDispUI, [2]string{first, second})
			}
			itemInfo.SetText(fmt.Sprintf("基底 %d 件（目录共 %d）", len(found), len(catalog.Bases)))
		}
		itemList.Refresh()
	}
	itemSearch.OnChanged = func(string) { refreshItems() }
	catSel.OnChanged = func(string) { refreshItems() }
	modeSeg := widget.NewRadioGroup([]string{"基底", "暗金"}, func(s string) {
		uniqueMode = s == "暗金"
		refreshItems()
	})
	modeSeg.Horizontal = true
	modeSeg.SetSelected("基底")
	itemSendBtn := widget.NewButtonWithIcon("发送到背包", theme.ContentAddIcon(), func() {
		if selectedItemIndex < 0 || selectedItemIndex >= len(itemNamesUI) {
			logf("✗ 先在列表里选一件物品")
			return
		}
		parts := []string{"/item", itemNamesUI[selectedItemIndex]}
		count := 1
		fmt.Sscanf(strings.TrimSpace(countEntry.Text), "%d", &count)
		if count > 1 {
			parts = append(parts, fmt.Sprint(count))
		}
		if !uniqueMode {
			switch raritySel.Selected {
			case "魔法 magic":
				parts = append(parts, "magic")
			case "稀有 rare":
				parts = append(parts, "rare")
			}
		}
		sendCommand(strings.Join(parts, " "))
	})
	itemSendBtn.Importance = widget.HighImportance
	itemTab := container.NewBorder(
		container.NewVBox(
			container.NewHBox(modeSeg, widget.NewLabel("分类"), catSel),
			itemSearch,
		),
		container.NewBorder(nil, nil, itemInfo, nil,
			container.NewHBox(
				widget.NewLabel("数量"), countEntry,
				widget.NewLabel("稀有度（基底）"), raritySel,
				itemSendBtn,
			)),
		nil, nil,
		itemList,
	)

	// ---------- held item tab ----------
	mkBtn := func(text, cmd string) *widget.Button {
		return widget.NewButton(text, func() { sendCommand(cmd) })
	}
	sockEntry := widget.NewEntry()
	sockEntry.SetText("RRGBBB")
	// mods browser
	modSearch := widget.NewEntry()
	modSearch.SetPlaceHolder("搜索词缀：Id 片段、词缀名或属性，如 life / strength / IncreasedLife")
	modGenSel := widget.NewSelect([]string{"全部", "前缀", "后缀", "特殊"}, nil)
	modGenSel.SetSelected("全部")
	modItemsOnly := widget.NewCheck("只看装备词缀", nil)
	modItemsOnly.SetChecked(true)
	modInfo := widget.NewLabel("")
	modList := twoLineList(
		func() int { return len(modShownUI) },
		func(i int) (string, string) {
			m := modShownUI[i]
			first := m.ID
			if m.Name != "" {
				first += " · " + m.Name
			}
			second := fmt.Sprintf("%s · 需求等级 %d", genName(m.Gen), m.Level)
			if m.Stat != "" {
				second += " · " + m.Stat
				if m.Max > m.Min {
					second += fmt.Sprintf(" %d–%d", m.Min, m.Max)
				}
			}
			return first, second
		},
	)
	modList.OnSelected = func(i widget.ListItemID) { selectedModIndex = int(i) }
	modList.OnUnselected = func(widget.ListItemID) { selectedModIndex = -1 }
	var refreshMods func()
	refreshMods = func() {
		gen := 0
		switch modGenSel.Selected {
		case "前缀":
			gen = 1
		case "后缀":
			gen = 2
		case "特殊":
			gen = 3
		}
		modShownUI = filterMods(modSearch.Text, gen, modItemsOnly.Checked, 300)
		selectedModIndex = -1
		modInfo.SetText(fmt.Sprintf("词缀 %d 条（词缀库共 %d）", len(modShownUI), len(allMods)))
		modList.Refresh()
	}
	modSearch.OnChanged = func(string) { refreshMods() }
	modGenSel.OnChanged = func(string) { refreshMods() }
	modItemsOnly.OnChanged = func(bool) { refreshMods() }
	modSectionSel := widget.NewSelect([]string{"明文 explicit", "固有 implicit", "附魔 enchant"}, nil)
	modSectionSel.SetSelected("明文 explicit")
	modValues := widget.NewEntry()
	modValues.SetPlaceHolder("数值（可空，空格分隔多个；空 = 随机 Roll）")
	sectionArg := func() string {
		return strings.Fields(modSectionSel.Selected)[1]
	}
	applyMod := func() {
		if selectedModIndex < 0 || selectedModIndex >= len(modShownUI) {
			logf("✗ 先在词缀库里选一条词缀")
			return
		}
		m := modShownUI[selectedModIndex]
		cmd := "/item_mod " + sectionArg() + " " + m.ID
		if v := strings.TrimSpace(modValues.Text); v != "" {
			cmd += " " + v
		}
		sendCommand(cmd)
	}
	applyModBtn := widget.NewButtonWithIcon("设置到手持物品", theme.ConfirmIcon(), applyMod)
	applyModBtn.Importance = widget.HighImportance
	heldTab := container.NewBorder(
		container.NewVBox(
			widget.NewCard("手持定制", "先在游戏里左键把要改的物品拾到光标上（拿在手里），再用下面的按钮或词缀库。", nil),
			container.NewGridWithColumns(3,
				mkBtn("查看词缀", "/item_mods"),
				mkBtn("腐化", "/corrupt"),
				mkBtn("清除明文词缀", "/item_mod clear"),
				mkBtn("重 Roll（蓝装）", "/roll magic"),
				mkBtn("重 Roll（黄装）", "/roll rare"),
				mkBtn("设为暗金", "/rarity unique"),
			),
			container.NewBorder(nil, nil, widget.NewLabel("孔型（RRGBBB=六连）"), nil,
				container.NewBorder(nil, nil, nil,
					widget.NewButton("应用孔型", func() {
						if t := strings.TrimSpace(sockEntry.Text); t != "" {
							sendCommand("/sockets " + t)
						}
					}), sockEntry)),
			widget.NewSeparator(),
			container.NewHBox(widget.NewLabelWithStyle("词缀库", fyne.TextAlignLeading, fyne.TextStyle{Bold: true}), modInfo),
			container.NewHBox(modGenSel, modItemsOnly),
			modSearch,
		),
		container.NewBorder(nil, nil, nil, nil,
			container.NewHBox(
				widget.NewLabel("区段"), modSectionSel,
				widget.NewLabel("数值"), modValues,
				applyModBtn,
				widget.NewButton("清除该区段", func() { sendCommand("/item_mod clear " + sectionArg()) }),
			)),
		nil, nil,
		modList,
	)

	tabs := container.NewAppTabs(
		container.NewTabItemWithIcon("游戏命令", theme.ListIcon(), cmdTab),
		container.NewTabItemWithIcon("发送物品", theme.StorageIcon(), itemTab),
		container.NewTabItemWithIcon("手持定制", theme.SettingsIcon(), heldTab),
	)
	tabs.SetTabLocation(container.TabLocationTop)

	// ---------- log ----------
	logText = widget.NewLabel("")
	logText.TextStyle = fyne.TextStyle{Monospace: true}
	logText.Wrapping = fyne.TextWrapWord
	logScroll = container.NewVScroll(logText)
	logCard := widget.NewCard("日志", "", logScroll)

	split := container.NewVSplit(tabs, logCard)
	split.SetOffset(0.76)
	w.SetContent(container.NewBorder(
		container.NewPadded(header), nil, nil, nil,
		split,
	))
	logf("命令台已启动：%d 条命令、%d 件基底、%d 件暗金、%d 条词缀", len(allCommands), len(catalog.Bases), len(uniques), len(allMods))
	refreshItems()
	refreshMods()
	if len(cmdShownUI) > 0 {
		cmdList.Select(0)
	}
	go pollStatus()
	w.ShowAndRun()
}

func countZhUniques() int {
	n := 0
	for _, u := range uniques {
		if u.Zh != "" {
			n++
		}
	}
	return n
}
