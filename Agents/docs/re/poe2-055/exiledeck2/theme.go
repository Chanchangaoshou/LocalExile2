package main

import (
	"image/color"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/theme"
)

// poeTheme: a dark, gold-accented theme in the spirit of the game's own UI.
// Only Color and Size are overridden; Font and Icon delegate to the dark theme
// (embedding the Theme interface uninitialised would leave it nil and panic).
type poeTheme struct{}

func (t *poeTheme) Font(style fyne.TextStyle) fyne.Resource {
	return theme.DarkTheme().Font(style)
}

func (t *poeTheme) Icon(name fyne.ThemeIconName) fyne.Resource {
	return theme.DarkTheme().Icon(name)
}

var (
	colBackground = color.NRGBA{R: 0x16, G: 0x11, B: 0x0c, A: 0xff}
	colCard       = color.NRGBA{R: 0x21, G: 0x1a, B: 0x12, A: 0xff}
	colInput      = color.NRGBA{R: 0x26, G: 0x1e, B: 0x14, A: 0xff}
	colGold       = color.NRGBA{R: 0xc9, G: 0xa2, B: 0x27, A: 0xff}
	colGoldBright = color.NRGBA{R: 0xe8, G: 0xc5, B: 0x6a, A: 0xff}
	colText       = color.NRGBA{R: 0xe9, G: 0xdf, B: 0xcd, A: 0xff}
	colMuted      = color.NRGBA{R: 0x9a, G: 0x8a, B: 0x74, A: 0xff}
	colSelection  = color.NRGBA{R: 0x5a, G: 0x46, B: 0x14, A: 0xff}
)

func (t *poeTheme) Color(name fyne.ThemeColorName, variant fyne.ThemeVariant) color.Color {
	switch name {
	case theme.ColorNameBackground:
		return colBackground
	case theme.ColorNameButton, theme.ColorNameInputBackground:
		return colInput
	case theme.ColorNamePrimary:
		return colGold
	case theme.ColorNameForeground:
		return colText
	case theme.ColorNameForegroundOnPrimary:
		return color.NRGBA{R: 0x1a, G: 0x12, B: 0x04, A: 0xff}
	case theme.ColorNameDisabled:
		return colMuted
	case theme.ColorNameSelection:
		return colSelection
	case theme.ColorNameScrollBar:
		return colCard
	case theme.ColorNameShadow:
		return color.NRGBA{A: 0x66}
	}
	return theme.DarkTheme().Color(name, variant)
}

func (t *poeTheme) Size(name fyne.ThemeSizeName) float32 {
	switch name {
	case theme.SizeNamePadding:
		return 6
	case theme.SizeNameText:
		return 14
	case theme.SizeNameHeadingText:
		return 20
	}
	return theme.DarkTheme().Size(name)
}
