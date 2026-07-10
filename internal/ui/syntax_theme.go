package ui

import (
	"strings"

	"github.com/rabarbra/exex/internal/config"
	"github.com/rabarbra/exex/internal/theme"
)

const darkSyntaxTheme = "catppuccin-mocha"

func sourceSyntaxTheme(cfg config.Config) string {
	if theme := strings.TrimSpace(cfg.Colors.SyntaxTheme); theme != "" {
		return theme
	}
	themeName := effectiveThemeName(cfg.Theme)
	if themeName == "dark" {
		return darkSyntaxTheme
	}
	if theme := presetColors(themeName).SyntaxTheme; theme != "" {
		return theme
	}
	return darkSyntaxTheme
}

func sourceSyntaxForeground(cfg config.Config) string {
	return theme.ForegroundFor(sourceSyntaxTheme(cfg))
}
