package ui

import (
	"github.com/charmbracelet/lipgloss"

	"github.com/rabarbra/exex/internal/binfile"
	"github.com/rabarbra/exex/internal/disasm"
)

// styleForClass picks the rendering style for an instruction's class. The
// default (Other) falls through to the mnemonic colour so most instructions
// look uniform and the interesting ones jump out.
func styleForClass(c disasm.InstClass) lipgloss.Style {
	switch c {
	case disasm.ClassCall:
		return classCallStyle
	case disasm.ClassRet:
		return classRetStyle
	case disasm.ClassJumpUnc:
		return classJumpUncStyle
	case disasm.ClassJumpCond:
		return classJumpCndStyle
	case disasm.ClassSyscall:
		return classSyscallStyle
	case disasm.ClassNop:
		return classNopStyle
	}
	return mnemonicStyle
}

// styleForSymbol picks the row colour for a symbol based on its neutral kind.
// Bind (LOCAL/GLOBAL/WEAK) is folded in: globals are bold, weaks are italic,
// locals stay plain — so the same colour family stays consistent for the kind
// while letting the eye spot scope at a glance.
func styleForSymbol(k binfile.SymKind, b binfile.SymBind) lipgloss.Style {
	var base lipgloss.Style
	switch k {
	case binfile.SymFunc:
		base = symFuncStyle
	case binfile.SymObject:
		base = symObjectStyle
	case binfile.SymFile:
		base = symFileStyle
	case binfile.SymSection:
		base = symSectionStyle
	case binfile.SymTLS:
		base = symTLSStyle
	case binfile.SymCommon:
		base = symCommonStyle
	default:
		base = symOtherStyle
	}
	switch b {
	case binfile.BindGlobal:
		base = base.Bold(true)
	case binfile.BindWeak:
		base = base.Italic(true)
	}
	return base
}

// styleForSection picks the row colour for a section based on its category.
func styleForSection(s *binfile.Section) lipgloss.Style {
	if s == nil {
		return tableRowStyle
	}
	switch s.Category {
	case binfile.CatDebug:
		return secDebugStyle
	case binfile.CatNote:
		return secNoteStyle
	case binfile.CatSymtab:
		return secSymtabStyle
	case binfile.CatDynamic:
		return secDynamicStyle
	case binfile.CatReloc:
		return secRelocStyle
	case binfile.CatText:
		return secTextStyle
	case binfile.CatTLS:
		return secTLSStyle
	case binfile.CatData, binfile.CatBSS:
		return secDataStyle
	case binfile.CatRodata:
		return secRodataStyle
	}
	return tableRowStyle
}

// kindString / bindString render neutral symbol kinds and bindings for the
// symbol table's Type and Bind columns.
func kindString(k binfile.SymKind) string {
	switch k {
	case binfile.SymFunc:
		return "FUNC"
	case binfile.SymObject:
		return "OBJECT"
	case binfile.SymSection:
		return "SECTION"
	case binfile.SymFile:
		return "FILE"
	case binfile.SymTLS:
		return "TLS"
	case binfile.SymCommon:
		return "COMMON"
	}
	return "NOTYPE"
}

func bindString(b binfile.SymBind) string {
	switch b {
	case binfile.BindGlobal:
		return "GLOBAL"
	case binfile.BindWeak:
		return "WEAK"
	}
	return "LOCAL"
}
