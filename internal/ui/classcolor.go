package ui

import (
	"github.com/charmbracelet/lipgloss"

	"github.com/rabarbra/exex/internal/binfile"
	"github.com/rabarbra/exex/internal/disasm"
)

// styleForClass picks the rendering style for an instruction's class. The
// default (Other) falls through to the mnemonic colour so most instructions
// look uniform and the interesting ones jump out.
func (t Theme) styleForClass(c disasm.InstClass) lipgloss.Style {
	switch c {
	case disasm.ClassCall:
		return t.classCallStyle
	case disasm.ClassRet:
		return t.classRetStyle
	case disasm.ClassJumpUnc:
		return t.classJumpUncStyle
	case disasm.ClassJumpCond:
		return t.classJumpCndStyle
	case disasm.ClassSyscall:
		return t.classSyscallStyle
	case disasm.ClassNop:
		return t.classNopStyle
	}
	return t.mnemonicStyle
}

// styleForSymbol picks the row colour for a symbol based on its neutral kind.
// Bind (LOCAL/GLOBAL/WEAK) is folded in: globals are bold, weaks are italic,
// locals stay plain — so the same colour family stays consistent for the kind
// while letting the eye spot scope at a glance.
func (t Theme) styleForSymbol(k binfile.SymKind, b binfile.SymBind) lipgloss.Style {
	var base lipgloss.Style
	switch k {
	case binfile.SymFunc:
		base = t.symFuncStyle
	case binfile.SymObject:
		base = t.symObjectStyle
	case binfile.SymFile:
		base = t.symFileStyle
	case binfile.SymSection:
		base = t.symSectionStyle
	case binfile.SymTLS:
		base = t.symTLSStyle
	case binfile.SymCommon:
		base = t.symCommonStyle
	default:
		base = t.symOtherStyle
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
func (t Theme) styleForSection(s *binfile.Section) lipgloss.Style {
	if s == nil {
		return t.tableRowStyle
	}
	switch s.Category {
	case binfile.CatDebug:
		return t.secDebugStyle
	case binfile.CatNote:
		return t.secNoteStyle
	case binfile.CatSymtab:
		return t.secSymtabStyle
	case binfile.CatDynamic:
		return t.secDynamicStyle
	case binfile.CatReloc:
		return t.secRelocStyle
	case binfile.CatText:
		return t.secTextStyle
	case binfile.CatTLS:
		return t.secTLSStyle
	case binfile.CatData, binfile.CatBSS:
		return t.secDataStyle
	case binfile.CatRodata:
		return t.secRodataStyle
	}
	return t.tableRowStyle
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
