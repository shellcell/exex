package ui

import (
	"strings"

	"charm.land/lipgloss/v2"

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
	case disasm.ClassMove:
		return t.asmMoveStyle
	case disasm.ClassArithmetic:
		return t.asmArithStyle
	}
	return t.mnemonicStyle
}

// styleForSymbol picks the row colour for a symbol based on its neutral kind.
// Bind (LOCAL/GLOBAL/WEAK) is folded in: weaks are italic, globals and locals
// stay plain — so the same colour family stays consistent for the kind while
// letting the eye spot weak symbols. Symbols are never bold (it made most of the
// table heavy, since most symbols are global).
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
	if b == binfile.BindWeak {
		base = base.Italic(true)
	}
	return base
}

// styleForSection picks the row colour for a section based on its type/flags,
// with the loader's neutral category as a fallback. This keeps section colours
// useful across ELF, Mach-O, and PE even when format-specific type labels vary.
func (t *Theme) styleForSection(s *binfile.Section) lipgloss.Style {
	if s == nil {
		return t.tableRowStyle
	}
	switch sectionColorCategory(s) {
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

// styleForSegment picks the row colour for a segment from its permissions:
// executable segments reuse the .text row colour, writable ones the data
// colour, the rest read-only data — so segment colours read like the section
// table.
func (t *Theme) styleForSegment(exec, write bool) lipgloss.Style {
	switch {
	case exec:
		return t.secTextStyle
	case write:
		return t.secDataStyle
	}
	return t.secRodataStyle
}

func sectionColorCategory(s *binfile.Section) binfile.SectionCategory {
	name := strings.ToLower(s.Name)
	typ := strings.ToLower(s.TypeName)
	flags := strings.ToUpper(s.Flags)
	exec := s.Exec || strings.Contains(flags, "X")
	write := s.Write || strings.Contains(flags, "W")
	alloc := s.Alloc || strings.Contains(flags, "A")
	tls := strings.Contains(flags, "T") || strings.Contains(name, "tls") || strings.Contains(typ, "tls")

	switch {
	case strings.HasPrefix(name, ".debug") || strings.HasPrefix(name, ".zdebug") || strings.Contains(name, "dwarf") || strings.Contains(typ, "dwarf"):
		return binfile.CatDebug
	case strings.HasPrefix(name, ".note") || strings.Contains(typ, "note"):
		return binfile.CatNote
	case strings.Contains(typ, "symtab") || strings.Contains(typ, "dynsym") || strings.Contains(typ, "strtab") || strings.Contains(name, "symtab") || strings.Contains(name, "strtab"):
		return binfile.CatSymtab
	case strings.Contains(typ, "dynamic") || strings.Contains(typ, "hash") || strings.Contains(name, "dynamic") || strings.HasPrefix(name, ".dyn"):
		return binfile.CatDynamic
	case strings.Contains(typ, "rela") || strings.Contains(typ, "rel") || strings.Contains(name, "reloc") || strings.HasPrefix(name, ".rel"):
		return binfile.CatReloc
	case tls:
		return binfile.CatTLS
	case exec:
		return binfile.CatText
	case strings.Contains(typ, "nobits") || strings.Contains(typ, "zerofill") || (alloc && write && s.FileSize == 0 && s.Size > 0):
		return binfile.CatBSS
	case write:
		return binfile.CatData
	case alloc:
		return binfile.CatRodata
	}
	return s.Category
}

