package dump

// Relocations dump (`-o relocs`): a readelf-style table of relocation entries,
// one per line, from binfile's neutral model.

import (
	"fmt"
	"strings"

	"github.com/rabarbra/exex/internal/binfile"
)

// Relocs dumps the binary's relocation table.
func Relocs(f *binfile.File) string {
	rels := f.Relocations()
	if len(rels) == 0 {
		return relocsEmptyNote(f)
	}
	addrW := f.AddrHexWidth()
	var b strings.Builder
	fmt.Fprintf(&b, "%-*s  %-24s %-12s %s\n", addrW+2, "Offset", "Type", "Section", "Symbol / Addend")
	for _, r := range rels {
		target := r.Sym
		if r.HasAddend {
			if target != "" {
				target += fmt.Sprintf(" + 0x%x", uint64(r.Addend))
			} else {
				target = fmt.Sprintf("0x%x", uint64(r.Addend))
			}
		}
		fmt.Fprintf(&b, "0x%0*x  %-24s %-12s %s\n", addrW, r.Offset, r.Type, r.Section, target)
	}
	return b.String()
}

// relocsEmptyNote explains an empty relocation table per format (Mach-O linked
// images and PE without a base-reloc directory legitimately have none we decode).
func relocsEmptyNote(f *binfile.File) string {
	switch f.Format {
	case binfile.FormatMachO:
		return "no relocations (linked Mach-O images use dyld bind/rebase or chained fixups, not decoded)\n"
	case binfile.FormatPE:
		return "no relocations (no base-relocation directory; stripped or /FIXED image)\n"
	}
	return "no relocations\n"
}
