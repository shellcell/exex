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
	b.Grow(len(rels) * (addrW + 56)) // size once: offset + type + section + target/row
	fmt.Fprintf(&b, "%-*s  %-24s %-12s %s\n", addrW+2, "Offset", "Type", "Section", "Symbol / Addend")
	// Demangle bind-target names (Itanium/Rust) the same way the symbols dump does,
	// caching by raw name so a big reloc table doesn't redo the work per row.
	demangled := map[string]string{}
	symName := func(s string) string {
		if s == "" {
			return ""
		}
		d, ok := demangled[s]
		if !ok {
			d = binfile.DemangleName(s)
			demangled[s] = d
		}
		if d != "" {
			return d
		}
		return s
	}
	// Each row is formatted into one reused buffer (no boxed Fprintf / per-row
	// Sprintf), so a relocatable object with tens of thousands of relocs stays cheap.
	var line []byte
	for i := range rels {
		r := &rels[i]
		line = append(line[:0], '0', 'x')
		line = appendHexPad(line, r.Offset, addrW)
		line = append(line, ' ', ' ')
		line = appendLeftStr(line, r.Type, 24)
		line = append(line, ' ')
		line = appendLeftStr(line, r.Section, 12)
		line = append(line, ' ')
		line = append(line, symName(r.Sym)...)
		if r.HasAddend {
			if r.Sym != "" {
				line = append(line, " + 0x"...)
			} else {
				line = append(line, '0', 'x')
			}
			line = appendHexPad(line, uint64(r.Addend), 0)
		}
		line = append(line, '\n')
		b.Write(line)
	}
	return b.String()
}

// relocsEmptyNote explains an empty relocation table per format (Mach-O linked
// images and PE without a base-reloc directory legitimately have none we decode).
func relocsEmptyNote(f *binfile.File) string {
	switch f.Format {
	case binfile.FormatMachO:
		return "no relocations (no dyld bind/rebase, chained fixups, or per-section relocations)\n"
	case binfile.FormatPE:
		return "no relocations (no base-relocation directory; stripped or /FIXED image)\n"
	}
	return "no relocations\n"
}
