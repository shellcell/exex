// Package arch defines CPU architecture identifiers shared by binary parsers
// and decoder adapters.
package arch

// Arch is a format-neutral CPU architecture selector. Container loaders map
// ELF/Mach-O/PE machine fields onto these values; decoder packages consume them.
type Arch uint8

const (
	ArchUnknown Arch = iota
	ArchX86          // 32-bit x86
	ArchAMD64        // x86-64
	ArchARM64        // AArch64
	ArchRISCV64      // 64-bit RISC-V
)
