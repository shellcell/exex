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
	ArchARM          // 32-bit ARM (A32, little-endian)
	ArchPPC64        // 64-bit PowerPC, big-endian
	ArchPPC64LE      // 64-bit PowerPC, little-endian
	ArchS390X        // IBM Z (s390x, big-endian)
	ArchLoong64      // LoongArch 64 (little-endian)
	ArchPPC          // 32-bit PowerPC, big-endian
	ArchPPCLE        // 32-bit PowerPC, little-endian
)

// String returns the conventional name of the architecture.
func (a Arch) String() string {
	switch a {
	case ArchX86:
		return "x86 (32-bit)"
	case ArchAMD64:
		return "x86-64"
	case ArchARM64:
		return "arm64"
	case ArchRISCV64:
		return "riscv64"
	case ArchARM:
		return "arm (32-bit)"
	case ArchPPC64:
		return "ppc64"
	case ArchPPC64LE:
		return "ppc64le"
	case ArchS390X:
		return "s390x"
	case ArchLoong64:
		return "loong64"
	case ArchPPC:
		return "ppc"
	case ArchPPCLE:
		return "ppcle"
	}
	return "unknown"
}
