// Package cpufeat classifies disassembled instructions into the CPU-feature
// families they require, so a binary can be summarised as "needs AVX2, SSE4.2,
// FMA" → an implied baseline (x86-64-v3). The classification is by mnemonic (and,
// where needed, operand shape) from the GNU-syntax assembly text the disassembler
// already produces, so no second decode is needed.
package cpufeat

import "strings"

// Mnemonic splits assembly text into its lower-cased opcode and the operand
// remainder.
func Mnemonic(text string) (op, operands string) {
	text = strings.TrimSpace(text)
	if i := strings.IndexAny(text, " \t"); i >= 0 {
		return lowerASCII(text[:i]), text[i+1:]
	}
	return lowerASCII(text), ""
}

func lowerASCII(s string) string {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 'A' && c <= 'Z' {
			b := []byte(s)
			b[i] = c + ('a' - 'A')
			for j := i + 1; j < len(b); j++ {
				if b[j] >= 'A' && b[j] <= 'Z' {
					b[j] += 'a' - 'A'
				}
			}
			return string(b)
		}
		if c >= 0x80 {
			return strings.ToLower(s)
		}
	}
	return s
}

// X86 reports the feature an x86/x86-64 instruction requires beyond the baseline,
// or "" for a baseline (or unclassified) instruction. SSE/SSE2 are the x86-64
// baseline, so they're not reported.
func X86(text string) string {
	op, rest := Mnemonic(text)

	// VEX/EVEX-encoded (AVX family): the GNU mnemonic starts with 'v' and uses
	// xmm/ymm/zmm vector registers.
	if len(op) > 1 && op[0] == 'v' && (strings.Contains(rest, "mm") || strings.Contains(rest, "%k")) {
		switch {
		case strings.Contains(rest, "zmm") || strings.Contains(rest, "%k"):
			return "AVX-512"
		case strings.HasPrefix(op, "vfmadd") || strings.HasPrefix(op, "vfmsub") ||
			strings.HasPrefix(op, "vfnmadd") || strings.HasPrefix(op, "vfnmsub"):
			return "FMA"
		case strings.HasPrefix(op, "vcvtph2ps") || strings.HasPrefix(op, "vcvtps2ph"):
			return "F16C"
		case strings.HasPrefix(op, "vaes"):
			return "AES"
		case strings.HasPrefix(op, "vpclmul"):
			return "PCLMUL"
		case strings.Contains(rest, "ymm") && (strings.HasPrefix(op, "vp") ||
			strings.HasPrefix(op, "vperm") || strings.Contains(op, "broadcast") ||
			strings.Contains(op, "gather") || strings.Contains(op, "blendd")):
			return "AVX2"
		}
		return "AVX"
	}

	switch {
	case op == "popcnt":
		return "POPCNT"
	case strings.HasPrefix(op, "crc32"):
		return "SSE4.2"
	case op == "pcmpgtq" || strings.HasPrefix(op, "pcmpistr") || strings.HasPrefix(op, "pcmpestr"):
		return "SSE4.2"
	case strings.HasPrefix(op, "pmovsx") || strings.HasPrefix(op, "pmovzx") || op == "ptest" ||
		op == "pmuldq" || op == "pmulld" || strings.HasPrefix(op, "blend") || strings.HasPrefix(op, "round") ||
		op == "dpps" || op == "dppd" || op == "mpsadbw" || op == "packusdw" ||
		strings.HasPrefix(op, "pmaxs") || strings.HasPrefix(op, "pmaxu") ||
		strings.HasPrefix(op, "pmins") || strings.HasPrefix(op, "pminu") ||
		op == "phminposuw" || op == "insertps" || op == "extractps":
		return "SSE4.1"
	case op == "pshufb" || strings.HasPrefix(op, "phadd") || strings.HasPrefix(op, "phsub") ||
		op == "pmaddubsw" || strings.HasPrefix(op, "palignr") || strings.HasPrefix(op, "psign") ||
		strings.HasPrefix(op, "pabs") || op == "pmulhrsw":
		return "SSSE3"
	case op == "addsubps" || op == "addsubpd" || strings.HasPrefix(op, "hadd") || strings.HasPrefix(op, "hsub") ||
		op == "movddup" || op == "movshdup" || op == "movsldup" || op == "lddqu":
		return "SSE3"
	case strings.HasPrefix(op, "aes"):
		return "AES"
	case op == "pclmulqdq":
		return "PCLMUL"
	case strings.HasPrefix(op, "sha1") || strings.HasPrefix(op, "sha256"):
		return "SHA"
	case op == "rdrand":
		return "RDRAND"
	case op == "rdseed":
		return "RDSEED"
	case op == "movbe":
		return "MOVBE"
	case op == "andn" || op == "bextr" || strings.HasPrefix(op, "bls") || op == "tzcnt":
		return "BMI1"
	case op == "bzhi" || op == "mulx" || op == "pdep" || op == "pext" || op == "rorx" ||
		op == "sarx" || op == "shlx" || op == "shrx":
		return "BMI2"
	case op == "lzcnt":
		return "ABM"
	case op == "adcx" || op == "adox":
		return "ADX"
	}
	return ""
}

// ARM64 reports the (mostly optional) ARMv8 extension an instruction requires, or
// "" for base instructions. NEON/ASIMD is mandatory in ARMv8-A but is reported so
// SIMD use is visible.
func ARM64(text string) string {
	op, rest := Mnemonic(text)
	switch {
	case strings.HasPrefix(op, "aes"):
		return "AES (crypto)"
	case strings.HasPrefix(op, "sha1") || strings.HasPrefix(op, "sha256") || strings.HasPrefix(op, "sha512"):
		return "SHA (crypto)"
	case strings.HasPrefix(op, "pmull"):
		return "PMULL (crypto)"
	case strings.HasPrefix(op, "crc32"):
		return "CRC32"
	case strings.HasPrefix(op, "cas") || strings.HasPrefix(op, "ldadd") || strings.HasPrefix(op, "stadd") ||
		strings.HasPrefix(op, "swp") || strings.HasPrefix(op, "ldset") || strings.HasPrefix(op, "stset") ||
		strings.HasPrefix(op, "ldclr") || strings.HasPrefix(op, "stclr") || strings.HasPrefix(op, "ldeor") ||
		strings.HasPrefix(op, "ldsmax") || strings.HasPrefix(op, "ldsmin") ||
		strings.HasPrefix(op, "ldumax") || strings.HasPrefix(op, "ldumin"):
		return "LSE atomics"
	case strings.HasPrefix(op, "pac") || strings.HasPrefix(op, "aut") || op == "xpaci" || op == "xpacd" ||
		op == "braa" || op == "brab" || op == "blraa" || op == "blrab" || op == "retaa" || op == "retab":
		return "Pointer auth"
	case op == "sdot" || op == "udot":
		return "DotProd"
	case op == "bfdot" || strings.HasPrefix(op, "bfmla") || op == "bfmmla":
		return "BF16"
	case hasSVEReg(rest):
		return "SVE"
	case hasNEONReg(rest):
		return "NEON/ASIMD"
	}
	return ""
}

// hasNEONReg reports an Advance-SIMD vector-register operand (v0.16b, v3.4s, …).
func hasNEONReg(operands string) bool {
	for i := 0; i+1 < len(operands); i++ {
		if (operands[i] == 'v') && operands[i+1] >= '0' && operands[i+1] <= '9' &&
			(i == 0 || !isIdentByte(operands[i-1])) {
			// a 'vN' token followed by '.<arrangement>' is a NEON register
			j := i + 1
			for j < len(operands) && operands[j] >= '0' && operands[j] <= '9' {
				j++
			}
			if j < len(operands) && operands[j] == '.' {
				return true
			}
		}
	}
	return false
}

// hasSVEReg reports an SVE register operand (z0.s, p0/z, …).
func hasSVEReg(operands string) bool {
	for i := 0; i+1 < len(operands); i++ {
		if operands[i] == 'z' && operands[i+1] >= '0' && operands[i+1] <= '9' &&
			(i == 0 || !isIdentByte(operands[i-1])) {
			j := i + 1
			for j < len(operands) && operands[j] >= '0' && operands[j] <= '9' {
				j++
			}
			if j < len(operands) && operands[j] == '.' {
				return true
			}
		}
	}
	return false
}

func isIdentByte(b byte) bool {
	return b == '%' || b == '_' || (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z') || (b >= '0' && b <= '9')
}

// BaselineX86 names the minimum x86-64 microarchitecture level implied by the set
// of features used (the highest level any used feature belongs to).
func BaselineX86(feats map[string]int) string {
	any := func(names ...string) bool {
		for _, n := range names {
			if feats[n] > 0 {
				return true
			}
		}
		return false
	}
	switch {
	case any("AVX-512"):
		return "x86-64-v4"
	case any("AVX", "AVX2", "FMA", "F16C", "BMI1", "BMI2", "MOVBE"):
		return "x86-64-v3"
	case any("SSE3", "SSSE3", "SSE4.1", "SSE4.2", "POPCNT"):
		return "x86-64-v2"
	default:
		return "x86-64-v1 (baseline SSE2)"
	}
}

// DisplayOrder lists features in a stable, roughly-increasing-requirement order
// for reporting.
var DisplayOrder = []string{
	// x86
	"SSE3", "SSSE3", "SSE4.1", "SSE4.2", "POPCNT", "ABM", "LZCNT",
	"AVX", "AVX2", "FMA", "F16C", "BMI1", "BMI2", "MOVBE", "ADX", "AVX-512",
	"AES", "PCLMUL", "SHA", "RDRAND", "RDSEED",
	// arm64
	"NEON/ASIMD", "LSE atomics", "CRC32", "Pointer auth", "DotProd", "BF16", "SVE",
	"AES (crypto)", "SHA (crypto)", "PMULL (crypto)",
}
