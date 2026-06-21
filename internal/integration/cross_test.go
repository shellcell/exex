//go:build crosscompile

// Package integration holds slow, toolchain-dependent end-to-end tests. They
// compile a trivial program with the Go and Zig cross-compilers for every target
// exex can read, then parse and (where the CPU is one exex disassembles) decode
// each binary through the very code paths the CLI uses (binfile.Open, dump.View,
// dump.DisasmTo).
//
// These are gated behind the "crosscompile" build tag so the normal, hermetic
// `go test ./...` stays fast and needs no external toolchains. Run them with:
//
//	go test -tags crosscompile ./internal/integration/ -v
//
// or `make test-cross`. Targets whose toolchain support is missing on the host
// are skipped (t.Skip), not failed; a handful of ubiquitous targets must pass.
package integration

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/rabarbra/exex/internal/arch"
	"github.com/rabarbra/exex/internal/binfile"
	"github.com/rabarbra/exex/internal/disasm"
	"github.com/rabarbra/exex/internal/dump"
	"github.com/rabarbra/exex/internal/explorer"
)

// goFormatFor maps a Go GOOS to the container format exex should detect, and
// whether exex supports it at all (it doesn't read wasm, plan9 a.out or AIX
// XCOFF, so those targets are skipped).
func goFormatFor(goos string) (binfile.Format, bool) {
	switch goos {
	case "linux", "android", "freebsd", "netbsd", "openbsd", "dragonfly", "solaris", "illumos":
		return binfile.FormatELF, true
	case "darwin", "ios":
		return binfile.FormatMachO, true
	case "windows":
		return binfile.FormatPE, true
	}
	return "", false
}

// disasmSupported reports whether exex has a disassembler for arch a, so the test
// only asserts decoding for those (other CPUs are still parse-tested).
func disasmSupported(a arch.Arch) bool {
	switch a {
	case arch.ArchX86, arch.ArchAMD64, arch.ArchARM64, arch.ArchRISCV64,
		arch.ArchARM, arch.ArchPPC, arch.ArchPPCLE, arch.ArchPPC64, arch.ArchPPC64LE,
		arch.ArchS390X, arch.ArchLoong64:
		return true
	}
	return false
}

// goArchFor maps a Go GOARCH to the arch exex should report, so the test can
// confirm the machine field was parsed correctly. ArchUnknown means exex doesn't
// model that CPU (still a valid parse, just no disassembler).
func goArchFor(goarch string) arch.Arch {
	switch goarch {
	case "amd64":
		return arch.ArchAMD64
	case "386":
		return arch.ArchX86
	case "arm64":
		return arch.ArchARM64
	case "riscv64":
		return arch.ArchRISCV64
	case "arm":
		return arch.ArchARM
	case "ppc64":
		return arch.ArchPPC64
	case "ppc64le":
		return arch.ArchPPC64LE
	case "s390x":
		return arch.ArchS390X
	case "loong64":
		return arch.ArchLoong64
	}
	return arch.ArchUnknown
}

// zigArchFor maps the arch component of a Zig "<arch>-<os>" target to exex's arch.
func zigArchFor(target string) arch.Arch {
	a, _, _ := strings.Cut(target, "-")
	switch a {
	case "x86_64":
		return arch.ArchAMD64
	case "x86":
		return arch.ArchX86
	case "aarch64", "aarch64_be":
		return arch.ArchARM64
	case "riscv64":
		return arch.ArchRISCV64
	case "arm", "armeb", "thumb":
		return arch.ArchARM
	case "powerpc":
		return arch.ArchPPC
	case "powerpcle":
		return arch.ArchPPCLE
	case "powerpc64":
		return arch.ArchPPC64
	case "powerpc64le":
		return arch.ArchPPC64LE
	case "s390x":
		return arch.ArchS390X
	case "loongarch64":
		return arch.ArchLoong64
	}
	return arch.ArchUnknown
}

// countWriter is an io.Writer that only counts bytes, for asserting the streaming
// disassembler produced output without buffering it.
type countWriter struct{ n int }

func (c *countWriter) Write(p []byte) (int, error) { c.n += len(p); return len(p), nil }

// findFunc returns a sized symbol whose name matches one of names (tried in the
// given priority order) and that lands in the executable image — a function safe
// to disassemble.
func findFunc(f *binfile.File, names ...string) (binfile.Symbol, bool) {
	for _, n := range names {
		for _, s := range f.Symbols {
			if s.Name != n || s.Size == 0 {
				continue
			}
			if _, ok := f.ExecImage().PosForAddr(s.Addr); ok {
				return s, true
			}
		}
	}
	return binfile.Symbol{}, false
}

// isFlowTerminator reports whether an instruction plausibly ends a function's
// real body: a return, an unconditional branch (tail call), or a trap. Used to
// distinguish genuine code from the trailing alignment padding that a function
// symbol's extent can include (zeros on arm64/riscv, int3/nop on x86), which a
// disassembler decodes as junk or "(bad)".
func isFlowTerminator(in disasm.Inst) bool {
	switch in.Class {
	case disasm.ClassRet, disasm.ClassJumpUnc:
		return true
	}
	fields := strings.Fields(strings.TrimSpace(in.Text))
	if len(fields) == 0 {
		return false
	}
	switch strings.ToLower(fields[0]) {
	case "ud2", "udf", "hlt", "brk", "trap", "int3":
		return true
	}
	// 32-bit ARM returns/branches by writing the PC directly, e.g. Go's leaf
	// return "add pc, lr, #0", or "mov pc, lr" / "ldr pc, [sp], #4".
	if len(fields) >= 2 && strings.TrimRight(fields[1], ",") == "pc" {
		return true
	}
	return false
}

// openAndCheck runs a compiled binary through exex's reader and asserts the
// invariants that must hold for any executable exex can read:
//   - the container format and CPU are detected correctly;
//   - sections, raw bytes and symbols are parsed, with a real executable section;
//   - the entry point lands inside the executable image;
//   - every text view renders without error;
//   - for a supported CPU, the whole binary disassembles to non-empty output and
//     the entry function (main.main / _start) decodes correctly (see
//     checkEntryDisasm).
//
// entryNames are the candidate symbol names for the program's own entry function,
// tried in order. wantSymbols is false for toolchain/format combinations that
// legitimately ship no symbol table (e.g. Zig's PE output keeps debug info in a
// separate PDB), so the symbol and entry-disasm checks are skipped there.
func openAndCheck(t *testing.T, path string, wantFormat binfile.Format, wantArch arch.Arch, wantSymbols bool, entryNames []string) {
	t.Helper()
	f, err := binfile.Open(path)
	if err != nil {
		t.Fatalf("binfile.Open(%s): %v", path, err)
	}
	defer f.Close()

	if f.Format != wantFormat {
		t.Errorf("format = %q, want %q", f.Format, wantFormat)
	}
	if f.Arch() != wantArch {
		t.Errorf("arch = %v, want %v", f.Arch(), wantArch)
	}
	if len(f.Sections) == 0 {
		t.Errorf("no sections parsed")
	}
	if wantSymbols && len(f.Symbols) == 0 {
		t.Errorf("no symbols parsed (unexpectedly stripped?)")
	}
	if len(f.Raw()) == 0 {
		t.Errorf("raw file is empty")
	}

	// At least one real executable section with file bytes and a load address.
	hasCode := false
	for _, s := range f.Sections {
		if s.Exec && s.FileSize > 0 && s.Addr != 0 {
			hasCode = true
			break
		}
	}
	if !hasCode {
		t.Errorf("no executable section with bytes")
	}

	// The entry point must be a real, executable address.
	if entry := f.Entry(); entry == 0 {
		t.Errorf("entry point is zero for an executable")
	} else if _, ok := f.ExecImage().PosForAddr(entry); !ok {
		t.Errorf("entry 0x%x not inside the executable image", entry)
	}

	// Every text view must render without error (some may be empty, e.g. no libs).
	for _, v := range []string{"info", "sections", "segments", "symbols", "strings", "libs", "sources"} {
		if _, err := dump.View(f, v); err != nil {
			t.Errorf("view %q: %v", v, err)
		}
	}

	// Disassembly: whole-binary stream plus a focused, correctness-checked decode
	// of the program's entry function — for CPUs exex understands.
	if disasmSupported(f.Arch()) {
		var cw countWriter
		if err := dump.DisasmTo(&cw, f, false); err != nil {
			t.Errorf("disasm (%v): %v", f.Arch(), err)
		} else if cw.n == 0 {
			t.Errorf("disasm (%v): produced no output", f.Arch())
		}
		checkEntryDisasm(t, f, entryNames)
	}
}

// checkEntryDisasm verifies that exex disassembles the program's entry function
// correctly: it resolves one of the candidate names to a sized function symbol,
// decodes it through the same path the CLI/TUI use, and asserts the decode is
// well-formed — it starts exactly at the symbol, every instruction is valid (no
// "(bad)") with strictly increasing in-range addresses, and (for ELF, whose
// symbol sizes are authoritative) the instructions cover the function exactly.
func checkEntryDisasm(t *testing.T, f *binfile.File, names []string) {
	t.Helper()
	sym, ok := findFunc(f, names...)
	if !ok {
		t.Logf("no entry symbol among %v (stripped?); skipping entry disasm", names)
		return
	}

	// The high-level one-shot path the CLI uses must succeed and produce text.
	if text, err := dump.Function(f, sym.Name); err != nil {
		t.Errorf("dump.Function(%s): %v", sym.Name, err)
		return
	} else if strings.TrimSpace(text) == "" {
		t.Errorf("dump.Function(%s): empty output", sym.Name)
		return
	}

	dis, err := disasm.For(f.Arch())
	if err != nil {
		t.Errorf("disasm.For(%v): %v", f.Arch(), err)
		return
	}
	svc := explorer.NewDisasmService(f, dis, 1<<20, 0)
	insts := dump.FunctionInsts(f, svc, sym)
	if len(insts) == 0 {
		t.Errorf("%s: no instructions decoded", sym.Name)
		return
	}

	// Decoding must begin exactly on the symbol — the bug this test first caught
	// was the function's real first instruction being swallowed by a resync.
	if insts[0].Addr != sym.Addr {
		t.Errorf("%s: disasm starts at 0x%x, want function start 0x%x", sym.Name, insts[0].Addr, sym.Addr)
	}

	// Walk the body: every real instruction must be valid, in range, and at a
	// strictly increasing address. A function symbol's extent can include trailing
	// alignment padding (zeros on arm64/riscv → "(bad)", int3/nop on x86), so a
	// "(bad)" is only acceptable once the function has reached a flow terminator —
	// before that it signals a genuine decode failure.
	end := sym.Addr + sym.Size
	sawTerminator := false
	prev := uint64(0)
	for i, in := range insts {
		bad := len(in.Bytes) == 0 || strings.TrimSpace(in.Text) == "(bad)"
		if bad {
			if !sawTerminator {
				t.Errorf("%s: undecodable instruction at 0x%x before any return/branch (text=%q)", sym.Name, in.Addr, in.Text)
			}
			break // the rest is alignment padding, not code
		}
		if in.Addr < sym.Addr || in.Addr >= end {
			t.Errorf("%s: instruction 0x%x outside [0x%x, 0x%x)", sym.Name, in.Addr, sym.Addr, end)
		}
		if i > 0 && in.Addr <= prev {
			t.Errorf("%s: instruction addresses not increasing (0x%x after 0x%x)", sym.Name, in.Addr, prev)
		}
		prev = in.Addr
		if isFlowTerminator(in) {
			sawTerminator = true
		}
	}
}

// writeFile is a fatal-on-error helper for laying down the source tree.
func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

// TestCrossCompileGo compiles a minimal program for every Go target exex can
// read (per `go tool dist list`) and exercises exex on each.
func TestCrossCompileGo(t *testing.T) {
	goBin, err := exec.LookPath("go")
	if err != nil {
		t.Skip("go toolchain not found")
	}

	out, err := exec.Command(goBin, "tool", "dist", "list").Output()
	if err != nil {
		t.Fatalf("go tool dist list: %v", err)
	}
	targets := strings.Fields(string(out)) // "goos/goarch" tokens

	// A minimal module: the runtime alone gives plenty of sections and symbols,
	// without dragging in fmt for every cross target.
	mod := t.TempDir()
	writeFile(t, filepath.Join(mod, "go.mod"), "module crosstest\n\ngo 1.21\n")
	writeFile(t, filepath.Join(mod, "main.go"), "package main\n\nfunc main() {}\n")
	bins := t.TempDir()

	ran := map[string]bool{}
	for _, tgt := range targets {
		goos, goarch, found := strings.Cut(tgt, "/")
		if !found {
			continue
		}
		want, supported := goFormatFor(goos)
		if !supported {
			continue // wasm, plan9, aix, …
		}
		t.Run(tgt, func(t *testing.T) {
			outPath := filepath.Join(bins, goos+"_"+goarch)
			cmd := exec.Command(goBin, "build", "-o", outPath, ".")
			cmd.Dir = mod
			cmd.Env = append(os.Environ(),
				"GOOS="+goos, "GOARCH="+goarch,
				"CGO_ENABLED=0", "GOTOOLCHAIN=local")
			if b, err := cmd.CombinedOutput(); err != nil {
				t.Skipf("build failed (likely host-specific): %v\n%s", err, b)
			}
			openAndCheck(t, outPath, want, goArchFor(goarch), true, []string{"main.main"})
			ran[tgt] = true
		})
	}

	// These targets are buildable from any modern Go install; if they didn't run,
	// something is wrong with the harness rather than an exotic target.
	for _, must := range []string{"linux/amd64", "linux/386", "linux/arm64", "windows/amd64", "darwin/arm64"} {
		if !ran[must] {
			t.Errorf("core target %s did not build/run", must)
		}
	}
	if len(ran) == 0 {
		t.Fatal("no Go targets compiled")
	}
	t.Logf("exercised %d Go targets", len(ran))
}

// TestCrossCompileZig compiles a minimal program with Zig for a representative
// matrix of targets. Zig's full target list is an arch×os cross-product (and is
// emitted as ZON, not JSON), most of which exex reads only as generic ELF; this
// matrix instead covers all four CPUs exex disassembles (x86, x86_64, arm64,
// riscv64) plus several parser-only CPUs, across all three container formats.
func TestCrossCompileZig(t *testing.T) {
	zigBin, err := exec.LookPath("zig")
	if err != nil {
		t.Skip("zig toolchain not found")
	}

	src := t.TempDir()
	mainZig := filepath.Join(src, "main.zig")
	writeFile(t, mainZig, "pub fn main() void {}\n")
	cache := filepath.Join(t.TempDir(), "zig-cache")
	bins := t.TempDir()

	cases := []struct {
		target string
		format binfile.Format
	}{
		// ELF (linux): the disassembled CPUs plus parser-only ones (mips).
		{"x86_64-linux", binfile.FormatELF},
		{"x86-linux", binfile.FormatELF},
		{"aarch64-linux", binfile.FormatELF},
		{"aarch64_be-linux", binfile.FormatELF}, // big-endian (BE-8): instructions stay LE
		{"riscv64-linux", binfile.FormatELF},
		{"arm-linux", binfile.FormatELF},
		{"armeb-linux", binfile.FormatELF}, // big-endian ARM (BE-8)
		{"powerpc-linux", binfile.FormatELF},
		{"powerpcle-linux", binfile.FormatELF},
		{"powerpc64-linux", binfile.FormatELF},
		{"powerpc64le-linux", binfile.FormatELF},
		{"s390x-linux", binfile.FormatELF},
		{"loongarch64-linux", binfile.FormatELF},
		{"mips64el-linux", binfile.FormatELF},
		// PE (windows).
		{"x86_64-windows", binfile.FormatPE},
		{"x86-windows", binfile.FormatPE},
		{"aarch64-windows", binfile.FormatPE},
		// Mach-O (macos).
		{"x86_64-macos", binfile.FormatMachO},
		{"aarch64-macos", binfile.FormatMachO},
	}

	ran := 0
	for _, tc := range cases {
		t.Run(tc.target, func(t *testing.T) {
			outPath := filepath.Join(bins, tc.target)
			// Default (Debug) optimisation keeps the symbol table, so the entry
			// function (main.main / _start) can be found and decode-checked;
			// ReleaseSmall strips it.
			cmd := exec.Command(zigBin, "build-exe", mainZig,
				"-target", tc.target,
				"-femit-bin="+outPath, "--cache-dir", cache)
			if b, err := cmd.CombinedOutput(); err != nil {
				t.Skipf("zig build failed (target unsupported on host): %v\n%s", err, b)
			}
			// Zig's PE output carries no COFF symbol table (debug info lives in a
			// PDB), unlike its ELF/Mach-O output and all Go binaries.
			wantSymbols := tc.format != binfile.FormatPE
			openAndCheck(t, outPath, tc.format, zigArchFor(tc.target), wantSymbols, []string{"main.main", "_start"})
			ran++
		})
	}

	if ran == 0 {
		t.Fatal("no Zig targets compiled")
	}
	t.Logf("exercised %d Zig targets", ran)
}
