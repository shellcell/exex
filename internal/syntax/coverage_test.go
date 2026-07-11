//go:build !lite

package syntax

import (
	"testing"

	"github.com/rabarbra/exex/internal/binfile"
	"github.com/rabarbra/exex/internal/chromalexers"
)

// langSample maps every source language exex can identify from DWARF
// (binfile.DwarfLanguageNames) to a representative source filename. A non-empty
// value must resolve to a curated Chroma lexer; the empty string marks a language
// we knowingly leave to the minimal highlighter (dead, GPU-only, or C/C++
// dialects whose real source files carry a covered extension).
//
// TestDwarfLanguagesHaveCoverage keeps this in lockstep with dwarfLangNames: add
// a DWARF language there and this test fails until you record a decision here, so
// the language table and the highlighter set cannot silently drift apart.
var langSample = map[string]string{
	"C":              "main.c",
	"C++":            "main.cpp",
	"Ada":            "main.adb",
	"COBOL":          "main.cob",
	"Fortran":        "main.f90",
	"Pascal":         "main.pas",
	"Modula-2":       "main.mod",
	"Java":           "Main.java",
	"Objective-C":    "main.m",
	"Objective-C++":  "main.mm",
	"D":              "main.d",
	"Python":         "main.py",
	"OpenCL":         "kernel.cl",
	"Go":             "main.go",
	"Haskell":        "main.hs",
	"OCaml":          "main.ml",
	"Rust":           "main.rs",
	"Swift":          "main.swift",
	"Julia":          "main.jl",
	"Dylan":          "main.dylan",
	"Kotlin":         "main.kt",
	"Zig":            "main.zig",
	"Crystal":        "main.cr",
	"Assembly":       "boot.s",
	"C#":             "main.cs",
	"Mojo":           "main.mojo",
	"GLSL":           "shader.frag",
	"GLSL ES":        "shader.frag",
	"HLSL":           "shader.hlsl",
	"Metal":          "shader.metal",
	"Ruby":           "main.rb",
	"Delphi":         "main.pas",
	"OpenCL C++":     "kernel.cpp", // C++ dialect; real sources are .cpp
	"C++ for OpenCL": "kernel.cpp", // C++ dialect; real sources are .cpp
	"SYCL":           "main.cpp",   // C++ dialect; real sources are .cpp

	// Knowingly minimal-fallback: no lexer, and no realistic ELF/Mach-O DWARF
	// source we could route to one. Dead/niche (Modula-3, BLISS, Move, Hylo,
	// RenderScript, UPC) or GPU dialects handled via their .cpp sources (HIP).
	"UPC":          "",
	"Modula-3":     "",
	"RenderScript": "",
	"BLISS":        "",
	"HIP":          "",
	"Move":         "",
	"Hylo":         "",
}

func TestDwarfLanguagesHaveCoverage(t *testing.T) {
	for _, name := range binfile.DwarfLanguageNames() {
		sample, recorded := langSample[name]
		if !recorded {
			t.Errorf("DWARF language %q has no coverage decision: add it to langSample "+
				"(a sample filename if a lexer should highlight it, or \"\" for minimal fallback)", name)
			continue
		}
		if sample == "" {
			continue // explicitly minimal-fallback
		}
		if l := chromalexers.Match(sample); l == nil {
			t.Errorf("DWARF language %q: sample %q resolves to no curated lexer", name, sample)
		}
	}
}
