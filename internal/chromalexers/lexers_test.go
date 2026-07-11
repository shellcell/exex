package chromalexers

import "testing"

func TestCuratedLexers(t *testing.T) {
	for _, name := range []string{
		"Ada", "Arduino", "ArmAsm", "Ballerina", "Beef", "C", "C++", "C#", "C3", "Chapel", "Clojure", "COBOL",
		"Crystal", "Cython", "D", "Dart", "Dylan", "FSharp", "Fortran", "FortranFixed", "GAS", "GLSL", "Go", "golang",
		"Groovy", "Hare", "Haskell", "HLSL", "Idris", "Java", "Julia", "Kotlin", "Lean4", "LLVM", "Metal", "MLIR",
		"Modelica", "Modula-2", "Mojo", "NASM", "Nim", "ObjectPascal", "Objective-C", "OCaml", "Odin", "Pony",
		"Python", "ReasonML", "Rust", "Scala", "Standard ML", "Swift", "systemverilog", "V", "Vala", "VB.net", "VHDL", "YAML", "Zig",
	} {
		if l := Get(name); l == nil {
			t.Fatalf("Get(%q) returned nil", name)
		}
	}
}

func TestCuratedLexerMatching(t *testing.T) {
	tests := map[string]string{
		"app.bal":        "Ballerina",
		"board.ino":      "Arduino",
		"calc.bf":        "Beef",
		"class.dylan":    "Dylan",
		"kernel.chpl":    "Chapel",
		"kernel.metal":   "Metal",
		"main.adb":       "Ada",
		"main.c":         "C",
		"main.c3":        "C3",
		"main.clj":       "Clojure",
		"main.cob":       "COBOL",
		"main.d":         "D",
		"main.dart":      "Dart",
		"main.groovy":    "Groovy",
		"main.ha":        "Hare",
		"main.f90":       "Fortran",
		"main.go":        "Go",
		"main.hs":        "Haskell",
		"main.idr":       "Idris",
		"main.jl":        "Julia",
		"main.lean":      "Lean4",
		"main.ml":        "OCaml",
		"main.mo":        "Modelica",
		"main.mod":       "Modula-2",
		"main.mojo":      "Mojo",
		"main.nim":       "Nim",
		"main.odin":      "Odin",
		"main.pas":       "ObjectPascal",
		"main.pony":      "Pony",
		"main.pyx":       "Cython",
		"main.re":        "ReasonML",
		"main.rs":        "Rust",
		"main.sig":       "Standard ML",
		"main.sv":        "systemverilog",
		"main.v":         "V",
		"main.vala":      "Vala",
		"main.vb":        "VB.net",
		"main.vhdl":      "VHDL",
		"module.ll":      "LLVM",
		"module.mlir":    "MLIR",
		"v.mod":          "V",
		"CMakeLists.txt": "CMake",
		"foo.s":          "GAS",
		"schema.proto":   "Protocol Buffer",
	}
	for filename, want := range tests {
		l := Match(filename)
		if l == nil {
			t.Fatalf("Match(%q) returned nil", filename)
		}
		if got := l.Config().Name; got != want {
			t.Fatalf("Match(%q) = %q, want %q", filename, got, want)
		}
	}
}

func TestCuratedLexerAnalyse(t *testing.T) {
	l := Analyse("package main\n\nfunc main() { fmt.Println(\"hi\") }\n")
	if l == nil {
		t.Fatal("Analyse Go source returned nil")
	}
	if got := l.Config().Name; got != "Go" {
		t.Fatalf("Analyse Go source = %q, want Go", got)
	}
}

func TestUnsupportedLexerIsAbsent(t *testing.T) {
	if l := Get("elixir"); l != nil {
		t.Fatalf("Get(elixir) = %q, want nil", l.Config().Name)
	}
}
