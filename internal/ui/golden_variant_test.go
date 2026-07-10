//go:build !lite

package ui

// The default build highlights assembly with Chroma; the lite build swaps in the
// small built-in highlighter. Frames that show disassembly therefore differ by
// design between the two, so each variant gets its own snapshot directory rather
// than one of them losing coverage.
const goldenVariant = "golden"
