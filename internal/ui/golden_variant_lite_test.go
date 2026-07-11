//go:build lite

package ui

// See golden_variant_test.go: the lite build's assembly highlighter produces
// different (still deterministic) frames, snapshotted separately.
const goldenVariant = "golden-lite"
