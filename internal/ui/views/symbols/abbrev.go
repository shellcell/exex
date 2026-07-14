// Package symbols implements the Symbols view: a filterable, sortable table of
// the merged symbol table (matching on both raw and demangled names), with an
// alternative collapsible namespace-tree mode, kind/scope/bind facet filters,
// clickable facet chips on the status row, and per-row or global abbreviation
// of bracketed argument/template lists. Like relocs and sections, the view
// depends only on a view.Context (render inputs) and a view.Host (actions).
package symbols

import (
	"strconv"
	"strings"

	"github.com/shellcell/exex/internal/binfile"
	"github.com/shellcell/exex/internal/ui/layout"
)

// abbrevMinInner is the smallest "(…)"/"<…>" content (in bytes, brackets excluded)
// worth collapsing: only content longer than 5 bytes is replaced with "...". Short
// inner text (e.g. "<int>", "<A>", "<int16>", "(d)") is kept verbatim — it's
// readable as-is and "<...>" would barely shorten it.
const abbrevMinInner = 6

// AbbrevBrackets replaces the contents of every top-level "(…)" and "<…>" group in
// s whose inner text is at least abbrevMinInner bytes with "..." — "f<Alloc, Traits>"
// becomes "f<...>" while "Foo<A>" and "find(x)" are left as-is. "[…]" is untouched.
// C++ "operator" names (operator<<, operator->, operator(), …) are passed through
// whole so their punctuation isn't mistaken for template/parameter brackets. If the
// "()"/"<>" nesting doesn't balance, s is returned unchanged so a pathological name
// is never truncated.
func AbbrevBrackets(s string) string {
	if !bracketsBalanced(s) {
		return s
	}
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); {
		if ol := operatorTokenLen(s, i); ol > 0 {
			b.WriteString(s[i : i+ol])
			i += ol
			continue
		}
		// The outer loop only ever runs at bracket depth 0 (groups are jumped over
		// whole), so any "("/"<" here opens a top-level group and any ">" is a "->"
		// arrow, never a close.
		if c := s[i]; c == '(' || c == '<' {
			j := matchClose(s, i)
			if j < 0 { // unreachable after bracketsBalanced; stay safe
				b.WriteByte(c)
				i++
				continue
			}
			if j-i-1 < abbrevMinInner {
				b.WriteString(s[i : j+1]) // short content: keep verbatim
			} else {
				b.WriteByte(c)
				b.WriteString("...")
				b.WriteByte(s[j])
			}
			i = j + 1
			continue
		}
		b.WriteByte(s[i])
		i++
	}
	return b.String()
}

// matchClose returns the index of the bracket that closes the "("/"<" at open,
// honouring nested groups, "operator" tokens and "->" arrows, or -1 if unbalanced.
func matchClose(s string, open int) int {
	depth := 0
	for k := open; k < len(s); {
		if ol := operatorTokenLen(s, k); ol > 0 {
			k += ol
			continue
		}
		switch s[k] {
		case '(', '<':
			depth++
		case ')':
			depth--
			if depth == 0 {
				return k
			}
		case '>':
			if k > 0 && s[k-1] == '-' { // "->" arrow, not a close
				break
			}
			depth--
			if depth == 0 {
				return k
			}
		}
		k++
	}
	return -1
}

// bracketsBalanced reports whether s has at least one "("/"<" group and its
// "()"/"<>" nesting balances under a single depth counter, skipping "operator"
// punctuation. "[]" is ignored.
func bracketsBalanced(s string) bool {
	depth, seen := 0, false
	for i := 0; i < len(s); {
		if ol := operatorTokenLen(s, i); ol > 0 {
			i += ol
			continue
		}
		switch s[i] {
		case '(', '<':
			depth++
			seen = true
		case '>':
			if i > 0 && s[i-1] == '-' { // "->" arrow, not a close
				break
			}
			depth--
			if depth < 0 {
				return false
			}
		case ')':
			depth--
			if depth < 0 {
				return false
			}
		}
		i++
	}
	return depth == 0 && seen
}

// operatorTokenLen returns the byte length of a C++ "operator…" name starting at
// s[i] — the word "operator" plus its symbol form ("operator<<", "operator()",
// "operator->", "operator<=>") — or 0 when s[i] does not begin such a token. The
// operator's punctuation must be consumed wholesale so its "<"/">"/"(" are not read
// as template or parameter brackets. "operator" spelt out as part of a longer
// identifier, or followed by a word (conversion / new / delete), returns 0.
func operatorTokenLen(s string, i int) int {
	const kw = "operator"
	if i > 0 && isIdentByte(s[i-1]) {
		return 0
	}
	if !strings.HasPrefix(s[i:], kw) {
		return 0
	}
	j := i + len(kw)
	if j < len(s) && s[j] == ' ' { // tolerate "operator <"
		j++
	}
	// operator() and operator[] (and their array-new/delete cousins are handled by
	// the punctuation run below since "[]" isn't tracked anyway).
	if j+1 < len(s) && (s[j] == '(' && s[j+1] == ')' || s[j] == '[' && s[j+1] == ']') {
		return j + 2 - i
	}
	k := j
	for k < len(s) && isOpPunct(s[k]) {
		k++
	}
	if k == j {
		return 0 // "operator" + a name (conversion op, new, delete): nothing to skip
	}
	return k - i
}

// isOpPunct reports whether c is punctuation that can form an overloaded operator's
// name (excluding "()"/"[]", handled separately).
func isOpPunct(c byte) bool {
	switch c {
	case '<', '>', '=', '!', '+', '-', '*', '/', '%', '^', '&', '|', '~', ',':
		return true
	}
	return false
}

// isIdentByte reports whether c can appear inside a C identifier.
func isIdentByte(c byte) bool {
	return c == '_' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9'
}

// abbrevKey is the stable per-row key for a node's individual abbreviation
// override: the symbol index for a leaf, the (unique) path for a group node.
func abbrevKey(n *layout.TreeNode) string {
	if n.Leaf >= 0 {
		return "s" + strconv.Itoa(n.Leaf)
	}
	return "g" + n.Path
}

// splitStyledRows splits wrapped output into lines, dropping a trailing newline
// and never returning an empty slice.
func splitStyledRows(wrapped string) []string {
	parts := strings.Split(strings.TrimRight(wrapped, "\n"), "\n")
	if len(parts) == 0 {
		return []string{""}
	}
	return parts
}

// kindString / bindString render neutral symbol kinds and bindings for the
// symbol table's Type and Bind columns and the facet labels.
func kindString(k binfile.SymKind) string {
	switch k {
	case binfile.SymFunc:
		return "FUNC"
	case binfile.SymObject:
		return "OBJECT"
	case binfile.SymSection:
		return "SECTION"
	case binfile.SymFile:
		return "FILE"
	case binfile.SymTLS:
		return "TLS"
	case binfile.SymCommon:
		return "COMMON"
	}
	return "NOTYPE"
}

func bindString(b binfile.SymBind) string {
	switch b {
	case binfile.BindGlobal:
		return "GLOBAL"
	case binfile.BindWeak:
		return "WEAK"
	}
	return "LOCAL"
}
