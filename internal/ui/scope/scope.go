// Package scope names what a search looks through.
//
// It is the one piece of vocabulary the three search surfaces share: the goto
// palette (which searches a scope), the Find seed picker (each seed names the
// scope it would search), and the global value search (which routes a seed's
// scope to a query). Keeping it here lets each of those live in its own package
// without one of them owning a type the others need.
package scope

// Scope selects the corpus a search runs over.
type Scope uint8

const (
	All      Scope = iota // symbols + sections + a typed address
	Symbols               // symbols only
	Sections              // section names
	Strings               // printable strings (its own scope — the corpus is large)
	Libs                  // linked libraries
	Addr                  // a raw address (virtual, or physical when toggled)
	Count                 // number of scopes; not a scope itself
)

// String is the scope's user-facing name.
func (s Scope) String() string {
	switch s {
	case Symbols:
		return "symbols"
	case Sections:
		return "sections"
	case Strings:
		return "strings"
	case Libs:
		return "libraries"
	case Addr:
		return "address"
	default:
		return "all"
	}
}

// Next cycles forward through the scopes, wrapping.
func Next(s Scope) Scope { return (s + 1) % Count }

// Prev cycles backward through the scopes, wrapping.
func Prev(s Scope) Scope { return (s + Count - 1) % Count }
