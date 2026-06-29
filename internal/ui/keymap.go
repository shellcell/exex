package ui

// Keymap for top-level dispatch. Per-view keys (j/k, /, PgUp/PgDn, ...) stay
// hardcoded in each update<View> function — they're tightly coupled to the
// view's domain (filter input, list cursor, etc.) and not generally worth
// remapping.

import "github.com/rabarbra/exex/internal/config"

// action is what a key resolves to in the top-level dispatch. ActionNone
// means "the key isn't a top-level command; let the per-view handler have
// a go at it".
type action int

const (
	actionNone action = iota
	actionQuit
	actionGoto
	actionViewInfo
	actionViewSections
	actionViewSymbols
	actionViewDisasm
	actionViewHex
	actionViewLibs
	actionViewRaw
	actionViewStrings
	actionViewSources
	actionViewRelocs
	actionToggleSource
	actionSettings
	actionBack        // pop the cross-file stack (return to the file we came from)
	actionCPUFeatures // scan & show the CPU features the binary requires
	actionHeader      // show the raw container-header overlay
)

// keyMap maps key strings (as returned by tea.KeyMsg.String()) to the
// top-level action they trigger. Empty value = no top-level meaning.
type keyMap map[string]action

// defaultKeyMap returns the compiled-in defaults. The keys are the canonical
// strings Bubble Tea uses ("ctrl+c", "tab", "enter", letter literals, …).
func defaultKeyMap() keyMap {
	return keyMap{
		"q":      actionQuit,
		"ctrl+c": actionQuit,
		"g":      actionGoto,
		"1":      actionViewInfo,
		"2":      actionViewSections,
		"3":      actionViewSymbols,
		"4":      actionViewDisasm,
		"5":      actionViewHex,
		"6":      actionViewRaw,
		"7":      actionViewStrings,
		"8":      actionViewLibs,
		"9":      actionViewSources,
		"0":      actionViewRelocs,
		"tab":    actionToggleSource,
		",":      actionSettings,
		"ctrl+o": actionBack,
		"F":      actionCPUFeatures,
		"H":      actionHeader,
	}
}

// applyConfig overlays a Keys config: for each action that's set in the
// config, it first removes any default bindings to that action, then adds
// the configured key(s). This lets a user fully rebind an action without
// inheriting the default. Untouched actions keep their defaults.
func (m keyMap) applyConfig(k config.Keys) {
	bind := func(act action, keys []string) {
		if len(keys) == 0 {
			return
		}
		for key, a := range m {
			if a == act {
				delete(m, key)
			}
		}
		for _, key := range keys {
			m[key] = act
		}
	}
	bind(actionQuit, k.Quit)
	bind(actionGoto, k.Goto)
	bind(actionViewInfo, k.ViewInfo)
	bind(actionViewSections, k.ViewSections)
	bind(actionViewSymbols, k.ViewSymbols)
	bind(actionViewDisasm, k.ViewDisasm)
	bind(actionViewHex, k.ViewHex)
	bind(actionViewLibs, k.ViewLibs)
	bind(actionViewRaw, k.ViewRaw)
	bind(actionViewStrings, k.ViewStrings)
	bind(actionViewSources, k.ViewSources)
	bind(actionToggleSource, k.ToggleSource)
	bind(actionSettings, k.Settings)
	// Per-view actions are intentionally NOT in the top-level dispatch:
	// they read the cursor context of the current view (disasm/hex/symbols/
	// sections/libs), so the per-view handler owns them. We expose them in
	// config for future per-view rebinding.
	_ = k.CopyAddress
	_ = k.CopySymbol
	_ = k.CopyPath
	_ = k.OpenDisasm
	_ = k.Wrap
	_ = k.FilterType
	_ = k.SearchMode
	_ = k.SearchDirection
	_ = k.SearchOrigin
	_ = k.TreeExpand
	_ = k.TreeCollapse
	_ = k.TreeExpandAll
	_ = k.TreeCollapseAll
}
