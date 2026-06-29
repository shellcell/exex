# Ideas — UX & exploration

The north star: open *anything* executable (or library / object file) and easily
explore it — see what it contains and how it's organized, find any symbol /
address / string and jump to it immediately, see and explore dependencies, and
see what it *uses* and *needs* (syscalls, CPU features, arch/OS).

Below are UX improvements ranked by how much they make working with exex clearer
and more straightforward. (Feature-level capability work — CPU features,
requirements panel, dyld cache — lives in `docs/ROADMAP.md` #34–#37.)

---

## Tier 1 — biggest clarity wins

### 1. Universal "jump to anything" palette  ✅ (done)

Built on the `g` modal: scopes (All / Symbols / Sections / Strings / Libraries /
Address) cycled with ⇥, an ⌥p virtual↔physical address toggle (when LMAs differ),
kind-tagged colour-coded results, and smart routing per kind. Remaining polish:
optional "go to in <view>" picking; include strings in All behind a length guard.

Today finding things is split across `g` (goto: symbol/addr), `/` (in-view
search) and five per-view filters — the user must know which to use. One key
should open a fuzzy palette over **everything** and jump on Enter.

- **Scopes** (switchable, e.g. Tab to cycle, shown as a segmented bar):
  - **All** — symbols + sections + libraries (+ auto-detect a typed address).
  - **Symbols**, **Sections**, **Strings**, **Libraries**, **Address**.
  - Strings is its own scope (the corpus can be millions — don't scan it in All
    on every keystroke).
- **Address mode** — interpret the typed address as **virtual** (default) or
  **physical / LMA**. Physical input resolves through the section whose LMA range
  contains it (`virtual = sec.Addr + (input − sec.PhysAddr)`), so a higher-half
  kernel can be navigated by physical address. Only offered when the binary has
  distinct LMAs. (Synthetic-address objects: real position is section-relative,
  so "physical" doesn't apply there.)
- **Destination is smart by result kind** — symbol → disasm (or hex if not
  code), section → hex at its address, string → hex/strings, library → open it,
  address → disasm/hex/raw by mapping. (Explicit "go to in <view>" picking is a
  possible later refinement — keep the default smart for now.)
- **Results coloured by kind** (matching the Symbols view + the xref/syscall
  modal vocabulary), with a kind tag.

### 2. Cross-file back-stack + breadcrumb  ✅ (done)

Opening a dependency (`openLibAsPrimary`) now pushes the model we came from onto a
stack and carries it into the new model; **Ctrl+O** pops back to it with its view
and cursor exactly as left. A breadcrumb (`app ▸ libfoo.so ▸ libbar.so  ^O`) is
right-aligned in the tab strip while descended. (Archive members and fat-arch
slices stay lateral — they already have the member list / arch cycle via `t`.)

### 3. Info as a landing dashboard  ✅ (done)

The Info view now leads with a **Requirements** block (CPU/arch + bits + endian,
minimum OS, linking/PIE, and a "press F" CPU-features pointer) and a **Contents**
table-of-contents (Sections/Symbols/Libraries counts + Disassembly/Strings/Sources,
each with its "→ press N" jump key, plus "Find anything → press g"). The Identity
section was trimmed so it no longer repeats those facts. CPU-feature detection
(ROADMAP #34) and the Requirements panel (#35) shipped: `⇧F` scans and shows the
required features + baseline (jump to first use), and `-o cpu-features` dumps it.

---

## Tier 2 — clarity polish

### 4. Make the search model legible

`/` (search within view) vs `g`/palette (jump) vs per-view filters overlap. Show
the active filter/scope as a persistent chip in the header (`filter: "kbd" ·
12/138`) so it's always clear what's narrowing the view and how to clear it.

### 5. Colour / vocabulary legend in `?`

A lot of colour now carries meaning (symbol kinds, section categories,
syscall/xref categories) plus address terms (synthetic / LMA). A short legend
reachable from help removes "why is this row yellow / what's LMA?".

### 6. Direct mouse affordances

Click a library row to open it; click a symbol / xref / goto result to jump
(some exists). Lower the barrier for mouse-first users.

---

## Tier 3 — polish

- First-run hint line (`? help · g jump · 1–9 views`).
- Clearer `t`-toggle affordance — persistently show what `t` does in the current
  view (it's heavily context-overloaded).
