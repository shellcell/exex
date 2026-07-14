#!/usr/bin/env sh
# Reports what makes up the exex binary:
#   1. build totals (stripped full vs lite) and the Chroma cost as their difference
#      — embedded lexer/style XML hides under "go:string.*" in the symbol table,
#      so a build diff is the only honest measure of its full cost;
#   2. a per-module attribution from the symbol table, for both the full and lite
#      builds (so you can see what the `lite` tag actually drops).
#
# Usage: scripts/size-report.sh [binary-name]   (default: exex)
set -eu

bin="${1:-exex}"
full="$(mktemp)"
lite="$(mktemp)"
fullsym="$(mktemp)"
litesym="$(mktemp)"
trap 'rm -f "$full" "$lite" "$fullsym" "$litesym"' EXIT

# Portable "size in bytes" and "bytes -> MB".
fsize() { stat -f%z "$1" 2>/dev/null || stat -c%s "$1"; }
mb()    { awk "BEGIN{printf \"%.2f\", $1/1048576}"; }

# breakdown <symbol-binary>: per-module attribution from the symbol table.
breakdown() {
	total=$(go tool nm -size "$1" 2>/dev/null | awk 'NF==4{s+=$2} END{print s}')
	go tool nm -size "$1" 2>/dev/null | awk -v total="$total" '
	NF==4 {
	  n=$4; sz=$2
	  if      (n ~ /alecthomas\/chroma/ || n ~ /dlclark\/regexp2/) b="Chroma (code; +regexp2)"
	  else if (n ~ /charm\.land\/lipgloss/)        b="Lip Gloss"
	  else if (n ~ /charm\.land\/bubbletea/)       b="Bubble Tea"
	  else if (n ~ /charm\.land\/bubbles/)         b="Bubbles"
	  else if (n ~ /charmbracelet\/|xo\/terminfo/) b="Charm (ansi/uv/term)"
	  else if (n ~ /clipperhouse\//)               b="Unicode width (uax29)"
	  else if (n ~ /golang.org\/x\/arch/)          b="x/arch decoders"
	  else if (n ~ /ianlancetaylor\/demangle/)     b="C++ demangler"
	  else if (n ~ /yaml/)                         b="yaml.v3 (config)"
	  else if (n ~ /atotto\/clipboard/)            b="clipboard"
	  else if (n ~ /golang.org\/x\/sys/)           b="x/sys"
	  else if (n ~ /shellcell\/exex/)               b="exex (our code)"
	  else if (n ~ /^go:string/)                   b="Go: strings + embedded data"
	  else if (n ~ /^go:func/)                     b="Go: func metadata"
	  else if (n ~ /^type:|^go:itab|^gcbits|^go:map/) b="Go: type/reflect metadata"
	  else if (n ~ /pclntab|findfunctab|epclntab/) b="Go: pclntab"
	  else if (n ~ /^runtime\./)                   b="Go runtime (code+data+bss)"
	  else                                         b="Go stdlib (other)"
	  sum[b]+=sz
	}
	END{ for(k in sum) printf "%9.0f KB  %5.1f%%  %s\n", sum[k]/1024, 100*sum[k]/total, k }' \
	  | sort -rn
}

echo "building (full + lite, stripped for totals and unstripped for symbols)…" >&2
go build -trimpath -ldflags="-s -w" -o "$full" .
go build -tags lite -trimpath -ldflags="-s -w" -o "$lite" .
go build -o "$fullsym" .
go build -tags lite -o "$litesym" .

bf=$(fsize "$full"); bl=$(fsize "$lite"); bd=$((bf - bl))

echo
echo "== $bin build totals (stripped, -s -w) =="
printf "  %-7s %8s MB\n" "full" "$(mb "$bf")"
printf "  %-7s %8s MB\n" "lite" "$(mb "$bl")"
printf "  %-7s %8s MB  (full - lite: Chroma + regexp2 + encoding/xml + curated assets)\n" "Chroma" "$(mb "$bd")"

echo
echo "== per-module attribution: FULL build (symbol sizes, unstripped) =="
echo "   note: Chroma's embedded lexer/style XML is counted under 'Go: strings + embedded data',"
echo "         not 'Chroma' — see the build-diff above for its real cost."
echo
breakdown "$fullsym"

echo
echo "== per-module attribution: LITE build (symbol sizes, unstripped) =="
echo
breakdown "$litesym"
