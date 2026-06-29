# bash completion for exex
#
# Install: source this file from ~/.bashrc, or copy it to a bash-completion dir:
#   - Linux:  /usr/share/bash-completion/completions/exex
#   - Homebrew: "$(brew --prefix)/etc/bash_completion.d/exex"

_exex() {
	local cur prev views flags i pos
	cur="${COMP_WORDS[COMP_CWORD]}"
	prev="${COMP_WORDS[COMP_CWORD-1]}"
	views="info sections segments symbols strings libs sources relocs syscalls syscalls-all syscalls-full disasm disasm-all"
	flags="-s -o -d -debug -arch -h"

	# Value completion for the flag immediately before the cursor.
	case "$prev" in
	-o|--o)
		COMPREPLY=( $(compgen -W "$views" -- "$cur") )
		return ;;
	-d|--d|-debug|--debug)
		COMPREPLY=( $(compgen -f -- "$cur") )
		return ;;
	-arch|--arch)
		COMPREPLY=( $(compgen -W "x86_64 arm64 i386 arm" -- "$cur") )
		return ;;
	-s|--s)
		return ;; # free-form string
	esac

	if [[ "$cur" == -* ]]; then
		COMPREPLY=( $(compgen -W "$flags" -- "$cur") )
		return
	fi

	# Count positional args already given, mirroring how exex parses the line:
	# -d/-debug/-s always take a value; -o takes one only when it's a known view.
	pos=0
	for (( i=1; i < COMP_CWORD; i++ )); do
		case "${COMP_WORDS[i]}" in
		-d|--d|-debug|--debug|-s|--s|-arch|--arch) (( i++ )) ;;
		-o|--o)
			case "${COMP_WORDS[i+1]}" in
			info|sections|segments|symbols|strings|libs|sources|relocs|syscalls|syscalls-all|syscalls-full|disasm|disasm-all) (( i++ )) ;;
			esac ;;
		-*) ;;
		*) (( pos++ )) ;;
		esac
	done

	# First positional is the binary: complete $PATH commands and files. The
	# second (goto: an address or symbol) has no static completion.
	if (( pos == 0 )); then
		COMPREPLY=( $(compgen -c -- "$cur") $(compgen -f -- "$cur") )
	fi
}
complete -F _exex exex
