# fish completion for exex
#
# Install: copy to a fish completions directory, e.g.
#   ~/.config/fish/completions/exex.fish

complete -c exex -s s -r -d 'search printable strings on startup'
complete -c exex -s d -l debug -r -d 'external debug-symbols file or directory'
complete -c exex -s o -x \
	-a 'info sections segments symbols strings libs sources disasm disasm-all' \
	-d 'print a view or disassembly to stdout and exit'
complete -c exex -s h -d 'show usage and exit'

# The binary argument: files (fish completes these by default) plus command
# names on $PATH, so `exex ls` resolves /bin/ls. -k keeps them above files.
complete -c exex -k -a '(__fish_complete_command)' -d 'command on $PATH'
