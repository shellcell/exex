package binfile

// Static-library (ar) archive support: a `.a` file is an `!<arch>\n`-prefixed
// container of object members (each typically an ELF `.o`). exex can't show an
// archive as a single object, but it can iterate the members — e.g. to scan a
// static libc.a for the system calls it provides. Both the GNU long-name string
// table (`//` + `/offset` references) and BSD `#1/len` extended names are
// handled; the symbol-table member is skipped.

import (
	"fmt"
	"strconv"
	"strings"
)

const arMagic = "!<arch>\n"

// ArchiveMember is one object stored in an ar archive: its name and a sub-slice
// of the archive image (no copy).
type ArchiveMember struct {
	Name string
	Data []byte
}

// IsArchive reports whether raw begins with the ar magic.
func IsArchive(raw []byte) bool {
	return len(raw) >= len(arMagic) && string(raw[:len(arMagic)]) == arMagic
}

// OpenArchive maps an ar archive at path and returns its object members (slicing
// into the mapping) plus a closer that releases it; the members must not be used
// after the closer runs.
func OpenArchive(path string) (members []ArchiveMember, closer func() error, err error) {
	raw, c, err := mapFile(path)
	if err != nil {
		return nil, nil, err
	}
	close := func() error {
		if c != nil {
			return c()
		}
		return nil
	}
	members, err = ArchiveMembers(raw)
	if err != nil {
		close()
		return nil, nil, err
	}
	return members, close, nil
}

// ArchiveMembers parses an ar archive image into its object members, skipping
// the archive's own bookkeeping members (symbol table, name table).
func ArchiveMembers(raw []byte) ([]ArchiveMember, error) {
	if !IsArchive(raw) {
		return nil, fmt.Errorf("not an ar archive")
	}
	var nameTable []byte // GNU `//` long-name string table
	var members []ArchiveMember
	for p := len(arMagic); p+60 <= len(raw); {
		hdr := raw[p : p+60]
		if hdr[58] != 0x60 || hdr[59] != 0x0a { // header terminator "`\n"
			break
		}
		rawName := strings.TrimRight(string(hdr[0:16]), " ")
		size, err := strconv.Atoi(strings.TrimSpace(string(hdr[48:58])))
		if err != nil || size < 0 || p+60+size > len(raw) {
			break
		}
		data := raw[p+60 : p+60+size]
		name := rawName

		switch {
		case rawName == "//": // GNU long-name string table
			nameTable = data
			name = ""
		case rawName == "/" || rawName == "/SYM64/" || strings.HasPrefix(rawName, "__.SYMDEF"):
			name = "" // symbol table — skip
		case strings.HasPrefix(rawName, "/") && len(rawName) > 1: // GNU `/offset`
			name = longName(nameTable, rawName[1:])
		case strings.HasPrefix(rawName, "#1/"): // BSD extended name: name precedes data
			if n, err := strconv.Atoi(rawName[3:]); err == nil && n <= len(data) {
				name = strings.TrimRight(string(data[:n]), "\x00")
				data = data[n:]
			}
		default:
			name = strings.TrimSuffix(rawName, "/") // GNU appends '/' to short names
		}
		// The BSD symbol table is stored as a regular member with an extended name
		// (`#1/…` → "__.SYMDEF" / "__.SYMDEF SORTED"); skip it like the GNU one.
		if strings.HasPrefix(name, "__.SYMDEF") {
			name = ""
		}

		if name != "" && len(data) > 0 {
			members = append(members, ArchiveMember{Name: name, Data: data})
		}
		// Members are 2-byte aligned (a padding '\n' follows an odd-sized member).
		p += 60 + size
		if size%2 == 1 {
			p++
		}
	}
	if len(members) == 0 {
		return nil, fmt.Errorf("archive has no object members")
	}
	return members, nil
}

// longName resolves a GNU `/offset` long-name reference into the `//` name table
// (entries are '/'- or newline-terminated).
func longName(table []byte, offStr string) string {
	off, err := strconv.Atoi(offStr)
	if err != nil || off < 0 || off >= len(table) {
		return offStr
	}
	end := off
	for end < len(table) && table[end] != '\n' {
		end++
	}
	return strings.TrimSuffix(strings.TrimRight(string(table[off:end]), " "), "/")
}
