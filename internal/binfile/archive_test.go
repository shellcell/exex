package binfile

import (
	"fmt"
	"testing"
)

// makeAr builds a minimal GNU ar archive from (name, data) members.
func makeAr(members [][2]string) []byte {
	out := []byte("!<arch>\n")
	for _, m := range members {
		name, data := m[0]+"/", m[1]
		hdr := fmt.Sprintf("%-16s%-12s%-6s%-6s%-8s%-10d`\n", name, "0", "0", "0", "644", len(data))
		out = append(out, hdr...)
		out = append(out, data...)
		if len(data)%2 == 1 {
			out = append(out, '\n')
		}
	}
	return out
}

func TestArchiveMembers(t *testing.T) {
	if !IsArchive([]byte("!<arch>\n")) {
		t.Fatal("IsArchive false for valid magic")
	}
	if IsArchive([]byte("\x7fELF")) {
		t.Fatal("IsArchive true for ELF")
	}
	ar := makeAr([][2]string{{"foo.o", "abcd"}, {"bar.o", "xyz"}}) // bar odd length → padded
	mems, err := ArchiveMembers(ar)
	if err != nil {
		t.Fatalf("ArchiveMembers: %v", err)
	}
	if len(mems) != 2 {
		t.Fatalf("got %d members, want 2", len(mems))
	}
	if mems[0].Name != "foo.o" || string(mems[0].Data) != "abcd" {
		t.Errorf("member 0 = %q %q", mems[0].Name, mems[0].Data)
	}
	if mems[1].Name != "bar.o" || string(mems[1].Data) != "xyz" {
		t.Errorf("member 1 = %q %q", mems[1].Name, mems[1].Data)
	}
}

func TestArchiveSkipsSymbolTable(t *testing.T) {
	// The symbol-table member ("/") and name table ("//") must be skipped.
	ar := makeAr([][2]string{{"", "symtab"}, {"obj.o", "data"}})
	// Rewrite the first member's name to the bare "/" symbol table marker.
	mems, err := ArchiveMembers(ar)
	if err != nil {
		t.Fatalf("ArchiveMembers: %v", err)
	}
	for _, m := range mems {
		if m.Name == "/" || m.Name == "//" {
			t.Errorf("bookkeeping member %q not skipped", m.Name)
		}
	}
}
