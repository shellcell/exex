package ui

// Static-library (ar) archive browsing. A `.a` isn't a single object, so it gets
// an extra Info-view sub-mode: a list of its object members. Selecting a member
// loads it as the active object (rebuilding the model, like the fat-Mach-O arch
// switch), giving it the full disasm/symbols/strings/… experience. `t`/`tab` on
// the Info view toggles between the member list and the loaded member's info.

import (
	"fmt"
	"path/filepath"

	tea "charm.land/bubbletea/v2"
	"github.com/charmbracelet/x/ansi"

	"github.com/rabarbra/exex/internal/binfile"
	"github.com/rabarbra/exex/internal/ui/layout"
)

// archiveState holds the archive's members and the Info view's members-list mode.
type archiveState struct {
	archivePath    string
	archiveMembers []binfile.ArchiveMember
	archiveIndex   int  // member currently loaded as the active object
	infoMembers    bool // Info view showing the members list (vs the loaded member's header)
	memberSel      int  // selection within the members list
	memberTop      int  // members-list scroll top
}

// isArchive reports whether the model is browsing a static library.
func (m *Model) isArchive() bool { return len(m.archiveMembers) > 0 }

// NewArchive builds the model for a static library: it loads the first parseable
// member as the active object and opens the Info view in its members-list mode.
// The caller must keep the archive image (which members slice into) mapped for
// the model's lifetime.
func NewArchive(path string, members []binfile.ArchiveMember, opts Options) (*Model, error) {
	idx := -1
	var f *binfile.File
	for i, mem := range members {
		if ff, err := binfile.OpenBytes(mem.Name, mem.Data); err == nil {
			idx, f = i, ff
			break
		}
	}
	if f == nil {
		return nil, fmt.Errorf("archive %s: no parseable object members", path)
	}
	m, err := New(f, opts)
	if err != nil {
		return nil, err
	}
	m.archivePath = path
	m.archiveMembers = members
	m.archiveIndex = idx
	m.memberSel = idx
	m.infoMembers = true // libraries open straight into the members list
	m.mode = modeInfo
	return m, nil
}

// enterMembersList switches the Info view to the members list, selecting the
// member that is currently loaded.
func (m *Model) enterMembersList() {
	m.infoMembers = true
	m.memberSel = m.archiveIndex
	m.memberTop = 0
}

// loadArchiveMember parses the i-th member and returns a fresh model for it (the
// archive context carries over), showing that member's header info. Mirrors the
// fat-Mach-O arch switch: the previous member's image stays mapped, so any
// in-flight background decode is safe.
func (m *Model) loadArchiveMember(i int) (tea.Model, tea.Cmd) {
	if i < 0 || i >= len(m.archiveMembers) {
		return m, nil
	}
	mem := m.archiveMembers[i]
	f, err := binfile.OpenBytes(mem.Name, mem.Data)
	if err != nil {
		m.setStatus("member "+mem.Name+": "+err.Error(), true)
		return m, nil
	}
	nm, err := New(f, Options{Config: &m.cfg})
	if err != nil {
		m.setStatus("member "+mem.Name+": "+err.Error(), true)
		return m, nil
	}
	nm.archivePath = m.archivePath
	nm.archiveMembers = m.archiveMembers
	nm.archiveIndex = i
	nm.memberSel = i
	nm.infoMembers = false // show the loaded member's info; t/tab returns to the list
	nm.width, nm.height = m.width, m.height
	nm.setStatus(fmt.Sprintf("member %d/%d: %s", i+1, len(m.archiveMembers), mem.Name), false)
	return nm, nm.Init()
}

// updateMembersList drives the Info view's members-list mode: navigate the list,
// t/tab/Enter open the selected member, Esc returns to the loaded member's info.
func (m *Model) updateMembersList(key string) (tea.Model, tea.Cmd) {
	switch key {
	case "t", "enter":
		return m.loadArchiveMember(m.memberSel)
	case "esc":
		m.infoMembers = false // back to the loaded member's header
		return m, nil
	}
	navKey(&m.memberSel, len(m.archiveMembers), m.listPage(), key)
	return m, nil
}

// renderMembersList draws the archive's object members with the loaded one marked
// and the selection highlighted.
func (m *Model) renderMembersList() string {
	bodyH := m.bodyHeight()
	mems := m.archiveMembers
	rowW := max(1, m.width-2)

	hdr := fmt.Sprintf("  %s — %d members", filepath.Base(m.archivePath), len(mems))
	rows := []string{m.tableHeader(layout.FitANSIWidth(hdr, rowW)), ""}

	visible := max(1, bodyH-2) // header + blank
	top := m.visualTopForView(m.memberSel, m.memberTop, len(mems), visible, oneRow)
	m.memberTop = top
	end := min(top+visible, len(mems))
	nameW := layout.Clamp(rowW-26, 16, 90)
	for i := top; i < end; i++ {
		mem := mems[i]
		mark := " "
		if i == m.archiveIndex { // the member currently loaded into the other views
			mark = "●"
		}
		line := fmt.Sprintf("%s %s  %9d  %-6s",
			mark, layout.PadVisual(layout.TruncateMiddle(mem.Name, nameW), nameW), len(mem.Data), memberFormatTag(mem.Data))
		line = layout.PadVisual(line, rowW)
		if i == m.memberSel {
			line = m.theme.tableSelStyle.Render(ansi.Strip(line))
		}
		rows = append(rows, line)
	}
	return layout.PadBodyRows(rows, m.width, bodyH)
}

// memberFormatTag names a member's container format from its magic bytes — cheap
// enough to compute per row, so the list needn't parse every member upfront.
func memberFormatTag(data []byte) string {
	switch {
	case len(data) >= 4 && data[0] == 0x7f && data[1] == 'E' && data[2] == 'L' && data[3] == 'F':
		return "ELF"
	case len(data) >= 4 && isMachOMagic(data):
		return "Mach-O"
	case len(data) >= 2 && data[0] == 'M' && data[1] == 'Z':
		return "PE"
	}
	return "?"
}

// isMachOMagic reports whether data begins with a (thin or fat, either endianness)
// Mach-O magic number.
func isMachOMagic(data []byte) bool {
	switch string(data[:4]) {
	case "\xfe\xed\xfa\xce", "\xfe\xed\xfa\xcf", // MH_MAGIC / MH_MAGIC_64 (BE)
		"\xce\xfa\xed\xfe", "\xcf\xfa\xed\xfe", // MH_CIGAM / MH_CIGAM_64 (LE)
		"\xca\xfe\xba\xbe", "\xbe\xba\xfe\xca": // FAT_MAGIC / FAT_CIGAM
		return true
	}
	return false
}
