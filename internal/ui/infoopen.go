package ui

// Shell-side Info actions. The overview page itself lives in
// internal/ui/views/info; archive-member browsing (archive.go) and fat-arch
// switching stay in the shell because they replace the whole Model — the same
// boundary as libopen.go's open-as-primary.

import (
	tea "charm.land/bubbletea/v2"

	"github.com/rabarbra/exex/internal/binfile"
)

func (m *Model) updateInfo(msg tea.KeyMsg, key string) (tea.Model, tea.Cmd) {
	if m.isArchive() && m.infoMembers {
		return m.updateMembersList(key)
	}
	if key == "t" {
		// For a static library, `t`/`tab` opens the members list (doc #22). For a
		// fat Mach-O it toggles the next architecture slice (doc #27). Both mirror
		// the toggle role `t` plays in the other views.
		if m.isArchive() {
			m.enterMembersList()
			return m, nil
		}
		if len(m.file.FatArches) > 1 {
			return m.switchFatArch()
		}
		return m, nil
	}
	return m, m.info.Update(m.viewContext(), m, msg, key)
}

func (m *Model) renderInfo() string {
	if m.isArchive() && m.infoMembers {
		return m.renderMembersList()
	}
	return m.info.Render(m.viewContext())
}

// switchFatArch re-opens the binary at the next architecture slice of a fat
// Mach-O, returning a fresh model for it. The previous mapping is retired after
// its model-owned background commands have physically completed.
func (m *Model) switchFatArch() (tea.Model, tea.Cmd) {
	arches := m.file.FatArches
	next := arches[0]
	for i, a := range arches {
		if a == m.file.FatArch {
			next = arches[(i+1)%len(arches)]
			break
		}
	}
	opts := []binfile.Option{binfile.WithArch(next)}
	if dp := m.file.DebugPath(); dp != "" {
		opts = append(opts, binfile.WithDebugPath(dp))
	}
	f, err := binfile.Open(m.file.Path, opts...)
	if err != nil {
		m.setStatus("switch arch: "+err.Error(), true)
		return m, nil
	}
	nm, err := New(f, Options{Config: &m.cfg})
	if err != nil {
		f.Close()
		m.setStatus("switch arch: "+err.Error(), true)
		return m, nil
	}
	nm.width, nm.height = m.width, m.height
	nm.fileStack = append([]*Model(nil), m.fileStack...)
	nm.fileLabel = m.fileLabel
	nm.setStatus("architecture: "+next, false)
	m.retireFile()
	return nm, nm.Init()
}
