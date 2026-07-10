package ui

import (
	"testing"

	tea "charm.land/bubbletea/v2"

	"github.com/rabarbra/exex/internal/binfile"
)

func openLifetimeTestModel(t *testing.T) *Model {
	t.Helper()
	path := firstExisting("/bin/ls", "/usr/bin/true", "/bin/cat")
	if path == "" {
		t.Skip("no system binary available")
	}
	f, err := binfile.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	m, err := New(f)
	if err != nil {
		f.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() { f.Close() })
	return m
}

func TestGoBackClosesIdleChildFile(t *testing.T) {
	parent := openLifetimeTestModel(t)
	child := openLifetimeTestModel(t)
	child.fileStack = []*Model{parent}

	got, _, ok := child.goBackFile()
	if !ok || got != parent {
		t.Fatal("goBackFile did not restore parent")
	}
	if child.file.Raw() != nil {
		t.Fatal("idle child mapping remained open")
	}
	if parent.file.Raw() == nil {
		t.Fatal("restored parent mapping was closed")
	}
}

func TestGoBackDefersCloseUntilBackgroundCommandReturns(t *testing.T) {
	parent := openLifetimeTestModel(t)
	child := openLifetimeTestModel(t)
	child.fileStack = []*Model{parent}

	started := make(chan struct{})
	release := make(chan struct{})
	cmd := child.backgroundCmd(func() tea.Msg {
		close(started)
		<-release
		return prewarmMsg{}
	})
	result := make(chan tea.Msg, 1)
	go func() { result <- cmd() }()
	<-started

	got, _, ok := child.goBackFile()
	if !ok || got != parent {
		t.Fatal("goBackFile did not restore parent")
	}
	if child.file.Raw() == nil {
		t.Fatal("child mapping closed while its command was still running")
	}

	close(release)
	model, next := parent.Update(<-result)
	if model != parent || next != nil {
		t.Fatal("stale child completion affected restored parent")
	}
	if child.file.Raw() != nil {
		t.Fatal("child mapping remained open after its final command returned")
	}
	if parent.dasm.Decoding {
		t.Fatal("stale child prewarm started a decode on the parent")
	}
}

func TestEnterFileCancelsParentWork(t *testing.T) {
	parent := openLifetimeTestModel(t)
	child := openLifetimeTestModel(t)

	channels := []chan struct{}{make(chan struct{}), make(chan struct{}), make(chan struct{}), make(chan struct{}), make(chan struct{}), make(chan struct{})}
	parent.findCancel = channels[0]
	parent.searchCancel = channels[1]
	parent.xrefCancel = channels[2]
	parent.syscallCancel = channels[3]
	parent.syscallFullCancel = channels[4]
	parent.cpufeatCancel = channels[5]
	parent.searchRunning = true
	parent.xrefRunning = true
	parent.syscallRunning = true
	parent.syscallFullRunning = true
	parent.cpufeatRunning = true
	parent.dasm.Decoding = true

	parent.enterFile(child, "child")
	for i, ch := range channels {
		select {
		case <-ch:
		default:
			t.Fatalf("cancellation channel %d was not closed", i)
		}
	}
	if parent.searchRunning || parent.xrefRunning || parent.syscallRunning || parent.syscallFullRunning || parent.cpufeatRunning || parent.dasm.Decoding {
		t.Fatal("parent still reports background work after suspension")
	}
	if parent.file.Raw() == nil {
		t.Fatal("suspended parent mapping was closed")
	}
}
