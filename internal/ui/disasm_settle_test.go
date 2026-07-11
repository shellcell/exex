package ui

import tea "charm.land/bubbletea/v2"

// disasmReadyFor synthesises the disasmReadyMsg the background decode would
// deliver, so a test can settle the disassembly view synchronously instead of
// waiting on the event loop. Four test files (and the perf harness) drained the
// decode by hand; this is that loop, once.
func disasmReadyFor(m *Model) tea.Msg {
	addr := m.dasm.PendingAddr
	return disasmReadyMsg{addr: addr, span: m.decodeDisasmAt(addr, m.disasmLeadBytes())}
}

// settleDisasmDecode applies pending background decodes until none is in flight.
func settleDisasmDecode(model tea.Model) tea.Model {
	for {
		mm, ok := model.(*Model)
		if !ok || !mm.dasm.Decoding {
			return model
		}
		model, _ = mm.Update(disasmReadyFor(mm))
	}
}
