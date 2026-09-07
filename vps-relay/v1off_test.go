package main

import (
	"testing"
	"time"
)

// Выключатель v1: с --v1-off клиент старого протокола получает отказ
// v1_disabled и сессию не поднимает, а v2 работает как ни в чём не бывало.
// Решение Марка 07.09.2026: «не хотят обновляться — пусть остаются без телеги».
func TestV1_RejectedWhenSwitchedOff(t *testing.T) {
	old := *v1Off
	*v1Off = true
	t.Cleanup(func() { *v1Off = old })

	m := withMemEvents(t)
	startFakeDC(t, echoDC)
	url := startRelay(t)
	id, priv := testInstall(t)

	// Отказ без установки эмитится раз в час на адрес; прежние тесты уже
	// заняли слот 127.0.0.1 — освобождаем, иначе событие тут не появится.
	legacyRejects.mu.Lock()
	delete(legacyRejects.last, "127.0.0.1")
	legacyRejects.mu.Unlock()

	ws := dialV1(t, url, id, priv)
	defer ws.Close()
	if !m.wait("session_close", 1, 2*time.Second) {
		t.Fatal("сессия v1 не закрылась")
	}
	if got := m.byEv("session_close")[0].Reason; got != "v1_disabled" {
		t.Fatalf("причина закрытия %q, ждали v1_disabled", got)
	}
	if n := len(m.byEv("session_open")); n != 0 {
		t.Fatalf("v1 открыл сессию при выключенном протоколе: %d", n)
	}

	// v2 при том же флаге обязан жить.
	ws2, _ := dialV2(t, url, id, priv, "p-82.18")
	defer ws2.Close()
	sendFrame(t, ws2, 1, muxCONNECT, connectPayload(tgTarget, 443))
	expectFrame(t, ws2, 1, muxCONNECT_OK, 2*time.Second)
	sendFrame(t, ws2, 1, muxDATA, []byte("ping"))
	if got := expectFrame(t, ws2, 1, muxDATA, 2*time.Second); string(got) != "ping" {
		t.Fatalf("v2 при --v1-off сломан: %q", got)
	}
}
