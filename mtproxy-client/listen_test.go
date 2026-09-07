package main

import (
	"net"
	"testing"
)

func TestListenListRepeatableAndComma(t *testing.T) {
	var l listenList
	if got := l.addrs(); len(got) != 1 || got[0] != ":1443" {
		t.Fatalf("умолчание должно быть :1443, получили %v", got)
	}
	_ = l.Set(":1443")
	_ = l.Set(":1444, 127.0.0.1:1445")
	got := l.addrs()
	want := []string{":1443", ":1444", "127.0.0.1:1445"}
	if len(got) != len(want) {
		t.Fatalf("ждали %v, получили %v", want, got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("ждали %v, получили %v", want, got)
		}
	}
}

// Самонабор при двух портах: петля на ЛЮБОЙ из них — самонабор. Проверка
// только первого порта оставила бы дыру на втором, ровно ту, что давала
// 16 000 отказов в сутки на одном порту до появления гварда.
func TestSelfDialAnyCoversEveryListenPort(t *testing.T) {
	ports := map[int]bool{1443: true, 1444: true}
	pub := net.ParseIP("149.154.167.99")
	if !isSelfDialAny(pub, 1444, ports) {
		t.Fatal("петля на второй порт не отсечена")
	}
	if !isSelfDialAny(pub, 1443, ports) {
		t.Fatal("петля на первый порт не отсечена")
	}
	if isSelfDialAny(pub, 443, ports) {
		t.Fatal("обычный адресат Telegram принят за самонабор")
	}
	if !isSelfDialAny(net.ParseIP("192.168.1.1"), 443, ports) {
		t.Fatal("приватный адрес не отсечён")
	}
}
