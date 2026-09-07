package main

import "strings"

// listenList — значения флага --listen. ОДИН ПРОЦЕСС НА ОБА ПОРТА.
//
// До этого клиент слушал ровно один адрес, и роутер держал ДВА процесса из
// одного бинарника: S98tg-tunnel на :1443 (Telegram) и S97z2k-http-tunnel на
// :1444 (cdnbase). Каждый со своим надзирателем, своей сессией к релею и
// своим рукопожатием; сторож был только у первого. На релее это удваивало
// число сессий на роутер безо всякой пользы: назначение соединения и так
// берётся из SO_ORIGINAL_DST и от порта не зависит.
//
// Флаг повторяемый (--listen=:1443 --listen=:1444) и понимает запятую
// (--listen=:1443,:1444). Без флага — прежний умолчательный :1443, чтобы
// старые вызовы работали как раньше.
type listenList []string

func (l *listenList) String() string { return strings.Join(*l, ",") }

func (l *listenList) Set(v string) error {
	for _, a := range strings.Split(v, ",") {
		a = strings.TrimSpace(a)
		if a != "" {
			*l = append(*l, a)
		}
	}
	return nil
}

// addrs — итоговый список адресов с умолчанием.
func (l listenList) addrs() []string {
	if len(l) == 0 {
		return []string{":1443"}
	}
	return []string(l)
}
