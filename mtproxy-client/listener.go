package main

import (
	"encoding/binary"
	"fmt"
	"net"
	"strconv"
	"syscall"
)

const (
	soOriginalDst = 80 // SO_ORIGINAL_DST (SOL_IP)
)

// sockaddrOrder is the byte order of the sa_family_t field the kernel fills in.
// It is HOST order — unlike sin_port two bytes later, which is always network
// order. Hardcoding little-endian here was correct on every little-endian build
// and silently wrong on big-endian MIPS (Keenetic mips-3.4_kn): AF_INET came
// back as 0x0200 = 512, the correct IPv4 answer was discarded, execution fell
// through to the IPv6 branch, and every redirected Telegram connection was
// dropped with "IP6T_SO_ORIGINAL_DST: invalid argument" — a message about IPv6
// on a path where no IPv6 was involved. Diagnosed 2026-08-22 from a mips-3.4_kn
// router whose tunnel logged nothing else; an aarch64 router on the same build
// was unaffected, which is why it read as a user-side fault for so long.
var sockaddrOrder binary.ByteOrder = binary.NativeEndian

// decodeIPv4Dst reads a redirected IPv4 destination out of a raw sockaddr_in.
// ok is false when the buffer does not hold an AF_INET address under the given
// order — kept as a pure function so both byte orders are exercised by tests on
// any host, which the inline version could not be.
func decodeIPv4Dst(order binary.ByteOrder, raw []byte) (net.IP, int, bool) {
	if len(raw) < 8 || order.Uint16(raw[0:2]) != syscall.AF_INET {
		return nil, 0, false
	}
	return net.IPv4(raw[4], raw[5], raw[6], raw[7]), int(binary.BigEndian.Uint16(raw[2:4])), true
}

// getOriginalDst — адрес, на который клиент шёл ДО редиректа (SO_ORIGINAL_DST).
//
// ТОЛЬКО IPv4, И ЭТО НЕ УПУЩЕНИЕ. Сюда приходят соединения после iptables
// REDIRECT на наш порт, а редиректим мы только IPv4: v6-подсети Telegram
// фаервол отрезает REJECT'ом ещё до нас (см. правила «TG v6 REJECT» в
// диагностике) — их DC по v6 сервис не отдают. Так что IPv6-соединения здесь
// не появляются в принципе.
//
// Раньше тут стояла ветка на IP6T_SO_ORIGINAL_DST «на всякий случай». Она
// была мертва по построению и вредна вдвойне: во-первых, GetsockoptIPv6Mreq
// отдаёт 20 байт, а sockaddr_in6 занимает 28 — последние четыре байта
// адреса терялись, и ветка честно возвращала ОБРЕЗАННЫЙ адрес; во-вторых,
// именно она подписывала чужую ошибку: на big-endian MIPS сломанный разбор
// IPv4 проваливался сюда, и в логе стояло «IP6T_SO_ORIGINAL_DST: invalid
// argument» про IPv6 там, где IPv6 не было и близко (разбор 2026-08-22).
// Теперь отказ IPv4 остаётся отказом IPv4, с тем именем, что и есть.
//
// GetsockoptIPv6Mreq используется как удобный 20-байтовый буфер: для
// sockaddr_in (16 байт) его хватает с запасом; сам разбор — decodeIPv4Dst,
// вынесенный в чистую функцию ради тестов на оба порядка байт.
func getOriginalDst(conn *net.TCPConn) (net.IP, int, error) {
	rawConn, err := conn.SyscallConn()
	if err != nil {
		return nil, 0, fmt.Errorf("SyscallConn: %w", err)
	}

	var origIP net.IP
	var origPort int
	var syscallErr error

	err = rawConn.Control(func(fd uintptr) {
		addr, gerr := syscall.GetsockoptIPv6Mreq(int(fd), syscall.IPPROTO_IP, soOriginalDst)
		if gerr != nil {
			syscallErr = fmt.Errorf("getsockopt SO_ORIGINAL_DST: %w", gerr)
			return
		}
		raw := addr.Multiaddr
		ip, port, ok := decodeIPv4Dst(sockaddrOrder, raw[:])
		if !ok {
			syscallErr = fmt.Errorf("SO_ORIGINAL_DST: not an AF_INET sockaddr (family %d)",
				sockaddrOrder.Uint16(raw[0:2]))
			return
		}
		origIP, origPort = ip, port
	})

	if err != nil {
		return nil, 0, err
	}
	if syscallErr != nil {
		return nil, 0, syscallErr
	}
	return origIP, origPort, nil
}

// isSelfDial — просят ли нас набрать наш же слушатель.
//
// SO_ORIGINAL_DST возвращает адрес, на который клиент шёл ДО редиректа. Если
// соединение пришло на порт слушателя НАПРЯМУЮ, а не через REDIRECT, редиректа
// не было — и ядро отдаёт адрес самого сокета. Мы просили релей набрать его,
// релей отказывал («rejected non-Telegram»), клиент повторял. Петля.
//
// Замер на VPS 26.08.2026, отказы за три часа — все на порт 1443:
//
//	9504  37.193.146.91:1443   WAN-адрес роутера (порт открыт наружу)
//	3379  192.168.1.1:1443     LAN-адрес самого роутера
//	1408  127.0.0.1:1443       локальная петля
//
// Одна такая сессия давала две попытки в секунду круглосуточно, ~16 000
// отказов в сутки — больше, чем все прочие источники релея вместе.
//
// Признак — ПОРТ, а не адрес. Адрес зависит от того, куда постучались: петля,
// LAN, WAN — вариантов много и все заранее не перечислить. А порт всегда наш
// собственный, потому что именно на него пришло соединение. Дополнительно
// отсекаем приватные и петлевые адреса: телеграм там не живёт по определению,
// и просить релей их набирать бессмысленно в любом случае.
// listenPorts — порты всех наших слушателей (заполняется в runTunnel).
var listenPorts map[int]bool

// isSelfDialAny — isSelfDial для процесса с несколькими портами.
func isSelfDialAny(origIP net.IP, origPort int, ports map[int]bool) bool {
	if ports[origPort] {
		return true
	}
	return isSelfDial(origIP, origPort, 0)
}

func isSelfDial(origIP net.IP, origPort, listenPort int) bool {
	if origPort == listenPort {
		return true
	}
	if origIP == nil {
		return false
	}
	if origIP.IsLoopback() || origIP.IsPrivate() || origIP.IsLinkLocalUnicast() || origIP.IsUnspecified() {
		return true
	}
	return false
}

// listenPortOf — порт из строки вида ":1443" или "127.0.0.1:1443".
// Не разобрали — возвращаем 0: тогда гвард по порту не сработает, но проверка
// приватных адресов останется. Молча ошибиться в сторону «набираем» лучше, чем
// перекрыть человеку телеграм из-за нестандартной записи адреса.
func listenPortOf(addr string) int {
	_, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return 0
	}
	p, err := strconv.Atoi(portStr)
	if err != nil {
		return 0
	}
	return p
}
