#!/bin/sh
# tests/test_tunnel_single_process.sh — оба порта туннеля обслуживает ОДИН
# процесс, которым владеет S98tg-tunnel; S97z2k-http-tunnel ничего не запускает.
#
# Повод: 07.09.2026, п. 7 дорожной карты после релея v2. Два процесса из одного
# бинарника давали две сессии к релею на роутер, двух надзирателей и сторожа
# только у одного из них. Назначение соединения берётся из SO_ORIGINAL_DST и
# от порта не зависит — второй процесс не давал ничего.
#
# Переход — самое тонкое: прежний надзиратель S97 остаётся в памяти со старым
# кодом и продолжал бы поднимать демон на :1444. Его добивает `stop` пустышки
# и `stop` S98; проверяется здесь по тексту, а живой переход — на роутере.
# POSIX sh (busybox ash).

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
PASS=0; FAIL=0
ok()  { PASS=$((PASS + 1)); printf '[PASS] %s\n' "$1"; }
bad() { FAIL=$((FAIL + 1)); printf '[FAIL] %s\n' "$1"; }
S98="$ROOT/files/init.d/S98tg-tunnel"; S97="$ROOT/files/init.d/S97z2k-http-tunnel"
HOOK="$ROOT/files/ndm/91-z2k-http-tunnel-redirect.sh"
body() { awk -v fn="^$2\\\\(\\\\)" '$0 ~ fn {f=1} f{print} f && /^\}/{exit}' "$1"; }

launch=$(grep -E '\$BIN .*--listen=' "$S98" | grep -v '^\s*#')
if printf '%s' "$launch" | grep -q -- '--listen=:1443' && printf '%s' "$launch" | grep -q -- '--listen=:\$CDN_PORT'; then
    ok "S98 поднимает один процесс на оба порта"
else
    bad "S98 не запускает оба порта одним процессом"
fi

if body "$S97" start | grep -qE '\$BIN .*--listen|\) &'; then
    bad "S97 start всё ещё запускает процесс — на релее снова две сессии на роутер"
else
    ok "S97 start ничего не запускает (пустышка)"
fi

if body "$S97" stop | grep -q 'PPid' && body "$S97" stop | grep -q 'S97z2k-http-tunnel'; then
    ok "S97 stop добивает своего осиротевшего надзирателя (переход)"
else
    bad "S97 stop не добивает старого надзирателя — тот поднимет :1444 обратно"
fi

if body "$S97" stop | grep -q -- '! tr .*--listen=:1443'; then
    ok "S97 stop не трогает новый общий процесс (у него есть :1443)"
else
    bad "S97 stop может убить новый общий процесс"
fi

if body "$S98" stop | grep -qE -- '--listen=:\(1443\|\$CDN_PORT\)' && body "$S98" stop | grep -q 'S97z2k-http-tunnel'; then
    ok "S98 stop освобождает оба порта и добивает надзирателей S97"
else
    bad "S98 stop не освобождает :1444 или не добивает S97 — старт упрётся в занятый порт"
fi

if body "$S98" start | grep -q 'cdn_rules_add' && body "$S98" stop | grep -q 'cdn_rules_del'; then
    ok "редирект cdnbase живёт вместе с процессом в S98"
else
    bad "редирект cdnbase не привязан к S98"
fi

if grep -q 'PIDFILE="/var/run/tg-tunnel.pid"' "$HOOK"; then
    ok "хук NDM для :1444 смотрит на pidfile S98"
else
    bad "хук NDM смотрит на несуществующий pidfile S97 — редирект не восстановится после регена"
fi

echo; echo "PASSED: $PASS"; echo "FAILED: $FAIL"; [ "$FAIL" -eq 0 ]
