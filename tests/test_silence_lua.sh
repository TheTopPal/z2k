#!/bin/sh
# tests/test_silence_lua.sh — обёртка над lua-харнесом tests/test_silence_lua.lua,
# чтобы общий прогон (tests/run_all.sh) и CI видели его как обычный набор.
# Без lua — SKIP с ненулевым кодом не считается: в CI lua есть.
LUA=""
for c in lua5.3 lua5.4 lua luajit; do
    if command -v "$c" >/dev/null 2>&1; then LUA=$c; break; fi
done
if [ -z "$LUA" ]; then
    printf '[SKIP] lua не найден — test_silence_lua.lua не запущен\n'
    printf '\nPASSED: 0\nFAILED: 0\n'
    exit 0
fi
cd "$(dirname "$0")/.." || exit 1
exec "$LUA" tests/test_silence_lua.lua
