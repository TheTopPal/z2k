#!/bin/sh
# tests/test_silence_wiring.sh — цепочка детектора молчания: от доставки файла
# до ссылки на функцию в конфиге.
#
# ЗАЧЕМ ОТДЕЛЬНЫЙ НАБОР. Детектор резолвится движком ПО ИМЕНИ в _G. Если
# конфиг ссылается на z2k_fail_silence, а файла модуля на роутере нет,
# nfqws2 падает в error() на каждом пакете профиля — то есть обход умирает
# целиком, а не деградирует. Ровно так уже было с рантаймом обрыва на 16 КБ,
# когда файл не попал в карту доставки. Поэтому здесь сторожится вся цепочка
# сразу: init грузит, установщик качает, карта обновлений знает цель.
# POSIX sh (busybox ash).
PASS=0; FAIL=0
ok() { PASS=$((PASS+1)); printf '[PASS] %s\n' "$1"; }
no() { FAIL=$((FAIL+1)); printf '[FAIL] %s (want=%s got=%s)\n' "$1" "$2" "$3"; }
assert_eq() { if [ "$2" = "$3" ]; then ok "$1"; else no "$1" "$2" "$3"; fi; }
ROOT=$(cd "$(dirname "$0")/.." && pwd)
LUA="$ROOT/files/lua/z2k-silence.lua"

assert_eq "модуль на месте" "1" "$([ -f "$LUA" ] && echo 1 || echo 0)"

# --- 1. init грузит модуль, и ПОСЛЕ zapret-auto.lua --------------------------
#
# Порядок обязателен: детектор зовёт standard_failure_detector,
# automate_host_record и automate_failure_counter — всё это объявляет
# zapret-auto.lua. Загрузись он раньше, функции были бы nil в момент вызова.
INIT="$ROOT/files/S99zapret2.new"
_n_auto=$(grep -n 'LUAOPT="$LUAOPT --lua-init=@$LUA_AUTO"' "$INIT" | head -1 | cut -d: -f1)
_n_sil=$(grep -n 'lua-init=@\$LUA_Z2K_SILENCE' "$INIT" | head -1 | cut -d: -f1)
if [ -n "$_n_sil" ]; then
    ok "init грузит модуль детектора"
    if [ -n "$_n_auto" ] && [ "$_n_sil" -gt "$_n_auto" ]; then
        ok "модуль грузится после zapret-auto.lua"
    else
        no "модуль грузится после zapret-auto.lua" "строка > $_n_auto" "$_n_sil"
    fi
else
    no "init грузит модуль детектора" "--lua-init" "нет"
fi
# Файл проверяется на существование: без него строка --lua-init=@ с пустым
# путём валит запуск демона.
assert_eq "init проверяет файл перед загрузкой" "1" \
    "$(grep -c '\[ -f "\$LUA_Z2K_SILENCE" \]' "$INIT" | tr -d ' ')"

# --- 2. установщик качает модуль ---------------------------------------------
assert_eq "z2k.sh качает модуль с того же адреса, что и остальные" "1" \
    "$(grep -c 'url="${GITHUB_RAW}/files/lua/z2k-silence.lua"' "$ROOT/z2k.sh" | tr -d ' ')"
assert_eq "и кладёт его в каталог lua установки" "1" \
    "$(grep -c 'output="${lua_dir}/z2k-silence.lua"' "$ROOT/z2k.sh" | tr -d ' ')"

# --- 3. карта обновлений знает, куда класть -----------------------------------
. "$ROOT/lib/release_map.sh"
assert_eq "карта доставки даёт цель на роутере" "/opt/zapret2/lua/z2k-silence.lua" \
    "$(ZAPRET2_DIR=/opt/zapret2 z2k_install_paths files/lua/z2k-silence.lua)"
# Модуль резолвится по имени, значит после его замены профиль обязан быть
# пересобран и сервис перезапущен — иначе движок продолжит держать старый код.
_steps=$(z2k_steps_for files/lua/z2k-silence.lua | tr '\n' ' ')
case "$_steps" in
    *restart-service*) ok "замена модуля перезапускает сервис" ;;
    *) no "замена модуля перезапускает сервис" "restart-service" "$_steps" ;;
esac

printf '\nPASSED: %d\nFAILED: %d\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]
