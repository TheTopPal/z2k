#!/bin/sh
# tests/test_scheduler_mtime_busybox.sh — планировщик обязан читать время файла
# ТАМ, ГДЕ `stat` НЕ УМЕЕТ НИЧЕГО.
#
# ОБОЖГЛО 06.09.2026, аудит роутера (Ultra NC-1812, KeeneticOS 5.1.4, Entware,
# busybox 1.37.0, z2k p-82.14):
#
#   $ stat -c %Y /opt/zapret2/z2k-scheduler.sh
#   stat: invalid option -- c
#   Usage: stat [-lt] FILE...
#   $ which stat
#   /opt/bin/stat            <- это тоже busybox, дело не в PATH
#
# Ключа для времени файла у этого stat нет ни одного, поэтому `_z2k_mtime`
# всегда отдавала пусто, ветка перезапуска не исполнялась ни разу, и оболочка
# девять суток дочитывала код из инода, у которого уже нет имени: обновление
# кладёт новый файл через mv, а открытый дескриптор держит старый.
#
#   /proc/1587/fd/10 -> /opt/zapret2/z2k-scheduler.sh (deleted)
#   14488 байт исполняется, 30044 лежит на диске
#
# Снятая из кода задача get-config при этом каждое утро опустошала nozapret.
#
# Почему не поймали раньше: test_scheduler_code_refresh проверяет ЛОГИКУ
# перезапуска и делает это на хозяине с GNU stat, где -c работает. Дефект живёт
# там, где stat не работает, — значит stat надо подделать.

PASS=0; FAIL=0; SKIP=0
ok()   { PASS=$((PASS+1)); printf '[PASS] %s\n' "$1"; }
bad()  { FAIL=$((FAIL+1)); printf '[FAIL] %s\n' "$1"; }
skip() { SKIP=$((SKIP+1)); printf '[SKIP] %s\n' "$1"; }

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SCHED="$ROOT/files/z2k-scheduler.sh"
INIT="$ROOT/files/S99zapret2.new"

TMP=$(mktemp -d) || exit 1
trap 'rm -rf "$TMP"' EXIT INT TERM

# --- стенд -------------------------------------------------------------------
mkdir -p "$TMP/bin" "$TMP/opt"

# Подставной stat — ровно тот, что на роутере: usage `stat [-lt] FILE...`,
# любой ключ времени даёт «invalid option», выход ненулевой, stdout пуст.
cat > "$TMP/bin/stat" <<'STUBSTAT'
#!/bin/sh
printf 'stat: invalid option\n' >&2
exit 1
STUBSTAT
chmod +x "$TMP/bin/stat"

echo '# планировщик' > "$TMP/opt/z2k-scheduler.sh"

# Умеет ли ХОЗЯИН читать время файла портируемо. У BSD `date -r` ждёт секунды,
# а не файл: там регрессию воспроизвести нечем, и это надо сказать вслух, а не
# позеленеть молча.
HOST_DATE_R=0
date -r "$TMP/opt/z2k-scheduler.sh" +%s 2>/dev/null | grep -qE '^[0-9]{9,}$' && HOST_DATE_R=1

# Аргументы передаются ОКРУЖЕНИЕМ: на роутере вложенная `sh -c` глотает
# позиционные, и набор проверял бы пустоту (tests/test_router_shell_portability).
mtime_of() {
    Z2K_MT_FILE="$1" Z2K_MT_PATH="$2" Z2K_MT_FN="$TMP/mtime.sh" \
    sh -c '. "$Z2K_MT_FN"; PATH="$Z2K_MT_PATH"; export PATH; _z2k_mtime "$Z2K_MT_FILE"' 2>/dev/null
}

# --- 1. функция вырезается из боевого файла ----------------------------------
awk '/^_z2k_mtime\(\)/{f=1} f{print} f && /\}[[:space:]]*$/{exit}' "$SCHED" > "$TMP/mtime.sh"
if [ -s "$TMP/mtime.sh" ]; then
    ok "_z2k_mtime вырезана из files/z2k-scheduler.sh"
else
    bad "в files/z2k-scheduler.sh нет функции _z2k_mtime — проверять нечего"
    printf '\nPASSED: %s\nFAILED: %s\nSKIPPED: %s\n' "$PASS" "$FAIL" "$SKIP"
    exit 1
fi

# --- 2. обычный хозяин: число -------------------------------------------------
_v=$(mtime_of "$TMP/opt/z2k-scheduler.sh" "$PATH")
case "$_v" in
    ''|*[!0-9]*) bad "на исправном хозяине _z2k_mtime вернула не число: '$_v'" ;;
    *)           ok  "на исправном хозяине _z2k_mtime возвращает число" ;;
esac

# --- 3. несуществующий файл: пусто --------------------------------------------
# Пустая строка — договор: вызывающий код по ней понимает «сравнивать не с чем»
# и не перезапускается. Нулём подменять нельзя — это было бы «файл от 1970-го».
_v=$(mtime_of "$TMP/opt/net-takogo" "$PATH")
if [ -z "$_v" ]; then
    ok "на несуществующем файле _z2k_mtime возвращает пусто"
else
    bad "на несуществующем файле вернулось '$_v', ожидалась пустая строка"
fi

# --- 4. РЕГРЕССИЯ: stat не умеет ничего, время всё равно обязано читаться ------
if [ "$HOST_DATE_R" = 1 ]; then
    _v=$(mtime_of "$TMP/opt/z2k-scheduler.sh" "$TMP/bin:$PATH")
    case "$_v" in
        ''|*[!0-9]*)
            bad "со сломанным stat _z2k_mtime вернула '$_v' — планировщик снова не подхватит новый код" ;;
        *)  ok  "со сломанным stat _z2k_mtime всё равно возвращает число" ;;
    esac

    # --- 5. и это НАСТОЯЩЕЕ время файла, а не что попало ----------------------
    _want=$(date -r "$TMP/opt/z2k-scheduler.sh" +%s 2>/dev/null)
    if [ -n "$_want" ] && [ "$_v" = "$_want" ]; then
        ok "значение совпадает со временем файла ($_want)"
    else
        bad "значение '$_v' не равно времени файла '$_want'"
    fi
else
    skip "хозяин не умеет date -r ФАЙЛ (BSD) — сломанный stat здесь не подделать"
    skip "проверка совпадения со временем файла — по той же причине"
fi

# --- 6. init: со сломанным stat планировщик обязан быть перезапущен -----------
# Вырезаем только испытуемую функцию: init целиком трогает firewall и демонов.
awk '/^_z2k_scheduler_sync\(\)/,/^}/' "$INIT" > "$TMP/sync.sh"
if [ ! -s "$TMP/sync.sh" ]; then
    bad "в files/S99zapret2.new нет функции _z2k_scheduler_sync"
elif [ "$HOST_DATE_R" != 1 ]; then
    skip "перезапуск при сломанном stat — хозяин не умеет date -r ФАЙЛ"
    skip "журнал без «не читается время файлов» — по той же причине"
else
    printf '#!/bin/sh\necho "$1" >> "%s/calls.log"\n' "$TMP" > "$TMP/opt/S99z2k-scheduler"
    chmod +x "$TMP/opt/S99z2k-scheduler"
    : > "$TMP/calls.log"
    : > "$TMP/sched.log"

    Z2K_SCHED_FILE="$TMP/opt/z2k-scheduler.sh" \
    Z2K_SCHED_PROBE="$TMP/opt/z2k-tcp16-probe.sh" \
    Z2K_SCHED_INIT="$TMP/opt/S99z2k-scheduler" \
    Z2K_SCHED_STAMP="$TMP/stamp" \
    Z2K_SCHED_LOG="$TMP/sched.log" \
    Z2K_SYNC_FN="$TMP/sync.sh" \
    Z2K_SYNC_PATH="$TMP/bin:$PATH" \
    sh -c '. "$Z2K_SYNC_FN"; PATH="$Z2K_SYNC_PATH"; export PATH; _z2k_scheduler_sync' >/dev/null 2>&1

    _calls=$(wc -l < "$TMP/calls.log" | tr -d ' ')
    if [ "$_calls" = "1" ]; then
        ok "со сломанным stat служба перезапускает планировщик"
    else
        bad "перезапуска не было (вызовов: $_calls) — новый код так и лежит на диске"
    fi

    if grep -q 'не читается время файлов' "$TMP/sched.log" 2>/dev/null; then
        bad "в журнал ушло «не читается время файлов» — механизм выключен молча"
    else
        ok "журнал без «не читается время файлов»"
    fi
fi

# --- 7. ГВАРД: в боевом коде date -r обязан стоять ПЕРЕД stat -----------------
#
# Правило по строке ЛОГИЧЕСКОЙ: цепочка запасных вариантов пишется через `\`,
# и по физическим строкам её не проверить. Комментарии не считаются — их в
# проекте много, и они как раз про то, что stat тут не работает.
_rule() {
    awk -v F="$1" '
        {
            line = $0; start = FNR
            while (line ~ /\\$/ && (getline nxt) > 0) { sub(/\\$/, "", line); line = line nxt }
            if (line ~ /^[[:space:]]*#/) next
            c = index(line, "stat -c")
            if (c == 0) c = index(line, "stat --format")
            d = index(line, "date -r")
            if (c > 0 && line ~ /%[Yy]/ && (d == 0 || d > c)) printf "%s:%d\n", F, start
        }
    ' "$1"
}
# Список и обход разделены намеренно: `for f in $(find …)` роняет shellcheck
# правилом SC2044, и оно право — разбор вывода find подстановкой хрупок. Тот же
# приём в tests/test_portability_traps.sh: находим, потом читаем построчно.
_files=$(find "$ROOT/files" "$ROOT/lib" "$ROOT/webpanel" -type f \
         \( -name '*.sh' -o -name 'S*' -o -name '*.new' \) 2>/dev/null)
_viol=$(printf '%s\n' "$_files" | while IFS= read -r _f; do
    [ -f "$_f" ] || continue
    _rule "$_f"
done | sed '/^$/d' | sed "s|$ROOT/||")
if [ -z "$_viol" ]; then
    ok "в боевом коде время файла берётся через date -r раньше stat"
else
    printf '%s\n' "$_viol" | head -5 | sed 's/^/   /'
    bad "время файла берётся через stat без date -r впереди — на busybox вернётся пусто"
fi

# --- 8. контроль на само правило ----------------------------------------------
# Сторож, который не умеет краснеть, охраняет только спокойствие автора. Сторож,
# который кричит на исправный код, перестаёт читаться. Проверяем оба конца.
_bait() { printf '#!/bin/sh\n_m() { %s; }\n' "$1" > "$TMP/bait.sh"; _rule "$TMP/bait.sh"; }

_missed=""
for _b in 'stat -c %Y "$1"' 'stat -c%Y "$1"' 'stat -c "%Y" "$1"' \
          'stat --format=%Y "$1"' 'stat -c %y "$1"'; do
    [ -z "$(_bait "$_b")" ] && _missed="$_missed
   $_b"
done
if [ -z "$_missed" ]; then
    ok "правило ловит все формы записи, не только -c %Y"
else
    printf '%s\n' "$_missed" | sed '/^$/d'
    bad "правило не ловит формы выше — их можно внести и не заметить"
fi

_false=""
for _b in 'date -r "$1" +%s 2>/dev/null || stat -c %Y "$1"' 'stat -c %a "$1"'; do
    [ -n "$(_bait "$_b")" ] && _false="$_false
   $_b"
done
if [ -z "$_false" ]; then
    ok "правило молчит на исправной цепочке и на stat -c %a — это права, не время"
else
    printf '%s\n' "$_false" | sed '/^$/d'
    bad "правило краснеет на исправном коде — такого сторожа перестанут читать"
fi

printf '\nPASSED: %s\nFAILED: %s\nSKIPPED: %s\n' "$PASS" "$FAIL" "$SKIP"
[ "$FAIL" = 0 ]
