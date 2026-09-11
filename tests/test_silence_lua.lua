-- tests/test_silence_lua.lua
-- Юнит-тесты детектора «сервер молчит» (files/lua/z2k-silence.lua).
--
-- Запуск: lua tests/test_silence_lua.lua
--
-- ЗАЧЕМ ЭТОТ ДЕТЕКТОР. Штатные признаки провала в zapret2 все активные:
-- ретрансмиссия исходящего запроса, входящий RST, HTTP-редирект. Замер на
-- линии владельца 11.09.2026 (x.com, instagram, discord): DPI пропускает
-- ClientHello до сервера, сервер подтверждает ВСЕ байты и замолкает навсегда.
-- Клиенту ретрансмитить нечего — его данные приняты, — RST не приходит,
-- редиректа нет. Штатный детектор слеп по построению, ротация стоит на первой
-- стратегии вечно, человек видит ERR_TIMED_OUT. Мануал zapret2 прямо называет
-- таймеры средством «для обработки ситуаций отсутствия реакции из сети».
--
-- Здесь сторожится вся механика: постановка таймера, отметка ответа,
-- засчёт провала, сдвиг стратегии и защиты от ложных и лавинных ротаций.

local PASS, FAIL = 0, 0
local function ok(m) PASS = PASS + 1; print("[PASS] " .. m) end
local function no(m, want, got)
    FAIL = FAIL + 1
    print(string.format("[FAIL] %s (want=%s got=%s)", m, tostring(want), tostring(got)))
end
local function is(m, want, got) if want == got then ok(m) else no(m, want, got) end end

-- ----- заглушки движка -------------------------------------------------------
function DLOG() end
b_debug = false
TH_RST = 0x04

-- Штатный детектор: по умолчанию молчит, тест подменяет при необходимости.
STD_VERDICT = false
function standard_failure_detector() return STD_VERDICT end

-- Позиция в потоке: 's' — байтовая позиция текущего пакета.
function pos_get(desync, what)
    if what == 's' then return desync._s or 1 end
    return 0
end

-- Запись хоста: та же таблица, что получает circular (общий autostate).
HREC = nil
function automate_host_record() return HREC end

-- Счётчик провалов апстрима: мок считает вызовы и отдаёт заранее заданный ответ.
COUNTER_CALLS, COUNTER_VERDICT = 0, false
function automate_failure_counter(hrec, crec, fails, maxtime)
    COUNTER_CALLS = COUNTER_CALLS + 1
    LAST_COUNTER = { hrec = hrec, crec = crec, fails = fails, maxtime = maxtime }
    return COUNTER_VERDICT
end

TIMERS = {}
function timer_set(name, func, period, oneshot, data)
    TIMERS[name] = { func = func, period = period, oneshot = oneshot, data = data }
end
function timer_del(name) TIMERS[name] = nil end

SENT = {}
function rawsend_dissect(dis, opts) SENT[#SENT + 1] = { dis = dis, opts = opts } end
function dis_reverse(dis) dis.reversed = true end
-- Счётчики conntrack в Lua — СНИМОК на момент пакета (lua.c:
-- lua_pushf_ctrack_pos создаёт новую таблицу), а не живая ссылка. Проверено
-- на стенде 11.09.2026: сохранённая таблица в таймере показывает нули, когда
-- сервер уже ответил. Поэтому состояние соединения детектор ведёт сам, в
-- записи соединения.
function deepcopy(t)
    if type(t) ~= "table" then return t end
    local c = {}
    for k, v in pairs(t) do c[k] = deepcopy(v) end
    return c
end

-- Модуль перечитывается на каждый сценарий: у него есть своё состояние
-- (счётчик живых таймеров), и без перезагрузки тесты тянули бы хвост друг за
-- другом — потолок срабатывал бы не там, где его проверяют.
local function reset_state()
    TIMERS, SENT = {}, {}
    COUNTER_CALLS, COUNTER_VERDICT, LAST_COUNTER = 0, false, nil
    STD_VERDICT = false
    HREC = { nstrategy = 1, ctstrategy = 5 }
    dofile("files/lua/z2k-silence.lua")
end

-- Исходящий пакет с данными на позиции pos (по умолчанию первый байт потока).
local function out_req(pos)
    return {
        outgoing = true, ifin = "br0",
        dis = { tcp = { th_flags = 0x18 }, payload = string.rep("x", 300) },
        track = { pos = { reverse = { pdcounter = 0, tcp = { winsize = 64 } } } },
        arg = { key = "rkn_tcp", nld = "2", fails = "3", time = "60" },
        _s = pos or 1,
    }
end

-- Входящий пакет: data=true — с полезной нагрузкой, иначе голый ACK.
local function in_pkt(data)
    return {
        outgoing = false,
        dis = { tcp = {}, payload = data and string.rep("y", 100) or "" },
        track = {}, arg = { key = "rkn_tcp" }, _s = 1,
    }
end

local function fire_one()
    for name, t in pairs(TIMERS) do
        TIMERS[name] = nil          -- однократный таймер движок удаляет сам
        t.func(name, t.data)
    end
end
-- Обычный порядок: запрос, затем подтверждение сервера (голый ACK). До
-- запроса имени хоста ещё нет, и ротатор до детектора не доходит вовсе —
-- поэтому входящие вызовы бывают только ПОСЛЕ запроса.
local function arm(crec, d)
    local r = z2k_fail_silence(d or out_req(), crec)
    z2k_fail_silence(in_pkt(false), crec)
    return r
end
local function count_timers()
    local n = 0
    for _ in pairs(TIMERS) do n = n + 1 end
    return n
end

-- ----- 1. штатные признаки не теряются --------------------------------------
--
-- Детектор подменяет собой standard_failure_detector, а не дополняет его в
-- конфиге: у circular одна ручка failure_detector. Значит первым делом он
-- обязан спросить штатный, иначе ретрансмиссии, входящий RST и DPI-редирект
-- перестанут ротировать вовсе.
do
    reset_state()
    STD_VERDICT = true
    is("штатный провал остаётся провалом", true, z2k_fail_silence(out_req(), {}))
    reset_state()
    is("без штатного провала сам по себе провала не объявляет", false, z2k_fail_silence(out_req(), {}))
end

-- ----- 2. таймер на первый запрос -------------------------------------------
do
    reset_state()
    local crec = {}
    arm(crec)
    local n = 0
    for _ in pairs(TIMERS) do n = n + 1 end
    is("на первый исходящий запрос ставится таймер", 1, n)
    for _, t in pairs(TIMERS) do
        is("таймер однократный", true, t.oneshot)
        is("порог по умолчанию — 5 секунд", 5000, t.period)
    end

    -- Второй пакет того же соединения (продолжение запроса или ретрансмиссия)
    -- не должен плодить таймеры: иначе на одно молчание придётся столько
    -- провалов, сколько пакетов успел послать клиент.
    z2k_fail_silence(out_req(1301), crec)
    z2k_fail_silence(out_req(), crec)
    n = 0
    for _ in pairs(TIMERS) do n = n + 1 end
    is("на соединение таймер ровно один", 1, n)
end

-- ----- 3. порог настраивается ------------------------------------------------
do
    reset_state()
    local d = out_req(); d.arg.silence = "2"
    arm({}, d)
    for _, t in pairs(TIMERS) do is("silence=2 даёт таймер на 2 секунды", 2000, t.period) end

    reset_state()
    d = out_req(); d.arg.silence = "0"
    arm({}, d)
    local n = 0
    for _ in pairs(TIMERS) do n = n + 1 end
    is("silence=0 выключает детектор", 0, n)
end

-- ----- 4. срабатывание таймера: молчание — провал, ответ — нет ---------------
--
-- Ответом считаются только ДАННЫЕ сервера. Голый ACK — это и есть картина
-- блокировки: DPI пропустил запрос, сервер его подтвердил, а ServerHello
-- вырезан на обратном пути. Считать ACK ответом значило бы не увидеть блок.
do
    reset_state()
    local crec = {}
    arm(crec)
    z2k_fail_silence(in_pkt(true), crec)
    fire_one()
    is("сервер ответил данными — провала нет", 0, COUNTER_CALLS)

    reset_state()
    crec = {}
    arm(crec)
    z2k_fail_silence(in_pkt(false), crec)
    fire_one()
    is("голый ACK ответом не считается — провал засчитан", 1, COUNTER_CALLS)

    reset_state()
    crec = {}
    arm(crec)
    fire_one()
    is("тишина — провал засчитан", 1, COUNTER_CALLS)
    is("провал считается той же записью хоста, что у circular", HREC, LAST_COUNTER.hrec)
    -- crec передаётся, чтобы апстримная защита «дубль в одном соединении»
    -- работала и против нас: штатный детектор и таймер не должны дать два
    -- провала на одно соединение.
    is("провал привязан к соединению", crec, LAST_COUNTER.crec)
    is("порог провалов взят из аргументов", 3, LAST_COUNTER.fails)
    is("окно счётчика взято из аргументов", 60, LAST_COUNTER.maxtime)
end

-- ----- 5. ротация и защиты от ложных сдвигов ---------------------------------
--
-- Лавина — не гипотеза: 19.08.2026 на нерабочей стратегии instagram.com за
-- ОДНУ секунду пролистал двенадцать плеч. Страница открывает десятки
-- соединений разом, все они молчат, и каждое несёт свой провал уже после
-- того, как ротация случилась. Поэтому соединение помнит, на какой стратегии
-- началось, и провал засчитывается, только если она всё ещё текущая.
do
    reset_state(); COUNTER_VERDICT = true
    local crec = {}
    arm(crec)
    fire_one()
    is("набрались провалы — стратегия сдвигается на следующую", 2, HREC.nstrategy)

    reset_state(); COUNTER_VERDICT = true; HREC.nstrategy = 5
    crec = {}
    arm(crec)
    fire_one()
    is("с последней стратегии ротация идёт по кругу на первую", 1, HREC.nstrategy)

    reset_state(); COUNTER_VERDICT = true
    crec = {}
    arm(crec)
    HREC.nstrategy = 2   -- ротация уже случилась по соседнему соединению
    fire_one()
    is("провал соединения с прежней стратегии не считается", 0, COUNTER_CALLS)
    is("и стратегию второй раз не двигает", 2, HREC.nstrategy)

    -- Закреплённая человеком стратегия (freeze в панели) — final. Её не трогаем.
    reset_state(); COUNTER_VERDICT = true; HREC.final = 1
    crec = {}
    arm(crec)
    fire_one()
    is("закреплённую стратегию молчание не сдвигает", 1, HREC.nstrategy)
    is("и счётчик провалов на ней не копится", 0, COUNTER_CALLS)

    -- Число плеч в запись хоста кладёт circular. Если его там ещё нет,
    -- двигать некуда: молча выходим, а не падаем с ошибкой — упавшая
    -- таймер-функция удаляется движком навсегда, и детектор умер бы весь.
    reset_state(); COUNTER_VERDICT = true; HREC.ctstrategy = nil
    crec = {}
    arm(crec)
    local fired_ok = pcall(fire_one)
    is("без числа плеч таймер не падает", true, fired_ok)
    is("и стратегию не трогает", 1, HREC.nstrategy)
end

-- ----- 6. RST клиенту: не ждать таймаута браузера ---------------------------
--
-- Без него одиночный клиент (curl, приложение) до порога провалов не дойдёт:
-- он висит на своём таймауте в десятки секунд и второго соединения не делает.
-- Шлём ровно как штатный детектор при ретрансмиссиях: развёрнутый диссект без
-- payload с флагом RST, на тот интерфейс, откуда пришёл запрос.
do
    reset_state(); COUNTER_VERDICT = false
    local crec = {}
    local d = out_req(); d.arg.reset = true
    arm(crec, d)
    fire_one()
    is("при reset клиенту уходит один пакет", 1, #SENT)
    if SENT[1] then
        is("это RST", TH_RST, SENT[1].dis.tcp.th_flags)
        is("адреса развёрнуты — пакет идёт клиенту", true, SENT[1].dis.reversed)
        is("без полезной нагрузки", nil, SENT[1].dis.payload)
        is("на интерфейс, откуда пришёл запрос", "br0", SENT[1].opts.ifout)
    end

    reset_state()
    crec = {}
    arm(crec)                              -- reset не задан
    fire_one()
    is("без reset соединение не рвём", 0, #SENT)

    reset_state()
    crec = {}
    d = out_req(); d.arg.reset = true
    arm(crec, d)
    z2k_fail_silence(in_pkt(true), crec)  -- сервер ответил
    fire_one()
    is("ответившему серверу RST не шлём", 0, #SENT)
end

-- ----- 7. потолок одновременных таймеров ------------------------------------
--
-- Таймеры живут в памяти демона на роутере с 500 МБ. Пул TLS-соединений на
-- загруженной странице — десятки, при заблокированном домене все молчат.
-- Потолок не даёт очереди таймеров расти неограниченно.
do
    reset_state()
    Z2K_SILENCE_MAX = 2
    arm({}); arm({}); arm({})
    is("сверх потолка таймеры не ставятся", 2, count_timers())
    fire_one()
    arm({})
    is("сработавший таймер освобождает место", 1, count_timers())
    Z2K_SILENCE_MAX = nil
end

-- ----- 8. только TCP ---------------------------------------------------------
--
-- У UDP-пулов (QUIC, discord) провал считается иначе и штатно: «отослано N,
-- принято не более M». Молчание там — обычное дело между пачками, и таймер
-- ротировал бы рабочие плечи. Детектор обязан молчать на UDP, даже если его
-- по ошибке повесят на такой профиль.
do
    reset_state()
    local d = {
        outgoing = true, ifin = "br0",
        dis = { udp = {}, payload = string.rep("q", 1200) },
        track = {}, arg = { key = "yt_quic" }, _s = 1,
    }
    is("на UDP провала не объявляет", false, z2k_fail_silence(d, {}))
    is("и таймер не ставит", 0, count_timers())
end

-- ----- 9. слепое направление — не повод ротировать ---------------------------
--
-- Об ответе сервера детектор узнаёт только из вызовов на входящих пакетах:
-- счётчики conntrack в Lua — снимок на момент пакета (lua.c,
-- lua_pushf_ctrack_pos), сохранённая таблица в таймере показывает нули.
-- Если у circular стоит фильтр по типу payload или входящие не заведены в
-- очередь, входящих вызовов не будет вовсе — и «ответа не было» станет
-- неправдой: стенд 11.09.2026 в такой конфигурации выдал отвечающему серверу
-- два провала и ротацию. Значит судить можно, только если обратное
-- направление мы видим: хотя бы один входящий пакет через детектор прошёл.
do
    reset_state()
    local crec = {}
    z2k_fail_silence(out_req(), crec)      -- запрос ушёл, входящих вызовов нет
    fire_one()
    is("обратное направление не видно — провала нет", 0, COUNTER_CALLS)

    reset_state()
    crec = {}
    arm(crec)                              -- запрос, следом голый ACK сервера
    fire_one()
    is("подтверждение без данных — провал", 1, COUNTER_CALLS)
end

printf = nil
print(string.format("\nPASSED: %d\nFAILED: %d", PASS, FAIL))
os.exit(FAIL == 0 and 0 or 1)
