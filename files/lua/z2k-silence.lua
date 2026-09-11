-- z2k-silence.lua — детектор «сервер молчит».
--
-- Грузится ПОСЛЕ zapret-auto.lua: нужны standard_failure_detector,
-- automate_host_record, automate_failure_counter.

-- Порог молчания в секундах: сколько ждать ответа сервера, прежде чем считать
-- стратегию провалившейся. 0 выключает детектор.
local function silence_seconds(desync)
    local v = tonumber(desync.arg.silence)
    if v == nil then return 5 end
    return v
end

-- Сколько байт ответа считать состоявшимся обменом. Тот же порог, что у
-- штатного детектора удачи (inseq): «сервер прислал больше — соединение
-- рабочее». Ниже него ответ мог начаться и встать, а это тоже блокировка.
local function success_bytes(desync)
    return tonumber(desync.arg.inseq) or 4096
end

local timer_seq = 0
local timers_active = 0

-- Потолок одновременных таймеров: на роутере с 500 МБ очередь ожиданий не
-- должна расти неограниченно. Загруженная страница к заблокированному домену
-- открывает десятки молчащих соединений разом.
local function timers_ceiling()
    return Z2K_SILENCE_MAX or 512
end

-- RST клиенту от имени сервера — ровно как у штатного детектора при
-- ретрансмиссиях. Готовим заранее: в момент срабатывания таймера пакета уже
-- нет, а клиент с тех пор ничего не слал, значит seq и ack ещё верны.
local function rst_for(desync)
    local dis = deepcopy(desync.dis)
    dis.payload = nil
    dis_reverse(dis)
    dis.tcp.th_flags = TH_RST
    dis.tcp.th_win = desync.track and desync.track.pos.reverse.tcp.winsize or 64
    dis.tcp.options = nil
    if dis.ip6 then
        dis.ip6.ip6_flow = (desync.track and desync.track.pos.reverse.ip6_flow)
            and desync.track.pos.reverse.ip6_flow or 0x60000000
    end
    return dis
end

function z2k_silence_fire(name, d)
    local crec, hrec = d.crec, d.hrec
    timers_active = timers_active - 1
    crec.z2k_sil = nil

    if crec.z2k_answered then return end

    -- СЛЕПОЕ НАПРАВЛЕНИЕ — НЕ ПОВОД РОТИРОВАТЬ.
    --
    -- Об ответе сервера детектор узнаёт только из вызовов на входящих пакетах:
    -- счётчики conntrack в Lua — снимок на момент пакета (lua.c,
    -- lua_pushf_ctrack_pos), сохранённая таблица в таймере показывает нули.
    -- Если у circular стоит фильтр по типу payload или входящие не заведены в
    -- очередь, входящих вызовов не будет вовсе — и «ответа не было» станет
    -- неправдой: стенд 11.09.2026 в такой конфигурации выдал отвечающему
    -- серверу два провала и ротацию. Судим, только когда обратное направление
    -- действительно видим. Наш класс блока этому не мешает: сервер
    -- подтверждает запрос, и хотя бы голый ACK через детектор проходит.
    if not crec.z2k_in_seen then
        DLOG("z2k_fail_silence: входящих пакетов не видно — не сужу")
        return
    end

    -- ПРОВАЛ ЗАСЧИТЫВАЕТСЯ ТОЙ СТРАТЕГИИ, НА КОТОРОЙ СОЕДИНЕНИЕ НАЧАЛОСЬ.
    -- Страница открывает десятки соединений разом; если стратегию уже
    -- сдвинуло соседнее, провалы остальных относятся к прошлой и считать их
    -- нельзя — иначе одно молчание пролистывает пул насквозь (замер
    -- 19.08.2026: instagram.com прошёл двенадцать плеч за секунду).
    if hrec.nstrategy ~= d.strategy then return end
    -- Закреплённую человеком стратегию не трогаем, как и circular.
    if hrec.final == hrec.nstrategy then return end
    -- Число плеч кладёт circular. Нет его — двигать некуда; выходим молча,
    -- потому что упавшая таймер-функция удаляется движком навсегда.
    if not hrec.ctstrategy or hrec.ctstrategy < 1 then return end

    -- МОЛЧАНИЯ СЧИТАЮТСЯ ОТДЕЛЬНО ОТ ШТАТНОГО СЧЁТЧИКА.
    --
    -- Штатный счётчик провалов хоста обнуляет ЛЮБОЙ успех
    -- (automate_failure_counter_reset). Для домена, часть соединений которого
    -- работает, это значит «не ротировать никогда»: замер 11.09.2026 на
    -- стенде — 8 соединений, 4 молчания, 4 успеха, 0 ротаций, стратегия стоит.
    -- Так выглядит крупный сайт за CDN: мелочь отдаётся, основной ресурс
    -- режется, человек видит «полуработает».
    --
    -- Успех соседнего соединения не отменяет того, что ЭТОТ путь не работает,
    -- поэтому свой счётчик гаснет только временем — тем же окном time, что и
    -- штатный. Штатный при этом тоже кормим: если провалы набежали по обоим
    -- признакам, ротация случится по тому, кто первый дошёл до порога.
    local now = os.time()
    if hrec.z2k_sil_last and now > (hrec.z2k_sil_last + d.maxtime) then
        hrec.z2k_sil_count = nil
    end
    hrec.z2k_sil_count = (hrec.z2k_sil_count or 0) + 1
    hrec.z2k_sil_last = now

    local rotate = automate_failure_counter(hrec, crec, d.fails, d.maxtime)
    if not rotate and hrec.z2k_sil_count >= d.fails then rotate = true end

    if rotate then
        hrec.z2k_sil_count = nil
        hrec.nstrategy = (hrec.nstrategy % hrec.ctstrategy) + 1
        DLOG("z2k_fail_silence: сервер молчит — стратегия " .. hrec.nstrategy)
    end

    -- Рвём соединение, чтобы клиент не досиживал свой таймаут в десятки
    -- секунд, а переоткрыл сразу: одиночный клиент иначе до порога провалов
    -- не дойдёт вовсе, а браузер откроет следующее соединение уже на
    -- сдвинутой стратегии.
    if d.rst then
        DLOG("z2k_fail_silence: рву молчащее соединение")
        rawsend_dissect(d.rst, { ifout = d.ifout })
    end
end

function z2k_fail_silence(desync, crec)
    if standard_failure_detector(desync, crec) then return true end

    local secs = silence_seconds(desync)
    if secs <= 0 then return false end
    -- ТОЛЬКО TCP. У UDP-пулов провал считается штатно и иначе («отослано N,
    -- принято не более M»), а молчание между пачками там обычное дело.
    if not desync.dis.tcp then return false end

    -- ВХОДЯЩИЕ: отмечаем, что они до нас доходят, и считаем объём ответа.
    --
    -- Голый ACK ответом не считается: это и есть картина блока — запрос до
    -- сервера дошёл, он его подтвердил, а ответ вырезан на обратном пути.
    --
    -- Данные ожидание ПРОДЛЕВАЮТ, но не отменяют: часть блокировок пропускает
    -- начало ответа и режет поток дальше (стенд 11.09.2026), и тогда «ответ
    -- был» означало бы «провала не будет никогда». Отменяем ожидание, только
    -- когда обмен состоялся: получено больше порога удачи или сервер сам
    -- закрыл соединение.
    if not desync.outgoing then
        crec.z2k_in_seen = true
        local n = desync.dis.payload and #desync.dis.payload or 0
        local fin = desync.dis.tcp and bitand(desync.dis.tcp.th_flags or 0, TH_FIN) ~= 0
        if crec.z2k_sil then
            if fin then
                crec.z2k_answered = true
                timer_del(crec.z2k_sil)
                timers_active = timers_active - 1
                crec.z2k_sil = nil
            elseif n > 0 then
                crec.z2k_in_bytes = (crec.z2k_in_bytes or 0) + n
                if crec.z2k_in_bytes >= success_bytes(desync) then
                    crec.z2k_answered = true
                    timer_del(crec.z2k_sil)
                    timers_active = timers_active - 1
                    crec.z2k_sil = nil
                else
                    -- Тот же таймер с тем же именем: движок заменяет его и
                    -- начинает отсчёт заново (мануал, timer_set).
                    timer_set(crec.z2k_sil, z2k_silence_fire, silence_seconds(desync) * 1000,
                              true, crec.z2k_sil_data)
                end
            end
        end
        return false
    end

    if not desync.dis.payload or #desync.dis.payload == 0 then return false end
    if crec.z2k_sil then return false end

    local hrec = automate_host_record(desync)
    if not hrec then return false end
    if timers_active >= timers_ceiling() then
        DLOG("z2k_fail_silence: потолок таймеров, пропускаю")
        return false
    end

    timer_seq = timer_seq + 1
    local name = "z2k_sil_" .. timer_seq
    crec.z2k_sil = name
    timers_active = timers_active + 1
    crec.z2k_sil_data = {
        crec = crec,
        hrec = hrec,
        strategy = hrec.nstrategy,
        fails = tonumber(desync.arg.fails) or 3,
        maxtime = tonumber(desync.arg.time) or 60,
        rst = desync.arg.reset and rst_for(desync) or nil,
        ifout = desync.ifin,
    }
    timer_set(name, z2k_silence_fire, secs * 1000, true, crec.z2k_sil_data)
    return false
end
