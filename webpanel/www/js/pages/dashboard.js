import { apiGet, apiPost, toastErr } from "../core/api.js";
import { $app, escapeHtml, skeletonBlocks } from "../core/dom.js";
import { refreshStatus } from "../core/loadorder.js";
import { toast } from "../core/toast.js";
import { JOB_FAIL, _updateGlobalUILock, awaitPanelBack, confirmTypedModal, jobOutcome, jobUnresolved, openJobModal, unresolvedMsg } from "../job.js";
import { renderStatsNotice } from "./telemetry.js";
import { refreshUpdateBanner } from "./update.js";

export async function renderDashboard() {
  $app.innerHTML = `
    <div id="update-banner" hidden></div>
    <div id="stats-notice" hidden></div>
    <h1 class="page-title">Дашборд</h1>
    <div class="card" id="status-card">
      <h3>Состояние</h3>
      <div class="status-grid" id="status-grid">${skeletonBlocks(7)}</div>
    </div>
    <div class="card">
      <h3>Управление сервисом</h3>
      <p class="desc">Запуск, остановка и перезапуск nfqws2.</p>
      <div class="btn-row">
        <button class="btn btn-primary" data-svc="start" data-target="active">Запустить</button>
        <button class="btn" data-svc="restart" data-target="active">Перезапустить</button>
        <button class="btn btn-danger" data-svc="stop" data-target="stopped">Остановить</button>
      </div>
    </div>
    <!-- Обрыв на 16 КБ живёт отдельной системой: проба линии по опорным
         адресам, карта «сеть → имя», подстановка имени. В ротацию стратегий
         он не входит, поэтому и карточка своя, а не строка в состоянии. -->
    <div class="card" id="tcp16-card">
      <h3>Обрыв на 16 КБ</h3>
      <p class="desc">
        Блокировка, при которой сайт открывается, а страница обрывается на
        первых 15–16 КБ. Перебор стратегий её не лечит — z2k проверяет линию
        по опорным адресам и подбирает каждой сети с обрывом своё имя.
        Проверка идёт сама каждую ночь; здесь её можно запустить сейчас.
      </p>
      <div class="status-grid" id="tcp16-grid">${skeletonBlocks(3)}</div>
      <div class="btn-row">
        <button class="btn btn-primary" id="tcp16-probe-btn">Пробить 16 КБ</button>
      </div>
    </div>
    <!-- ОТДЕЛЬНАЯ КАРТОЧКА, А НЕ ЧЕТВЁРТАЯ КНОПКА В РЯДУ ВЫШЕ.
         «Остановить» обратимо и делается каждый день; удаление необратимо и
         делается один раз. В одном ряду они получили бы одинаковый вес и
         отличались бы только подписью — так и промахиваются. -->
    <div class="card card-danger" id="uninstall-card">
      <h3>Удаление z2k</h3>
      <p class="desc">
        Снимает z2k с роутера полностью: сервис, правила обхода, настройки,
        подобранные стратегии и саму эту панель. Отмены нет — вернуть можно
        только установкой заново, с нуля.
      </p>
      <div class="btn-row">
        <button class="btn btn-danger" id="uninstall-btn">Удалить z2k</button>
      </div>
    </div>
  `;

  // querySelectorAll().forEach, а не querySelector().addEventListener — тем же
  // приёмом, что и обработчик [data-svc] выше. Пустая выборка просто ничего не
  // делает, а обращение к .addEventListener у null роняет весь рендер
  // страницы: дашборд собирается одной строкой innerHTML, и любой сторонний
  // рендер этой же разметки (тестовый харнесс, будущая подстраница) уронил бы
  // не кнопку, а экран целиком.
  $app.querySelectorAll("#uninstall-btn").forEach(btn => btn.addEventListener("click", async () => {
    const ok = await confirmTypedModal(
      "Удалить z2k с роутера",
      [
        "Будут удалены: служба обхода и её автозапуск, все правила iptables, " +
          "настройки, списки доменов и подобранные для них стратегии.",
        "Вместе с ними исчезнет и эта панель — страница перестанет отвечать " +
          "примерно на середине, и это нормальный конец, а не сбой.",
        "Интернет продолжит работать, но уже без обхода блокировок.",
      ],
      "УДАЛИТЬ",
      "Удалить z2k"
    );
    if (!ok) return;
    let resp;
    try {
      resp = await apiPost("/uninstall", { confirm: "УДАЛИТЬ" });
    } catch (e) {
      toastErr("Не удалось запустить удаление: ", e);
      return;
    }
    openJobModal("Удаление z2k", resp.job, {
      tolerateOutage: true,
      // Панель входит в удаляемое и обратно не поднимется. Без этого флага
      // опрос честно ждал бы её возвращения десять минут и всё это время
      // писал «ждём…» — про сервер, которого больше нет.
      expectGone: true,
    });
  }));

  refreshTcp16();
  $app.querySelectorAll("#tcp16-probe-btn").forEach(btn => btn.addEventListener("click", async () => {
    if (btn.disabled) return;
    btn.disabled = true;
    let resp;
    try {
      resp = await apiPost("/tcp16/probe");
    } catch (e) {
      btn.disabled = false;
      toastErr("Не удалось запустить пробу: ", e);
      return;
    }
    btn.disabled = false;
    openJobModal("Проба линии на обрыв 16 КБ", resp.job, {
      // Если ответ пробы сменил картину, она пересобирает конфиг и
      // перезапускает сервис — короткий обрыв панели тут штатный.
      tolerateOutage: true,
      onDone: (d) => {
        const outcome = jobOutcome(d);
        if (outcome === JOB_FAIL) toast("Проба не завершилась — подробности в журнале выше", "bad");
        // Проба могла перезапустить сервис; дождаться панели, потом читать.
        if (jobUnresolved(outcome)) awaitPanelBack().then(() => { refreshTcp16(); refreshStatus(); });
        else setTimeout(() => { refreshTcp16(); refreshStatus(); }, 500);
      },
    });
  }));

  $app.querySelectorAll("[data-svc]").forEach(btn => {
    btn.addEventListener("click", async () => {
      if (btn.disabled) return;
      const action = btn.dataset.svc;
      const titleByAction = { start: "Запуск сервиса", stop: "Остановка сервиса", restart: "Перезапуск сервиса" };
      const title = titleByAction[action] || ("Действие: " + action);
      // Глобальный лок включается только когда придёт id задачи, а до тех
      // пор кнопка кликабельна: второй клик по «Перезапустить» запускал
      // второй конкурентный S99zapret2 restart.
      btn.disabled = true;
      let resp;
      try {
        resp = await apiPost("/service/" + action);
      } catch (e) {
        btn.disabled = false;
        toastErr("Ошибка запуска: ", e);
        return;
      }
      // Кнопку возвращаем в исходное состояние ДО openJobModal: лок
      // запоминает текущее disabled как «правильное» и после задачи вернул
      // бы её навсегда выключенной.
      btn.disabled = false;
      // Backend теперь async — возвращает {ok, job:<id>}. Открываем
      // модалку с live-логом точно как при auto-update apply. После
      // завершения refreshStatus подтянет grid вверху.
      openJobModal(title, resp.job, {
        // Старт/стоп/рестарт бьют по тому же iptables, через который открыта
        // панель — короткий обрыв здесь штатный, а не отказ команды.
        tolerateOutage: true,
        onDone: (d) => {
          const outcome = jobOutcome(d);
          if (outcome === JOB_FAIL) {
            toast("Команда завершилась с кодом " + d.exit, "bad");
          } else {
            const m = unresolvedMsg(outcome);
            if (m) toast(m, "bad");
          }
          if (jobUnresolved(outcome)) awaitPanelBack().then(() => refreshStatus());
          else setTimeout(refreshStatus, 500);
        },
      });
    });
  });

  refreshStatus();
  refreshUpdateBanner();
  renderStatsNotice();
  _updateGlobalUILock();
}

// Карточка «Обрыв на 16 КБ»: состояние из файлов пробы, а не из конфига.
// Три плитки: вердикт (с давностью), сколько сетей с обрывом и сколько имён
// подобрано, и доехал ли механизм до конфига — расхождение флага и конфига
// и есть самая частая его болезнь, человеку её надо видеть.
export function tcp16Cells(t) {
  const ago = (s) => {
    if (s == null) return "";
    if (s < 3600) return ` · ${Math.max(1, Math.floor(s / 60))} мин назад`;
    if (s < 86400) return ` · ${Math.floor(s / 3600)} ч назад`;
    return ` · ${Math.floor(s / 86400)} дн назад`;
  };
  let verdict, vkind;
  if (t.running) { verdict = "проверяется…"; vkind = ""; }
  else if (t.measured === "1") { verdict = "блок есть" + ago(t.age); vkind = "warn"; }
  else if (t.measured === "0") { verdict = "блока нет" + ago(t.age); vkind = "good"; }
  else { verdict = "не измерялась"; vkind = ""; }
  const cells = [
    { label: "Проба линии", value: verdict, kind: vkind },
    { label: "Сети с обрывом", value: t.measured === "1" ? `${t.nets_blocked} · имён ${t.names}` : "—", kind: "" },
  ];
  if (t.measured === "1") {
    // Блок найден — механизм обязан быть в конфиге; иначе это расхождение.
    cells.push({ label: "Обход в конфиге", value: t.in_config ? "включён" : "НЕТ", kind: t.in_config ? "good" : "bad" });
  } else {
    cells.push({ label: "Обход в конфиге", value: t.in_config ? "включён" : "не нужен", kind: "" });
  }
  return cells;
}

async function refreshTcp16() {
  const grid = document.getElementById("tcp16-grid");
  if (!grid) return;
  let t;
  try {
    t = await apiGet("/tcp16");
  } catch (e) {
    grid.innerHTML = `<div class="status-cell bad"><div class="label">Проба линии</div><div class="value">недоступна</div></div>`;
    return;
  }
  grid.innerHTML = tcp16Cells(t).map(c =>
    `<div class="status-cell ${c.kind}"><div class="label">${c.label}</div><div class="value">${escapeHtml(c.value)}</div></div>`
  ).join("");
  const btn = document.getElementById("tcp16-probe-btn");
  if (btn) btn.disabled = !!t.running;
}
