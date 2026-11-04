// Модуль 1. Интерфейс проверки пароля и генератора.

import { checkLeak, assessStrength, ruPlural } from './password.js';
import { POLICIES, getPolicy, evaluatePolicy } from './policies.js';
import { generatePassword, poolSize, estimateEntropyBits } from './generator.js';
import { recommend, RULES_PASSWORD } from './recommendations.js';
import { setResult, state } from './state.js';
import { $, el, badge, fmtNum, recoList } from './ui-common.js';

// ---------- Индикатор стойкости (работает на каждое нажатие, всё локально) ----------
let meterTimer = null;

function updateMeter() {
  const pwd = $('pwd').value;
  const meter = $('meter');
  if (!pwd) {
    meter.dataset.score = '';
    $('meter-label').textContent = 'Введите пароль';
    $('meter-detail').textContent = '';
    return;
  }
  try {
    const s = assessStrength(pwd);
    meter.dataset.score = String(s.score);
    $('meter-label').textContent = s.label;
    $('meter-detail').textContent = `— подбор по украденному хешу: ${s.offline.display}`;
  } catch (e) {
    meter.dataset.score = '';
    $('meter-label').textContent = 'Оценка недоступна';
    $('meter-detail').textContent = e.message;
  }
}

// ---------- Отрисовка результатов ----------
function renderLeak(leak) {
  const box = $('res-leak');
  box.replaceChildren();
  let head;
  if (leak.status === 'found') head = badge('bad', 'Найден в утечках');
  else if (leak.status === 'clean') head = badge('ok', 'В утечках не найден');
  else head = badge('warn', 'Не проверено');
  box.append(el('h3', {}, 'Проверка по базе утечек ', head));

  if (leak.status === 'found') {
    box.append(el('p', { class: 'result-line' }, `Этот пароль встречался в утечках данных ${fmtNum(leak.count)} ${ruPlural(leak.count, 'раз', 'раза', 'раз')}. Его нельзя считать безопасным.`));
  } else if (leak.status === 'clean') {
    box.append(el('p', { class: 'result-line' }, 'Пароль не найден в известных утечках. Это не гарантирует надёжность: оценка стойкости ниже тоже важна.'));
  } else {
    box.append(el('p', { class: 'result-line' }, leak.message || 'Проверка не удалась.'));
  }
  if (leak.prefix) {
    box.append(
      el('p', { class: 'hint' },
        'Наружу ушли только первые 5 символов SHA-1-хеша: ', el('span', { class: 'mono' }, leak.prefix),
        leak.returned ? `. Сервис вернул ${fmtNum(leak.returned)} ${ruPlural(leak.returned, 'хеш', 'хеша', 'хешей')} с таким началом, а совпадение с вашим мы искали у себя в браузере.` : '.')
    );
  }
}

function renderStrength(s) {
  const box = $('res-strength');
  box.replaceChildren();
  const kinds = ['bad', 'bad', 'warn', 'ok', 'ok'];
  box.append(el('h3', {}, 'Оценка стойкости ', badge(kinds[s.score], `${s.score} из 4 — ${s.label}`)));
  box.append(el('p', { class: 'result-line' }, 'Онлайн-подбор без защиты от перебора (10 попыток в секунду): ', el('strong', {}, s.online.display)));
  box.append(el('p', { class: 'result-line' }, 'Офлайн-подбор по украденному хешу (10 млрд попыток в секунду): ', el('strong', {}, s.offline.display)));
  if (s.warning) box.append(el('p', { class: 'result-line' }, el('strong', {}, 'Замечание: '), s.warning));
  if (s.suggestions.length) {
    box.append(el('ul', { class: 'sug-list' }, s.suggestions.map((t) => el('li', {}, t))));
  }
}

function renderPolicy(p) {
  const box = $('res-policy');
  box.replaceChildren();
  let head;
  if (p.passed) head = badge('ok', 'Соответствует');
  else if (p.unverified && p.results.every((r) => r.ok !== false)) head = badge('warn', 'Не подтверждено');
  else head = badge('bad', 'Не соответствует');
  box.append(el('h3', {}, `Политика «${p.name}» `, head));
  box.append(
    el('ul', { class: 'crit-list' },
      p.results.map((r) => {
        const mark = r.ok === true ? ['✓', 'ok'] : r.ok === false ? ['✗', 'bad'] : ['?', 'unk'];
        return el('li', {}, el('span', { class: `crit-mark ${mark[1]}`, 'aria-label': r.ok === true ? 'выполнено' : r.ok === false ? 'не выполнено' : 'не проверено' }, mark[0]), el('span', {}, r.label));
      })
    )
  );
}

function renderRecommendations() {
  const box = $('res-reco');
  box.replaceChildren();
  const list = recommend(state.results, RULES_PASSWORD);
  box.append(el('h3', {}, 'Рекомендации'));
  if (!list.length) {
    box.append(el('p', { class: 'hint' }, 'Пока нет рекомендаций.'));
    return;
  }
  box.append(recoList(list));
}

// ---------- Проверка пароля ----------
let lastPassword = '';
let lastStrength = null;
let lastLeak = null;
let checkToken = 0;

function buildPasswordResult() {
  const policy = evaluatePolicy(getPolicy($('policy').value), {
    password: lastPassword,
    length: [...lastPassword].length,
    score: lastStrength.score,
    leakCount: lastLeak.status === 'error' ? null : lastLeak.count,
  });
  setResult('password', {
    score: lastStrength.score,
    length: [...lastPassword].length,
    leakStatus: lastLeak.status,
    leakCount: lastLeak.status === 'error' ? null : lastLeak.count,
    policy,
  });
  return policy;
}

function renderPasswordResults() {
  const policy = buildPasswordResult();
  renderLeak(lastLeak);
  renderStrength(lastStrength);
  renderPolicy(policy);
  renderRecommendations();
  $('pwd-results').hidden = false;
}

async function runCheck() {
  const pwd = $('pwd').value;
  if (!pwd) {
    $('pwd').focus();
    return;
  }
  const btn = $('pwd-check');
  const token = ++checkToken;
  btn.disabled = true;
  btn.textContent = 'Проверяю…';
  try {
    const strength = assessStrength(pwd);
    const leak = await checkLeak(pwd);
    if (token !== checkToken) return; // пароль успели изменить, результат устарел
    lastPassword = pwd;
    lastStrength = strength;
    lastLeak = leak;
    renderPasswordResults();
    $('pwd-results').scrollIntoView({ behavior: 'smooth', block: 'nearest' });
  } catch (e) {
    $('pwd-results').hidden = false;
    $('res-leak').replaceChildren(el('p', { class: 'result-line' }, `Ошибка проверки: ${e.message}`));
    for (const id of ['res-strength', 'res-policy', 'res-reco']) $(id).replaceChildren();
  } finally {
    if (token === checkToken) {
      btn.disabled = false;
      btn.textContent = 'Проверить пароль';
    }
  }
}

export function initPassword() {
  const pwd = $('pwd');

  // политики
  const select = $('policy');
  POLICIES.forEach((p) => select.append(el('option', { value: p.id }, p.name)));
  const showPolicyDesc = () => ($('policy-desc').textContent = getPolicy(select.value).description);
  showPolicyDesc();
  select.addEventListener('change', () => {
    showPolicyDesc();
    if (lastStrength && lastLeak && !$('pwd-results').hidden) renderPasswordResults(); // без нового запроса в сеть
  });

  // ввод
  pwd.addEventListener('input', () => {
    clearTimeout(meterTimer);
    meterTimer = setTimeout(updateMeter, 120);
    checkToken++; // отменяем незавершённую проверку
    $('pwd-results').hidden = true; // результаты относились к прежнему паролю
    setResult('password', null);
    $('pwd-check').disabled = false;
    $('pwd-check').textContent = 'Проверить пароль';
  });
  pwd.addEventListener('keydown', (e) => {
    if (e.key === 'Enter') runCheck();
  });
  $('pwd-check').addEventListener('click', runCheck);

  // показать/скрыть
  $('pwd-toggle').addEventListener('click', () => {
    const show = pwd.type === 'password';
    pwd.type = show ? 'text' : 'password';
    $('pwd-toggle').textContent = show ? 'Скрыть' : 'Показать';
    $('pwd-toggle').setAttribute('aria-pressed', String(show));
  });
}

// ---------- Генератор ----------
function readGenOptions() {
  return {
    length: Number($('gen-length').value),
    lower: $('gen-lower').checked,
    upper: $('gen-upper').checked,
    digits: $('gen-digits').checked,
    symbols: $('gen-symbols').checked,
    excludeAmbiguous: $('gen-ambiguous').checked,
  };
}

export function initGenerator() {
  const length = $('gen-length');
  length.addEventListener('input', () => ($('gen-length-out').textContent = length.value));

  $('gen-run').addEventListener('click', () => {
    const info = $('gen-info');
    try {
      const opts = readGenOptions();
      const password = generatePassword(opts);
      $('gen-output').value = password;
      $('pwd').value = password;
      const bits = estimateEntropyBits(opts.length, poolSize(opts));
      info.textContent = `Длина ${opts.length}, алфавит ${poolSize(opts)} символов, энтропия около ${bits} бит. Пароль подставлен в поле проверки.`;
      updateMeter();
      runCheck();
    } catch (e) {
      info.textContent = e.message;
    }
  });

  $('gen-copy').addEventListener('click', async () => {
    const value = $('gen-output').value;
    if (!value) return;
    const btn = $('gen-copy');
    try {
      await navigator.clipboard.writeText(value);
      btn.textContent = 'Скопировано';
    } catch {
      $('gen-output').select();
      btn.textContent = 'Выделено: нажмите Ctrl+C';
    }
    setTimeout(() => (btn.textContent = 'Копировать'), 1800);
  });
}
