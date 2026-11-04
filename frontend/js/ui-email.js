// Модуль 2. Интерфейс проверки e-mail.

import { checkEmail, isValidEmail, classLabel, uniqueLabels } from './email.js';
import { recommend } from './recommendations.js';
import { RULES_EMAIL } from './recommendations.js';
import { setResult, state } from './state.js';
import { $, el, badge, fmtNum, recoList, showTab } from './ui-common.js';
import { ruPlural } from './password.js';

const VISIBLE_BREACHES = 8;
let token = 0;

const PWD_RISK = {
  plaintext: ['bad', 'пароли в открытом виде'],
  easytocrack: ['bad', 'пароли легко подобрать'],
  hardtocrack: ['warn', 'пароли захешированы стойко'],
};

/** Бейдж про пароли: только если пароли реально среди раскрытых данных; степень риска — по данным сервиса. */
function passwordBadge(b) {
  const has = (b.dataClasses || []).some((c) => ['passwords', 'password'].includes(String(c).toLowerCase()));
  if (!has) return null;
  const [kind, text] = PWD_RISK[String(b.passwordRisk || '').toLowerCase()] || ['warn', 'раскрыты пароли'];
  return badge(kind, text);
}

function breachItem(b) {
  const classes = uniqueLabels(b.dataClasses || []);
  const meta = [b.year ? String(b.year) : null, b.domain || null, b.records ? `${fmtNum(b.records)} записей` : null].filter(Boolean).join(' · ');
  return el(
    'li',
    { class: 'breach' },
    el('div', { class: 'breach-head' }, el('strong', {}, b.name || 'Без названия'), passwordBadge(b)),
    meta ? el('div', { class: 'breach-meta' }, meta) : null,
    classes.length ? el('div', { class: 'chips' }, classes.slice(0, 12).map((c) => el('span', { class: 'chip' }, c))) : null
  );
}

function renderEmail(r) {
  const box = $('email-results');
  box.replaceChildren();
  box.hidden = false;

  const card = el('div', { class: 'card' });
  if (r.status === 'error') {
    card.append(el('h3', {}, 'Проверка e-mail ', badge('warn', 'Не выполнена')), el('p', { class: 'result-line' }, r.message || 'Проверка не удалась.'));
    box.append(card);
    return;
  }

  if (r.status === 'clean') {
    card.append(
      el('h3', {}, 'Проверка e-mail ', badge('ok', 'Не найден в утечках')),
      el('p', { class: 'result-line' }, 'Адрес не найден в известных утечках данных. Это не гарантия: в базы попадают не все утечки.')
    );
  } else {
    card.append(
      el('h3', {}, 'Проверка e-mail ', badge('bad', `Найден в ${fmtNum(r.count)} ${ruPlural(r.count, 'утечке', 'утечках', 'утечках')}`)),
      el('p', { class: 'result-line' }, r.riskLabel ? `Оценка риска сервиса: ${r.riskLabel}.` : 'Ниже список утечек, в которых встречался адрес.')
    );
    const top = (r.dataClassCounts || []).slice(0, 8);
    if (top.length) {
      card.append(
        el('p', { class: 'hint' }, 'Какие данные раскрывались чаще всего:'),
        el('div', { class: 'chips' }, top.map((c) => el('span', { class: 'chip' }, `${classLabel(c.name)} · ${fmtNum(c.count)}`)))
      );
    }
  }
  card.append(
    el('p', { class: 'hint' }, `Источник: ${r.source === 'leakcheck' ? 'LeakCheck (резервный сервис)' : 'XposedOrNot'}${r.cached ? '. Ответ взят из кеша.' : '.'} Адрес на сервере не сохраняется.`)
  );
  if (r.source === 'leakcheck') {
    const link = el('a', { href: 'https://leakcheck.io', target: '_blank', rel: 'noopener noreferrer' }, 'LeakCheck');
    card.append(el('p', { class: 'hint' }, 'Powered by ', link));
  }
  box.append(card);

  if (r.status === 'found' && r.breaches && r.breaches.length) {
    const list = el('ul', { class: 'breach-list' }, r.breaches.slice(0, VISIBLE_BREACHES).map(breachItem));
    const bcard = el('div', { class: 'card' }, el('h3', {}, 'Утечки'), list);
    if (r.breaches.length > VISIBLE_BREACHES) {
      const rest = r.breaches.length - VISIBLE_BREACHES;
      bcard.append(
        el('details', {}, el('summary', {}, `Показать ещё ${fmtNum(rest)}`), el('ul', { class: 'breach-list' }, r.breaches.slice(VISIBLE_BREACHES).map(breachItem)))
      );
    }
    if (r.count > r.breaches.length) {
      bcard.append(el('p', { class: 'hint' }, `Показаны ${fmtNum(r.breaches.length)} новейших из ${fmtNum(r.count)}.`));
    }
    box.append(bcard);
  }

  const reco = recommend(state.results, RULES_EMAIL);
  if (reco.length) box.append(el('div', { class: 'card' }, el('h3', {}, 'Рекомендации'), recoList(reco)));

  const toPhone = el('button', { type: 'button', class: 'btn btn-ghost' }, 'Проверить телефон');
  toPhone.addEventListener('click', () => showTab('phone'));
  box.append(el('div', { class: 'next-row' }, toPhone));
}

async function run() {
  const input = $('email');
  const value = input.value.trim();
  const err = $('email-error');
  err.textContent = '';
  if (!isValidEmail(value)) {
    err.textContent = 'Введите корректный адрес, например name@example.com';
    input.focus();
    return;
  }
  const btn = $('email-check');
  const my = ++token;
  btn.disabled = true;
  btn.textContent = 'Проверяю…';
  try {
    const result = await checkEmail(value);
    if (my !== token) return;
    setResult('email', result);
    renderEmail(result);
    $('email-results').scrollIntoView({ behavior: 'smooth', block: 'nearest' });
  } finally {
    if (my === token) {
      btn.disabled = false;
      btn.textContent = 'Проверить e-mail';
    }
  }
}

export function initEmail() {
  const input = $('email');
  input.addEventListener('keydown', (e) => {
    if (e.key === 'Enter') run();
  });
  input.addEventListener('input', () => {
    token++;
    $('email-error').textContent = '';
    $('email-results').hidden = true;
    setResult('email', null);
    $('email-check').disabled = false;
    $('email-check').textContent = 'Проверить e-mail';
  });
  $('email-check').addEventListener('click', run);
}
