// Модуль 3. Интерфейс анализа номера телефона (всё происходит в браузере).

import { analyzePhone, COUNTRIES, phoneExposureFromEmail } from './phone.js';
import { recommend, RULES_PHONE } from './recommendations.js';
import { setResult, state, subscribe } from './state.js';
import { $, el, badge, recoList, showTab } from './ui-common.js';

let lastAnalysis = null;

function row(label, value) {
  return el('div', { class: 'kv-row' }, el('dt', {}, label), el('dd', {}, value));
}

function render() {
  const box = $('phone-results');
  const a = lastAnalysis;
  box.replaceChildren();
  if (!a) {
    box.hidden = true;
    return;
  }
  box.hidden = false;
  const card = el('div', { class: 'card' });
  if (!a.ok) {
    card.append(el('h3', {}, 'Анализ номера ', badge('warn', 'Не распознан')), el('p', { class: 'result-line' }, a.message));
    box.append(card);
    return;
  }
  const head = a.valid ? badge('ok', 'Номер корректен') : badge('bad', 'Номер некорректен');
  card.append(
    el('h3', {}, 'Анализ номера ', head),
    el(
      'dl',
      { class: 'kv' },
      row('В международном формате', a.international),
      row('Страна', a.countryName),
      row('Тип линии', a.valid ? a.typeLabel : 'Не определён'),
      row('Формально возможен', a.possible ? 'Да' : 'Нет')
    )
  );
  if (!a.valid) card.append(el('p', { class: 'result-line' }, 'Такой номер не существует в плане нумерации выбранной страны. Проверьте цифры и страну.'));
  card.append(el('p', { class: 'hint' }, 'Номер обработан в вашем браузере и никуда не отправлялся.'));
  box.append(card);

  if (a.valid) {
    const exposure = phoneExposureFromEmail(state.results.email);
    const risk = el('div', { class: 'card' }, el('h3', {}, 'Риск раскрытия номера'));
    if (exposure === true) {
      risk.append(el('p', { class: 'result-line' }, badge('bad', 'Повышенный'), ' В утечках, где найден ваш e-mail, раскрывались телефоны. Вероятно, номер мог попасть к посторонним.'));
    } else if (exposure === false) {
      risk.append(el('p', { class: 'result-line' }, badge('ok', 'Не выявлен'), ' В утечках вашего e-mail телефоны не раскрывались.'));
    } else {
      const go = el('button', { type: 'button', class: 'btn btn-ghost' }, 'Перейти к e-mail');
      go.addEventListener('click', () => showTab('email'));
      risk.append(
        el('p', { class: 'result-line' }, badge('neutral', 'Неизвестно'), ' Прямой проверки «номер — утечки» в бесплатных открытых сервисах нет. Риск оценивается косвенно: по утечкам вашего e-mail.'),
        go
      );
    }
    box.append(risk);
  }

  const reco = recommend(state.results, RULES_PHONE);
  if (reco.length) box.append(el('div', { class: 'card' }, el('h3', {}, 'Рекомендации'), recoList(reco)));

  const toReport = el('button', { type: 'button', class: 'btn btn-primary' }, 'Открыть итоговую оценку');
  toReport.addEventListener('click', () => showTab('report'));
  box.append(el('div', { class: 'next-row' }, toReport));
}

function run() {
  const err = $('phone-error');
  err.textContent = '';
  try {
    lastAnalysis = analyzePhone($('phone').value, $('phone-country').value);
  } catch (e) {
    lastAnalysis = null;
    err.textContent = e.message;
    setResult('phone', null);
    render();
    return;
  }
  if (!lastAnalysis.ok && lastAnalysis.reason === 'empty') {
    err.textContent = lastAnalysis.message;
    lastAnalysis = null;
    setResult('phone', null);
    render();
    $('phone').focus();
    return;
  }
  setResult('phone', lastAnalysis.ok ? lastAnalysis : { ok: false, valid: false });
  render();
}

export function initPhone() {
  const sel = $('phone-country');
  COUNTRIES.forEach((c) => sel.append(el('option', { value: c.code }, c.name)));
  $('phone-check').addEventListener('click', run);
  $('phone').addEventListener('keydown', (e) => {
    if (e.key === 'Enter') run();
  });
  $('phone').addEventListener('input', () => {
    lastAnalysis = null;
    $('phone-error').textContent = '';
    setResult('phone', null);
    render();
  });
  // если e-mail проверили позже, блок «Риск раскрытия» должен обновиться
  subscribe(() => {
    if (lastAnalysis) render();
  });
}
