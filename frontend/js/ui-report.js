// Итоговый отчёт: индекс безопасности 0–100, оценки по разделам и общий список рекомендаций.

import { computeSecurityIndex, WEIGHTS, CAP_MARGIN } from './score.js';
import { recommend } from './recommendations.js';
import { subscribe, state } from './state.js';
import { $, el, badge, recoList, showTab } from './ui-common.js';

const SVG_NS = 'http://www.w3.org/2000/svg';
const RING_R = 52;
const RING_LEN = 2 * Math.PI * RING_R;

function svg(tag, attrs) {
  const n = document.createElementNS(SVG_NS, tag);
  for (const [k, v] of Object.entries(attrs)) n.setAttribute(k, String(v));
  return n;
}

/** Круговой индикатор. Длина дуги задаётся атрибутом SVG (не inline-стилем), чтобы работала строгая CSP. */
function ring(index, kind) {
  const root = svg('svg', { viewBox: '0 0 120 120', class: `ring ring-${kind}`, role: 'img', 'aria-label': `Индекс безопасности ${index} из 100` });
  root.append(svg('circle', { class: 'ring-track', cx: 60, cy: 60, r: RING_R, fill: 'none', 'stroke-width': 10 }));
  root.append(
    svg('circle', {
      class: 'ring-value',
      cx: 60,
      cy: 60,
      r: RING_R,
      fill: 'none',
      'stroke-width': 10,
      'stroke-linecap': 'round',
      'stroke-dasharray': `${((RING_LEN * index) / 100).toFixed(2)} ${RING_LEN.toFixed(2)}`,
      transform: 'rotate(-90 60 60)',
    })
  );
  const t = svg('text', { class: 'ring-num', x: 60, y: 66, 'text-anchor': 'middle' });
  t.textContent = String(index);
  const s = svg('text', { class: 'ring-sub', x: 60, y: 84, 'text-anchor': 'middle' });
  s.textContent = 'из 100';
  root.append(t, s);
  return root;
}

function barKind(score) {
  return score < 40 ? 'bad' : score < 65 ? 'warn' : 'ok';
}

function categoryRow(c) {
  const fill = el('span', { class: `bar-fill ${c.assessed ? barKind(c.score) : ''}` });
  fill.style.setProperty('width', `${c.assessed ? c.score : 0}%`);
  const open = c.assessed ? null : el('button', { type: 'button', class: 'btn btn-ghost btn-sm' }, 'Проверить');
  if (open) open.addEventListener('click', () => showTab(c.id));
  return el(
    'li',
    { class: 'cat' },
    el('div', { class: 'cat-head' }, el('strong', {}, c.name), el('span', { class: 'cat-score' }, c.assessed ? `${c.score} / 100` : '—')),
    el('div', { class: 'bar', role: 'presentation' }, fill),
    el('div', { class: 'cat-note' }, c.note, open ? [' ', open] : null)
  );
}

function render() {
  const box = $('report-body');
  box.replaceChildren();
  const r = computeSecurityIndex(state.results);

  if (r.index === null) {
    box.append(
      el(
        'div',
        { class: 'card' },
        el('h2', {}, 'Итоговая оценка безопасности'),
        el('p', {}, 'Пока нечего оценивать. Проверьте хотя бы один пункт, и здесь появится индекс безопасности от 0 до 100 с советами, что улучшить.'),
        el('ul', { class: 'cat-list' }, r.categories.map(categoryRow))
      )
    );
    $('report-print').hidden = true;
    return;
  }
  $('report-print').hidden = false;

  const summary = el(
    'div',
    { class: 'card summary' },
    ring(r.index, r.rating.kind),
    el(
      'div',
      { class: 'summary-text' },
      el('h2', {}, 'Итоговая оценка безопасности'),
      el('p', { class: 'rating' }, badge(r.rating.kind, r.rating.label)),
      el('p', { class: 'hint' }, `Учтено разделов: ${r.assessedCount} из ${r.totalCount}.` + (r.assessedCount < r.totalCount ? ' Проверьте остальные, чтобы оценка стала полнее.' : '')),
      r.capped
        ? el('p', { class: 'hint' }, `Индекс ограничен самым слабым разделом (${r.categories.find((c) => c.id === r.weakest).name}): он не может быть выше его оценки больше чем на ${CAP_MARGIN} баллов, а среднее по разделам было бы ${r.weighted}.`)
        : null
    )
  );
  box.append(summary);

  box.append(el('div', { class: 'card' }, el('h3', {}, 'Оценка по разделам'), el('ul', { class: 'cat-list' }, r.categories.map(categoryRow))));

  const all = recommend(state.results);
  const actionable = all.filter((x) => x.priority !== 'good');
  const start = actionable.slice(0, 3);
  if (start.length) {
    box.append(el('div', { class: 'card' }, el('h3', {}, 'С чего начать'), recoList(start)));
  } else {
    box.append(el('div', { class: 'card' }, el('h3', {}, 'С чего начать'), el('p', {}, 'Срочных действий нет. Поддерживайте уровень: проверяйте данные раз в несколько месяцев.')));
  }
  const rest = all.filter((x) => !start.includes(x));
  if (rest.length) box.append(el('div', { class: 'card' }, el('h3', {}, 'Остальные рекомендации'), recoList(rest)));

  box.append(
    el(
      'div',
      { class: 'card' },
      el(
        'details',
        {},
        el('summary', {}, 'Как считается индекс'),
        el('p', {}, 'Каждый проверенный раздел получает оценку от 0 до 100, затем берётся среднее с весами. Непроверенные разделы не учитываются, веса пересчитываются.'),
        el('ul', {}, [
          el('li', {}, `Пароль (вес ${WEIGHTS.password}): оценка стойкости 0–4 даёт 5, 25, 50, 80 или 100 баллов; пароль из утечки получает не более 10, а непроверенный по утечкам не более 70.`),
          el('li', {}, `E-mail (вес ${WEIGHTS.email}): 100 минус 12 баллов за каждую утечку (до 60), ещё минус 25, если раскрывались пароли, и минус 10, если телефоны.`),
          el('li', {}, `Телефон (вес ${WEIGHTS.phone}): корректный номер даёт 80 (IP-телефония 60); минус 35, если телефоны раскрывались в утечках вашего e-mail; плюс 20, если не раскрывались.`),
          el('li', {}, `Слабое звено: индекс не выше самого слабого раздела больше чем на ${CAP_MARGIN} баллов, иначе хорошие оценки скрыли бы серьёзную проблему.`),
          el('li', {}, 'Границы: до 39 — высокий риск, 40–64 — средний, 65–84 — хороший уровень, от 85 — отличный.'),
        ]),
        el('p', { class: 'hint' }, 'Это учебная модель оценки, а не гарантия безопасности. Веса и штрафы можно менять в файле score.js.')
      )
    )
  );
}

export function initReport() {
  $('report-print').addEventListener('click', () => window.print());
  subscribe(render);
  render();
}
