// Общие помощники интерфейса. Все тексты выводятся через textContent / текстовые узлы,
// поэтому введённые или полученные от сервера данные не могут внедрить HTML в страницу.

export const $ = (id) => document.getElementById(id);

/** Короткий помощник для создания элементов. */
export function el(tag, attrs = {}, ...children) {
  const node = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (v === undefined || v === null || v === false) continue;
    if (k === 'class') node.className = v;
    else node.setAttribute(k, v === true ? '' : v);
  }
  for (const c of children.flat()) {
    if (c === null || c === undefined || c === false) continue;
    node.append(c instanceof Node ? c : document.createTextNode(String(c)));
  }
  return node;
}

export const badge = (kind, text) => el('span', { class: `badge ${kind}` }, text);

export const fmtNum = (n) => Number(n).toLocaleString('ru-RU');

/** Список рекомендаций (одинаково выглядит в разделах и в итоговом отчёте). */
export function recoList(list) {
  return el(
    'ul',
    { class: 'reco-list' },
    list.map((r) =>
      el('li', {}, badge(r.priority, r.label), el('p', { class: 'reco-text' }, r.text), el('p', { class: 'reco-why' }, `Почему это важно: ${r.why}`))
    )
  );
}

/** Переключает вкладку по имени (password | email | phone | report). */
export function showTab(name) {
  document.querySelectorAll('.tab').forEach((b) => {
    const active = b.dataset.tab === name;
    b.setAttribute('aria-selected', String(active));
    $(`tab-${b.dataset.tab}`).hidden = !active;
  });
}
