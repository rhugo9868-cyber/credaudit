// Общее хранилище результатов проверок. Каждый модуль записывает сюда свой результат,
// а отчёт и рекомендации читают его и перерисовываются при любом изменении.
//
//   state.results.password / .email / .phone   (формат полей описан в README)

export const state = { results: {} };

const listeners = new Set();

/** Записывает результат модуля (null или undefined — удалить) и уведомляет подписчиков. */
export function setResult(key, value) {
  if (value === null || value === undefined) delete state.results[key];
  else state.results[key] = value;
  listeners.forEach((fn) => fn(state.results));
}

/** Подписка на изменения. Возвращает функцию отписки. */
export function subscribe(fn) {
  listeners.add(fn);
  return () => listeners.delete(fn);
}
