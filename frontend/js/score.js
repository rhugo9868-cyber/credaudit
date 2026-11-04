// Индекс безопасности 0–100. Формула намеренно простая, чтобы её можно было объяснить и изменить.
//
//  1. Каждый проверенный раздел получает оценку 0–100 (scorePassword, scoreEmail, scorePhone).
//  2. Общая оценка — среднее по разделам с весами WEIGHTS (разделы, которые не проверяли, не учитываются).
//  3. Принцип «слабого звена»: индекс не может быть выше самого слабого раздела больше чем на CAP_MARGIN баллов.
//     Иначе скомпрометированный пароль «растворился» бы в хороших оценках остальных разделов.

import { phoneExposureFromEmail } from './phone.js';

export const WEIGHTS = { password: 50, email: 30, phone: 20 };
export const CAP_MARGIN = 40;

const NAMES = { password: 'Пароль', email: 'E-mail', phone: 'Телефон' };
const PASSWORD_BASE = [5, 25, 50, 80, 100]; // по оценке zxcvbn 0–4

const clamp = (n) => Math.max(0, Math.min(100, Math.round(n)));
const plural = (n, one, few, many) => {
  const n100 = n % 100, n10 = n % 10;
  if (n100 > 10 && n100 < 20) return many;
  if (n10 > 1 && n10 < 5) return few;
  return n10 === 1 ? one : many;
};

/** Пароль: стойкость по zxcvbn, но найденный в утечках пароль не получает больше 10, непроверенный — больше 70. */
export function scorePassword(p) {
  if (!p) return null;
  const base = PASSWORD_BASE[p.score] ?? 5;
  if (p.leakCount > 0) return { score: Math.min(base, 10), note: 'Пароль найден в утечках, его нужно заменить' };
  if (p.leakCount === null || p.leakCount === undefined || p.leakStatus === 'error') {
    return { score: Math.min(base, 70), note: `Стойкость ${p.score} из 4, но утечки проверить не удалось` };
  }
  return { score: base, note: `Стойкость ${p.score} из 4, в утечках не найден` };
}

/** E-mail: 100 минус штраф за каждую утечку (до 60), за раскрытые пароли (25) и телефоны (10). */
export function scoreEmail(e) {
  if (!e || e.status === 'error' || e.status === undefined) return null;
  if (e.status === 'clean') return { score: 100, note: 'Адрес не найден в известных утечках' };
  const count = e.count || 0;
  let score = 100 - Math.min(60, 12 * count);
  const flags = [];
  if (e.exposedPasswords) { score -= 25; flags.push('раскрывались пароли'); }
  if (e.exposedPhones) { score -= 10; flags.push('раскрывались телефоны'); }
  const note = `Найден в ${count} ${plural(count, 'утечке', 'утечках', 'утечках')}` + (flags.length ? `: ${flags.join(', ')}` : '');
  return { score: clamp(score), note };
}

/** Телефон: корректный номер — 80 (VoIP — 60); ещё −35, если телефоны раскрывались в утечках e-mail, и +20, если нет. */
export function scorePhone(ph, email) {
  if (!ph || !ph.valid) return null;
  let score = ph.type === 'VOIP' ? 60 : 80;
  const exposure = phoneExposureFromEmail(email);
  let note;
  if (exposure === true) { score -= 35; note = 'Телефоны раскрывались в утечках вашего e-mail'; }
  else if (exposure === false) { score += 20; note = 'По утечкам e-mail номер не раскрывался'; }
  else note = 'Оценка неполная: проверьте e-mail, чтобы учесть риск раскрытия номера';
  if (ph.type === 'VOIP') note += '; номер определён как VoIP';
  return { score: clamp(score), note };
}

export function ratingFor(index) {
  if (index < 40) return { label: 'Высокий риск', kind: 'bad' };
  if (index < 65) return { label: 'Средний риск', kind: 'warn' };
  if (index < 85) return { label: 'Хороший уровень', kind: 'ok' };
  return { label: 'Отличный уровень', kind: 'ok' };
}

function missingNote(id, results) {
  if (id === 'phone' && results.phone && !results.phone.valid) return 'Номер введён некорректно, оценка не выполнена';
  return 'Не проверялось';
}

/**
 * Считает индекс по результатам модулей.
 * Возвращает { index | null, rating, categories[{id,name,weight,assessed,score,note}], assessedCount, totalCount,
 *              weighted, capped, weakest }.
 */
export function computeSecurityIndex(results = {}) {
  const parts = {
    password: scorePassword(results.password),
    email: scoreEmail(results.email),
    phone: scorePhone(results.phone, results.email),
  };
  const categories = Object.keys(WEIGHTS).map((id) => ({
    id,
    name: NAMES[id],
    weight: WEIGHTS[id],
    assessed: Boolean(parts[id]),
    score: parts[id] ? parts[id].score : null,
    note: parts[id] ? parts[id].note : missingNote(id, results),
  }));
  const assessed = categories.filter((c) => c.assessed);
  const base = { categories, assessedCount: assessed.length, totalCount: categories.length };
  if (!assessed.length) return { ...base, index: null, rating: null, weighted: null, capped: false, weakest: null };

  const weightSum = assessed.reduce((s, c) => s + c.weight, 0);
  const weighted = assessed.reduce((s, c) => s + c.weight * c.score, 0) / weightSum;
  const weakest = assessed.reduce((a, b) => (b.score < a.score ? b : a));
  const cap = weakest.score + CAP_MARGIN;
  const index = clamp(Math.min(weighted, cap));
  return { ...base, index, rating: ratingFor(index), weighted: clamp(weighted), capped: weighted > cap, weakest: weakest.id };
}
