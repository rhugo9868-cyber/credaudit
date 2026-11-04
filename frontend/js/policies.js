// Политики стойкости пароля. Каждая политика — набор критериев; критерий возвращает
//   true (выполнен), false (не выполнен) или null (не удалось проверить, например нет связи с сервисом утечек).
//
// Контекст проверки ctx: { password, length, score, leakCount }
//   leakCount === null означает «проверка утечек не выполнена».

const hasLower = (p) => /\p{Ll}/u.test(p);
const hasUpper = (p) => /\p{Lu}/u.test(p);
const hasLetter = (p) => /\p{L}/u.test(p);
const hasDigit = (p) => /\d/.test(p);
const hasSymbol = (p) => /[^\p{L}\d\s]/u.test(p);

const lengthAtLeast = (n, label) => ({
  id: `length-${n}`,
  label: label || `Длина не менее ${n} символов`,
  test: (c) => c.length >= n,
});

const notLeaked = {
  id: 'not-leaked',
  label: 'Пароля нет в известных утечках',
  test: (c) => (c.leakCount === null || c.leakCount === undefined ? null : c.leakCount === 0),
};

export const POLICIES = [
  {
    id: 'basic',
    name: 'Базовая',
    description: 'Минимальные требования, которые часто встречаются на сайтах.',
    criteria: [
      lengthAtLeast(8),
      { id: 'letter-digit', label: 'Есть буквы и цифры', test: (c) => hasLetter(c.password) && hasDigit(c.password) },
    ],
  },
  {
    id: 'nist',
    name: 'NIST SP 800-63B',
    description: 'Без требований к составу: важны длина и отсутствие пароля в утечках.',
    criteria: [
      lengthAtLeast(15, 'Длина не менее 15 символов (если пароль — единственный фактор входа)'),
      notLeaked,
    ],
  },
  {
    id: 'strict',
    name: 'Строгая (корпоративная)',
    description: 'Длина, все типы символов, высокая оценка стойкости и отсутствие в утечках.',
    criteria: [
      lengthAtLeast(14),
      { id: 'lower', label: 'Есть строчные буквы', test: (c) => hasLower(c.password) },
      { id: 'upper', label: 'Есть заглавные буквы', test: (c) => hasUpper(c.password) },
      { id: 'digit', label: 'Есть цифры', test: (c) => hasDigit(c.password) },
      { id: 'symbol', label: 'Есть спецсимволы', test: (c) => hasSymbol(c.password) },
      { id: 'score', label: 'Оценка стойкости не ниже 3 из 4', test: (c) => c.score >= 3 },
      notLeaked,
    ],
  },
];

export function getPolicy(id) {
  return POLICIES.find((p) => p.id === id) || POLICIES[0];
}

/** Проверяет пароль по политике. Возвращает { id, name, passed, unverified, results[{id,label,ok}] }. */
export function evaluatePolicy(policy, ctx) {
  const results = policy.criteria.map((c) => ({ id: c.id, label: c.label, ok: c.test(ctx) }));
  return {
    id: policy.id,
    name: policy.name,
    passed: results.every((r) => r.ok === true),
    unverified: results.some((r) => r.ok === null),
    results,
  };
}
