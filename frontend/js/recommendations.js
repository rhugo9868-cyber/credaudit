// Движок рекомендаций: правила «если – то». Каждое правило смотрит на результаты модулей
// и, если условие выполнено, добавляет рекомендацию с приоритетом и объяснением «почему».
//
// Контракт данных (results), который заполняют модули:
//   results.password = { score, length, leakStatus, leakCount, policy: { name, passed, unverified, results } }
//   results.email    = результат серверной части: { status, count, breaches[], exposedPasswords, exposedPhones, ... }
//   results.phone    = { ok, valid, type, country, countryName, e164, ... }  (см. phone.js)
//
// Чтобы добавить правило, допишите объект в нужный массив RULES_* и включите его в RULES.

import { ruPlural } from './password.js';
import { phoneExposureFromEmail } from './phone.js';

export const PRIORITY_LABELS = {
  critical: 'Критично',
  important: 'Важно',
  desirable: 'Желательно',
  good: 'Хорошо',
};

const ORDER = ['critical', 'important', 'desirable', 'good'];

const fmt = (n) => Number(n || 0).toLocaleString('ru-RU');

export const RULES_PASSWORD = [
  {
    id: 'pwd-leaked',
    priority: 'critical',
    when: (r) => r.password && r.password.leakCount > 0,
    text: (r) =>
      `Пароль уже встречался в утечках данных (${fmt(r.password.leakCount)} ${ruPlural(r.password.leakCount, 'раз', 'раза', 'раз')}). Замените его везде, где он используется, и больше не применяйте.`,
    why: 'Пароли из утечек входят в словари, по которым злоумышленники подбирают пароли в первую очередь.',
  },
  {
    id: 'pwd-weak',
    priority: 'important',
    when: (r) => r.password && r.password.score < 3,
    text: (r) =>
      `Пароль слабый (оценка ${r.password.score} из 4). Смените его: возьмите 14 и более символов или фразу из нескольких несвязанных слов.`,
    why: 'Короткие и предсказуемые пароли подбираются за секунды, даже если в них есть цифры и заглавные буквы.',
  },
  {
    id: 'pwd-short',
    priority: 'important',
    when: (r) => r.password && r.password.length < 12 && r.password.score >= 3,
    text: () => 'Пароль короче 12 символов. Увеличьте длину: каждый лишний символ сильно усложняет подбор.',
    why: 'Длина влияет на стойкость сильнее, чем набор символов.',
  },
  {
    id: 'pwd-policy',
    priority: 'important',
    when: (r) => r.password && r.password.policy && !r.password.policy.passed && !r.password.policy.unverified,
    text: (r) => {
      const failed = r.password.policy.results.filter((x) => x.ok === false).map((x) => x.label.toLowerCase());
      return `Пароль не проходит политику «${r.password.policy.name}»: ${failed.join('; ')}.`;
    },
    why: 'Политика задаёт минимальные требования, которые принято предъявлять к паролям в организации или стандарте.',
  },
  {
    id: 'pwd-leak-unchecked',
    priority: 'desirable',
    when: (r) => r.password && r.password.leakStatus === 'error',
    text: () => 'Не удалось проверить пароль по базе утечек. Повторите проверку при наличии интернета.',
    why: 'Без проверки утечек нельзя быть уверенным, что пароль не скомпрометирован.',
  },
  {
    id: 'pwd-unique',
    priority: 'desirable',
    when: (r) => !!r.password,
    text: () => 'Используйте уникальный пароль для каждого сервиса и храните пароли в менеджере паролей.',
    why: 'Один и тот же пароль на разных сайтах превращает утечку одного сервиса во взлом всех остальных.',
  },
  {
    id: 'pwd-good',
    priority: 'good',
    when: (r) =>
      r.password && r.password.score >= 3 && r.password.leakCount === 0 && (!r.password.policy || r.password.policy.passed),
    text: () => 'Пароль надёжный и не найден в известных утечках. Включите двухфакторную аутентификацию там, где он используется.',
    why: 'Даже хороший пароль можно украсть фишингом, второй фактор защищает от такого сценария.',
  },
];

export const RULES_EMAIL = [
  {
    id: 'email-passwords-leaked',
    priority: 'critical',
    when: (r) => r.email && r.email.status === 'found' && r.email.exposedPasswords,
    text: () =>
      'В утечках с вашим адресом раскрывались пароли. Смените пароль от почты и от сервисов из списка утечек, а если он повторялся на других сайтах, то и там.',
    why: 'Раскрытые пароли и адрес почты используют для автоматического входа в другие аккаунты (подстановка учётных данных).',
  },
  {
    id: 'email-found',
    priority: 'important',
    when: (r) => r.email && r.email.status === 'found',
    text: (r) =>
      `Адрес найден в ${fmt(r.email.count)} ${ruPlural(r.email.count, 'утечке', 'утечках', 'утечках')}. Включите двухфакторную аутентификацию на почте и в сервисах из списка и будьте внимательны к письмам со ссылками.`,
    why: 'Попавший в утечку адрес попадает в рассылки мошенников, а письма от них часто ссылаются на реальные сервисы, которыми вы пользовались.',
  },
  {
    id: 'email-many',
    priority: 'desirable',
    when: (r) => r.email && r.email.status === 'found' && r.email.count >= 5,
    text: () => 'Для регистраций на сторонних сайтах заведите отдельный адрес или используйте псевдонимы (алиасы) почты.',
    why: 'Отдельный адрес ограничивает ущерб: утечка с мелкого сайта не раскрывает основную почту.',
  },
  {
    id: 'email-unchecked',
    priority: 'desirable',
    when: (r) => r.email && r.email.status === 'error',
    text: () => 'Проверить e-mail не удалось. Повторите проверку чуть позже.',
    why: 'Без проверки неизвестно, раскрывался ли ваш адрес.',
  },
  {
    id: 'email-clean',
    priority: 'good',
    when: (r) => r.email && r.email.status === 'clean',
    text: () => 'Адрес не найден в известных утечках. Всё равно включите двухфакторную аутентификацию на почте.',
    why: 'Почта открывает доступ к восстановлению паролей во всех остальных сервисах, поэтому её защищают в первую очередь.',
  },
];

export const RULES_PHONE = [
  {
    id: 'phone-invalid',
    priority: 'desirable',
    when: (r) => r.phone && !r.phone.valid,
    text: () => 'Номер не похож на существующий. Проверьте страну и цифры.',
    why: 'Оценку безопасности можно построить только для корректного номера.',
  },
  {
    id: 'phone-exposed',
    priority: 'important',
    when: (r) => r.phone && r.phone.valid && phoneExposureFromEmail(r.email) === true,
    text: () =>
      'В утечках с вашим адресом раскрывались телефоны, возможно, и ваш. Не сообщайте коды из SMS, не переходите по ссылкам из сообщений и звонков с незнакомых номеров.',
    why: 'Раскрытые номера используют для фишинга и телефонного мошенничества, сообщения и звонки выглядят правдоподобно.',
  },
  {
    id: 'phone-sms-2fa',
    priority: 'desirable',
    when: (r) => r.phone && r.phone.valid,
    text: () =>
      'Там, где возможно, используйте приложение-аутентификатор или ключ безопасности вместо кодов по SMS. Спросите у оператора, как защитить номер от переоформления SIM-карты.',
    why: 'Номер можно перехватить через подмену SIM-карты или переадресацию, а приложение-аутентификатор от этого не зависит.',
  },
  {
    id: 'phone-voip',
    priority: 'desirable',
    when: (r) => r.phone && r.phone.valid && r.phone.type === 'VOIP',
    text: () => 'Номер определён как IP-телефония. Не привязывайте его к важным аккаунтам как единственный способ восстановления.',
    why: 'Виртуальные номера проще потерять или переоформить, а сервисы нередко не принимают их для проверки.',
  },
];

export const RULES_CROSS = [
  {
    id: 'cross-email-weak-password',
    priority: 'important',
    when: (r) => r.email && r.email.status === 'found' && r.password && (r.password.score < 3 || r.password.leakCount > 0),
    text: () =>
      'Ваш адрес уже встречался в утечках, а проверенный пароль слабый или скомпрометирован. Смените пароль в первую очередь: адрес злоумышленникам уже известен.',
    why: 'Комбинация известного адреса и слабого пароля — самый простой путь взлома аккаунта.',
  },
];

for (const [rules, module] of [[RULES_PASSWORD, 'password'], [RULES_EMAIL, 'email'], [RULES_PHONE, 'phone'], [RULES_CROSS, 'cross']]) {
  rules.forEach((rule) => (rule.module = module));
}

export const RULES = [...RULES_PASSWORD, ...RULES_EMAIL, ...RULES_PHONE, ...RULES_CROSS];

/** Возвращает список рекомендаций { id, priority, label, text, why }, отсортированный по приоритету. */
export function recommend(results, rules = RULES) {
  return rules
    .filter((rule) => rule.when(results))
    .map((rule) => ({
      id: rule.id,
      module: rule.module,
      priority: rule.priority,
      label: PRIORITY_LABELS[rule.priority],
      text: rule.text(results),
      why: rule.why,
    }))
    .sort((a, b) => ORDER.indexOf(a.priority) - ORDER.indexOf(b.priority));
}
