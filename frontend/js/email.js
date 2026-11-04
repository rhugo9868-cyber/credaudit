// Модуль 2. Проверка e-mail по базам утечек (клиентская часть).
// Браузер не обращается к сервисам утечек напрямую: запрос идёт на серверную часть сайта (/api/email),
// которая ограничивает частоту запросов, кеширует ответы и не сохраняет адрес.

export const EMAIL_RE = /^[^@\s]{1,64}@[^@\s]{1,251}\.[^@\s.]{2,}$/;

export function isValidEmail(value) {
  const s = (value || '').trim();
  return s.length <= 254 && EMAIL_RE.test(s);
}

function apiBase() {
  return String(globalThis.CREDAUDIT_API_BASE || '').replace(/\/$/, '');
}

const SERVER_DOWN = 'Серверная часть сайта недоступна. Запустите сайт через start.bat (или командой python run.py).';

/**
 * Проверяет адрес. Возвращает объект результата серверной части:
 *   { status: 'found' | 'clean' | 'error', source, count, breaches[], exposedPasswords, exposedPhones,
 *     dataClassCounts[], riskLabel, message, cached }
 * Любая ошибка (нет сети, лимит, неверный адрес) возвращается как status 'error' с понятным текстом.
 */
export async function checkEmail(email, fetchFn, base) {
  if (!isValidEmail(email)) {
    return { status: 'error', message: 'Введите корректный адрес электронной почты' };
  }
  const doFetch = fetchFn || globalThis.fetch.bind(globalThis);
  let resp;
  try {
    resp = await doFetch(`${base === undefined ? apiBase() : base}/api/email`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email: email.trim() }),
    });
  } catch {
    return { status: 'error', message: SERVER_DOWN };
  }
  let data = null;
  try {
    data = await resp.json();
  } catch {
    /* тело не JSON */
  }
  if (!data || typeof data !== 'object' || !data.status) {
    return { status: 'error', message: resp.status === 404 ? SERVER_DOWN : `Сервер ответил непонятно (код ${resp.status})` };
  }
  if (!resp.ok && data.status !== 'error') data.status = 'error';
  return data;
}

// ---------- Русские названия категорий раскрытых данных ----------
const RU = {
  'email addresses': 'Адреса e-mail',
  passwords: 'Пароли',
  'phone numbers': 'Номера телефонов',
  names: 'Имена',
  usernames: 'Имена пользователей',
  'ip addresses': 'IP-адреса',
  'dates of birth': 'Даты рождения',
  'physical addresses': 'Физические адреса',
  genders: 'Пол',
  'social media profiles': 'Профили в соцсетях',
  'geographic locations': 'Местоположение',
  employers: 'Места работы',
  'job titles': 'Должности',
  'credit cards': 'Банковские карты',
  'partial credit card data': 'Часть данных банковских карт',
  'bank account numbers': 'Номера банковских счетов',
  'auth tokens': 'Токены доступа',
  'device information': 'Данные об устройстве',
  'browser user agents': 'Данные браузера',
  'private messages': 'Личные сообщения',
  'website activity': 'Активность на сайтах',
  'security questions and answers': 'Контрольные вопросы и ответы',
  'password hints': 'Подсказки к паролям',
  purchases: 'Покупки',
  'payment histories': 'История платежей',
  ages: 'Возраст',
  'education levels': 'Образование',
  'instant messenger identities': 'Аккаунты в мессенджерах',
  'vehicle registration numbers': 'Номера автомобилей',
  'government issued ids': 'Номера документов',
  // поля LeakCheck
  password: 'Пароли',
  phone: 'Номера телефонов',
  first_name: 'Имена',
  last_name: 'Имена',
  middle_name: 'Имена',
  name: 'Имена',
  username: 'Имена пользователей',
  profile_name: 'Имена пользователей',
  gender: 'Пол',
  dob: 'Даты рождения',
  address: 'Физические адреса',
  city: 'Физические адреса',
  state: 'Физические адреса',
  zip: 'Физические адреса',
  country: 'Физические адреса',
  ip: 'IP-адреса',
  ip1: 'IP-адреса',
  ip2: 'IP-адреса',
  ssn: 'Номера документов',
  company_name: 'Места работы',
  id: 'Идентификаторы',
  origin: 'Источник',
};

export function classLabel(name) {
  return RU[String(name).toLowerCase()] || String(name);
}

/** Список русских названий без повторов (несколько полей LeakCheck сводятся к одному названию). */
export function uniqueLabels(classes) {
  return [...new Set(classes.map(classLabel))];
}
