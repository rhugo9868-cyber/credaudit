// Модуль 3. Анализ номера телефона. Всё выполняется в браузере: номер никуда не отправляется.
// Разбор номера делает библиотека libphonenumber-js (подключена в index.html как глобальный объект libphonenumber).
//
// Важно: прямой поиск «номер телефона – утечки» через бесплатный легальный API невозможен,
// поэтому риск раскрытия номера оценивается косвенно: по тому, раскрывались ли телефоны
// в тех утечках, где найден ваш e-mail (см. phoneExposureFromEmail).

export const COUNTRIES = [
  { code: 'RU', name: 'Россия (+7)' },
  { code: 'BY', name: 'Беларусь (+375)' },
  { code: 'KZ', name: 'Казахстан (+7)' },
  { code: 'UA', name: 'Украина (+380)' },
  { code: 'US', name: 'США (+1)' },
  { code: 'GB', name: 'Великобритания (+44)' },
  { code: 'DE', name: 'Германия (+49)' },
];

const TYPE_RU = {
  MOBILE: 'Мобильный',
  FIXED_LINE: 'Стационарный',
  FIXED_LINE_OR_MOBILE: 'Стационарный или мобильный',
  TOLL_FREE: 'Бесплатный (например, 8-800)',
  PREMIUM_RATE: 'Платный (повышенный тариф)',
  SHARED_COST: 'С разделением стоимости',
  VOIP: 'IP-телефония (VoIP)',
  PERSONAL_NUMBER: 'Персональный номер',
  PAGER: 'Пейджер',
  UAN: 'Единый номер организации',
  VOICEMAIL: 'Голосовая почта',
};

export function typeLabel(type) {
  return TYPE_RU[type] || 'Не определён';
}

export function countryName(code) {
  if (!code) return 'Не определена';
  try {
    return new Intl.DisplayNames(['ru'], { type: 'region' }).of(code) || code;
  } catch {
    return code;
  }
}

/**
 * Разбирает и проверяет номер.
 * Возвращает { ok: false, reason, message } если номер не распознан, иначе
 * { ok: true, valid, possible, e164, international, national, country, countryName, callingCode, type, typeLabel }.
 * Номер можно вводить в любом виде: «8 912 345-67-89», «+7 (912) 345-67-89», «9123456789».
 */
export function analyzePhone(raw, defaultCountry = 'RU', lib = globalThis.libphonenumber) {
  const text = (raw || '').trim();
  if (!text) return { ok: false, reason: 'empty', message: 'Введите номер телефона' };
  if (!lib) throw new Error('Библиотека libphonenumber не загружена');
  let parsed;
  try {
    parsed = lib.parsePhoneNumberFromString(text, defaultCountry);
  } catch {
    parsed = undefined;
  }
  if (!parsed) {
    return { ok: false, reason: 'unparsable', message: 'Не удалось распознать номер. Введите его цифрами, например +7 912 345-67-89.' };
  }
  const type = parsed.getType() || null;
  return {
    ok: true,
    valid: parsed.isValid(),
    possible: parsed.isPossible(),
    e164: parsed.number,
    international: parsed.formatInternational(),
    national: parsed.formatNational(),
    country: parsed.country || null,
    countryName: countryName(parsed.country),
    callingCode: parsed.countryCallingCode,
    type,
    typeLabel: typeLabel(type),
  };
}

/**
 * Косвенный признак раскрытия номера по результату проверки e-mail:
 *   true  — в утечках с этим адресом раскрывались телефоны;
 *   false — адрес чист либо телефоны в его утечках не раскрывались;
 *   null  — e-mail не проверен или проверка не удалась, судить нельзя.
 */
export function phoneExposureFromEmail(email) {
  if (!email || email.status === 'error') return null;
  if (email.status === 'clean') return false;
  return Boolean(email.exposedPhones);
}
