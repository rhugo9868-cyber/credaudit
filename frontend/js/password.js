// Модуль 1. Проверка пароля.
//   1) утечки: Have I Been Pwned, Pwned Passwords API, модель k-anonymity;
//   2) стойкость: zxcvbn-ts (оценка 0–4 и время подбора).
// Пароль никуда не отправляется: в сервис утечек уходят только первые 5 символов его SHA-1.

export const HIBP_RANGE_URL = 'https://api.pwnedpasswords.com/range/';

// ---------- 1. Утечки (k-anonymity) ----------

/** SHA-1 строки в виде 40 символов HEX в верхнем регистре (средствами Web Crypto). */
export async function sha1Hex(text) {
  const subtle = globalThis.crypto && globalThis.crypto.subtle;
  if (!subtle) {
    throw new Error('Web Crypto недоступен: откройте сайт по https:// или по адресу http://localhost');
  }
  const bytes = new TextEncoder().encode(text);
  const digest = await subtle.digest('SHA-1', bytes);
  return Array.from(new Uint8Array(digest), (b) => b.toString(16).padStart(2, '0')).join('').toUpperCase();
}

/**
 * Разбирает ответ API: строки вида «ХВОСТ_ХЕША:КОЛИЧЕСТВО».
 * Возвращает Map(хвост -> количество). Строки с количеством 0 — это «заполнение» (Add-Padding).
 */
export function parseRangeResponse(text) {
  const map = new Map();
  for (const line of text.split(/\r?\n/)) {
    const [suffix, count] = line.trim().split(':');
    if (!suffix || count === undefined) continue;
    const n = parseInt(count, 10);
    if (Number.isNaN(n)) continue;
    map.set(suffix.toUpperCase(), n);
  }
  return map;
}

/**
 * Проверяет пароль по базе утечек.
 * Возвращает { status: 'found' | 'clean' | 'error', count, prefix, returned, message }.
 *   count    — сколько раз пароль встречался в утечках (null при ошибке);
 *   prefix   — те самые 5 символов хеша, которые были отправлены наружу;
 *   returned — сколько хешей с таким началом вернул сервис.
 */
export async function checkLeak(password, fetchFn) {
  const doFetch = fetchFn || globalThis.fetch.bind(globalThis);
  let hash;
  try {
    hash = await sha1Hex(password);
  } catch (e) {
    return { status: 'error', count: null, prefix: null, returned: 0, message: e.message };
  }
  const prefix = hash.slice(0, 5);
  const suffix = hash.slice(5);
  try {
    // Add-Padding: сервис добавляет фиктивные строки, чтобы длина ответа не выдавала результат.
    const resp = await doFetch(HIBP_RANGE_URL + prefix, { headers: { 'Add-Padding': 'true' } });
    if (!resp.ok) {
      return { status: 'error', count: null, prefix, returned: 0, message: `Сервис проверки ответил кодом ${resp.status}` };
    }
    const map = parseRangeResponse(await resp.text());
    const count = map.get(suffix) || 0;
    return { status: count > 0 ? 'found' : 'clean', count, prefix, returned: map.size };
  } catch (e) {
    return { status: 'error', count: null, prefix, returned: 0, message: `Не удалось связаться с сервисом проверки: ${e.message}` };
  }
}

// ---------- 2. Стойкость (zxcvbn-ts) ----------

export const SCORE_LABELS = ['Очень слабый', 'Слабый', 'Средний', 'Хороший', 'Надёжный'];

// Английские словари zxcvbn не знают русских паролей, поэтому добавляем небольшой свой список.
const RU_PASSWORDS = [
  'пароль', 'привет', 'любовь', 'люблю', 'солнце', 'солнышко', 'котик', 'кошка', 'собака', 'дружба',
  'москва', 'россия', 'админ', 'вход', 'секрет', 'зенит', 'спартак', 'динамо', 'машина', 'деньги',
  'йцукен', 'йцукенг', 'фывапр', 'фывапролдж', 'ячсмить', 'qazwsx',
  'саша', 'наташа', 'дима', 'андрей', 'сергей', 'алексей', 'анна', 'мария', 'елена', 'ольга',
  'татьяна', 'юля', 'катя', 'вася', 'коля', 'максим', 'настя', 'иван', 'владимир', 'артем',
  'parol', 'privet', 'lubov', 'lyubov', 'moskva', 'rossiya', 'vasya', 'sasha', 'natasha', 'dimon',
];

const RU_TRANSLATIONS = {
  warnings: {
    straightRow: 'Ряды клавиш, идущие подряд на клавиатуре, легко угадать.',
    keyPattern: 'Короткие клавиатурные комбинации легко угадать.',
    simpleRepeat: 'Повторяющиеся символы вроде «aaa» легко угадать.',
    extendedRepeat: 'Повторяющиеся блоки символов вроде «abcabcabc» легко угадать.',
    sequences: 'Типичные последовательности символов вроде «abc» легко угадать.',
    recentYears: 'Недавние годы легко угадать.',
    dates: 'Даты легко угадать.',
    topTen: 'Это один из самых популярных паролей.',
    topHundred: 'Это очень часто используемый пароль.',
    common: 'Это широко распространённый пароль.',
    similarToCommon: 'Пароль похож на распространённый.',
    wordByItself: 'Одно слово легко угадать.',
    namesByThemselves: 'Одно имя или одну фамилию легко угадать.',
    commonNames: 'Распространённые имена и фамилии легко угадать.',
    userInputs: 'В пароле не должно быть личных данных или слов со страницы.',
    pwned: 'Этот пароль уже попадал в утечки в интернете.',
  },
  suggestions: {
    l33t: 'Не используйте предсказуемые замены вроде «@» вместо «a».',
    reverseWords: 'Не пишите слова задом наперёд.',
    allUppercase: 'Делайте заглавными только часть букв, а не все.',
    capitalization: 'Используйте заглавные буквы не только в начале.',
    dates: 'Избегайте дат и годов, связанных с вами.',
    recentYears: 'Избегайте недавних годов.',
    associatedYears: 'Избегайте годов, связанных с вами.',
    sequences: 'Избегайте типичных последовательностей символов.',
    repeated: 'Избегайте повторяющихся слов и символов.',
    longerKeyboardPattern: 'Используйте более длинные клавиатурные комбинации и меняйте направление ввода.',
    anotherWord: 'Добавьте ещё слов, которые встречаются реже.',
    useWords: 'Используйте несколько слов, но не устойчивые фразы.',
    noNeed: 'Надёжный пароль можно составить и без спецсимволов, цифр и заглавных букв.',
    pwned: 'Если вы используете этот пароль где-то ещё, смените его.',
  },
  // Время мы форматируем сами (formatDuration), эти шаблоны нужны только для полноты.
  timeEstimation: {
    ltSecond: 'меньше секунды',
    second: '{base} секунда',
    seconds: '{base} секунд',
    minute: '{base} минута',
    minutes: '{base} минут',
    hour: '{base} час',
    hours: '{base} часов',
    day: '{base} день',
    days: '{base} дней',
    month: '{base} месяц',
    months: '{base} месяцев',
    year: '{base} год',
    years: '{base} лет',
    centuries: 'столетия',
  },
};

let factory = null;

/** Создаёт (один раз) оценщик zxcvbn-ts из глобального объекта zxcvbnts (подключается в index.html). */
export function getEstimator(zxcvbnts = globalThis.zxcvbnts) {
  if (factory) return factory;
  if (!zxcvbnts || !zxcvbnts.core) throw new Error('Библиотека zxcvbn-ts не загружена');
  const common = zxcvbnts['language-common'];
  const en = zxcvbnts['language-en'];
  factory = new zxcvbnts.core.ZxcvbnFactory({
    translations: RU_TRANSLATIONS,
    graphs: common.adjacencyGraphs,
    dictionary: { ...common.dictionary, ...en.dictionary, russian: RU_PASSWORDS },
  });
  return factory;
}

/** Склонение: 1 минута, 2 минуты, 5 минут. */
export function ruPlural(n, one, few, many) {
  const n100 = Math.abs(n) % 100;
  const n10 = n100 % 10;
  if (n100 > 10 && n100 < 20) return many;
  if (n10 > 1 && n10 < 5) return few;
  if (n10 === 1) return one;
  return many;
}

/** Время подбора в секундах -> «5 минут», «3 года», «столетия». */
export function formatDuration(seconds) {
  const MIN = 60, HOUR = 3600, DAY = 86400, MONTH = DAY * 30, YEAR = DAY * 365;
  if (seconds < 1) return 'меньше секунды';
  const fmt = (n, one, few, many) => `${n} ${ruPlural(n, one, few, many)}`;
  if (seconds < MIN) return fmt(Math.round(seconds), 'секунда', 'секунды', 'секунд');
  if (seconds < HOUR) return fmt(Math.round(seconds / MIN), 'минута', 'минуты', 'минут');
  if (seconds < DAY) return fmt(Math.round(seconds / HOUR), 'час', 'часа', 'часов');
  if (seconds < MONTH) return fmt(Math.round(seconds / DAY), 'день', 'дня', 'дней');
  if (seconds < YEAR) return fmt(Math.round(seconds / MONTH), 'месяц', 'месяца', 'месяцев');
  if (seconds < YEAR * 100) return fmt(Math.round(seconds / YEAR), 'год', 'года', 'лет');
  return 'столетия';
}

/**
 * Оценка стойкости пароля.
 * Возвращает { score 0–4, label, warning, suggestions[], online{seconds,display}, offline{seconds,display} }
 * или null для пустого пароля.
 */
export function assessStrength(password, userInputs = []) {
  if (!password) return null;
  const r = getEstimator().check(password, userInputs);
  const online = r.crackTimes.onlineNoThrottlingXPerSecond.seconds;
  const offline = r.crackTimes.offlineFastHashingXPerSecond.seconds;
  return {
    score: r.score,
    label: SCORE_LABELS[r.score],
    warning: r.feedback.warning || '',
    suggestions: r.feedback.suggestions || [],
    online: { seconds: online, display: formatDuration(online) },
    offline: { seconds: offline, display: formatDuration(offline) },
  };
}
