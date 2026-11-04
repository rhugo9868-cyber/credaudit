// Генератор паролей. Использует криптографический генератор случайных чисел браузера
// (crypto.getRandomValues), а не Math.random(), который для паролей непригоден.

export const CHARSETS = {
  lower: 'abcdefghijklmnopqrstuvwxyz',
  upper: 'ABCDEFGHIJKLMNOPQRSTUVWXYZ',
  digits: '0123456789',
  symbols: '!@#$%^&*()-_=+[]{};:,.?',
};

const AMBIGUOUS = new Set('O0oIl1|'.split(''));

/**
 * Равномерное случайное целое от 0 до max-1.
 * Метод отбраковки: числа из «хвоста» диапазона отбрасываем, иначе малые значения выпадали бы чаще.
 */
export function randomInt(max, rng = globalThis.crypto) {
  if (!Number.isInteger(max) || max <= 0 || max > 2 ** 32) throw new RangeError('max должен быть целым от 1 до 2^32');
  const limit = Math.floor(2 ** 32 / max) * max;
  const buf = new Uint32Array(1);
  do {
    rng.getRandomValues(buf);
  } while (buf[0] >= limit);
  return buf[0] % max;
}

function pickChar(chars, rng) {
  return chars[randomInt(chars.length, rng)];
}

/** Перемешивание Фишера — Йетса на криптографическом генераторе. */
function shuffle(array, rng) {
  for (let i = array.length - 1; i > 0; i--) {
    const j = randomInt(i + 1, rng);
    [array[i], array[j]] = [array[j], array[i]];
  }
  return array;
}

function buildSets(opts) {
  const sets = [];
  for (const name of ['lower', 'upper', 'digits', 'symbols']) {
    if (!opts[name]) continue;
    let chars = CHARSETS[name].split('');
    if (opts.excludeAmbiguous) chars = chars.filter((ch) => !AMBIGUOUS.has(ch));
    sets.push(chars);
  }
  return sets;
}

/**
 * Генерирует пароль. Параметры: length (8–128), lower, upper, digits, symbols, excludeAmbiguous.
 * Из каждого выбранного набора в пароле гарантированно есть хотя бы один символ.
 */
export function generatePassword(opts = {}, rng = globalThis.crypto) {
  const o = { length: 16, lower: true, upper: true, digits: true, symbols: true, excludeAmbiguous: false, ...opts };
  const sets = buildSets(o);
  if (sets.length === 0) throw new Error('Выберите хотя бы один набор символов');
  if (!Number.isInteger(o.length) || o.length < Math.max(8, sets.length) || o.length > 128) {
    throw new RangeError('Длина пароля должна быть целым числом от 8 до 128');
  }
  const pool = sets.flat();
  const chars = sets.map((s) => pickChar(s, rng));
  while (chars.length < o.length) chars.push(pickChar(pool, rng));
  return shuffle(chars, rng).join('');
}

/** Размер алфавита для заданных параметров (нужен для оценки энтропии). */
export function poolSize(opts = {}) {
  const o = { lower: true, upper: true, digits: true, symbols: true, excludeAmbiguous: false, ...opts };
  return new Set(buildSets(o).flat()).size;
}

/** Энтропия в битах: длина × log2(размер алфавита). Это верхняя оценка для случайного пароля. */
export function estimateEntropyBits(length, pool) {
  return Math.round(length * Math.log2(pool));
}
