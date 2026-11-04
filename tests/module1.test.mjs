// Тесты модуля 1 (пароль), движка рекомендаций и генератора. Запуск: node --test tests/
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import vm from 'node:vm';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const here = path.dirname(fileURLToPath(import.meta.url));
const vendor = path.join(here, '..', 'frontend', 'vendor');

// Подключаем те же файлы библиотеки, что и браузер (они создают глобальный объект zxcvbnts).
const sandbox = {};
vm.createContext(sandbox);
for (const f of ['zxcvbn-ts-core.js', 'zxcvbn-ts-language-common.js', 'zxcvbn-ts-language-en.js']) {
  vm.runInContext(fs.readFileSync(path.join(vendor, f), 'utf8'), sandbox, { filename: f });
}
globalThis.zxcvbnts = sandbox.zxcvbnts;

const pw = await import('../frontend/js/password.js');
const pol = await import('../frontend/js/policies.js');
const gen = await import('../frontend/js/generator.js');
const rec = await import('../frontend/js/recommendations.js');

// ---------- SHA-1 и разбор ответа ----------
test('sha1Hex: известное значение для "password"', async () => {
  assert.equal(await pw.sha1Hex('password'), '5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8');
});

test('sha1Hex: кириллица считается по UTF-8', async () => {
  const h = await pw.sha1Hex('пароль');
  assert.match(h, /^[0-9A-F]{40}$/);
});

test('parseRangeResponse: CRLF, нули заполнения и мусорные строки', () => {
  const m = pw.parseRangeResponse('0018A45C4D1DEF81644B54AB7F969B88D65:3\r\n00D4F6E8FA6EECAD2A3AA415EEC418D38EC:0\r\nнет двоеточия\r\n\r\nABC:xx');
  assert.equal(m.get('0018A45C4D1DEF81644B54AB7F969B88D65'), 3);
  assert.equal(m.get('00D4F6E8FA6EECAD2A3AA415EEC418D38EC'), 0);
  assert.equal(m.size, 2);
});

// ---------- Проверка утечек с подменой сети ----------
const mockFetch = (body, ok = true, status = 200) => {
  const calls = [];
  const fn = async (url, init) => {
    calls.push({ url, init });
    return { ok, status, text: async () => body };
  };
  fn.calls = calls;
  return fn;
};

test('checkLeak: пароль найден, наружу уходит только 5 символов хеша', async () => {
  const fetchFn = mockFetch('1E4C9B93F3F0682250B6CF8331B7EE68FD8:10437277\r\n0000000000000000000000000000000000A:2');
  const r = await pw.checkLeak('password', fetchFn);
  assert.equal(r.status, 'found');
  assert.equal(r.count, 10437277);
  assert.equal(r.prefix, '5BAA6');
  assert.equal(fetchFn.calls.length, 1);
  assert.equal(fetchFn.calls[0].url, 'https://api.pwnedpasswords.com/range/5BAA6');
  // после адреса сервиса в запросе только 5 символов хеша — ни пароля, ни остальных 35 символов хеша
  assert.equal(fetchFn.calls[0].url.slice(pw.HIBP_RANGE_URL.length), '5BAA6');
  assert.equal(fetchFn.calls[0].init.headers['Add-Padding'], 'true');
});

test('checkLeak: хеш из строки заполнения (счётчик 0) не считается утечкой', async () => {
  const r = await pw.checkLeak('password', mockFetch('1E4C9B93F3F0682250B6CF8331B7EE68FD8:0'));
  assert.equal(r.status, 'clean');
  assert.equal(r.count, 0);
});

test('checkLeak: пароля нет в ответе', async () => {
  const r = await pw.checkLeak('password', mockFetch('AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA:5'));
  assert.equal(r.status, 'clean');
});

test('checkLeak: HTTP-ошибка и сбой сети дают status=error, а не «чисто»', async () => {
  const bad = await pw.checkLeak('password', mockFetch('', false, 503));
  assert.equal(bad.status, 'error');
  assert.equal(bad.count, null);
  const down = await pw.checkLeak('password', async () => { throw new Error('offline'); });
  assert.equal(down.status, 'error');
  assert.equal(down.count, null);
});

// ---------- Стойкость ----------
test('assessStrength: слабые и сильные пароли', () => {
  assert.equal(pw.assessStrength('password').score, 0);
  assert.ok(pw.assessStrength('P@ssw0rd2024').score <= 1);
  assert.ok(pw.assessStrength('vX9#kLq2!mTz8@Rw').score >= 3);
  assert.equal(pw.assessStrength(''), null);
});

test('assessStrength: русский пароль из словаря не получает завышенную оценку', () => {
  assert.ok(pw.assessStrength('пароль123').score <= 1);
});

test('assessStrength: замечания выводятся по-русски', () => {
  const r = pw.assessStrength('qwerty123');
  assert.match(r.warning + r.suggestions.join(' '), /[а-яё]/i);
});

test('formatDuration и ruPlural', () => {
  assert.equal(pw.formatDuration(0.2), 'меньше секунды');
  assert.equal(pw.formatDuration(1), '1 секунда');
  assert.equal(pw.formatDuration(3), '3 секунды');
  assert.equal(pw.formatDuration(11), '11 секунд');
  assert.equal(pw.formatDuration(21), '21 секунда');
  assert.equal(pw.formatDuration(120), '2 минуты');
  assert.equal(pw.formatDuration(3600 * 5), '5 часов');
  assert.equal(pw.formatDuration(86400 * 365 * 3), '3 года');
  assert.equal(pw.formatDuration(86400 * 365 * 150), 'столетия');
  assert.equal(pw.ruPlural(112, 'год', 'года', 'лет'), 'лет');
});

// ---------- Политики ----------
const ctx = (password, score, leakCount) => ({ password, length: [...password].length, score, leakCount });

test('политика «Строгая»: слабый пароль не проходит, сильный проходит', () => {
  const strict = pol.getPolicy('strict');
  assert.equal(pol.evaluatePolicy(strict, ctx('abc12345', 0, 0)).passed, false);
  const good = 'vX9#kLq2!mTz8@Rw';
  assert.equal(pol.evaluatePolicy(strict, ctx(good, pw.assessStrength(good).score, 0)).passed, true);
});

test('политика NIST: длина и утечки, состав не требуется', () => {
  const nist = pol.getPolicy('nist');
  assert.equal(pol.evaluatePolicy(nist, ctx('correct horse battery staple', 4, 0)).passed, true);
  assert.equal(pol.evaluatePolicy(nist, ctx('Short1!', 2, 0)).passed, false);
  assert.equal(pol.evaluatePolicy(nist, ctx('correct horse battery staple', 4, 12)).passed, false);
});

test('политика: если утечки не проверены, критерий null и итог «не подтверждено»', () => {
  const r = pol.evaluatePolicy(pol.getPolicy('nist'), ctx('correct horse battery staple', 4, null));
  assert.equal(r.unverified, true);
  assert.equal(r.passed, false);
});

// ---------- Генератор ----------
test('generatePassword: длина, наборы символов, по символу из каждого набора', () => {
  for (let i = 0; i < 200; i++) {
    const p = gen.generatePassword({ length: 12 });
    assert.equal(p.length, 12);
    assert.match(p, /[a-z]/);
    assert.match(p, /[A-Z]/);
    assert.match(p, /\d/);
    assert.match(p, /[^A-Za-z0-9]/);
  }
});

test('generatePassword: только выбранные наборы и без похожих символов', () => {
  for (let i = 0; i < 100; i++) {
    const p = gen.generatePassword({ length: 20, upper: false, symbols: false, excludeAmbiguous: true });
    assert.match(p, /^[a-z0-9]+$/);
    assert.doesNotMatch(p, /[O0oIl1|]/);
  }
});

test('generatePassword: ошибки при неверных параметрах', () => {
  assert.throws(() => gen.generatePassword({ lower: false, upper: false, digits: false, symbols: false }));
  assert.throws(() => gen.generatePassword({ length: 4 }));
  assert.throws(() => gen.generatePassword({ length: 500 }));
});

test('randomInt: границы и равномерность', () => {
  const counts = new Array(6).fill(0);
  for (let i = 0; i < 60000; i++) counts[gen.randomInt(6)]++;
  for (const c of counts) assert.ok(c > 9000 && c < 11000, `неравномерно: ${counts}`);
  assert.throws(() => gen.randomInt(0));
});

test('estimateEntropyBits: 16 символов из 94 ≈ 105 бит', () => {
  assert.equal(gen.estimateEntropyBits(16, 94), Math.round(16 * Math.log2(94)));
});

test('poolSize: учитывает выбранные наборы и исключение похожих символов', () => {
  assert.equal(gen.poolSize({ upper: false, digits: false, symbols: false }), 26);
  assert.ok(gen.poolSize({ excludeAmbiguous: true }) < gen.poolSize({}));
});

// ---------- Рекомендации ----------
test('recommend: пароль из утечки — критичная рекомендация первой', () => {
  const list = rec.recommend({ password: { score: 0, length: 8, leakStatus: 'found', leakCount: 5, policy: pol.evaluatePolicy(pol.getPolicy('basic'), ctx('password', 0, 5)) } });
  assert.equal(list[0].priority, 'critical');
  assert.match(list[0].text, /утечках/);
  assert.ok(list.some((x) => x.id === 'pwd-weak'));
});

test('recommend: надёжный пароль без утечек — есть «Хорошо», нет критичных', () => {
  const good = 'vX9#kLq2!mTz8@Rw';
  const s = pw.assessStrength(good).score;
  const list = rec.recommend({ password: { score: s, length: good.length, leakStatus: 'clean', leakCount: 0, policy: pol.evaluatePolicy(pol.getPolicy('strict'), ctx(good, s, 0)) } });
  assert.ok(list.some((x) => x.priority === 'good'));
  assert.ok(!list.some((x) => x.priority === 'critical' || x.priority === 'important'));
});

test('recommend: без результатов пароля правил нет', () => {
  assert.deepEqual(rec.recommend({}), []);
});
