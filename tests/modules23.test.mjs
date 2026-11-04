import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import vm from 'node:vm';

vm.runInThisContext(fs.readFileSync('frontend/vendor/libphonenumber-js-max.js', 'utf8'));
const { checkEmail, isValidEmail, classLabel, uniqueLabels } = await import('../frontend/js/email.js');
const { analyzePhone, phoneExposureFromEmail } = await import('../frontend/js/phone.js');
const { computeSecurityIndex, scorePassword, scoreEmail, scorePhone, ratingFor } = await import('../frontend/js/score.js');
const { recommend, RULES } = await import('../frontend/js/recommendations.js');

const resp = (status, body) => ({ ok: status < 400, status, json: async () => body });

test('isValidEmail', () => {
  assert.ok(isValidEmail('a@b.co'));
  assert.ok(!isValidEmail('a@b'));
  assert.ok(!isValidEmail('a b@c.de'));
  assert.ok(!isValidEmail(''));
});

test('checkEmail: успех, ошибка сети, ответ не JSON, 429', async () => {
  let call;
  const ok = await checkEmail('a@b.co', async (url, init) => ((call = { url, init }), resp(200, { status: 'clean', count: 0 })), '');
  assert.equal(ok.status, 'clean');
  assert.equal(call.url, '/api/email');
  assert.equal(JSON.parse(call.init.body).email, 'a@b.co');
  const down = await checkEmail('a@b.co', async () => { throw new TypeError('x'); }, '');
  assert.equal(down.status, 'error');
  assert.match(down.message, /start\.bat/);
  const bad = await checkEmail('a@b.co', async () => ({ ok: false, status: 404, json: async () => { throw new Error(); } }), '');
  assert.equal(bad.status, 'error');
  const lim = await checkEmail('a@b.co', async () => resp(429, { status: 'error', message: 'лимит' }), '');
  assert.equal(lim.message, 'лимит');
  assert.equal((await checkEmail('nope', async () => assert.fail('no fetch'), '')).status, 'error');
});

test('метки категорий данных', () => {
  assert.equal(classLabel('Passwords'), 'Пароли');
  assert.equal(classLabel('Unknown thing'), 'Unknown thing');
  assert.deepEqual(uniqueLabels(['first_name', 'last_name', 'phone']), ['Имена', 'Номера телефонов']);
});

test('analyzePhone', () => {
  const lib = globalThis.libphonenumber;
  const a = analyzePhone('8 912 345-67-89', 'RU', lib);
  assert.ok(a.ok && a.valid);
  assert.equal(a.e164, '+79123456789');
  assert.equal(a.type, 'MOBILE');
  assert.equal(a.country, 'RU');
  assert.equal(analyzePhone('+7 000 000 00 00', 'RU', lib).valid, false);
  assert.equal(analyzePhone('abc', 'RU', lib).ok, false);
  assert.equal(analyzePhone('', 'RU', lib).reason, 'empty');
  assert.equal(analyzePhone('+1 202 555 0143', 'RU', lib).country, 'US');
});

test('phoneExposureFromEmail', () => {
  assert.equal(phoneExposureFromEmail(undefined), null);
  assert.equal(phoneExposureFromEmail({ status: 'error' }), null);
  assert.equal(phoneExposureFromEmail({ status: 'clean' }), false);
  assert.equal(phoneExposureFromEmail({ status: 'found', exposedPhones: true }), true);
  assert.equal(phoneExposureFromEmail({ status: 'found', exposedPhones: false }), false);
});

test('оценки разделов', () => {
  assert.equal(scorePassword({ score: 4, leakCount: 0, leakStatus: 'clean' }).score, 100);
  assert.equal(scorePassword({ score: 4, leakCount: 5, leakStatus: 'found' }).score, 10);
  assert.equal(scorePassword({ score: 4, leakCount: null, leakStatus: 'error' }).score, 70);
  assert.equal(scorePassword({ score: 0, leakCount: 0 }).score, 5);
  assert.equal(scoreEmail({ status: 'clean' }).score, 100);
  assert.equal(scoreEmail({ status: 'found', count: 2 }).score, 76);
  assert.equal(scoreEmail({ status: 'found', count: 20, exposedPasswords: true, exposedPhones: true }).score, 5);
  assert.equal(scoreEmail({ status: 'error' }), null);
  const ph = { valid: true, type: 'MOBILE' };
  assert.equal(scorePhone(ph, undefined).score, 80);
  assert.equal(scorePhone(ph, { status: 'clean' }).score, 100);
  assert.equal(scorePhone(ph, { status: 'found', exposedPhones: true }).score, 45);
  assert.equal(scorePhone({ valid: true, type: 'VOIP' }, undefined).score, 60);
  assert.equal(scorePhone({ valid: false }, undefined), null);
});

test('индекс: пусто, веса, слабое звено, границы', () => {
  assert.equal(computeSecurityIndex({}).index, null);
  const only = computeSecurityIndex({ password: { score: 4, leakCount: 0 } });
  assert.equal(only.index, 100);
  assert.equal(only.assessedCount, 1);
  const capped = computeSecurityIndex({
    password: { score: 4, leakCount: 3, leakStatus: 'found' },
    email: { status: 'clean' },
    phone: { valid: true, type: 'MOBILE' },
  });
  assert.equal(capped.capped, true);
  assert.equal(capped.index, 50); // слабое звено 10 + 40
  assert.equal(capped.weakest, 'password');
  assert.equal(ratingFor(39).label, 'Высокий риск');
  assert.equal(ratingFor(40).label, 'Средний риск');
  assert.equal(ratingFor(65).label, 'Хороший уровень');
  assert.equal(ratingFor(85).label, 'Отличный уровень');
  const invalid = computeSecurityIndex({ phone: { ok: true, valid: false }, email: { status: 'clean' } });
  assert.equal(invalid.categories.find((c) => c.id === 'phone').assessed, false);
});

test('рекомендации модулей 2 и 3', () => {
  const ids = (r) => recommend(r, RULES).map((x) => x.id);
  assert.ok(ids({ email: { status: 'found', count: 6, exposedPasswords: true } }).includes('email-passwords-leaked'));
  assert.ok(ids({ email: { status: 'found', count: 6 } }).includes('email-many'));
  assert.ok(ids({ email: { status: 'clean' } }).includes('email-clean'));
  assert.ok(ids({ email: { status: 'error', message: 'x' } }).includes('email-unchecked'));
  assert.ok(ids({ phone: { valid: true, type: 'MOBILE' }, email: { status: 'found', exposedPhones: true } }).includes('phone-exposed'));
  assert.ok(!ids({ phone: { valid: true, type: 'MOBILE' } }).includes('phone-exposed'));
  assert.ok(ids({ phone: { valid: true, type: 'VOIP' } }).includes('phone-voip'));
  assert.ok(ids({ email: { status: 'found', count: 1 }, password: { score: 1, leakCount: 0, length: 8 } }).includes('cross-email-weak-password'));
  assert.deepEqual(ids({}), []);
});
