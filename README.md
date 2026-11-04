# CredAudit

Веб-сервис проверки **пароля, e-mail и номера телефона** на стойкость и утечки данных. Выдаёт рекомендации и общий **индекс безопасности 0–100**.

Проект выполнен в рамках дисциплины «Информационные технологии» (СПбГУТ, группа ИБ-2514).

## Как запустить (самый простой способ)

1. Установите Python 3.10 или новее с python.org (при установке отметьте «Add python.exe to PATH»).
2. **Windows:** дважды щёлкните `start.bat`. **Linux/macOS:** `./start.sh`.
3. Первый запуск скачает зависимости (1–2 минуты), затем сайт сам откроется по адресу http://localhost:8000.

Остановка: Ctrl+C в окне запуска. Вручную: `pip install -r backend/requirements.txt`, затем `python run.py`.

Без Python можно открыть только пароль и телефон: `npm start` (нужен Node.js) и адрес http://localhost:8000. Вкладка E-mail без серверной части работать не будет.

## Что умеет

| Раздел | Что делает | Куда уходят данные |
|---|---|---|
| Пароль | Оценка стойкости (zxcvbn-ts, русский словарь), время подбора, политики (Базовая / NIST / Строгая), проверка по HIBP Pwned Passwords, генератор | Только первые 5 символов SHA-1-хеша (k-анонимность) на api.pwnedpasswords.com |
| E-mail | Список утечек: название, год, какие данные раскрыты | На серверную часть сайта, оттуда в XposedOrNot (резерв: LeakCheck Public API). Адрес не сохраняется |
| Телефон | Корректность, страна, тип линии (libphonenumber-js), косвенный риск раскрытия | Никуда, всё в браузере |
| Итог | Индекс безопасности, оценка по разделам, «С чего начать», все рекомендации, печать в PDF | Никуда |

**Ограничения.** Прямого бесплатного легального сервиса «номер телефона — утечки» нет, поэтому риск для номера оценивается косвенно: по тому, раскрывались ли телефоны в утечках вашего e-mail. Оператор и регион библиотека не определяет, только страну и тип линии.

## Индекс безопасности

Оценки разделов (0–100) усредняются с весами: пароль 50, e-mail 30, телефон 20. Непроверенные разделы не учитываются. «Слабое звено»: индекс не выше самого слабого раздела больше чем на 40 баллов. Подробные формулы: `frontend/js/score.js` и блок «Как считается индекс» на вкладке «Итог». Границы: до 39 высокий риск, 40–64 средний, 65–84 хороший, от 85 отличный.

## Структура

```
run.py, start.bat, start.sh      запуск одной командой
backend/                         FastAPI: /api/email, /api/health, раздача сайта
  leaks.py                       запросы к XposedOrNot и LeakCheck, нормализация ответов
  ratelimit.py                   лимит запросов, кеш, хеширование адресов
  main.py                        приложение, заголовки безопасности
frontend/                        сайт без сборки (ES-модули, библиотеки лежат в vendor/)
  js/password.js policies.js generator.js   модуль 1
  js/email.js ui-email.js                   модуль 2
  js/phone.js ui-phone.js                   модуль 3
  js/score.js recommendations.js ui-report.js   индекс, правила, итог
  js/state.js                               общее хранилище результатов
tests/                           Node (npm test) и pytest
```

## Контракт данных

`state.results.password = { score, length, leakStatus, leakCount, policy }`
`state.results.email = { status: 'found'|'clean'|'error', source, count, breaches[{name,year,domain,dataClasses,records,passwordRisk}], exposedPasswords, exposedPhones, dataClassCounts[], riskLabel, message, cached }`
`state.results.phone = { ok, valid, possible, e164, international, country, countryName, type, typeLabel }`

Чтобы добавить рекомендацию, допишите правило в `RULES_*` в `recommendations.js`. Чтобы поменять расчёт индекса, правьте константы в `score.js`.

## Тесты

```
npm test              # 31 тест фронтенда (Node 20+)
pip install -r backend/requirements-dev.txt
python -m pytest      # 30 тестов серверной части
```

## Приватность и безопасность

- Пароль и телефон не покидают браузер (кроме 5 символов хеша пароля).
- Сервер не пишет e-mail в журналы, кеширует ответы по HMAC-хешу со случайным ключом, ограничивает частоту запросов (по умолчанию 10 в минуту на IP).
- Строгая CSP: без inline-скриптов и стилей, внешних CDN нет, соединения только на свой сервер и api.pwnedpasswords.com.

## Настройки (переменные окружения)

`CREDAUDIT_RATE_LIMIT_PER_MIN` (10), `CREDAUDIT_CACHE_TTL` (3600 с), `CREDAUDIT_TRUST_PROXY` (1, если сервис стоит за прокси), `CREDAUDIT_ALLOWED_ORIGINS` (для CORS, если сайт лежит отдельно), `CREDAUDIT_DOCS` (1 включает /docs).

## Публикация в интернете (необязательно)

Например, на Render: сборка `pip install -r backend/requirements.txt`, запуск `uvicorn backend.main:app --host 0.0.0.0 --port $PORT`. На бесплатном тарифе сервис «засыпает», первый запрос будет долгим.

## Условия внешних сервисов

- XposedOrNot: бесплатный API для личного и малообъёмного использования, при публичном запуске проверьте условия.
- LeakCheck Public API: при показе результатов нужна ссылка «Powered by LeakCheck» (сайт добавляет её сам).
- HIBP Pwned Passwords: открытый API с k-анонимностью.
- Библиотеки: zxcvbn-ts и libphonenumber-js (MIT), лицензии в `frontend/vendor/`.
