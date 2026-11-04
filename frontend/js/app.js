// Точка входа: вкладки и запуск модулей.

import { $, showTab } from './ui-common.js';
import { initPassword, initGenerator } from './ui-password.js';
import { initEmail } from './ui-email.js';
import { initPhone } from './ui-phone.js';
import { initReport } from './ui-report.js';

document.querySelectorAll('.tab').forEach((btn) => btn.addEventListener('click', () => showTab(btn.dataset.tab)));

initPassword();
initGenerator();
initEmail();
initPhone();
initReport();
$('year') && ($('year').textContent = String(new Date().getFullYear()));
