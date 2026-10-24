'use strict';

const $ = (id) => document.getElementById(id);

let current = null;
let pollTimer = null;
let polling = false;
let refreshSeq = 0;
let offline = false;
let lastDown = null;
let lastSampleAt = null;
let rates = [];
let toastTimer = null;
let targetFormDirty = false;
let wsFormDirty = false;

const LABEL_DIRECT = String.fromCharCode(84, 67, 80);
const LABEL_WS = 'WS';

function setStaticLabels() {
  $('badge-direct').textContent = LABEL_DIRECT;
  $('title-direct').textContent = 'کانال داده مستقیم';
  $('sub-direct').textContent = 'هر اتصالی که به اندپوینت عمومی (NodePort) برسد، عیناً به این آدرس پاس داده می‌شود.';
  $('note-direct').textContent = 'پروتکل روی خودِ سرور خارج اجرا می‌شود؛ این سرویس فقط کانال انتقال داده است و احراز هویت کاربر نهایی ندارد.';
  $('label-direct-host').textContent = 'هاست سرور خارج';
  $('hint-direct-host').textContent = 'IP یا دامنه';
  $('label-direct-port').textContent = 'پورت سرور خارج';
  $('target-save').textContent = 'ذخیره مقصد';
  $('hint-direct-newonly').textContent = 'فقط اتصال‌های جدید';
  $('fine-direct').innerHTML = 'تغییر مقصد فقط روی اتصال‌های <b>جدید</b> اعمال می‌شود و با ری‌استارت سرویس از بین می‌رود؛ مقدار دائمی همان متغیرهای محیطی <code dir="ltr">EXT_HOST</code> و <code dir="ltr">EXT_PORT</code> در تنظیمات سرویس است.';

  $('badge-ws').textContent = LABEL_WS;
  $('title-ws').textContent = 'مسیر استریم';
  $('sub-ws').textContent = 'ترافیک مسیر استریم از مسیر مخفی سرویس گرفته و به این مقصد پاس داده می‌شود.';
  $('note-ws').textContent = 'مسیر استریم فقط وقتی فعال است که پورت مقصد آن تنظیم شده باشد؛ خودِ مسیر از متغیر محیطی SVC_PATH خوانده می‌شود و از پنل قابل تغییر نیست. وضعیت «reachable» در این کارت یعنی قابل اتصال بودن پورت مقصد استریم.';
  $('label-ws-host').textContent = 'هاست سرور خارج';
  $('hint-ws-host').textContent = 'IP یا دامنه';
  $('label-ws-port').textContent = 'پورت مسیر استریم';
  $('ws-save').textContent = 'ذخیره مقصد استریم';
  $('hint-ws-newonly').textContent = 'فقط اتصال‌های جدید';
  $('fine-ws').innerHTML = 'تغییر مقصد استریم فقط روی اتصال‌های <b>جدید</b> اعمال می‌شود و با ری‌استارت سرویس از بین می‌رود؛ مقدار دائمی همان متغیرهای محیطی <code dir="ltr">EXT_HOST</code> و <code dir="ltr">EXT_WPORT</code> در تنظیمات سرویس است.';
}

class ApiError extends Error {
  constructor(status, data) {
    super((data && data.error) || `HTTP ${status}`);
    this.status = status;
    this.data = data || {};
  }
}

async function api(path, options = {}) {
  const init = { credentials: 'same-origin', ...options };
  if (init.body !== undefined && typeof init.body !== 'string') {
    init.headers = { ...(init.headers || {}), 'Content-Type': 'application/json' };
    init.body = JSON.stringify(init.body);
  }
  const response = await fetch(path, init);
  let data = {};
  try {
    data = await response.json();
  } catch {}
  if (!response.ok) throw new ApiError(response.status, data);
  return data;
}

function formatBytes(value) {
  const number = Number(value);
  if (!Number.isFinite(number) || number <= 0) return '0 B';
  const units = ['B', 'KiB', 'MiB', 'GiB', 'TiB'];
  const index = Math.min(units.length - 1, Math.floor(Math.log(number) / Math.log(1024)));
  const scaled = number / 1024 ** index;
  const digits = scaled >= 100 ? 0 : scaled >= 10 ? 1 : 2;
  return `${scaled.toFixed(digits)} ${units[index]}`;
}

function formatDuration(totalSeconds) {
  const seconds = Math.max(0, Math.floor(Number(totalSeconds) || 0));
  const days = Math.floor(seconds / 86400);
  const hours = Math.floor((seconds % 86400) / 3600);
  const minutes = Math.floor((seconds % 3600) / 60);
  if (days > 0) return `${days}d ${hours}h`;
  if (hours > 0) return `${hours}h ${minutes}m`;
  if (minutes > 0) return `${minutes}m ${seconds % 60}s`;
  return `${seconds}s`;
}

function formatTime(timestamp) {
  return new Date(timestamp).toLocaleTimeString('fa-IR', { hour12: false });
}

function toast(message, tone = 'info') {
  const element = $('toast');
  element.textContent = message;
  element.dataset.tone = tone;
  element.classList.add('show');
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => element.classList.remove('show'), 3600);
}

function showLogin(message) {
  stopPolling();
  current = null;
  $('dash-view').hidden = true;
  $('login-view').hidden = false;
  const error = $('login-error');
  if (message) {
    error.textContent = message;
    error.hidden = false;
  } else {
    error.hidden = true;
  }
  const field = $('login-password');
  field.value = '';
  field.focus();
}

function showDash() {
  $('login-view').hidden = true;
  $('dash-view').hidden = false;
}

function drawSpark() {
  const line = $('spark-line');
  const area = $('spark-area');
  const spark = $('spark');
  const width = 240;
  const height = 64;
  const baseline = height - 6;

  const max = Math.max(...rates, 0);
  if (!rates.length || max <= 0) {
    const flat = `0,${baseline} ${width},${baseline}`;
    spark.classList.add('is-empty');
    line.setAttribute('points', flat);
    area.setAttribute('points', flat);
    return;
  }

  spark.classList.remove('is-empty');
  const step = rates.length > 1 ? width / (rates.length - 1) : width;
  const points = rates.map((rate, index) => {
    const x = index * step;
    const y = height - 6 - (rate / max) * (height - 14);
    return `${x.toFixed(1)},${y.toFixed(1)}`;
  });
  if (rates.length === 1) points.unshift(`0,${baseline}`);
  line.setAttribute('points', points.join(' '));
  area.setAttribute('points', [`0,${baseline}`, ...points, `${width},${baseline}`].join(' '));
}

function render(data) {
  current = data;
  const live = !data.paused;

  $('hero-title').textContent = live ? 'سرویس فعال است' : 'سرویس متوقف است';
  $('hero-note').textContent = live
    ? `اتصال‌ها روی پورت ${data.listen.dataPort} گرفته و مستقیم به ${data.target.host}:${data.target.port} پاس داده می‌شوند.`
    : 'سرویس در حالت توقف است؛ اتصال‌های جدید رد می‌شوند ولی اتصال‌های فعلی ادامه دارند.';
  $('top-status').textContent = live ? 'فعال' : 'متوقف';
  $('status-pill').dataset.state = live ? 'live' : 'paused';
  $('lamp').className = `lamp ${live ? 'live' : 'paused'}`;
  $('route').classList.toggle('is-paused', !live);
  $('uptime').textContent = formatDuration(data.uptimeSec);

  $('chip-data-port').textContent = `پورت داده ${data.listen.dataPort}`;
  $('chip-target').textContent = `${data.target.host}:${data.target.port}`;

  const streamChip = $('chip-stream');
  const stream = data.stream || null;
  if (stream && stream.enabled) {
    streamChip.hidden = false;
    $('chip-stream-text').textContent = `${stream.path} -> ${stream.host}:${stream.port}`;
  } else if (data.wsTarget) {
    streamChip.hidden = false;
    $('chip-stream-text').textContent = `${data.wsPath} -> ${data.wsTarget}`;
  } else {
    streamChip.hidden = true;
  }

  const toggle = $('btn-toggle');
  toggle.disabled = false;
  toggle.classList.toggle('is-paused', !live);
  $('toggle-label').textContent = live ? 'توقف سرویس' : 'فعال‌کردن سرویس';

  $('target-current').textContent = `${data.target.host}:${data.target.port}`;
  const reach = $('target-reach');
  if (data.remote.reachable) {
    reach.textContent = `reachable · ${data.remote.pingMs} ms`;
    reach.dataset.state = 'ok';
  } else {
    reach.textContent = 'unreachable';
    reach.dataset.state = 'err';
  }

  if (!targetFormDirty) {
    $('target-host').value = data.target.host;
    $('target-port').value = data.target.port;
  }

  const wsEnabled = !!(stream && stream.enabled);
  $('ws-current').textContent = wsEnabled ? `${stream.host}:${stream.port}` : '—';
  $('ws-path').textContent = stream ? stream.path : '—';
  const wsReach = $('ws-reach');
  if (!wsEnabled) {
    wsReach.textContent = 'disabled';
    wsReach.dataset.state = 'err';
  } else if (stream.reachable) {
    wsReach.textContent = `reachable · ${stream.pingMs} ms`;
    wsReach.dataset.state = 'ok';
  } else {
    wsReach.textContent = 'unreachable';
    wsReach.dataset.state = 'err';
  }
  if (!wsFormDirty) {
    $('ws-host').value = wsEnabled ? stream.host : '';
    $('ws-port').value = wsEnabled ? stream.port : '';
  }
  $('ws-host').disabled = !wsEnabled;
  $('ws-port').disabled = !wsEnabled;
  $('ws-save').disabled = !wsEnabled;

  $('stat-down').textContent = formatBytes(data.traffic.down);
  $('stat-up').textContent = formatBytes(data.traffic.up);
  $('stat-active').textContent = String(data.connections.active);
  $('stat-total').textContent = String(data.connections.total);
  $('traffic-hint').textContent = data.connections.rejected
    ? `${data.connections.rejected} اتصال رد شده`
    : 'مجموع این نشست';

  const max = data.connections.max || 1;
  $('limit-text').textContent = `${data.connections.active} / ${max}`;
  $('limit-bar').max = max;
  $('limit-bar').value = data.connections.active;

  const now = Date.now();
  if (lastDown === null) drawSpark();
  if (lastDown !== null && lastSampleAt !== null && now > lastSampleAt) {
    const rate = Math.max(0, data.traffic.down - lastDown) / ((now - lastSampleAt) / 1000);
    rates.push(rate);
    if (rates.length > 48) rates.shift();
    $('spark-rate').textContent = rate > 0 ? `${formatBytes(rate)}/s` : 'idle';
    drawSpark();
  }
  lastDown = data.traffic.down;
  lastSampleAt = now;

  const list = $('event-list');
  list.replaceChildren();
  for (const entry of data.events || []) {
    const item = document.createElement('li');
    const time = document.createElement('time');
    time.textContent = formatTime(entry.t);
    const message = document.createElement('span');
    message.className = entry.level || 'info';
    message.textContent = entry.message;
    item.append(time, message);
    list.append(item);
  }

  $('version').textContent = `v${data.version}`;
}

function renderConnections(connections) {
  const body = $('conn-body');
  body.replaceChildren();
  for (const conn of connections) {
    const row = document.createElement('tr');
    row.append(
      cell(conn.id, 'ltr'),
      cell(conn.client, 'ltr'),
      cell(conn.target, 'ltr target'),
      cell(conn.state === 'open' ? 'باز' : 'در حال اتصال'),
      cell(formatDuration(conn.ageSec), 'ltr'),
      cell(formatBytes(conn.bytesDown), 'ltr'),
      cell(formatBytes(conn.bytesUp), 'ltr'),
      killCell(conn)
    );
    body.append(row);
  }
  $('conn-count').textContent = `${connections.length} فعال`;
  $('conn-empty').hidden = connections.length > 0;
}

function cell(text, className) {
  const element = document.createElement('td');
  element.textContent = text;
  if (className) {
    element.className = className;
    if (className.includes('ltr')) element.dir = 'ltr';
  }
  return element;
}

function killCell(conn) {
  const element = document.createElement('td');
  const button = document.createElement('button');
  button.type = 'button';
  button.className = 'kill';
  button.dataset.id = conn.id;
  button.textContent = 'قطع';
  button.title = `قطع اتصال ${conn.id}`;
  element.append(button);
  return element;
}

function setOffline() {
  $('top-status').textContent = 'قطع';
  $('status-pill').dataset.state = 'offline';
  $('lamp').className = 'lamp offline';
  $('hero-title').textContent = 'سرویس در دسترس نیست';
  $('hero-note').textContent = 'ارتباط با کانتینر برقرار نشد؛ چند ثانیه دیگر دوباره تلاش می‌شود.';
  $('route').classList.add('is-paused');
  $('btn-toggle').disabled = true;
}

function stopPolling() {
  polling = false;
  clearTimeout(pollTimer);
}

async function refresh() {
  clearTimeout(pollTimer);
  const sequence = ++refreshSeq;
  try {
    const [status, conns] = await Promise.all([
      api('/api/status'),
      api('/api/connections'),
    ]);
    if (sequence !== refreshSeq || !polling) return;
    if (offline) {
      offline = false;
      toast('ارتباط با پنل برقرار شد.');
    }
    render(status);
    renderConnections(conns.connections);
  } catch (error) {
    if (error instanceof ApiError && error.status === 401) {
      showLogin('نشست شما تمام شده است؛ دوباره وارد شوید.');
      return;
    }
    if (sequence !== refreshSeq || !polling) return;
    if (!offline) {
      offline = true;
      setOffline();
    }
  } finally {
    if (polling && sequence === refreshSeq) {
      pollTimer = setTimeout(refresh, 2500);
    }
  }
}

function startPolling() {
  polling = true;
  refreshSeq++;
  refresh();
}

$('login-form').addEventListener('submit', async (event) => {
  event.preventDefault();
  const button = $('login-submit');
  const errorBox = $('login-error');
  button.disabled = true;
  errorBox.hidden = true;
  try {
    await api('/api/login', {
      method: 'POST',
      body: { password: $('login-password').value },
    });
    $('login-password').value = '';
    showDash();
    startPolling();
  } catch (error) {
    if (error instanceof ApiError && error.status === 429) {
      const secs = error.data.retryAfterSec || 600;
      errorBox.textContent = `تلاش‌های ناموفق زیاد بوده است؛ ${Math.ceil(secs / 60)} دقیقه دیگر دوباره تلاش کنید.`;
    } else if (error instanceof ApiError && error.status === 401) {
      errorBox.textContent = 'رمز عبور اشتباه است.';
    } else {
      errorBox.textContent = 'خطا در برقراری ارتباط با سرور.';
    }
    errorBox.hidden = false;
  } finally {
    button.disabled = false;
  }
});

$('btn-logout').addEventListener('click', async () => {
  try {
    await api('/api/logout', { method: 'POST' });
  } catch {}
  showLogin();
  toast('خارج شدید.');
});

$('btn-toggle').addEventListener('click', async () => {
  if (!current) return;
  const button = $('btn-toggle');
  button.disabled = true;
  try {
    const data = await api('/api/state', {
      method: 'POST',
      body: { paused: !current.paused },
    });
    render(data);
    toast(data.paused ? 'سرویس متوقف شد؛ اتصال‌های فعلی ادامه دارند.' : 'سرویس فعال شد.');
  } catch (error) {
    if (error instanceof ApiError && error.status === 401) return showLogin('نشست شما تمام شده است؛ دوباره وارد شوید.');
    toast('خطا در تغییر وضعیت سرویس.', 'error');
    button.disabled = false;
  }
});

$('target-form').addEventListener('submit', async (event) => {
  event.preventDefault();
  const host = $('target-host').value.trim();
  const port = Number($('target-port').value);
  if (!host || !Number.isInteger(port) || port < 1 || port > 65535) {
    toast('هاست یا پورت معتبر نیست.', 'error');
    return;
  }
  const button = $('target-save');
  button.disabled = true;
  try {
    const data = await api('/api/target', { method: 'POST', body: { host, port } });
    targetFormDirty = false;
    render(data);
    toast(`مقصد جدید برای اتصال‌های بعدی: ${host}:${port}`);
  } catch (error) {
    if (error instanceof ApiError && error.status === 401) return showLogin('نشست شما تمام شده است؛ دوباره وارد شوید.');
    toast('خطا در ذخیره مقصد.', 'error');
  } finally {
    button.disabled = false;
  }
});

for (const field of [$('target-host'), $('target-port')]) {
  field.addEventListener('input', () => {
    targetFormDirty = true;
  });
  field.addEventListener('blur', () => {
    if (current && $('target-host').value === current.target.host && Number($('target-port').value) === current.target.port) {
      targetFormDirty = false;
    }
  });
}

$('ws-form').addEventListener('submit', async (event) => {
  event.preventDefault();
  const host = $('ws-host').value.trim();
  const port = Number($('ws-port').value);
  if (!host || !Number.isInteger(port) || port < 1 || port > 65535) {
    toast('هاست یا پورت معتبر نیست.', 'error');
    return;
  }
  const button = $('ws-save');
  button.disabled = true;
  try {
    const data = await api('/api/stream-target', { method: 'POST', body: { host, port } });
    wsFormDirty = false;
    render(data);
    toast(`مقصد استریم برای اتصال‌های بعدی: ${host}:${port}`);
  } catch (error) {
    if (error instanceof ApiError && error.status === 401) return showLogin('نشست شما تمام شده است؛ دوباره وارد شوید.');
    if (error instanceof ApiError && error.data && error.data.error === 'stream_not_armed') {
      toast('مسیر استریم فعال نیست؛ اول پورت مقصد آن را در تنظیمات سرویس ست کنید.', 'error');
    } else {
      toast('خطا در ذخیره مقصد استریم.', 'error');
    }
  } finally {
    button.disabled = false;
  }
});

for (const field of [$('ws-host'), $('ws-port')]) {
  field.addEventListener('input', () => {
    wsFormDirty = true;
  });
  field.addEventListener('blur', () => {
    if (current && current.stream && $('ws-host').value === current.stream.host && Number($('ws-port').value) === current.stream.port) {
      wsFormDirty = false;
    }
  });
}

$('conn-body').addEventListener('click', async (event) => {
  const button = event.target.closest('button.kill');
  if (!button) return;
  button.disabled = true;
  try {
    await api('/api/connections/kill', { method: 'POST', body: { id: button.dataset.id } });
    toast('اتصال قطع شد.');
    refresh();
  } catch (error) {
    if (error instanceof ApiError && error.status === 401) return showLogin('نشست شما تمام شده است؛ دوباره وارد شوید.');
    toast('خطا در قطع اتصال.', 'error');
    button.disabled = false;
  }
});

document.addEventListener('visibilitychange', () => {
  if (!document.hidden && polling) refresh();
});

setStaticLabels();

(async () => {
  try {
    const status = await api('/api/status');
    showDash();
    polling = true;
    render(status);
    try {
      const conns = await api('/api/connections');
      renderConnections(conns.connections);
    } catch {}
    pollTimer = setTimeout(refresh, 2500);
  } catch {
    showLogin();
  }
})();
