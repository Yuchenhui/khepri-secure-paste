'use strict';

const $ = (id) => document.getElementById(id);
// The server accepts 100000..1000000; the top of that range is what a stolen
// paste plus a stolen key has to brute force, so new pastes use the ceiling.
// Pastes created earlier keep the count they were made with.
const ITERATIONS = 1000000;
const MAX_FILE_BYTES = 256 * 1024;
// Same ceiling as core.js MAX_BODY. The request is pure ASCII (base64url), so
// string length and byte length agree and the check can run before sending.
const MAX_REQUEST_BYTES = 1024 * 1024;
const FILE_MARKER = 'KHEPRI-FILE 1';
const SHORTENER = '__SHORTENER__';
const MAX_TTL_S = Number('__MAX_TTL_S__');
let createErrorTimer;
const TTL_CHOICES = [
  { seconds: 3600, label: '1 hour' },
  { seconds: 6 * 3600, label: '6 hours' },
  { seconds: 24 * 3600, label: '24 hours' },
  { seconds: 3 * 86400, label: '3 days' },
  { seconds: 7 * 86400, label: '7 days' },
];

// The server env is the ceiling on any paste's life, so the form only offers
// lifetimes it will accept; the longest allowed one stays selected by default.
function fillExpiry() {
  const cap = Number.isFinite(MAX_TTL_S) && MAX_TTL_S >= 60 ? MAX_TTL_S : 86400;
  const select = $('ttl');
  const choices = TTL_CHOICES.filter((choice) => choice.seconds <= cap);
  if (!choices.length) {
    const label = cap % 3600 === 0 ? cap / 3600 + ' hours' : Math.round(cap / 60) + ' minutes';
    choices.push({ seconds: cap, label });
  }
  for (const choice of choices) {
    const option = document.createElement('option');
    option.value = String(choice.seconds);
    option.textContent = choice.label;
    select.append(option);
  }
  select.value = String(choices[choices.length - 1].seconds);
}
fillExpiry();

const lengthSlider = $('len');
function updateLengthLabel() {
  $('lenValue').value = lengthSlider.value;
}
lengthSlider.addEventListener('input', updateLengthLabel);
window.addEventListener('pageshow', updateLengthLabel);

const editor = $('t');
const editorNumbers = $('editorNumbers');
const editorSource = editor.parentElement;
const autoWrap = $('autoWrap');
let editorLineCount = 1;

function syncLineScroll() {
  editorNumbers.style.transform = `translateY(${-editor.scrollTop}px)`;
}

function updateLineNumbers() {
  const count = editor.value.split('\n').length;
  if (count !== editorLineCount) {
    editorLineCount = count;
    editor.parentElement.style.setProperty('--line-digits', String(count).length);
    editorNumbers.textContent = Array.from({ length: count }, (_, i) => i + 1).join('\n');
  }
  syncLineScroll();
}

function updateWrap() {
  editor.wrap = autoWrap.checked ? 'soft' : 'off';
  editorSource.classList.toggle('wrap', autoWrap.checked);
}

const settingsKey = 'khepri:create-settings';
const settingsControls = ['ttl', 'reads', 'pin', 'len', 'autoWrap'].map($);

try {
  const saved = JSON.parse(localStorage.getItem(settingsKey));
  for (const control of settingsControls) {
    const value = saved?.[control.id];
    if (control.type === 'checkbox') {
      if (typeof value === 'boolean') control.checked = value;
    } else if (control.type === 'range') {
      if (Number.isInteger(value) && value >= Number(control.min) && value <= Number(control.max)) {
        control.value = String(value);
      }
    } else if (Array.from(control.options).some((option) => option.value === value)) {
      control.value = value;
    }
  }
} catch { /* Invalid or unavailable storage leaves the form defaults in place. */ }

updateLengthLabel();
updateWrap();
for (const control of settingsControls) {
  control.addEventListener('input', () => {
    const settings = Object.fromEntries(settingsControls.map((field) => [
      field.id, field.type === 'checkbox' ? field.checked : field.type === 'range' ? field.valueAsNumber : field.value,
    ]));
    try { localStorage.setItem(settingsKey, JSON.stringify(settings)); }
    catch { /* The form still works when the browser blocks storage. */ }
  });
}

editor.addEventListener('input', () => { updateLineNumbers(); updateSize(); });
editor.addEventListener('scroll', syncLineScroll);
autoWrap.addEventListener('change', updateWrap);
window.addEventListener('pageshow', () => { updateWrap(); updateLineNumbers(); updateSize(); });

function b64u(buf) {
  const bytes = new Uint8Array(buf);
  let raw = '';
  for (let i = 0; i < bytes.length; i += 0x8000) {
    raw += String.fromCharCode(...bytes.subarray(i, i + 0x8000));
  }
  return btoa(raw).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function bytesToB64(bytes) {
  let raw = '';
  for (let i = 0; i < bytes.length; i += 0x8000) {
    raw += String.fromCharCode(...bytes.subarray(i, i + 0x8000));
  }
  return btoa(raw);
}

function formatBytes(n) {
  return n < 1024 ? n + ' B' : (n / 1024).toFixed(n < 10 * 1024 ? 1 : 0) + ' KB';
}

async function filePayload(file) {
  const bytes = new Uint8Array(await file.arrayBuffer());
  const meta = b64u(new TextEncoder().encode(JSON.stringify({
    name: file.name, type: file.type || '', size: bytes.length,
  })));
  return FILE_MARKER + '\n' + meta + '\n' + bytesToB64(bytes);
}

let attached = null;

// Live budget for the 1 MiB request cap. That cap is on bytes, not on
// characters, so the readout leads with what the user typed and then shows
// the encrypted weight: an emoji costs 4 bytes, a CJK character 3.
const sizeState = $('sizeState');

function countCodePoints(text) {
  let count = 0;
  for (let i = 0; i < text.length; i += 1) {
    const unit = text.charCodeAt(i);
    if (unit >= 0xD800 && unit <= 0xDBFF && i + 1 < text.length) {
      const next = text.charCodeAt(i + 1);
      if (next >= 0xDC00 && next <= 0xDFFF) i += 1;
    }
    count += 1;
  }
  return count;
}

// base64url length without padding, the same arithmetic the encoder uses.
function b64uLength(bytes) {
  return 4 * Math.ceil(bytes / 3) - ((3 - (bytes % 3)) % 3);
}

// Exactly the length of the JSON the form will send, so this warning and the
// server's 1 MiB cap agree byte for byte: ciphertext is plaintext plus the
// 16-byte GCM tag, and the remaining fields are built here with the values the
// form will really send.
function requestLength(plaintextBytes) {
  const reads = Number($('reads').value);
  const overhead = JSON.stringify({
    id: '0'.repeat(16), ct: '', iv: '0'.repeat(16), salt: '0'.repeat(11),
    claim: '0'.repeat(64), claimIv: '1'.repeat(16), claimHash: '0'.repeat(43),
    iterations: ITERATIONS, ttl: Number($('ttl').value), reads,
    burn: reads === 1, pinIp: $('pin').checked,
  }).length;
  return overhead + b64uLength(plaintextBytes + 16);
}

function updateSize() {
  const text = editor.value;
  const raw = attached ? attached.size : new TextEncoder().encode(text).byteLength;
  // A file travels as marker + metadata + base64 of the bytes, so it grows by
  // a third before encryption even starts.
  const plaintext = attached ? Math.ceil(raw / 3) * 4 + 160 : raw;
  const estimate = raw === 0 ? 0 : requestLength(plaintext);
  const over = estimate > MAX_REQUEST_BYTES;
  let label;
  if (attached) label = formatBytes(attached.size) + ' file';
  else {
    const chars = countCodePoints(text);
    label = chars.toLocaleString('en-US') + (chars === 1 ? ' character' : ' characters');
  }
  sizeState.textContent = label + ' · ' + formatBytes(estimate) + ' of ' +
    formatBytes(MAX_REQUEST_BYTES) + ' once encrypted' +
    (over ? ' — too large; trim it or attach a file' : '');
  sizeState.classList.toggle('over', over);
}

updateSize();

// A file travels as base64 text inside the same encrypted paste, so the
// server, the ciphertext format and the shortener all stay unchanged.
function setAttached(file) {
  attached = file;
  $('fileState').hidden = !file;
  $('file').value = '';
  editorSource.hidden = Boolean(file);
  $('wrapLabel').hidden = Boolean(file);
  editor.disabled = Boolean(file);
  if (!file) { updateSize(); return; }
  $('fileName').textContent = file.name;
  $('fileMeta').textContent = formatBytes(file.size) + (file.type ? ' · ' + file.type : '');
  setCreateError('');
  updateSize();
}

function attachFile(file) {
  if (!file) return;
  if (file.size > MAX_FILE_BYTES) {
    setCreateError('“' + file.name + '” is ' + file.size.toLocaleString('en-US') + ' B; the limit is ' +
      MAX_FILE_BYTES.toLocaleString('en-US') + ' B (' + formatBytes(MAX_FILE_BYTES) + ').');
    $('file').value = '';
    return;
  }
  setAttached(file);
}

// One file travels per paste: the payload is a single KHEPRI-FILE block, so a
// second file is refused instead of silently replacing or dropping the first.
function attachFrom(files) {
  const list = files ? Array.from(files) : [];
  if (list.length === 0) return;
  if (list.length > 1) {
    const extra = list.length - 1;
    setCreateError('One file per paste. Share ' +
      (extra === 1 ? 'the other file' : 'the other ' + extra + ' files') + ' as separate pastes.');
    $('file').value = '';
    return;
  }
  attachFile(list[0]);
}

$('pick').onclick = () => $('file').click();
$('file').onchange = () => attachFrom($('file').files);
$('dropFile').onclick = () => setAttached(null);

const editorBox = document.querySelector('.editor');
editorBox.addEventListener('dragover', (e) => {
  if (e.dataTransfer && Array.from(e.dataTransfer.types).includes('Files')) e.preventDefault();
});
editorBox.addEventListener('drop', (e) => {
  const files = e.dataTransfer && e.dataTransfer.files;
  if (!files || !files.length) return;
  e.preventDefault();
  attachFrom(files);
});

async function deriveKey(password, salt, keyBytes) {
  const passwordBytes = new TextEncoder().encode(password);
  // PrivateBin construction: random key bytes with the password appended.
  const material = new Uint8Array(keyBytes.length + passwordBytes.length);
  material.set(keyBytes, 0);
  material.set(passwordBytes, keyBytes.length);
  const km = await crypto.subtle.importKey('raw', material, 'PBKDF2', false, ['deriveKey']);
  return crypto.subtle.deriveKey(
    { name:'PBKDF2', salt, iterations:ITERATIONS, hash:'SHA-256' },
    km, { name:'AES-GCM', length:256 }, false, ['encrypt']);
}

// Digits in a different colour so y/O, 0/O and 1/l stay readable when the code
// is read off the screen or typed by hand.
function colorize(text) {
  const span = document.createElement('span');
  for (const ch of text) {
    if (/[0-9]/.test(ch)) {
      const digit = document.createElement('span');
      digit.className = 'digit';
      digit.textContent = ch;
      span.append(digit);
    } else span.append(ch);
  }
  return span;
}

function setMain(href, code) {
  $('openUrl').href = href;
  $('mainCode').replaceChildren(colorize(code || href));
  $('mainCode').classList.toggle('long', !code);
  $('shortOrigin').textContent = code ? href.slice(0, -code.length) : '';
  $('shortOrigin').hidden = !code;
  $('longWrap').hidden = !code;
  $('plateCap').textContent = code ? 'Short code' : 'Paste link';
}

function setState(text, isError) {
  const el = $('shortState');
  el.textContent = text;
  el.classList.toggle('err', Boolean(isError));
}

function setNote(text, isWarn) {
  const el = $('shortNote');
  el.textContent = text;
  el.className = text ? (isWarn ? 'note note--warn' : 'note') : '';
}

async function copyText(text) {
  try { await navigator.clipboard.writeText(text); }
  catch {
    const ta = document.createElement('textarea');
    ta.value = text;
    ta.style.position = 'fixed';
    ta.style.opacity = '0';
    document.body.appendChild(ta);
    ta.select();
    document.execCommand('copy');
    ta.remove();
  }
}

function wireCopy(btnId, getText) {
  $(btnId).onclick = async () => {
    const btn = $(btnId);
    await copyText(getText());
    const label = btnId === 'copyMain' ? 'Copy link' : 'Copy full link';
    clearTimeout(btn.copyTimer);
    btn.textContent = 'Copied';
    btn.copyTimer = setTimeout(() => { btn.textContent = label; }, 1400);
  };
}

wireCopy('copyMain', () => $('openUrl').href);
wireCopy('copyLong', () => $('longUrl').href);

// The encoder is vendored and fetched only when a code is asked for, so a page
// load that never shows a QR still downloads nothing beyond the HTML.
let qrLoading = null;

function loadQrEncoder() {
  if (typeof qrcode === 'function') return Promise.resolve();
  if (!qrLoading) {
    qrLoading = new Promise((resolve, reject) => {
      const el = document.createElement('script');
      el.src = '__QR_PATH__';
      el.onload = () => resolve();
      el.onerror = () => { qrLoading = null; reject(new Error('QR encoder failed to load')); };
      document.head.append(el);
    });
  }
  return qrLoading;
}

function drawQr(canvas, qr) {
  const count = qr.getModuleCount();
  const quiet = 4;
  const room = Math.max(160, Math.min(260, window.innerWidth - 96));
  const scale = Math.max(1, Math.floor(room / (count + quiet * 2)));
  const size = (count + quiet * 2) * scale;
  const dpr = Math.min(2, window.devicePixelRatio || 1);
  canvas.width = Math.round(size * dpr);
  canvas.height = Math.round(size * dpr);
  canvas.style.width = size + 'px';
  canvas.style.height = size + 'px';
  const ctx = canvas.getContext('2d');
  ctx.scale(dpr, dpr);
  ctx.fillStyle = '#ffffff';
  ctx.fillRect(0, 0, size, size);
  ctx.fillStyle = '#000000';
  for (let row = 0; row < count; row += 1) {
    for (let col = 0; col < count; col += 1) {
      if (qr.isDark(row, col)) {
        ctx.fillRect((col + quiet) * scale, (row + quiet) * scale, scale, scale);
      }
    }
  }
}

$('showQr').onclick = async () => {
  const box = $('qrBox');
  const button = $('showQr');
  if (!box.hidden) {
    box.hidden = true;
    button.setAttribute('aria-expanded', 'false');
    return;
  }
  const url = $('openUrl').href;
  if (!url || url === '#') return;
  try {
    await loadQrEncoder();
    if ($('openUrl').href !== url) return;
    const qr = qrcode(0, 'M');
    qr.addData(url);
    qr.make();
    drawQr($('qrCanvas'), qr);
    box.hidden = false;
    button.setAttribute('aria-expanded', 'true');
  } catch {
    if ($('openUrl').href === url) setCreateError('Could not load the QR encoder; the link still works.');
  }
};

async function shorten(longUrl, len) {
  const r = await fetch(SHORTENER + '/shorten', {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ url: longUrl, len }),
    signal: AbortSignal.timeout(5000),
  });
  const body = await r.text();
  if (!r.ok) throw new Error('HTTP ' + r.status + (body ? ' — ' + body.trim() : ''));
  return body.trim();
}

function setCreateError(message) {
  clearTimeout(createErrorTimer);
  const dismissFocused = document.activeElement === $('dismissCreateError');
  $('createError').textContent = message;
  const countdown = $('createErrorCountdown');
  if (!message) {
    countdown.textContent = '';
    if (dismissFocused) $('go').focus({ preventScroll: true });
    return;
  }
  const deadline = Date.now() + 5000;
  function tick() {
    const remaining = deadline - Date.now();
    if (remaining <= 0) {
      setCreateError('');
      return;
    }
    const seconds = Math.ceil(remaining / 1000);
    countdown.textContent = seconds + 's';
    createErrorTimer = setTimeout(tick, remaining - (seconds - 1) * 1000);
  }
  tick();
}

$('dismissCreateError').onclick = () => setCreateError('');

$('go').onclick = async () => {
  const btn = $('go');
  const file = attached;
  if (!file && !editor.value) {
    editor.focus();
    setCreateError('Write something, or attach a file.');
    return;
  }

  btn.disabled = true;
  btn.setAttribute('aria-busy', 'true');
  btn.textContent = 'Creating link';
  btn.prepend(makeSpinner());
  setCreateError('');

  try {
    const id = [...crypto.getRandomValues(new Uint8Array(8))]
      .map(b => b.toString(16).padStart(2, '0')).join('');
    const keyBytes = crypto.getRandomValues(new Uint8Array(32));
    const salt = crypto.getRandomValues(new Uint8Array(8));
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const password = $('pw').value;

    const key = await deriveKey(password, salt, keyBytes);
    const enc = new TextEncoder();
    const plaintext = file ? await filePayload(file) : $('t').value;
    const ct = await crypto.subtle.encrypt(
      { name: 'AES-GCM', iv, additionalData: enc.encode(id) }, key, enc.encode(plaintext));

    // The reader decrypts this token before the server releases the body.
    const proof = crypto.getRandomValues(new Uint8Array(32));
    const claimIv = crypto.getRandomValues(new Uint8Array(12));
    const claim = await crypto.subtle.encrypt(
      { name: 'AES-GCM', iv: claimIv, additionalData: enc.encode('claim:' + id) }, key, proof);
    const claimHash = await crypto.subtle.digest('SHA-256', proof);

    const payload = JSON.stringify({
        id, ct:b64u(ct), iv:b64u(iv), salt:b64u(salt),
        claim: b64u(claim), claimIv: b64u(claimIv), claimHash: b64u(claimHash), iterations: ITERATIONS,
        ttl: Number($('ttl').value), reads: Number($('reads').value),
        burn: Number($('reads').value) === 1, pinIp:$('pin').checked,
    });
    if (payload.length > MAX_REQUEST_BYTES) {
      throw new Error('this paste is ' + formatBytes(payload.length) + ' once encrypted; the limit is ' +
        formatBytes(MAX_REQUEST_BYTES) + '. Shorten the text or attach a smaller file.');
    }
    const r = await fetch('/api/paste', {
      method:'POST', headers:{'Content-Type':'application/json'},
      body: payload,
    });
    const j = await r.json();
    if (j.error) throw new Error(j.error);

    const longUrl = location.origin + '/?' + id + '#' + b64u(keyBytes);
    let href = longUrl;
    let code;
    let shortError = '';
    if (SHORTENER) {
      try {
        const short = await shorten(longUrl, Number($('len').value));
        code = new URL(short).pathname.split('/').pop();
        href = short;
      } catch (e) {
        shortError = 'Shorten failed — using the long link. ' + e.message;
      }
    }

    $('qrBox').hidden = true;
    $('showQr').setAttribute('aria-expanded', 'false');
    $('longWrap').open = false;
    $('longUrl').href = longUrl;
    $('longUrl').textContent = longUrl;
    $('longUrl').title = longUrl;

    setMain(href, code);
    setState(shortError, Boolean(shortError));
    setNote(code && !password
      ? 'No password set: the shortener holds the key from this link. Set a password if the content matters.'
      : '', true);
    $('out').hidden = false;
  } catch (e) {
    setCreateError('Could not create the paste: ' + e.message);
  } finally {
    btn.disabled = false;
    btn.removeAttribute('aria-busy');
    btn.textContent = 'Create link';
  }
};

function makeSpinner() {
  const sp = document.createElement('span');
  sp.className = 'bp-spinner';
  sp.setAttribute('aria-hidden', 'true');
  return sp;
}
