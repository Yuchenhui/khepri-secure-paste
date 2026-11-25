'use strict';

// The paste id is in the query string (sent to the server).
// The key is in the fragment (never sent to the server).
const id = location.search.slice(1);
const frag = location.hash.slice(1);
const FILE_MARKER = 'KHEPRI-FILE 1';
const SHORT_LINK_BASE = '__READER_SHORTENER__';

const $ = (x) => document.getElementById(x);

function b64uToBytes(s) {
  const b64 = s.replace(/-/g, '+').replace(/_/g, '/');
  const bin = atob(b64 + '='.repeat((4 - b64.length % 4) % 4));
  const a = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) a[i] = bin.charCodeAt(i);
  return a;
}

// File body: marker line, base64url JSON metadata line, base64 payload.
function parseFilePayload(text) {
  const head = FILE_MARKER + '\n';
  if (!text.startsWith(head)) return null;
  const metaEnd = text.indexOf('\n', head.length);
  if (metaEnd < 0) return null;
  let meta;
  try {
    meta = JSON.parse(new TextDecoder().decode(b64uToBytes(text.slice(head.length, metaEnd))));
  } catch { return null; }
  let bytes;
  try {
    bytes = b64uToBytes(text.slice(metaEnd + 1).replace(/\s+/g, ''));
  } catch { return null; }
  return {
    name: typeof meta.name === 'string' && meta.name ? meta.name : 'download',
    type: typeof meta.type === 'string' ? meta.type : '',
    size: bytes.length,
    bytes,
  };
}

function formatBytes(n) {
  return n < 1024 ? n + ' B' : (n / 1024).toFixed(n < 10 * 1024 ? 1 : 0) + ' KB';
}

function fileReadout(file) {
  // The sender controls the declared MIME type, so the blob is always handed
  // over as an opaque download: the browser must never treat a paste as HTML
  // or SVG and run it in this page's origin. The declared type stays a label.
  const url = URL.createObjectURL(new Blob([file.bytes], { type: 'application/octet-stream' }));

  const heading = document.createElement('h2');
  heading.textContent = 'Decrypted file';
  const save = document.createElement('a');
  save.className = 'button';
  save.href = url;
  save.download = file.name.replace(/[\\/:*?"<>|\u0000-\u001f]/g, '_').slice(0, 120) || 'download';
  save.textContent = 'Download';
  const bar = document.createElement('header');
  bar.className = 'readout-bar';
  bar.append(heading, save);

  const controls = document.createElement('div');
  controls.className = 'readout-controls';
  const copy = document.createElement('button');
  copy.className = 'button secondary';
  copy.type = 'button';
  copy.textContent = 'Copy';
  copy.onclick = async () => {
    try { await navigator.clipboard.writeText(file.bytes); }
    catch {
      const ta = document.createElement('textarea');
      ta.value = file.bytes;
      ta.style.position = 'fixed';
      ta.style.opacity = '0';
      document.body.appendChild(ta);
      ta.select();
      ta.remove();
    }
    copy.textContent = 'Copied';
    setTimeout(() => { copy.textContent = 'Copy'; }, 1400);
  };

  const name = document.createElement('p');
  name.className = 'file-name';
  name.textContent = file.name;
  const meta = document.createElement('p');
  meta.className = 'note';
  meta.textContent = formatBytes(file.size) + (file.type ? ' · ' + file.type : '');
  const card = document.createElement('div');
  card.className = 'file-card';
  card.append(name, meta);

  const section = document.createElement('section');
  section.className = 'panel readout';
  section.append(bar, card, controls);
  section.dataset.readout = 'file';
  return section;
}

// The core tells us which of the four reasons applies, so the reader can say
// something true instead of guessing.
async function missingPaste(status) {
  let reason = '';
  try { reason = (await (await fetch('/api/paste/' + id, { method: 'GET' })).text()).trim(); } catch { /* no detail */ }
  if (status === 429) return ['Too many requests', 'This address has been asking for too much. Give it a minute and try again.'];
  if (reason === 'expired') return ['Gone', 'It ran out of time.'];
  if (reason === 'pinned elsewhere') return ['Locked to another address', 'Only the first reader can open it.'];
  if (reason === 'wrong key') return ['Wrong password', 'That password did not open this paste. Try again, or ask for a new link.'];
  return ['Nothing here', 'It expired, was already read, or never existed.'];
}

// One message style for the whole site: a card floating at the top of the
// page, with a warning mark and a dismiss button. It never moves the page.
// The card speaks in three voices: neutral for progress, danger for a failure.
// Progress is not a warning, and the alert mark only belongs to a failure.
function setReadError(title, message, tone = 'danger') {
  $('readError').dataset.tone = tone;
  $('readErrorTitle').textContent = title || '';
  $('readErrorBody').textContent = message || '';
}

function wrapToggleFor(setWrap) {
  const box = document.createElement('input');
  box.type = 'checkbox';
  const label = document.createElement('label');
  label.className = 'readout-toggle';
  box.onchange = () => setWrap(box.checked);
  label.append(box, 'Auto wrap');
  return label;
}

function makeSpinner() {
  const sp = document.createElement('span');
  sp.className = 'bp-spinner';
  sp.setAttribute('aria-hidden', 'true');
  return sp;
}

// A single-read paste disappears on the first successful claim, so make the
// reader confirm before the claim is sent.
let confirmedOnce = false;

function askToReadOnce() {
  // Swaps the unlock panel only. Replacing the body here would strand the
  // references the rest of the flow still holds, and the password box would
  // outlive the paste it belongs to.
  const p = document.createElement('p');
  p.className = 'note';
  p.textContent = 'This paste allows one read. Opening it now deletes it from the server.';
  const go = document.createElement('button');
  go.className = 'button';
  go.type = 'button';
  go.textContent = 'Read once and destroy';
  go.onclick = () => { confirmedOnce = true; decrypt(); };
  const inner = document.createElement('div');
  inner.className = 'file-card';
  inner.append(p, go);
  const panel = document.createElement('section');
  panel.className = 'panel readout';
  panel.append(inner);
  // The confirmation sits between the password field and the button: the field
  // stays in the DOM because the confirmed run reads it again, and the Decrypt
  // button is replaced so there is exactly one way forward.
  const unlock = $('unlock');
  unlock.querySelector('.field').after(panel);
  $('go').replaceWith(document.createElement('span'));
}

function shortSpan(ms) {
  const minutes = Math.max(0, Math.round(ms / 60000));
  if (minutes < 60) return minutes + ' min';
  const hours = Math.round(minutes / 60);
  if (hours < 48) return hours + ' h';
  return Math.round(hours / 24) + ' days';
}

function lifetimeNote(meta) {
  const p = document.createElement('p');
  p.className = 'note';
  const parts = [];
  if (meta.reads === 1) parts.push('Single read: this paste is now deleted from the server.');
  else {
    if (meta.reads > 1) {
      const left = meta.reads - 1;
      parts.push(left + (left === 1 ? ' read left' : ' reads left'));
    } else if (meta.reads === 0) parts.push('No read limit.');
    if (Number.isFinite(meta.expires)) parts.push('Expires in ' + shortSpan(meta.expires - Date.now()) + '.');
  }
  p.textContent = parts.join(' ');
  return p;
}

// The button that started this, if it is still on the page. The burn
// confirmation replaces the panel, so the second run has no button to dress up.
function activeButton() {
  const btn = $('go');
  return btn && !btn.disabled ? btn : null;
}

async function decrypt() {
  setReadError();
  if (!/^[0-9a-f]{16}$/.test(id) || !/^[A-Za-z0-9_-]{43}$/.test(frag)) {
    setReadError('Malformed link', 'The id or the key is missing.');
    return;
  }

  const btn = activeButton();
  if (btn) {
    btn.disabled = true;
    // Fast requests keep the normal button appearance without allowing another submission.
    var busyTimer = setTimeout(() => {
      btn.setAttribute('aria-busy', 'true');
      btn.textContent = 'Decrypting';
      btn.prepend(makeSpinner());
    }, 250);
  } else {
    var busyTimer = null;
  }

  try {
    let d;
    try {
      const r = await fetch('/api/paste/' + id);
      if (!r.ok) { setReadError(...missingPaste(r.status)); return; }
      d = await r.json();
    } catch {
      setReadError('Network error', 'The request did not get through.');
      return;
    }

    if (d.reads === 1 && !confirmedOnce) { askToReadOnce(); return; }

    const enc = new TextEncoder();
    const passwordBytes = enc.encode($('pw').value);
    const keyBytes = b64uToBytes(frag);
    const salt = b64uToBytes(d.salt);
    // Same construction as the sender: random bytes ++ password.
    const material = new Uint8Array(keyBytes.length + passwordBytes.length);
    material.set(keyBytes, 0);
    material.set(passwordBytes, keyBytes.length);

    const km = await crypto.subtle.importKey('raw', material, 'PBKDF2', false, ['deriveKey']);
    const key = await crypto.subtle.deriveKey(
      { name:'PBKDF2', salt, iterations:d.iterations, hash:'SHA-256' },
      km, { name:'AES-GCM', length:256 }, false, ['decrypt']);

    const proof = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: b64uToBytes(d.claimIv), additionalData: enc.encode('claim:' + id) },
      key, b64uToBytes(d.claim));
    const encodedProof = btoa(String.fromCharCode(...new Uint8Array(proof)))
      .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');

    let envelope;
    try {
      const r = await fetch('/api/paste/' + id, {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ proof: encodedProof }),
      });
      if (!r.ok) {
        // A wrong password fails here, after the local decrypt of the claim
        // already succeeded; the server says so in the body.
        let why = '';
        try { why = (await r.json()).error; } catch { /* no detail */ }
        setReadError(...(why === 'wrong key'
          ? ['Wrong password', 'That password did not open this paste. Try again, or ask for a new link.']
          : missingPaste(r.status)));
        return;
      }
      envelope = await r.json();
    } catch {
      setReadError('Could not read it', 'It may already have been consumed.');
      return;
    }

    const pt = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: b64uToBytes(envelope.iv), additionalData: enc.encode(id) },
      key, b64uToBytes(envelope.ct));

    const plaintext = new TextDecoder().decode(pt);

    const file = parseFilePayload(plaintext);
    if (file) {
      const fileCard = fileReadout(file);
      const life = document.createElement('p');
      life.className = 'readout-life note';
      life.append(lifetimeNote(d));
      fileCard.append(life);
      showReadout(fileCard, fileCard.querySelector('a[download]'));
      return;
    }

    const pre = document.createElement('pre');
    pre.textContent = plaintext;   // textContent: every newline survives
    const setWrap = (wrap) => {
      pre.style.whiteSpace = wrap ? 'pre-wrap' : 'pre';
      pre.style.overflowWrap = wrap ? 'anywhere' : 'normal';
      pre.style.wordBreak = wrap ? 'break-all' : 'normal';
    };
    const numbers = document.createElement('pre');
    numbers.className = 'line-numbers';
    numbers.setAttribute('aria-hidden', 'true');
    numbers.textContent = Array.from({ length: plaintext.split('\n').length }, (_, i) => i + 1).join('\n');

    const source = document.createElement('div');
    source.className = 'readout-source';   // gains the wrap class when toggled
    source.tabIndex = 0;
    source.setAttribute('role', 'region');
    source.setAttribute('aria-label', 'Decrypted text');
    source.append(numbers, pre);

    const copy = document.createElement('button');
    copy.className = 'button secondary';
    copy.type = 'button';
    copy.textContent = 'Copy';
    copy.onclick = async () => {
      try { await navigator.clipboard.writeText(plaintext); }
      catch {
        const ta = document.createElement('textarea');
        ta.value = plaintext;
        ta.style.position = 'fixed';
        ta.style.opacity = '0';
        document.body.appendChild(ta);
        ta.select();
        document.execCommand('copy');
        ta.remove();
      }
      copy.textContent = 'Copied';
      setTimeout(() => { copy.textContent = 'Copy'; }, 1400);
    };

    const readout = document.createElement('section');
    readout.className = 'panel readout';
    const bar = document.createElement('header');
    bar.className = 'readout-bar';
    const heading = document.createElement('h2');
    heading.textContent = 'Decrypted content';
    bar.append(heading, copy);

    const controls = document.createElement('div');
    controls.className = 'readout-controls text-controls';
    controls.append(wrapToggleFor((on) => {
      setWrap(on);
      source.classList.toggle('wrap', on);
    }));
    readout.append(bar, controls, source);

    const life = document.createElement('p');
    life.className = 'readout-life note';
    life.append(lifetimeNote(d));
    readout.append(life);
    showReadout(readout, source);
  } catch {
    setReadError('Wrong password', 'Try again, or ask for a new link.');
  } finally {
    clearTimeout(busyTimer);
    if (btn) {
      btn.disabled = false;
      if (btn.hasAttribute('aria-busy')) {
        btn.removeAttribute('aria-busy');
        btn.textContent = 'Decrypt';
      }
    }
  }
}

function showReadout(readout, focusTarget) {
  // The password panel goes away the moment the paste is open: a decrypted
  // paste has no use for it, and the readout takes its place.
  const unlock = $('unlock');
  const moveFocus = unlock.contains(document.activeElement);
  $('pw').value = '';
  unlock.hidden = true;
  unlock.replaceWith(readout);
  setReadError();
  if (moveFocus) focusTarget.focus({ preventScroll: true });
}

$('dismissReadError').onclick = () => { setReadError(); $('pw').focus({ preventScroll: true }); };
$('go').onclick = decrypt;
$('pw').addEventListener('keydown', (e) => { if (e.key === 'Enter') decrypt(); });
$('pw').focus();

if (SHORT_LINK_BASE) {
  const form = $('shortLookup');
  const input = $('shortCode');
  form.hidden = false;

  input.addEventListener('input', () => { input.setCustomValidity(''); setReadError(); });
  form.addEventListener('submit', (event) => {
    event.preventDefault();
    const code = input.value.trim();
    if (!/^[A-Za-z0-9]{3,12}$/.test(code)) {
      input.setCustomValidity('Enter a 3–12 character code using letters and digits.');
      input.reportValidity();
      return;
    }
    // Ask the shortener first, so a code that does not resolve is explained on
    // this page instead of dumping the reader on a bare 404.
    input.disabled = true;
    setReadError('Checking that code…', '', 'neutral');
    const timer = setTimeout(() => setReadError('Still checking…', '', 'neutral'), 2000);
    (async () => {
      try {
        const r = await fetch(SHORT_LINK_BASE + '/' + code, {
          method: 'GET', redirect: 'manual', signal: AbortSignal.timeout(10000),
        });
        if (r.type === 'opaqueredirect' || (r.status >= 300 && r.status < 400 && r.headers.get('Location'))) {
          location.assign(SHORT_LINK_BASE + '/' + code);
          return;
        }
        if (r.status === 404) {
          setReadError('No paste under that code', 'It expired, or the code is wrong.');
          return;
        }
        if (r.status === 429) {
          setReadError('Too many requests', 'Wait a minute and try again.');
          return;
        }
        if (!r.ok) {
          setReadError('Short link service down', 'Try again in a moment.');
          return;
        }
        location.assign(SHORT_LINK_BASE + '/' + code);
      } catch {
        setReadError('Could not reach the short link service', 'Check the connection.');
      } finally {
        clearTimeout(timer);
        input.disabled = false;
        if (['Checking that code…', 'Still checking…'].includes($('readError').textContent)) {
          setReadError();
        }
      }
    })();
  });
}
