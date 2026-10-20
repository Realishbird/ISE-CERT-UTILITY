'use strict';

const csrfToken = document.querySelector('meta[name="csrf-token"]')?.content || '';
const $ = (selector, root = document) => root.querySelector(selector);
const $$ = (selector, root = document) => Array.from(root.querySelectorAll(selector));
const bound = (name) => $$(`[data-bind="${name}"]`);

let toastTimer;
function toast(text, isError = false) {
  const el = $('#toast');
  if (!el) return;
  el.textContent = text;
  el.classList.toggle('is-error', isError);
  el.hidden = false;
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => { el.hidden = true; }, isError ? 9000 : 4500);
}

async function api(path, data = new FormData()) {
  const response = await fetch(path, {
    method: 'POST',
    body: data,
    credentials: 'same-origin',
    headers: { 'X-CSRF-Token': csrfToken },
  });
  let body = {};
  try { body = await response.json(); } catch { /* non-JSON error page */ }
  if (response.status === 401) {
    window.location.href = body.login || '/login';
    throw new Error('Your session expired.');
  }
  if (!response.ok) throw new Error(body.error || 'The request failed. Reload the page and try again.');
  return body;
}

async function withBusy(button, task) {
  button.disabled = true;
  button.setAttribute('aria-busy', 'true');
  try { return await task(); } finally {
    button.disabled = false;
    button.removeAttribute('aria-busy');
  }
}

/* Confirmation dialog */
const CONFIRM = {
  renew: {
    title: 'Renew and deploy',
    text: 'If a new certificate is installed with the Admin role, ISE restarts its application services. The admin GUI and portals are unavailable for several minutes.',
    accept: 'Renew and deploy',
    force: true,
  },
  deploy: {
    title: 'Deploy current certificate',
    text: 'If ISE is not already serving this certificate it will be imported now. With the Admin role, ISE restarts its application services.',
    accept: 'Deploy',
  },
};

function confirmDialog({ title, text, accept = 'Continue', force = false }) {
  const dialog = $('#confirm-dialog');
  if (!dialog || typeof dialog.showModal !== 'function') {
    return Promise.resolve(window.confirm(text) ? { force: false } : null);
  }
  $('#confirm-title').textContent = title;
  $('#confirm-text').textContent = text;
  $('#confirm-accept').textContent = accept;
  $('#confirm-force-row').hidden = !force;
  $('#confirm-force').checked = false;
  dialog.returnValue = '';
  dialog.showModal();
  return new Promise((resolve) => {
    dialog.addEventListener('close', () => {
      resolve(dialog.returnValue === 'confirm' ? { force: $('#confirm-force').checked } : null);
    }, { once: true });
  });
}

/* Settings and account forms */
$$('form[data-api]').forEach((form) => {
  form.addEventListener('submit', async (event) => {
    event.preventDefault();
    const button = event.submitter || $('button[type="submit"]', form);
    await withBusy(button, async () => {
      try {
        const result = await api(form.dataset.api, new FormData(form));
        $$('input[type="password"], textarea', form).forEach((input) => { input.value = ''; });
        toast(result.message || 'Saved.');
        if (result.redirect) setTimeout(() => { window.location.href = result.redirect; }, 900);
      } catch (error) {
        toast(error.message, true);
      }
    });
  });
});

/* Simple POST buttons (tests, clear marker) */
$$('[data-post]').forEach((button) => {
  button.addEventListener('click', async () => {
    if (button.dataset.confirmText) {
      const ok = await confirmDialog({ title: 'Confirm', text: button.dataset.confirmText });
      if (!ok) return;
    }
    const form = button.closest('form');
    const data = 'includeForm' in button.dataset && form ? new FormData(form) : new FormData();
    await withBusy(button, async () => {
      try {
        const result = await api(button.dataset.post, data);
        toast(result.message || 'Done.');
        refresh();
      } catch (error) {
        toast(error.message, true);
      }
    });
  });
});

/* Operations */
$$('[data-action]').forEach((button) => {
  button.addEventListener('click', async () => {
    const data = new FormData();
    data.set('action', button.dataset.action);
    const prompt = CONFIRM[button.dataset.confirm];
    if (prompt) {
      const answer = await confirmDialog(prompt);
      if (!answer) return;
      data.set('confirm', 'yes');
      if (answer.force) data.set('force', 'yes');
    }
    await withBusy(button, async () => {
      try {
        const result = await api('/api/action', data);
        toast(result.message);
        await refresh();
      } catch (error) {
        toast(error.message, true);
      }
    });
  });
});

/* Certificate export */
const exportKind = $('#export-kind');
if (exportKind) {
  exportKind.addEventListener('change', () => {
    $('#export-form').action = `/download/${exportKind.value}`;
  });
  $('#export-form').addEventListener('submit', () => {
    setTimeout(() => $$('#export-form input[type="password"]').forEach((input) => { input.value = ''; }), 500);
  });
}

/* Time zone suggestions */
const tzList = $('#tz-list');
if (tzList && Intl.supportedValuesOf) {
  for (const zone of Intl.supportedValuesOf('timeZone')) {
    const option = document.createElement('option');
    option.value = zone;
    tzList.append(option);
  }
}

/* Live status */
const LABELS = { queued: 'Queued', running: 'Running', succeeded: 'Succeeded', failed: 'Failed', interrupted: 'Interrupted' };
const dateFormat = new Intl.DateTimeFormat(undefined, { dateStyle: 'medium' });
const dateTimeFormat = new Intl.DateTimeFormat(undefined, { dateStyle: 'medium', timeStyle: 'short' });
const relative = new Intl.RelativeTimeFormat(undefined, { numeric: 'auto' });

function ago(seconds) {
  const delta = seconds * 1000 - Date.now();
  const abs = Math.abs(delta);
  if (abs < 60e3) return relative.format(Math.round(delta / 1e3), 'second');
  if (abs < 3600e3) return relative.format(Math.round(delta / 60e3), 'minute');
  if (abs < 86400e3) return relative.format(Math.round(delta / 3600e3), 'hour');
  return relative.format(Math.round(delta / 86400e3), 'day');
}

function setText(name, text) { bound(name).forEach((el) => { el.textContent = text; }); }
function setTone(name, tone) {
  bound(name).forEach((el) => {
    el.classList.remove('is-ok', 'is-warn', 'is-bad');
    if (tone) el.classList.add(`is-${tone}`);
  });
}
function setStatus(name, state) {
  bound(name).forEach((el) => {
    el.className = `status${state ? ` status-${state}` : ''}`;
    el.textContent = LABELS[state] || 'Idle';
  });
}

function renderCertificate(cert, renewDays) {
  if (!cert.present) {
    setText('cert-days', 'Not issued');
    setText('cert-expiry', 'Run Renew and deploy to request one');
    setTone('cert-days', 'warn');
    bound('cert-meter').forEach((el) => { el.style.width = '0'; });
    return;
  }
  if (cert.error) {
    setText('cert-days', 'Unreadable');
    setText('cert-expiry', cert.error);
    setTone('cert-days', 'bad');
    return;
  }
  const tone = cert.days <= 7 ? 'bad' : cert.days <= renewDays ? 'warn' : 'ok';
  setText('cert-days', `${cert.days} days left`);
  setText('cert-expiry', `Expires ${dateFormat.format(new Date(cert.expires))} · ${cert.issuer_cn}`);
  setTone('cert-days', tone);
  bound('cert-meter').forEach((el) => {
    el.style.width = `${Math.max(2, Math.min(100, (cert.days / cert.lifetime_days) * 100))}%`;
    el.className = tone === 'ok' ? '' : `is-${tone}`;
  });
}

function renderIse(ise, cert) {
  if (!ise.checked_at) {
    setText('ise-state', 'Not checked');
    setText('ise-meta', 'Run Check ISE to read the current state');
    setTone('ise-state', null);
    return;
  }
  const current = cert.present && ise.admin_fingerprint === cert.fingerprint;
  const deployed = ise.deployed || current;
  setText('ise-state', deployed ? 'Serving current' : 'Out of date');
  setTone('ise-state', deployed ? 'ok' : 'warn');
  setText('ise-meta', `Node ${ise.node} · checked ${ago(ise.checked_at)}`);
}

function renderSchedule(schedule) {
  if (!schedule.enabled) {
    setText('sched-state', 'Manual');
    setText('sched-meta', 'Automatic renewal is off');
    setTone('sched-state', null);
    return;
  }
  setText('sched-state', schedule.in_window ? 'In window' : 'Scheduled');
  setTone('sched-state', 'ok');
  const last = schedule.last && schedule.last.started
    ? ` · last run ${ago(schedule.last.started)} (${LABELS[schedule.last.result] || schedule.last.result})` : '';
  const next = schedule.next ? `Next window ${dateTimeFormat.format(new Date(schedule.next))}` : 'No upcoming window';
  setText('sched-meta', next + last);
}

function renderHistory(items) {
  bound('history').forEach((tbody) => {
    tbody.replaceChildren();
    if (!items.length) {
      const row = tbody.insertRow();
      const cell = row.insertCell();
      cell.colSpan = 3;
      cell.className = 'empty';
      cell.textContent = 'No operations yet.';
      return;
    }
    for (const item of items) {
      const row = tbody.insertRow();
      const name = row.insertCell();
      name.textContent = item.label || item.action;
      if (item.scheduled) {
        const tag = document.createElement('span');
        tag.className = 'tag';
        tag.textContent = 'Scheduled';
        name.append(' ', tag);
      }
      if (item.message) {
        const sub = document.createElement('span');
        sub.className = 'cell-sub';
        sub.textContent = item.message;
        name.append(sub);
      }
      const state = document.createElement('span');
      state.className = `status status-${item.state}`;
      state.textContent = LABELS[item.state] || item.state;
      row.insertCell().append(state);
      const when = row.insertCell();
      when.className = 'nowrap';
      when.textContent = item.started ? ago(item.started) : '';
      when.title = item.started ? dateTimeFormat.format(new Date(item.started * 1000)) : '';
    }
  });
}

function renderJob(job, log) {
  const busy = ['queued', 'running'].includes(job.state);
  setStatus('job-state', job.state);
  setText('job-title', job.label || 'Current operation');
  setText('job-detail', job.action
    ? `${job.scheduled ? 'Scheduled' : 'Manual'} · started ${dateTimeFormat.format(new Date(job.started * 1000))}${job.message ? ` · ${job.message}` : ''}`
    : 'No operation has run yet.');
  bound('log').forEach((pre) => {
    const atBottom = pre.scrollHeight - pre.scrollTop - pre.clientHeight < 40;
    if (pre.textContent !== log) {
      pre.textContent = log || 'No output yet.';
      if (atBottom) pre.scrollTop = pre.scrollHeight;
    }
  });
  $$('[data-action]').forEach((button) => {
    if (!button.hasAttribute('aria-busy')) button.disabled = busy;
  });
  return busy;
}

let pollTimer;
async function refresh() {
  if (!$('[data-poll]')) return;
  clearTimeout(pollTimer);
  let busy = false;
  try {
    const response = await fetch('/api/status', { credentials: 'same-origin' });
    if (response.status === 401) { window.location.href = '/login'; return; }
    if (!response.ok) throw new Error();
    const data = await response.json();
    renderCertificate(data.certificate, data.renew_days);
    renderIse(data.ise || {}, data.certificate);
    renderSchedule(data.schedule);
    renderHistory(data.history || []);
    busy = renderJob(data.job || {}, data.log || '');
    bound('pending').forEach((el) => { el.hidden = !(data.pending && data.pending.fingerprint); });
  } catch {
    setStatus('job-state', null);
    setText('job-state', 'Status unavailable');
  }
  pollTimer = setTimeout(refresh, busy ? 2000 : 10000);
}
refresh();
