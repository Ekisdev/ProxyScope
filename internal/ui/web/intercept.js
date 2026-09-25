// Intercept view. Polls /api/intercept every 500ms (toggle state + list of held
// items). The editor's contents live in the DOM and are never touched by
// polling, so typing is not disturbed.
(() => {
  'use strict';
  const { $, el, fmtSize, statusClass, api, setConn } = window.PS;
  const POLL_MS = 500;

  const rowsEl = $('icpt-rows'), editorEl = $('icpt-editor');
  const rows = new Map();        // id -> {p, tr, cd}  (list rows, keyed by held-item id)
  let selectedId = null;
  let toggling = false;          // a settings PUT is in flight: don't let polls fight it
  let clockOffset = 0;           // server clock - browser clock, for accurate countdowns
  let current = null;            // {id, kind, getEdit()} of the item shown in the editor

  const emptyEditor = (msg) => {
    current = null;
    editorEl.replaceChildren(el('p', msg || 'Select a held item to inspect and edit it.', 'muted empty'));
  };

  // ---- polling ----
  async function poll() {
    try {
      const st = await api('/api/intercept');
      setConn(true);
      clockOffset = Date.parse(st.now) - Date.now();
      applyState(st);
    } catch (e) {
      setConn(false, e.message);
    }
    setTimeout(poll, POLL_MS);
  }

  function applyState(st) {
    if (!toggling) {
      $('icpt-req').checked = st.settings.request;
      $('icpt-resp').checked = st.settings.response;
    }
    $('icpt-info').textContent = st.timeoutSeconds > 0
      ? 'Held items auto-forward unmodified after ' + st.timeoutSeconds + 's'
      : 'No auto-forward timeout: held items wait until you act or the client disconnects';

    const badge = $('badge');
    badge.hidden = st.pending.length === 0;
    badge.textContent = st.pending.length;

    // Sync list rows with the pending set.
    const live = new Set(st.pending.map((p) => p.id));
    for (const [id, r] of rows) {
      if (!live.has(id)) { r.tr.remove(); rows.delete(id); }
    }
    for (const p of st.pending) {
      if (!rows.has(p.id)) addRow(p);
    }
    $('icpt-empty').hidden = st.pending.length > 0;

    // The selected item vanished: resolved elsewhere, timed out, or client gone.
    if (selectedId !== null && !live.has(selectedId)) {
      selectedId = null;
      emptyEditor('That item is no longer held (forwarded by the timeout, or the client disconnected).');
    }
    if (selectedId === null && st.pending.length > 0) select(st.pending[0].id);
    tick();
  }

  function addRow(p) {
    const tr = document.createElement('tr');
    const cd = el('td', '', 'countdown');
    const isResp = p.kind === 'response';
    const target = isResp ? p.status + '  ← ' + p.url : p.url;
    [p.id, isResp ? 'RESP' : 'REQ', p.method, target].forEach((v, i) => {
      const td = el('td', v);
      td.title = String(v);
      if (i === 1) td.className = isResp ? 'kind-resp' : 'kind-req';
      tr.appendChild(td);
    });
    tr.appendChild(cd);
    tr.addEventListener('click', () => select(p.id));
    if (p.id === selectedId) tr.classList.add('sel');
    rows.set(p.id, { p, tr, cd });
    rowsEl.appendChild(tr);
  }

  // Countdown labels, refreshed every second from the server-provided deadlines.
  function tick() {
    const now = Date.now() + clockOffset;
    for (const { p, cd } of rows.values()) {
      cd.textContent = p.expires ? Math.max(0, Math.ceil((Date.parse(p.expires) - now) / 1000)) + 's' : '—';
    }
  }
  setInterval(tick, 1000);

  // ---- editor ----
  async function select(id) {
    selectedId = id;
    rows.forEach((r, k) => r.tr.classList.toggle('sel', k === id));
    try {
      show(await api('/api/intercept/' + id));
    } catch (e) {
      if (selectedId === id) { selectedId = null; emptyEditor(e.status === 409 ? 'That item is no longer held.' : 'Failed to load: ' + e.message); }
    }
  }

  const field = (label, control) => {
    const wrap = el('label', null, 'field');
    wrap.append(el('span', label, 'field-label'), control);
    return wrap;
  };
  const input = (value, cls) => { const i = el('input', null, cls); i.type = 'text'; i.value = value; i.spellcheck = false; return i; };
  const area = (value, rows) => { const t = el('textarea'); t.value = value; t.rows = rows; t.spellcheck = false; t.wrap = 'off'; return t; };

  // bodyField returns {node, get} where get() is the edited text, or null when the body is not editable.
  function bodyField(b) {
    if (!b.editable) {
      const box = el('div', null, 'field');
      box.appendChild(el('span', 'Body (' + fmtSize(b.size) + ') — ' + (b.encoding === 'hex' ? 'binary: cannot be edited as text, forwarded unchanged' : 'too large to edit here, forwarded unchanged'), 'field-label'));
      if (b.size > 0) box.appendChild(el('pre', b.content));
      return { node: box, get: () => null };
    }
    const label = 'Body (' + fmtSize(b.size) + ')' + (b.decodedFrom ? ' — decoded from ' + b.decodedFrom + '; editing replaces it with plain text' : '');
    const t = area(b.content, 10);
    return { node: field(label, t), get: () => t.value };
  }

  function show(d) {
    const form = el('div', null, 'form');
    const isResp = d.kind === 'response';
    const head = el('div', null, 'detail-title');
    head.appendChild(el('span', '#' + d.id + '  ' + (isResp ? 'Response to ' + d.request.method + ' ' + d.request.url : 'Request'), 'title-text'));
    form.appendChild(head);

    let getEdit;
    if (!isResp) {
      const method = input(d.request.method, 'method-input'), url = input(d.request.url, 'url-input');
      const headers = area(d.request.headers, 10), body = bodyField(d.request.body);
      const line = el('div', null, 'row');
      line.append(field('Method', method), field('URL', url));
      form.append(line, field('Headers', headers), body.node);
      getEdit = () => ({ request: { method: method.value, url: url.value, headers: headers.value, body: body.get() } });
    } else {
      form.appendChild(el('p', 'The request above was sent; this is the upstream response, held before it reaches the client.', 'note'));
      const status = input(String(d.response.status), 'status-input');
      const headers = area(d.response.headers, 10), body = bodyField(d.response.body);
      form.append(field('Status code', status), field('Headers', headers), body.node);
      getEdit = () => ({ response: { status: parseInt(status.value, 10) || 0, headers: headers.value, body: body.get() } });
    }

    const msg = el('span', '', 'form-msg');
    const bar = el('div', null, 'actions');
    const mk = (text, cls, fn) => {
      const b = el('button', text, cls);
      b.addEventListener('click', async () => {
        bar.querySelectorAll('button').forEach((x) => { x.disabled = true; });
        msg.textContent = '';
        try { await fn(); } catch (e) { msg.textContent = e.message; if (e.status === 409) { selectedId = null; } }
        bar.querySelectorAll('button').forEach((x) => { x.disabled = false; });
      });
      return b;
    };
    const done = () => { rows.get(d.id)?.tr.remove(); rows.delete(d.id); selectedId = null; emptyEditor('Done.'); };
    bar.append(
      mk('Forward', 'primary', async () => { await api('/api/intercept/' + d.id + '/forward', { method: 'POST', json: {} }); done(); }),
      mk('Forward edited', 'primary', async () => { await api('/api/intercept/' + d.id + '/forward', { method: 'POST', json: getEdit() }); done(); }),
      mk('Drop', 'danger', async () => { await api('/api/intercept/' + d.id + '/drop', { method: 'POST' }); done(); }),
      msg);
    form.appendChild(bar);
    form.appendChild(el('p', 'Forward sends the original untouched. Forward edited sends the fields above (Content-Length is recalculated). Drop answers the client with a 403 error page.', 'note'));
    editorEl.replaceChildren(form);
    current = { id: d.id, kind: d.kind };
  }

  // ---- toggles ----
  async function pushSettings() {
    toggling = true;
    try {
      await api('/api/intercept/settings', { method: 'PUT', json: { request: $('icpt-req').checked, response: $('icpt-resp').checked } });
    } catch (e) {
      alert('Could not change intercept settings: ' + e.message);
    }
    toggling = false;
  }
  $('icpt-req').addEventListener('change', pushSettings);
  $('icpt-resp').addEventListener('change', pushSettings);

  poll();
})();
