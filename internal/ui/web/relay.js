// Relay view: generic TCP/UDP byte relay. Polls /api/relay every 500ms
// (targets, per-target intercept toggles, held chunks) like Intercept, and
// the session list every 2s (session history changes far less often than
// live traffic). Held-chunk editing works on plain hex text, not the
// offset/hex/ASCII dump used for read-only session chunk history.
(() => {
  'use strict';
  const { $, el, fmtSize, fmtTime, api, setConn } = window.PS;
  const PENDING_POLL_MS = 500;
  const SESSION_POLL_MS = 2000;

  const targetsEl = $('relay-targets'), pendingRows = $('relay-pending-rows'), sessionRows = $('relay-session-rows'), detailEl = $('relay-detail');
  let toggling = false; // a settings PUT is in flight: don't let polls fight it
  let clockOffset = 0;
  let selected = null; // {kind: 'pending'|'session', id}
  let pendingItems = new Map(); // id -> summary
  let lastSessions = [];

  // ---- toolbar: targets + per-target intercept toggles ----
  function renderTargets(targets) {
    if (toggling) return;
    targetsEl.replaceChildren();
    if (targets.length === 0) {
      targetsEl.appendChild(el('span', 'No relay targets configured (see -relay flag).', 'muted'));
      return;
    }
    for (const t of targets) {
      const box = el('span', null, 'relay-target');
      box.appendChild(el('b', t.name + ' ', 'kind-' + (t.protocol === 'tcp' ? 'req' : 'resp')));
      box.appendChild(el('span', '(' + t.protocol + ' ' + t.listen + ' → ' + t.upstream + ') ', 'muted hint'));
      const up = el('input'); up.type = 'checkbox'; up.checked = t.settings.up;
      const down = el('input'); down.type = 'checkbox'; down.checked = t.settings.down;
      const push = async () => {
        toggling = true;
        try {
          await api('/api/relay/targets/' + encodeURIComponent(t.name) + '/settings', { method: 'PUT', json: { up: up.checked, down: down.checked } });
        } catch (e) {
          alert('Could not change relay intercept settings: ' + e.message);
        }
        toggling = false;
      };
      up.addEventListener('change', push);
      down.addEventListener('change', push);
      const upLabel = el('label', null, 'hint'); upLabel.append(up, ' up ');
      const downLabel = el('label', null, 'hint'); downLabel.append(down, ' down ');
      box.append(upLabel, downLabel);
      targetsEl.appendChild(box);
    }
  }

  // ---- polling: state (targets + pending) ----
  async function pollState() {
    try {
      const st = await api('/api/relay');
      setConn(true);
      clockOffset = Date.parse(st.now) - Date.now();
      renderTargets(st.targets);
      applyPending(st.pending, st.timeoutSeconds);
    } catch (e) {
      setConn(false, e.message);
    }
    setTimeout(pollState, PENDING_POLL_MS);
  }

  function applyPending(list, timeoutSeconds) {
    const live = new Set(list.map((p) => p.id));
    for (const id of [...pendingItems.keys()]) {
      if (!live.has(id)) pendingItems.delete(id);
    }
    for (const p of list) pendingItems.set(p.id, p);
    renderPendingRows();
    $('relay-pending-empty').hidden = pendingItems.size > 0;
    if (selected && selected.kind === 'pending' && !live.has(selected.id)) {
      selected = null;
      showEmpty('That chunk is no longer held (forwarded, dropped, or timed out).');
    }
    tickCountdowns();
  }

  function renderPendingRows() {
    pendingRows.replaceChildren();
    const ids = [...pendingItems.keys()].sort((a, b) => a - b);
    for (const id of ids) {
      const p = pendingItems.get(id);
      const tr = document.createElement('tr');
      const cells = [p.id, p.target, p.direction.toUpperCase(), 'session #' + p.sessionId, fmtSize(p.size)];
      cells.forEach((v, i) => {
        const td = el('td', v);
        if (i === 2) td.className = p.direction === 'up' ? 'kind-req' : 'kind-resp';
        tr.appendChild(td);
      });
      const cd = el('td', '', 'countdown'); cd.dataset.expires = p.expires || '';
      tr.appendChild(cd);
      if (selected && selected.kind === 'pending' && selected.id === id) tr.classList.add('sel');
      tr.addEventListener('click', () => selectPending(id));
      pendingRows.appendChild(tr);
    }
  }

  function tickCountdowns() {
    const now = Date.now() + clockOffset;
    pendingRows.querySelectorAll('tr').forEach((tr) => {
      const cd = tr.querySelector('.countdown');
      if (!cd) return;
      cd.textContent = cd.dataset.expires ? Math.max(0, Math.ceil((Date.parse(cd.dataset.expires) - now) / 1000)) + 's' : '—';
    });
  }
  setInterval(tickCountdowns, 1000);

  // ---- polling: session history ----
  async function pollSessions() {
    try {
      lastSessions = await api('/api/relay/sessions');
      renderSessionRows(lastSessions);
    } catch (e) { /* connection status already reported by pollState */ }
    setTimeout(pollSessions, SESSION_POLL_MS);
  }

  function renderSessionRows(rows) {
    sessionRows.replaceChildren();
    for (const s of rows) {
      const tr = document.createElement('tr');
      const status = s.closedAt ? 'closed' : 'open';
      const cells = [s.id, s.target, s.protocol, s.clientAddr, fmtTime(s.openedAt), fmtSize(s.bytesUp), fmtSize(s.bytesDown), status];
      cells.forEach((v) => tr.appendChild(el('td', v)));
      if (s.error) tr.title = s.error;
      if (selected && selected.kind === 'session' && selected.id === s.id) tr.classList.add('sel');
      tr.addEventListener('click', () => selectSession(s.id));
      sessionRows.appendChild(tr);
    }
    $('relay-sessions-empty').hidden = rows.length > 0;
  }

  // ---- detail: held chunk editor ----
  const field = (label, control) => {
    const wrap = el('label', null, 'field');
    wrap.append(el('span', label, 'field-label'), control);
    return wrap;
  };
  const area = (value, rows) => { const t = el('textarea'); t.value = value; t.rows = rows; t.spellcheck = false; t.wrap = 'off'; t.style.fontFamily = 'var(--mono)'; return t; };

  function showEmpty(msg) {
    detailEl.replaceChildren(el('p', msg || 'Select a held chunk or a session to inspect it.', 'muted empty'));
  }

  async function selectPending(id) {
    selected = { kind: 'pending', id };
    renderPendingRows();
    try {
      showPendingEditor(await api('/api/relay/pending/' + id));
    } catch (e) {
      selected = null;
      showEmpty('That chunk is no longer held.');
    }
  }

  function showPendingEditor(p) {
    const form = el('div', null, 'form');
    const head = el('div', null, 'detail-title');
    head.appendChild(el('span', '#' + p.id + '  ' + p.direction.toUpperCase() + '  session #' + p.sessionId + '  (' + p.target + ')', 'title-text'));
    form.appendChild(head);
    form.appendChild(el('p', 'Held chunk, ' + fmtSize(p.size) + '. Edit the hex below (spaces/newlines are ignored) and Forward edited, or Forward as-is, or Drop.', 'note'));

    const hexArea = area(p.hex, 14);
    form.appendChild(field('Hex bytes', hexArea));

    const msg = el('span', '', 'form-msg');
    const bar = el('div', null, 'actions');
    const mk = (text, cls, fn) => {
      const b = el('button', text, cls);
      b.addEventListener('click', async () => {
        bar.querySelectorAll('button').forEach((x) => x.disabled = true);
        msg.textContent = '';
        try { await fn(); } catch (e) { msg.textContent = e.message; if (e.status === 409) selected = null; }
        bar.querySelectorAll('button').forEach((x) => x.disabled = false);
      });
      return b;
    };
    const done = () => { pendingItems.delete(p.id); renderPendingRows(); selected = null; showEmpty('Done.'); };
    bar.append(
      mk('Forward', 'primary', async () => { await api('/api/relay/pending/' + p.id + '/forward', { method: 'POST', json: {} }); done(); }),
      mk('Forward edited', 'primary', async () => { await api('/api/relay/pending/' + p.id + '/forward', { method: 'POST', json: { hex: hexArea.value } }); done(); }),
      mk('Drop', 'danger', async () => { await api('/api/relay/pending/' + p.id + '/drop', { method: 'POST' }); done(); }),
      msg);
    form.appendChild(bar);
    detailEl.replaceChildren(form);
  }

  // ---- detail: session chunk history ----
  async function selectSession(id) {
    selected = { kind: 'session', id };
    renderSessionRows(lastSessions); // reapply the "sel" highlight immediately, no need to refetch
    try {
      showSessionDetail(await api('/api/relay/sessions/' + id));
    } catch (e) {
      detailEl.replaceChildren(el('p', 'Failed to load session: ' + e.message, 'muted empty'));
    }
  }

  function showSessionDetail(d) {
    const frag = document.createDocumentFragment();
    const title = el('div', null, 'detail-title');
    title.appendChild(el('span', '#' + d.id + '  ' + d.target + ' (' + d.protocol + ')  ' + d.clientAddr + ' → ' + d.upstreamAddr, 'title-text'));
    frag.appendChild(title);
    if (d.error) frag.appendChild(el('div', d.error, 'error'));
    frag.appendChild(el('p', (d.closedAt ? 'Closed' : 'Open') + ' · ' + fmtSize(d.bytesUp) + ' up · ' + fmtSize(d.bytesDown) + ' down · ' + d.chunks.length + ' chunk(s)', 'note'));

    for (const c of d.chunks) {
      const box = el('div', null, 'pane');
      const notes = [fmtTime(c.timestamp), fmtSize(c.size)];
      if (c.edited) notes.push('edited');
      if (c.truncated) notes.push('TRUNCATED: only ' + fmtSize(c.stored) + ' stored' + (c.note ? ' — ' + c.note : ''));
      if (c.clipped) notes.push('display clipped');
      const h2 = el('h2', '#' + c.seq + ' ' + c.direction.toUpperCase());
      h2.className = c.direction === 'up' ? 'kind-req' : 'kind-resp';
      box.appendChild(h2);
      box.appendChild(el('p', notes.join(' · '), 'note'));
      box.appendChild(el('pre', c.hex));
      frag.appendChild(box);
    }
    detailEl.replaceChildren(frag);
  }

  pollState();
  pollSessions();
})();
