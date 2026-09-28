// System Capture view (Phase 6): WinDivert-based system-level capture,
// off unless started with -syscapture. Polls /api/syscapture every 500ms
// (state + held packets) like Relay, and the session list every 2s. There
// is exactly one configured filter in this phase (unlike Relay's multiple
// named targets), so the toolbar is a single pair of intercept checkboxes,
// not a per-target list. "Out"/"In" match WinDivert's own
// outbound/inbound terminology (this machine's traffic leaving vs
// arriving), not client/upstream the way Relay's up/down are, since there
// is no fixed client/server role at this layer.
(() => {
  'use strict';
  const { $, el, fmtSize, fmtTime, api, setConn } = window.PS;
  const PENDING_POLL_MS = 500;
  const SESSION_POLL_MS = 2000;

  const disabledEl = $('sc-disabled'), enabledEl = $('sc-enabled');
  const filterEl = $('sc-filter'), elevatedEl = $('sc-elevated');
  const upBox = $('sc-up'), downBox = $('sc-down');
  const pendingRows = $('sc-pending-rows'), sessionRows = $('sc-session-rows'), detailEl = $('sc-detail');
  let toggling = false;
  let clockOffset = 0;
  let selected = null; // {kind: 'pending'|'session', id}
  let pendingItems = new Map();
  let lastSessions = [];
  let knownEnabled = null; // avoid re-wiring checkbox listeners on every poll

  async function pollState() {
    try {
      const st = await api('/api/syscapture');
      setConn(true);
      clockOffset = Date.parse(st.now) - Date.now();
      applyState(st);
    } catch (e) {
      setConn(false, e.message);
    }
    setTimeout(pollState, PENDING_POLL_MS);
  }

  function applyState(st) {
    disabledEl.hidden = st.enabled;
    enabledEl.hidden = !st.enabled;
    if (!st.enabled) return;

    if (knownEnabled !== true) {
      knownEnabled = true;
      const push = async () => {
        toggling = true;
        try {
          await api('/api/syscapture/settings', { method: 'PUT', json: { up: upBox.checked, down: downBox.checked } });
        } catch (e) {
          alert('Could not change system-capture intercept settings: ' + e.message);
        }
        toggling = false;
      };
      upBox.addEventListener('change', push);
      downBox.addEventListener('change', push);
    }

    filterEl.textContent = 'filter: ' + st.filter;
    elevatedEl.textContent = st.elevated ? '' : '(not elevated — WinDivertOpen will fail)';
    elevatedEl.className = st.elevated ? 'muted' : 'muted form-msg';
    if (!toggling) {
      upBox.checked = !!st.settings.up;
      downBox.checked = !!st.settings.down;
    }
    applyPending(st.pending || [], st.timeoutSeconds);
  }

  function applyPending(list, timeoutSeconds) {
    const live = new Set(list.map((p) => p.id));
    for (const id of [...pendingItems.keys()]) {
      if (!live.has(id)) pendingItems.delete(id);
    }
    for (const p of list) pendingItems.set(p.id, p);
    renderPendingRows();
    $('sc-pending-empty').hidden = pendingItems.size > 0;
    if (selected && selected.kind === 'pending' && !live.has(selected.id)) {
      selected = null;
      showEmpty('That packet is no longer held (forwarded, dropped, or timed out).');
    }
    tickCountdowns();
  }

  function renderPendingRows() {
    pendingRows.replaceChildren();
    const ids = [...pendingItems.keys()].sort((a, b) => a - b);
    for (const id of ids) {
      const p = pendingItems.get(id);
      const tr = document.createElement('tr');
      const dirLabel = p.direction === 'up' ? 'OUT' : 'IN';
      const cells = [p.id, dirLabel, 'session #' + p.sessionId, fmtSize(p.size)];
      cells.forEach((v, i) => {
        const td = el('td', v);
        if (i === 1) td.className = p.direction === 'up' ? 'kind-req' : 'kind-resp';
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

  async function pollSessions() {
    try {
      lastSessions = await api('/api/syscapture/sessions');
      renderSessionRows(lastSessions);
    } catch (e) { /* connection status already reported by pollState */ }
    setTimeout(pollSessions, SESSION_POLL_MS);
  }

  function renderSessionRows(rows) {
    sessionRows.replaceChildren();
    for (const s of rows) {
      const tr = document.createElement('tr');
      const status = s.closedAt ? 'closed' : 'open';
      const cells = [s.id, s.protocol, s.clientAddr, s.upstreamAddr, fmtTime(s.openedAt), fmtSize(s.bytesUp), fmtSize(s.bytesDown), status];
      cells.forEach((v) => tr.appendChild(el('td', v)));
      if (s.error) tr.title = s.error;
      if (selected && selected.kind === 'session' && selected.id === s.id) tr.classList.add('sel');
      tr.addEventListener('click', () => selectSession(s.id));
      sessionRows.appendChild(tr);
    }
    $('sc-sessions-empty').hidden = rows.length > 0;
  }

  const field = (label, control) => {
    const wrap = el('label', null, 'field');
    wrap.append(el('span', label, 'field-label'), control);
    return wrap;
  };
  const area = (value, rows) => { const t = el('textarea'); t.value = value; t.rows = rows; t.spellcheck = false; t.wrap = 'off'; t.style.fontFamily = 'var(--mono)'; return t; };

  function showEmpty(msg) {
    detailEl.replaceChildren(el('p', msg || 'Select a held packet or a session to inspect it.', 'muted empty'));
  }

  async function selectPending(id) {
    selected = { kind: 'pending', id };
    renderPendingRows();
    try {
      showPendingEditor(await api('/api/syscapture/pending/' + id));
    } catch (e) {
      selected = null;
      showEmpty('That packet is no longer held.');
    }
  }

  function showPendingEditor(p) {
    const form = el('div', null, 'form');
    const dirLabel = p.direction === 'up' ? 'OUT' : 'IN';
    const head = el('div', null, 'detail-title');
    head.appendChild(el('span', '#' + p.id + '  ' + dirLabel + '  session #' + p.sessionId, 'title-text'));
    form.appendChild(head);
    form.appendChild(el('p', 'Held packet payload, ' + fmtSize(p.size) + '. Edit the hex below (spaces/newlines are ignored) and Forward edited, or Forward as-is, or Drop. ' +
      'A TCP payload must keep exactly the same length as the original (see README); UDP payloads may change length freely.', 'note'));

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
      mk('Forward', 'primary', async () => { await api('/api/syscapture/pending/' + p.id + '/forward', { method: 'POST', json: {} }); done(); }),
      mk('Forward edited', 'primary', async () => { await api('/api/syscapture/pending/' + p.id + '/forward', { method: 'POST', json: { hex: hexArea.value } }); done(); }),
      mk('Drop', 'danger', async () => { await api('/api/syscapture/pending/' + p.id + '/drop', { method: 'POST' }); done(); }),
      msg);
    form.appendChild(bar);
    detailEl.replaceChildren(form);
  }

  async function selectSession(id) {
    selected = { kind: 'session', id };
    renderSessionRows(lastSessions);
    try {
      showSessionDetail(await api('/api/syscapture/sessions/' + id));
    } catch (e) {
      detailEl.replaceChildren(el('p', 'Failed to load session: ' + e.message, 'muted empty'));
    }
  }

  function showSessionDetail(d) {
    const frag = document.createDocumentFragment();
    const title = el('div', null, 'detail-title');
    title.appendChild(el('span', '#' + d.id + '  ' + d.protocol + '  ' + d.clientAddr + ' ↔ ' + d.upstreamAddr, 'title-text'));
    frag.appendChild(title);
    if (d.error) frag.appendChild(el('div', d.error, 'error'));
    frag.appendChild(el('p', (d.closedAt ? 'Closed' : 'Open') + ' · ' + fmtSize(d.bytesUp) + ' out · ' + fmtSize(d.bytesDown) + ' in · ' + d.chunks.length + ' packet(s)', 'note'));

    for (const c of d.chunks) {
      const box = el('div', null, 'pane');
      const notes = [fmtTime(c.timestamp), fmtSize(c.size)];
      if (c.edited) notes.push('edited');
      if (c.truncated) notes.push('TRUNCATED: only ' + fmtSize(c.stored) + ' stored' + (c.note ? ' — ' + c.note : ''));
      if (c.clipped) notes.push('display clipped');
      const h2 = el('h2', '#' + c.seq + ' ' + (c.direction === 'up' ? 'OUT' : 'IN'));
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
