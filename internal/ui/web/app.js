// proxyscope UI. Polls /api/exchanges?after=<lastId> once a second.
// All captured data is untrusted: only textContent is ever used to render it.
(() => {
  'use strict';
  const $ = (id) => document.getElementById(id);
  const rowsEl = $('rows'), filterEl = $('filter'), connEl = $('conn');
  const POLL_MS = 1000;

  let lastId = 0;
  let paused = false;
  let selectedId = null;
  const items = new Map(); // id -> {summary, tr}

  const el = (tag, text, cls) => {
    const e = document.createElement(tag);
    if (text != null) e.textContent = text;
    if (cls) e.className = cls;
    return e;
  };

  const fmtSize = (n) => n < 1024 ? n + ' B' : n < 1048576 ? (n / 1024).toFixed(1) + ' KB' : (n / 1048576).toFixed(1) + ' MB';
  const fmtTime = (iso) => new Date(iso).toLocaleTimeString([], { hour12: false });
  const statusClass = (s) => 's' + Math.floor(s / 100);

  async function api(path, opts = {}) {
    const res = await fetch(path, { ...opts, headers: { 'X-Requested-With': 'proxyscope' } });
    if (!res.ok) throw new Error(res.status + ' ' + (await res.text()).trim());
    return res.status === 204 ? null : res.json();
  }

  // ---- list ----
  function matches(s, q) {
    if (!q) return true;
    return [s.method, s.host, s.path, String(s.status)].some((v) => v.toLowerCase().includes(q));
  }

  function makeRow(s) {
    const tr = document.createElement('tr');
    const status = s.status || 'ERR';
    const cells = [s.id, fmtTime(s.timestamp), s.method, s.host, s.path, status, fmtSize(s.size), s.durationMs.toFixed(1)];
    cells.forEach((v, i) => {
      const td = el('td', v);
      td.title = String(v);
      if (i === 5) td.className = statusClass(s.status);
      tr.appendChild(td);
    });
    tr.addEventListener('click', () => select(s.id));
    return tr;
  }

  function addRows(list) {
    const q = filterEl.value.trim().toLowerCase();
    const stick = $('autoscroll').checked;
    for (const s of list) {
      if (items.has(s.id)) continue;
      const tr = makeRow(s);
      tr.hidden = !matches(s, q);
      items.set(s.id, { s, tr });
      rowsEl.appendChild(tr);
      lastId = Math.max(lastId, s.id);
    }
    updateCount();
    if (stick && list.length) $('list').scrollTop = $('list').scrollHeight;
  }

  function updateCount() {
    const shown = [...items.values()].filter((i) => !i.tr.hidden).length;
    $('count').textContent = shown === items.size ? items.size + ' requests' : shown + ' / ' + items.size + ' requests';
    $('empty').hidden = items.size > 0;
  }

  async function poll() {
    if (!paused) {
      try {
        addRows(await api('/api/exchanges?after=' + lastId));
        connEl.className = 'conn ok';
      } catch (e) {
        connEl.className = 'conn bad';
        connEl.title = String(e);
      }
    }
    setTimeout(poll, POLL_MS);
  }

  // ---- detail ----
  async function select(id) {
    selectedId = id;
    items.forEach((it, k) => it.tr.classList.toggle('sel', k === id));
    try {
      renderDetail(await api('/api/exchanges/' + id));
    } catch (e) {
      $('detail-empty').hidden = false;
      $('detail-empty').textContent = 'Failed to load request: ' + e.message;
      $('detail-body').hidden = true;
    }
  }

  function headersBlock(startLine, headers) {
    const pre = el('pre', null, 'head');
    pre.appendChild(el('b', startLine));
    for (const h of headers) pre.appendChild(document.createTextNode('\n' + h.name + ': ' + h.value));
    return pre;
  }

  function bodyBlock(b) {
    const frag = document.createDocumentFragment();
    if (b.size === 0) {
      frag.appendChild(el('p', 'No body.', 'note'));
      return frag;
    }
    const notes = [fmtSize(b.size)];
    if (b.decodedFrom) notes.push('decoded from ' + b.decodedFrom);
    if (b.encoding === 'hex') notes.push('binary, shown as hex dump');
    if (b.truncated) notes.push('TRUNCATED: only ' + fmtSize(b.stored) + ' stored');
    if (b.clipped) notes.push('display clipped');
    frag.appendChild(el('p', 'Body — ' + notes.join(' · '), 'note'));
    frag.appendChild(el('pre', b.content));
    return frag;
  }

  function renderDetail(d) {
    $('detail-empty').hidden = true;
    $('detail-body').hidden = false;
    $('detail-title').textContent = '#' + d.id + '  ' + d.request.method + ' ' + d.url;
    const err = $('detail-error');
    err.hidden = !d.error;
    err.textContent = d.error || '';

    const req = $('req'), resp = $('resp');
    req.replaceChildren(
      headersBlock(d.request.method + ' ' + d.request.path + ' ' + d.request.proto + '\nHost: ' + d.request.host, d.request.headers),
      bodyBlock(d.request.body));

    if (d.response) {
      resp.replaceChildren(
        headersBlock('HTTP ' + d.response.status + ' ' + d.response.statusText, d.response.headers),
        bodyBlock(d.response.body));
    } else {
      resp.replaceChildren(el('p', 'No response was produced.', 'note'));
    }
  }

  // ---- controls ----
  filterEl.addEventListener('input', () => {
    const q = filterEl.value.trim().toLowerCase();
    items.forEach((it) => { it.tr.hidden = !matches(it.s, q); });
    updateCount();
  });

  $('pause').addEventListener('click', (e) => {
    paused = !paused;
    e.target.textContent = paused ? 'Resume' : 'Pause';
  });

  $('clear').addEventListener('click', async () => {
    if (!confirm('Delete the whole request history from the database?')) return;
    try {
      await api('/api/exchanges', { method: 'DELETE' });
      items.clear();
      rowsEl.replaceChildren();
      selectedId = null;
      $('detail-body').hidden = true;
      $('detail-empty').hidden = false;
      $('detail-empty').textContent = 'Select a request to see its details.';
      updateCount();
    } catch (e) {
      alert('Clear failed: ' + e.message);
    }
  });

  // Draggable divider between list and detail.
  (() => {
    const divider = $('divider'), list = $('list');
    divider.addEventListener('mousedown', (e) => {
      e.preventDefault();
      const move = (ev) => {
        const top = list.getBoundingClientRect().top;
        list.style.flex = '0 0 ' + Math.max(60, ev.clientY - top) + 'px';
      };
      const up = () => { document.removeEventListener('mousemove', move); document.removeEventListener('mouseup', up); };
      document.addEventListener('mousemove', move);
      document.addEventListener('mouseup', up);
    });
  })();

  poll();
})();
