// History view: polls /api/exchanges?after=<lastId> once a second.
(() => {
  'use strict';
  const { $, el, fmtSize, fmtTime, statusClass, api, renderExchange, setConn } = window.PS;
  const rowsEl = $('rows'), filterEl = $('filter');
  const POLL_MS = 1000;

  let lastId = 0;
  let paused = false;
  let selectedId = null;
  const items = new Map(); // id -> {s, tr}

  // ---- list ----
  function matches(s, q) {
    if ($('hide-replayed').checked && s.source === 'repeater') return false;
    if (!q) return true;
    return [s.method, s.url, s.path, String(s.status)].some((v) => v.toLowerCase().includes(q));
  }

  function flagsCell(s) {
    const td = el('td', null, 'flags');
    const add = (txt, cls, title) => { const b = el('span', txt, 'flag ' + cls); b.title = title; td.appendChild(b); };
    if (s.source === 'repeater') add('R', 'flag-r', 'Replayed from the repeater');
    if (s.edited) add('E', 'flag-e', 'Edited in the intercept queue');
    if (s.ruleFired) add('M', 'flag-m', 'Modified by a match & replace rule');
    if (s.note) add('N', 'flag-n', s.note);
    return td;
  }

  function makeRow(s) {
    const tr = document.createElement('tr');
    if (s.source === 'repeater') tr.classList.add('replayed');
    const host = s.url.startsWith('https://') ? 'https://' + s.host : s.host; // mark TLS rows
    const cells = [s.id, fmtTime(s.timestamp), s.method, host, s.path, s.status || 'ERR', fmtSize(s.size), s.durationMs.toFixed(1)];
    cells.forEach((v, i) => {
      const td = el('td', v);
      td.title = String(v);
      if (i === 5) td.className = statusClass(s.status);
      tr.appendChild(td);
    });
    tr.appendChild(flagsCell(s));
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

  function refilter() {
    const q = filterEl.value.trim().toLowerCase();
    items.forEach((it) => { it.tr.hidden = !matches(it.s, q); });
    updateCount();
  }

  async function poll() {
    if (!paused) {
      try {
        addRows(await api('/api/exchanges?after=' + lastId));
        setConn(true);
      } catch (e) {
        setConn(false, e.message);
      }
    }
    setTimeout(poll, POLL_MS);
  }

  // ---- detail ----
  async function select(id) {
    selectedId = id;
    items.forEach((it, k) => it.tr.classList.toggle('sel', k === id));
    try {
      showDetail(await api('/api/exchanges/' + id));
    } catch (e) {
      $('detail-empty').hidden = false;
      $('detail-empty').textContent = 'Failed to load request: ' + e.message;
      $('detail-body').hidden = true;
    }
  }

  function showDetail(d) {
    $('detail-empty').hidden = true;
    const box = $('detail-body');
    box.hidden = false;
    box.replaceChildren(renderExchange(d));
    // "Send to Repeater" sits in the title row.
    const btn = el('button', 'Send to Repeater', 'primary');
    btn.addEventListener('click', async () => {
      btn.disabled = true;
      try { await window.PS.repeater.openFromExchange(d.id); } catch (e) { alert('Send to Repeater failed: ' + e.message); }
      btn.disabled = false;
    });
    box.querySelector('.detail-title').appendChild(btn);
  }

  // ---- controls ----
  filterEl.addEventListener('input', refilter);
  $('hide-replayed').addEventListener('change', refilter);

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
