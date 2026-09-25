// Repeater view. Tabs (editable request copies) live in the browser
// (localStorage) so a reload doesn't lose them; every send is a real history
// entry on the server (marked "replayed"), referenced here by its id.
(() => {
  'use strict';
  const { $, el, fmtSize, statusClass, api, debounce, renderExchange, showView } = window.PS;

  const KEY = 'proxyscope.repeater.v1';
  const MAX_RESULTS = 50;
  let state = { tabs: [], active: null, nextId: 1 };
  let storageWarned = false;

  function load() {
    try {
      const s = JSON.parse(localStorage.getItem(KEY) || 'null');
      if (s && Array.isArray(s.tabs)) state = s;
      state.tabs.forEach((t) => { t.sending = false; }); // a reload cancels any in-flight send
    } catch (_) { /* unavailable or corrupt: start empty */ }
  }
  const save = debounce(() => {
    try { localStorage.setItem(KEY, JSON.stringify(state)); }
    catch (_) {
      if (!storageWarned) { storageWarned = true; console.warn('proxyscope: cannot persist repeater tabs (storage unavailable or full)'); }
    }
  }, 300);

  const activeTab = () => state.tabs.find((t) => t.id === state.active) || null;

  // ---- opening a tab from history ----
  async function openFromExchange(exchangeId) {
    const seed = await api('/api/exchanges/' + exchangeId + '/repeater');
    const tab = {
      id: state.nextId++,
      sourceId: seed.sourceId,
      label: seed.method + ' ' + seed.url.replace(/^https?:\/\//, ''),
      method: seed.method, url: seed.url, headers: seed.headers,
      bodyEditable: seed.body.editable,   // false: binary/oversized/truncated, resent unchanged
      body: seed.body.editable ? seed.body.content : '',
      bodySize: seed.body.size,
      bodyBinary: seed.body.encoding === 'hex',
      bodyTruncated: seed.bodyTruncated,
      results: [], selectedResult: null, sending: false, error: '',
    };
    state.tabs.push(tab);
    state.active = tab.id;
    save();
    render();
    showView('repeater');
  }

  // ---- rendering ----
  const tabsEl = $('rep-tabs'), mainEl = $('rep-main');

  function render() {
    $('rbadge').hidden = state.tabs.length === 0;
    $('rbadge').textContent = state.tabs.length;
    $('rep-empty').hidden = state.tabs.length > 0;
    renderTabs();
    renderEditor();
  }

  function renderTabs() {
    tabsEl.replaceChildren(...state.tabs.map((t) => {
      const row = el('div', null, 'rep-tab' + (t.id === state.active ? ' sel' : ''));
      const label = el('span', t.label, 'rep-tab-label');
      label.title = t.label;
      const close = el('button', '×', 'icon');
      close.title = 'Close this tab';
      close.addEventListener('click', (e) => {
        e.stopPropagation();
        state.tabs = state.tabs.filter((x) => x.id !== t.id);
        if (state.active === t.id) state.active = state.tabs.length ? state.tabs[state.tabs.length - 1].id : null;
        save(); render();
      });
      row.append(label, close);
      row.addEventListener('click', () => { state.active = t.id; save(); render(); });
      return row;
    }));
  }

  const field = (label, control) => {
    const wrap = el('label', null, 'field');
    wrap.append(el('span', label, 'field-label'), control);
    return wrap;
  };

  function renderEditor() {
    const t = activeTab();
    if (!t) { mainEl.replaceChildren(el('p', 'No repeater tab selected.', 'muted empty')); return; }

    const method = el('input', null, 'method-input'); method.value = t.method; method.spellcheck = false;
    const url = el('input', null, 'url-input'); url.value = t.url; url.spellcheck = false;
    const headers = el('textarea'); headers.value = t.headers; headers.rows = 9; headers.spellcheck = false; headers.wrap = 'off';
    method.addEventListener('input', () => { t.method = method.value; save(); });
    url.addEventListener('input', () => { t.url = url.value; save(); });
    headers.addEventListener('input', () => { t.headers = headers.value; save(); });

    const line = el('div', null, 'row');
    line.append(field('Method', method), field('URL', url));

    let bodyNode;
    if (t.bodyEditable) {
      const body = el('textarea'); body.value = t.body; body.rows = 8; body.spellcheck = false; body.wrap = 'off';
      body.addEventListener('input', () => { t.body = body.value; save(); });
      bodyNode = field('Body' + (t.bodySize ? ' (' + fmtSize(t.bodySize) + ' originally)' : ''), body);
    } else {
      const why = t.bodyTruncated ? 'the stored copy was truncated by -max-body, so the PARTIAL body is resent unchanged'
        : t.bodyBinary ? 'binary body, resent unchanged from the stored bytes' : 'body cannot be edited as text, resent unchanged';
      bodyNode = el('p', 'Body (' + fmtSize(t.bodySize) + '): ' + why + '.', 'note' + (t.bodyTruncated ? ' warn' : ''));
    }

    const send = el('button', t.sending ? 'Sending…' : 'Send', 'primary');
    send.disabled = t.sending;
    send.addEventListener('click', () => sendTab(t));
    const msg = el('span', t.error, 'form-msg');
    const bar = el('div', null, 'actions');
    bar.append(send, msg, el('span', 'Ctrl+Enter also sends', 'muted hint'));

    const results = el('div', null, 'results');
    results.appendChild(el('h2', 'Results (' + t.results.length + ')'));
    if (t.results.length) results.appendChild(resultsTable(t));
    const detail = el('div', null, 'result-detail');
    detail.id = 'rep-result-detail';
    results.appendChild(detail);

    const form = el('div', null, 'form');
    form.append(line, field('Headers', headers), bodyNode, bar);
    form.addEventListener('keydown', (e) => { if (e.ctrlKey && e.key === 'Enter') { e.preventDefault(); sendTab(t); } });
    mainEl.replaceChildren(form, results);
    if (t.selectedResult) showResult(t, t.selectedResult);
  }

  function resultsTable(t) {
    const table = el('table');
    const thead = el('thead'), hr = el('tr');
    ['#', 'Sent', 'Status', 'Time (ms)', 'Note'].forEach((h) => hr.appendChild(el('th', h)));
    thead.appendChild(hr);
    const tbody = el('tbody');
    for (const r of [...t.results].reverse()) {
      const tr = el('tr', null, r.id === t.selectedResult ? 'sel' : '');
      const status = el('td', r.status || 'ERR', statusClass(r.status));
      tr.append(el('td', r.id), el('td', new Date(r.at).toLocaleTimeString([], { hour12: false })), status,
        el('td', r.ms.toFixed(1)), el('td', r.error || ''));
      tr.addEventListener('click', () => { t.selectedResult = r.id; save(); showResult(t, r.id); tbody.querySelectorAll('tr').forEach((x) => x.classList.remove('sel')); tr.classList.add('sel'); });
      tbody.appendChild(tr);
    }
    table.append(thead, tbody);
    return table;
  }

  async function showResult(t, id, preloaded) {
    const box = $('rep-result-detail');
    if (!box) return;
    try {
      const d = preloaded || await api('/api/exchanges/' + id);
      if (t.id !== state.active || t.selectedResult !== id) return;
      box.replaceChildren(renderExchange(d));
    } catch (e) {
      box.replaceChildren(el('p', e.status === 404 ? 'This result is no longer in the history (it was cleared).' : 'Failed to load: ' + e.message, 'note warn'));
    }
  }

  // ---- sending ----
  async function sendTab(t) {
    if (t.sending) return;
    t.sending = true; t.error = '';
    renderIfActive(t);
    try {
      const d = await api('/api/repeater/send', {
        method: 'POST',
        json: { sourceId: t.sourceId, method: t.method, url: t.url, headers: t.headers, body: t.bodyEditable ? t.body : null },
      });
      t.results.push({ id: d.id, at: Date.now(), ms: d.durationMs, status: d.response ? d.response.status : 0, error: d.error || '' });
      if (t.results.length > MAX_RESULTS) t.results.splice(0, t.results.length - MAX_RESULTS);
      t.selectedResult = d.id;
      t.sending = false;
      save();
      renderIfActive(t);
      showResult(t, d.id, d);
    } catch (e) {
      t.sending = false;
      t.error = e.message;
      renderIfActive(t);
    }
  }

  // Re-render only if t is the visible tab, without losing focus on unrelated tabs.
  function renderIfActive(t) { if (t.id === state.active) renderEditor(); }

  window.PS.repeater = { openFromExchange };
  load();
  render();
})();
