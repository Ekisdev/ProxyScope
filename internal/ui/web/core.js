// proxyscope UI core: shared helpers, tab switching, and the exchange detail
// renderer used by History and Repeater.
// All captured data is untrusted: only textContent is ever used to render it.
(() => {
  'use strict';
  const $ = (id) => document.getElementById(id);

  const el = (tag, text, cls) => {
    const e = document.createElement(tag);
    if (text != null) e.textContent = text;
    if (cls) e.className = cls;
    return e;
  };

  const fmtSize = (n) => n < 1024 ? n + ' B' : n < 1048576 ? (n / 1024).toFixed(1) + ' KB' : (n / 1048576).toFixed(1) + ' MB';
  const fmtTime = (iso) => new Date(iso).toLocaleTimeString([], { hour12: false });
  const statusClass = (s) => 's' + Math.floor(s / 100);

  // api(path, {method, json}) -> parsed JSON (null for 204). Errors carry the server's message.
  async function api(path, opts = {}) {
    const init = { method: opts.method || 'GET', headers: { 'X-Requested-With': 'proxyscope' } };
    if (opts.json !== undefined) {
      init.headers['Content-Type'] = 'application/json';
      init.body = JSON.stringify(opts.json);
    }
    const res = await fetch(path, init);
    if (!res.ok) {
      const err = new Error((await res.text()).trim() || ('HTTP ' + res.status));
      err.status = res.status;
      throw err;
    }
    return res.status === 204 ? null : res.json();
  }

  function debounce(fn, ms) {
    let t;
    return (...a) => { clearTimeout(t); t = setTimeout(() => fn(...a), ms); };
  }

  // ---- exchange detail (shared by History and Repeater) ----
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

  // renderExchange(detail) -> DocumentFragment: title, banners, request/response panes.
  function renderExchange(d) {
    const frag = document.createDocumentFragment();
    const title = el('div', null, 'detail-title');
    title.appendChild(el('span', '#' + d.id + '  ' + d.request.method + ' ' + d.url, 'title-text'));
    frag.appendChild(title);

    if (d.source === 'repeater') frag.appendChild(el('div', 'Replayed from the repeater — not live-captured traffic.', 'banner replay'));
    if (d.reqEdited) frag.appendChild(el('div', 'The request was edited in the intercept queue; the stored copy is what was actually sent.', 'banner edit'));
    if (d.respEdited) frag.appendChild(el('div', 'The response was edited in the intercept queue; the stored copy is what was delivered to the client.', 'banner edit'));
    if (d.rulesApplied && d.rulesApplied.length) {
      frag.appendChild(el('div', 'Modified by match & replace rule(s): ' + d.rulesApplied.join(', '), 'banner rule'));
    }
    if (d.note) frag.appendChild(el('div', d.note, 'banner note'));
    if (d.error) frag.appendChild(el('div', d.error, 'error'));

    const panes = el('div', null, 'panes');
    const req = el('div', null, 'pane');
    req.appendChild(el('h2', 'Request'));
    req.appendChild(headersBlock(d.request.method + ' ' + d.request.path + ' ' + d.request.proto + '\nHost: ' + d.request.host, d.request.headers));
    req.appendChild(bodyBlock(d.request.body));
    const resp = el('div', null, 'pane');
    resp.appendChild(el('h2', 'Response'));
    if (d.response) {
      resp.appendChild(headersBlock('HTTP ' + d.response.status + ' ' + d.response.statusText, d.response.headers));
      resp.appendChild(bodyBlock(d.response.body));
    } else {
      resp.appendChild(el('p', 'No response was produced.', 'note'));
    }
    panes.append(req, resp);
    frag.appendChild(panes);
    return frag;
  }

  // ---- tabs ----
  const views = ['history', 'intercept', 'repeater', 'rules'];
  function showView(name) {
    if (!views.includes(name)) name = 'history';
    for (const v of views) $('view-' + v).hidden = v !== name;
    document.querySelectorAll('#tabs button').forEach((b) => b.classList.toggle('active', b.dataset.view === name));
    try { sessionStorage.setItem('proxyscope.view', name); } catch (_) { /* storage unavailable: fine */ }
    document.dispatchEvent(new CustomEvent('psview', { detail: name }));
  }
  document.querySelectorAll('#tabs button').forEach((b) => b.addEventListener('click', () => showView(b.dataset.view)));

  function setConn(ok, msg) {
    const c = $('conn');
    c.className = 'conn ' + (ok ? 'ok' : 'bad');
    c.title = ok ? 'connected to proxyscope' : String(msg);
  }

  window.PS = { $, el, fmtSize, fmtTime, statusClass, api, debounce, renderExchange, showView, setConn };

  let start = 'history';
  try { start = sessionStorage.getItem('proxyscope.view') || start; } catch (_) { /* ignore */ }
  document.addEventListener('DOMContentLoaded', () => showView(start));
})();
