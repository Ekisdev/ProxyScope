// Rules view: match & replace. GET /api/rules once on entering the tab (no
// polling: rules only change through this UI or a manual reload, unlike
// history/intercept which reflect live traffic). Rules are edited as a
// structured form by default; "Edit as raw YAML" swaps the editor for the
// whole file's text for power use for advanced changes (reordering rules,
// hand-written comments).
(() => {
  'use strict';
  const { $, el, api } = window.PS;

  const rowsEl = $('rules-rows'), editorEl = $('rules-editor'), pathEl = $('rules-path'), msgEl = $('rules-msg');
  let state = { path: '', rules: [], raw: '' };
  let draft = [];          // working copy of state.rules, edited in place
  let selected = null;     // index into draft, or null
  let isNew = false;       // the selected rule has not been saved yet
  let rawMode = false;

  function blankRule() {
    return { id: '', name: '', enabled: true, direction: 'request', scope: {}, conditions: [], action: { type: 'add_header' } };
  }

  async function load() {
    try {
      state = await api('/api/rules');
      draft = state.rules.map((r) => structuredClone(r));
      pathEl.textContent = state.path;
      if (selected !== null && !isNew && !draft[selected]) selected = null;
      render();
    } catch (e) {
      msgEl.textContent = 'Failed to load rules: ' + e.message;
    }
  }

  function render() {
    renderList();
    if (rawMode) renderRaw();
    else if (selected !== null) renderForm();
    else editorEl.replaceChildren(el('p', 'Select a rule to edit, or click "New rule".', 'muted empty'));
  }

  // ---- list ----
  function scopeSummary(r) {
    const parts = [];
    if (r.scope?.method) parts.push(r.scope.method);
    parts.push(r.scope?.host ? r.scope.host : 'any host');
    if (r.scope?.path) parts.push((r.scope.pathMatch || 'exact') + ' ' + r.scope.path);
    return parts.join(' · ');
  }
  function conditionSummary(r) {
    if (!r.conditions || r.conditions.length === 0) return '(none)';
    return r.conditions.length + ' condition' + (r.conditions.length > 1 ? 's' : '');
  }
  function actionSummary(r) {
    const a = r.action || {};
    switch (a.type) {
      case 'replace_header': return 'replace header ' + a.name;
      case 'add_header': return 'add header ' + a.name;
      case 'remove_header': return 'remove header ' + a.name;
      case 'replace_body': return 'replace body';
      case 'body_regex_replace': return 'replace in body (regex)';
      case 'set_status': return 'set status ' + a.status;
      default: return a.type || '(none)';
    }
  }

  function renderList() {
    rowsEl.replaceChildren();
    draft.forEach((r, i) => {
      const tr = document.createElement('tr');
      const en = el('input'); en.type = 'checkbox'; en.checked = !!r.enabled;
      en.addEventListener('click', (e) => e.stopPropagation());
      en.addEventListener('change', () => { r.enabled = en.checked; saveAll('Updating…'); });
      const enTd = el('td'); enTd.appendChild(en);
      const dir = el('td', r.direction === 'response' ? 'RESP' : 'REQ', r.direction === 'response' ? 'kind-resp' : 'kind-req');
      const idTd = el('td', r.id || '(unsaved)');
      const scopeTd = el('td', scopeSummary(r));
      const condTd = el('td', conditionSummary(r));
      const actTd = el('td', actionSummary(r));
      tr.append(enTd, dir, idTd, scopeTd, condTd, actTd);
      if (i === selected) tr.classList.add('sel');
      tr.addEventListener('click', () => { selected = i; isNew = false; rawMode = false; render(); });
      rowsEl.appendChild(tr);
    });
    $('rules-empty').hidden = draft.length > 0;
  }

  // ---- structured form ----
  const field = (label, control) => {
    const wrap = el('label', null, 'field');
    wrap.append(el('span', label, 'field-label'), control);
    return wrap;
  };
  const input = (value, cls) => { const i = el('input', null, cls); i.type = 'text'; i.value = value ?? ''; i.spellcheck = false; return i; };
  const numberInput = (value, cls) => { const i = el('input', null, cls); i.type = 'number'; i.value = value ?? ''; return i; };
  const checkbox = (checked) => { const i = el('input'); i.type = 'checkbox'; i.checked = !!checked; return i; };
  function select(options, value) {
    const s = el('select');
    for (const [v, label] of options) {
      const o = el('option', label); o.value = v; if (v === value) o.selected = true;
      s.appendChild(o);
    }
    return s;
  }
  const area = (value, rows) => { const t = el('textarea'); t.value = value ?? ''; t.rows = rows; t.spellcheck = false; t.wrap = 'off'; return t; };

  function conditionRow(c, onRemove) {
    const row = el('div', null, 'row');
    const type = select([['header', 'Header'], ['body', 'Body'], ['status', 'Status']], c.type || 'header');
    const rest = el('span', null, 'row');
    function renderFields() {
      rest.replaceChildren();
      if (type.value === 'header') {
        const name = input(c.name, 'method-input'); name.placeholder = 'Header name';
        const match = select([['exact', 'exact'], ['contains', 'contains'], ['regex', 'regex']], c.match || 'exact');
        const value = input(c.value); value.placeholder = 'value / pattern';
        name.oninput = () => c.name = name.value;
        match.onchange = () => c.match = match.value;
        value.oninput = () => c.value = value.value;
        rest.append(name, match, value);
      } else if (type.value === 'body') {
        const match = select([['contains', 'contains'], ['regex', 'regex']], c.match || 'contains');
        const value = input(c.value); value.placeholder = 'value / pattern';
        match.onchange = () => c.match = match.value;
        value.oninput = () => c.value = value.value;
        rest.append(match, value);
      } else {
        const eq = numberInput(c.equals, 'status-input'); eq.placeholder = 'status code';
        eq.oninput = () => c.equals = eq.value === '' ? null : parseInt(eq.value, 10);
        rest.append(eq);
      }
    }
    type.onchange = () => { c.type = type.value; c.name = ''; c.match = ''; c.value = ''; c.equals = null; renderFields(); };
    c.type = c.type || 'header';
    renderFields();
    const rm = el('button', '✕', 'icon'); rm.type = 'button'; rm.title = 'Remove condition'; rm.addEventListener('click', onRemove);
    row.append(type, rest, rm);
    return row;
  }

  function actionFields(r) {
    const box = el('div');
    const a = r.action;
    function renderFields() {
      box.replaceChildren();
      switch (a.type) {
        case 'replace_header':
        case 'add_header': {
          const name = input(a.name); name.placeholder = 'Header name';
          const value = input(a.value); value.placeholder = 'Value';
          name.oninput = () => a.name = name.value;
          value.oninput = () => a.value = value.value;
          box.append(field('Header name', name), field('Value', value));
          break;
        }
        case 'remove_header': {
          const name = input(a.name); name.placeholder = 'Header name';
          name.oninput = () => a.name = name.value;
          box.append(field('Header name', name));
          break;
        }
        case 'replace_body': {
          const body = area(a.body, 6);
          body.oninput = () => a.body = body.value;
          box.append(field('New body', body));
          break;
        }
        case 'body_regex_replace': {
          const pattern = input(a.pattern); pattern.placeholder = 'Regex pattern';
          const repl = input(a.replacement); repl.placeholder = 'Replacement ($1, ${name}, ...)';
          pattern.oninput = () => a.pattern = pattern.value;
          repl.oninput = () => a.replacement = repl.value;
          box.append(field('Pattern', pattern), field('Replacement', repl));
          break;
        }
        case 'set_status': {
          const status = numberInput(a.status, 'status-input');
          status.oninput = () => a.status = status.value === '' ? 0 : parseInt(status.value, 10);
          box.append(field('New status code', status));
          break;
        }
      }
    }
    renderFields();
    return { box, refresh: renderFields };
  }

  function renderForm() {
    const r = draft[selected];
    const form = el('div', null, 'form');
    const head = el('div', null, 'detail-title');
    head.appendChild(el('span', isNew ? 'New rule' : 'Editing rule', 'title-text'));
    form.appendChild(head);

    const id = input(r.id, 'method-input'); id.placeholder = 'unique-id';
    const name = input(r.name); name.placeholder = 'Human label (optional)';
    id.oninput = () => r.id = id.value;
    name.oninput = () => r.name = name.value;
    const row1 = el('div', null, 'row');
    row1.append(field('ID', id), field('Name', name));
    form.appendChild(row1);

    const enabled = checkbox(r.enabled);
    enabled.onchange = () => r.enabled = enabled.checked;
    const dirOnlyResp = () => r.direction === 'response';
    const direction = select([['request', 'Request'], ['response', 'Response']], r.direction);
    direction.onchange = () => { r.direction = direction.value; refreshActionKind(); };
    const row2 = el('div', null, 'row');
    row2.append(field('Enabled', enabled), field('Direction', direction));
    form.appendChild(row2);

    form.appendChild(el('h2', 'Scope'));
    r.scope = r.scope || {};
    const host = input(r.scope.host); host.placeholder = 'e.g. example.com or *.example.com (empty = any)';
    host.oninput = () => r.scope.host = host.value;
    const method = input(r.scope.method); method.placeholder = 'e.g. POST (empty = any)';
    method.oninput = () => r.scope.method = method.value;
    const row3 = el('div', null, 'row');
    row3.append(field('Host', host), field('Method', method));
    form.appendChild(row3);
    const path = input(r.scope.path); path.placeholder = '/api/verify (empty = any)';
    path.oninput = () => r.scope.path = path.value;
    const pathMatch = select([['exact', 'exact'], ['prefix', 'prefix'], ['regex', 'regex']], r.scope.pathMatch || 'exact');
    pathMatch.onchange = () => r.scope.pathMatch = pathMatch.value;
    const row4 = el('div', null, 'row');
    row4.append(field('Path', path), field('Path match', pathMatch));
    form.appendChild(row4);

    form.appendChild(el('h2', 'Conditions (AND-combined)'));
    r.conditions = r.conditions || [];
    const condBox = el('div');
    function renderConditions() {
      condBox.replaceChildren();
      r.conditions.forEach((c, i) => condBox.appendChild(conditionRow(c, () => { r.conditions.splice(i, 1); renderConditions(); })));
    }
    renderConditions();
    form.appendChild(condBox);
    const addCond = el('button', '+ Add condition', 'icon'); addCond.type = 'button';
    addCond.addEventListener('click', () => { r.conditions.push({ type: 'header' }); renderConditions(); });
    form.appendChild(addCond);

    form.appendChild(el('h2', 'Action'));
    r.action = r.action || { type: 'add_header' };
    const actionTypes = [
      ['replace_header', 'Replace header value'], ['add_header', 'Add header'], ['remove_header', 'Remove header'],
      ['replace_body', 'Replace full body'], ['body_regex_replace', 'Replace in body (regex)'],
    ];
    let statusOption = null;
    const actionType = select(actionTypes, r.action.type);
    let af = actionFields(r);
    function refreshActionKind() {
      // set_status only makes sense (and validates) on response-direction rules.
      const opts = actionTypes.slice();
      if (dirOnlyResp()) opts.push(['set_status', 'Set status code']);
      actionType.replaceChildren();
      for (const [v, label] of opts) {
        const o = el('option', label); o.value = v; if (v === r.action.type) o.selected = true;
        actionType.appendChild(o);
      }
      if (!dirOnlyResp() && r.action.type === 'set_status') { r.action.type = 'add_header'; actionType.value = 'add_header'; }
    }
    refreshActionKind();
    actionType.onchange = () => { r.action = { type: actionType.value }; af.box.replaceWith(actionFields(r).box); af = actionFields(r); };
    form.append(field('Action type', actionType), af.box);

    const msg = el('span', '', 'form-msg');
    const bar = el('div', null, 'actions');
    const mk = (text, cls, fn) => {
      const b = el('button', text, cls); b.type = 'button';
      b.addEventListener('click', async () => {
        bar.querySelectorAll('button').forEach((x) => x.disabled = true);
        msg.textContent = '';
        try { await fn(); } catch (e) { msg.textContent = e.message; }
        bar.querySelectorAll('button').forEach((x) => x.disabled = false);
      });
      return b;
    };
    bar.append(
      mk('Save', 'primary', () => saveAll()),
      mk('Delete', 'danger', async () => { draft.splice(selected, 1); selected = null; await saveAll(); }),
      msg,
    );
    form.appendChild(bar);
    editorEl.replaceChildren(form);
  }

  // ---- raw YAML ----
  function renderRaw() {
    const box = el('div', null, 'form');
    box.appendChild(el('div', 'Edit as raw YAML', 'detail-title'));
    box.appendChild(el('p', 'The whole rules file. Saving here preserves your formatting/comments; saving from the structured form regenerates the file without them.', 'note'));
    const text = area(state.raw, 24);
    text.style.fontFamily = 'var(--mono)';
    const msg = el('span', '', 'form-msg');
    const bar = el('div', null, 'actions');
    const save = el('button', 'Save', 'primary'); save.type = 'button';
    save.addEventListener('click', async () => {
      save.disabled = true; msg.textContent = '';
      try {
        state = await api('/api/rules/raw', { method: 'PUT', json: { yaml: text.value } });
        draft = state.rules.map((r) => structuredClone(r));
        selected = null;
        render();
      } catch (e) { msg.textContent = e.message; }
      save.disabled = false;
    });
    bar.append(save, msg);
    box.append(field('rules.yaml', text), bar);
    editorEl.replaceChildren(box);
  }

  // ---- save/reload ----
  async function saveAll(pendingMsg) {
    msgEl.textContent = pendingMsg || '';
    try {
      state = await api('/api/rules', { method: 'PUT', json: { rules: draft } });
      draft = state.rules.map((r) => structuredClone(r));
      isNew = false;
      msgEl.textContent = '';
      render();
    } catch (e) {
      msgEl.textContent = 'Save failed: ' + e.message;
      throw e;
    }
  }

  $('rules-new').addEventListener('click', () => {
    draft.push(blankRule());
    selected = draft.length - 1;
    isNew = true;
    rawMode = false;
    render();
  });
  $('rules-raw-toggle').addEventListener('click', () => { rawMode = !rawMode; render(); });
  $('rules-reload').addEventListener('click', async () => {
    msgEl.textContent = 'Reloading…';
    try {
      state = await api('/api/rules/reload', { method: 'POST' });
      draft = state.rules.map((r) => structuredClone(r));
      selected = null;
      msgEl.textContent = 'Reloaded from ' + state.path;
      render();
    } catch (e) {
      msgEl.textContent = 'Reload failed: ' + e.message;
    }
  });

  document.addEventListener('psview', (e) => { if (e.detail === 'rules') load(); });
})();
