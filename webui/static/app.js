'use strict';
/*
 * Email Guard console — the mock's behaviour, against the real API.
 *
 * Two rules run through the whole file and are worth stating once:
 *
 * 1. NOTHING FROM THE SERVER BECOMES MARKUP. Every address, flag, list key and
 *    message body is written with textContent or createTextNode. There is no
 *    innerHTML assignment anywhere below, so a message body containing
 *    "<img onerror=...>" is a body containing that text — visibly, inertly.
 *    The CSP is the second lock: `script-src 'self'` means even an injected
 *    <script> has nothing to execute with. This is the first.
 *
 * 2. EVERY HANDLER IS addEventListener. No inline onclick survived the move out
 *    of index.html; an inline handler is inline script, and the CSP forbids it.
 *
 * Skip is deliberately client-side: it re-queues a card in memory and tells the
 * server nothing, because "not yet" is not a decision and must not be recorded
 * as one.
 */

// --- constants -----------------------------------------------------------------

const THEMES = [
  'midnight-dark', 'midnight-light', 'slate-dark', 'slate-light',
  'forest-dark', 'forest-light', 'ember-dark', 'ember-light',
  'nord-dark', 'nord-light',
];

const AUTH_HEADER = 'X-Email-Guard-Token';
const TOKEN_KEY = 'email-guard-token';
const LIST_NAMES = ['whitelist', 'greylist', 'blacklist'];

// Mirrors email_guard.propose.STRUCTURE_NAME_LIMIT: a structure's name is a
// label a human reads in a list file, not a paragraph.
const STRUCTURE_NAME_LIMIT = 80;
// The scanner's de-fanged form is the only link form that ever leaves it.
const DEFANG_RE = /(hxxps?:\/\/[^\s]+)/g;
// email_guard.lists.structure_matches tests a phrase against the subject when
// it carries this prefix, and against the body otherwise.
const SUBJECT_PREFIX = 'Subject: ';

const state = {
  queue: [],          // review cards, in display order
  choice: null,       // whitelist | greylist | blacklist
  disposition: null,  // allow | block  (greylist only)
  wholeDomain: false, // list the domain rather than the address
  subjectMatch: false,// match the phrase against the subject
  addDisposition: null, // allow | block, for a manual greylist add
  curList: 'greylist',
  entries: [],
  hooks: ['https://n8n.local/webhook/email-guard'],
  rules: null,        // the live rules pack, as the updater reports it
};

// --- tiny DOM helpers ----------------------------------------------------------

function el(tag, className, text) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== undefined && text !== null) node.textContent = String(text);
  return node;
}

function clear(node) {
  while (node.firstChild) node.removeChild(node.firstChild);
}

function byId(id) {
  return document.getElementById(id);
}

let toastTimer;
function toast(message) {
  const box = byId('toast');
  box.textContent = message;
  box.classList.add('show');
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => box.classList.remove('show'), 2600);
}

// --- the API -------------------------------------------------------------------

/* The shared token, when the server has one configured.
 *
 * A browser cannot attach a header to a top-level navigation, so the token
 * arrives once as `?token=...`, moves into sessionStorage, and is stripped from
 * the address bar immediately — a token sitting in a URL ends up in history,
 * in a bookmark, and in the next screenshot. Every API call carries it as a
 * header from then on. With no token configured (the default) this is all inert.
 */
function readToken() {
  const params = new URLSearchParams(window.location.search);
  const supplied = (params.get('token') || '').trim();
  if (supplied) {
    try { window.sessionStorage.setItem(TOKEN_KEY, supplied); } catch (err) { /* private mode */ }
    params.delete('token');
    const query = params.toString();
    window.history.replaceState({}, '', window.location.pathname + (query ? '?' + query : ''));
    return supplied;
  }
  try { return window.sessionStorage.getItem(TOKEN_KEY) || ''; } catch (err) { return ''; }
}

const TOKEN = readToken();

function headers(extra) {
  const built = Object.assign({}, extra || {});
  if (TOKEN) built[AUTH_HEADER] = TOKEN;
  return built;
}

/* One error type for the whole client: whatever the server said, flattened.
 * The applier reports every error in a rejected document rather than the first,
 * so the reviewer sees the whole list. */
class ApiError extends Error {
  constructor(message, errors) {
    super(message);
    this.errors = errors || [];
  }
}

async function request(path, options) {
  let response;
  try {
    response = await fetch(path, Object.assign({ headers: headers() }, options || {}));
  } catch (err) {
    throw new ApiError('cannot reach the console server — is it still running?');
  }

  let payload = null;
  try { payload = await response.json(); } catch (err) { payload = null; }

  if (!response.ok) {
    const errors = (payload && Array.isArray(payload.errors)) ? payload.errors : [];
    const detail = payload ? payload.detail : null;
    const message = errors.length
      ? errors.join('; ')
      : (typeof detail === 'string' ? detail : 'request failed (HTTP ' + response.status + ')');
    throw new ApiError(message, errors);
  }
  return payload;
}

function getJSON(path) {
  return request(path, { method: 'GET' });
}

function postJSON(path, body) {
  return request(path, {
    method: 'POST',
    headers: headers({ 'Content-Type': 'application/json' }),
    body: JSON.stringify(body),
  });
}

// --- review --------------------------------------------------------------------

function localPart(address) {
  const at = String(address || '').indexOf('@');
  return at < 0 ? String(address || '') : address.slice(0, at);
}

function domainPart(address) {
  const at = String(address || '').indexOf('@');
  return at < 0 ? '' : address.slice(at);   // includes the '@', as the mock shows it
}

async function loadQueue() {
  const payload = await getJSON('/api/candidates');
  mergeQueue(payload.candidates || []);
}

/* Refresh the queue without losing the reviewer's place.
 *
 * A confirmed decision can change what the *other* cards should say — moving a
 * domain off the greylist changes the membership line on every card from that
 * domain — so the queue is re-read after each apply. Cards already on screen
 * keep their position, including any the reviewer skipped; only genuinely new
 * ones go on the end. */
function mergeQueue(fresh) {
  const byIdMap = new Map(fresh.map((card) => [card.id, card]));
  const kept = [];
  state.queue.forEach((card) => {
    const updated = byIdMap.get(card.id);
    if (updated) {
      kept.push(updated);
      byIdMap.delete(card.id);
    }
  });
  byIdMap.forEach((card) => kept.push(card));
  state.queue = kept;
}

function renderReview() {
  const area = byId('reviewArea');
  clear(area);
  state.choice = null;
  state.disposition = null;
  state.wholeDomain = false;
  state.subjectMatch = false;

  const card = el('div', 'card');
  area.appendChild(card);

  if (state.queue.length === 0) {
    const empty = el('div', 'empty-state');
    empty.appendChild(el('div', 'big', '✓'));
    empty.appendChild(document.createTextNode('All caught up — queue empty.'));
    card.appendChild(empty);
    return;
  }

  const current = state.queue[0];
  const address = (current.sender && current.sender.email) || 'unknown';
  const domain = (current.sender && current.sender.domain) || '';

  // --- top: address, membership, list choice
  const top = el('div', 'rev-top');
  const addr = el('div', 'rev-addr');
  addr.appendChild(el('div', 'lbl', 'From'));

  const line = el('div', 'addr');
  line.id = 'addr';
  const local = el('span', null, localPart(address));
  local.id = 'aLocal';
  const dom = el('span', null, domainPart(address));
  dom.id = 'aDom';
  line.appendChild(local);
  line.appendChild(dom);
  addr.appendChild(line);

  const membership = current.membership;
  addr.appendChild(el(
    'div',
    'member-note',
    membership
      ? 'currently on the ' + membership.list + ' as ' + membership.key
      : 'not on any list yet',
  ));

  const moveNote = el('div', 'move-note');
  moveNote.id = 'moveNote';
  addr.appendChild(moveNote);

  const wdToggle = el('label', 'wd-toggle hidden');
  wdToggle.id = 'wdToggle';
  const wdCheck = document.createElement('input');
  wdCheck.type = 'checkbox';
  wdCheck.id = 'wdCheck';
  wdCheck.disabled = !domain;
  wdToggle.appendChild(wdCheck);
  wdToggle.appendChild(document.createTextNode(
    domain
      ? 'list the whole domain, not just this address'
      : 'this sender has no domain to list',
  ));
  addr.appendChild(wdToggle);
  top.appendChild(addr);

  const segs = el('div', 'seg-vert');
  [['whitelist', 'WHITE'], ['greylist', 'GREY'], ['blacklist', 'BLACK']].forEach(([name, label]) => {
    const button = el('button', 'seg', label);
    button.dataset.c = name;
    // The greylist keys on a domain; a sender without one cannot go on it.
    button.disabled = (name === 'greylist' && !domain);
    button.addEventListener('click', () => pickList(button));
    segs.appendChild(button);
  });
  top.appendChild(segs);
  card.appendChild(top);

  // --- body: plain text, de-fanged by the scanner, rendered as text
  card.appendChild(el('div', 'body-lbl', 'Message body — links de-fanged, plain text only'));
  const bodyBox = el('div', 'body-box');
  renderBody(bodyBox, current.body);
  card.appendChild(bodyBox);

  // --- lower: flags, and the greylist structure form
  const lower = el('div', 'rev-lower');
  const flags = el('div', 'flags-box');
  flags.appendChild(el('div', 'mini-lbl', 'Flags'));
  if (current.flags && current.flags.length) {
    current.flags.forEach((flag) => {
      const chip = el('span', 'flag-chip' + (flag.indexOf('obfusc') >= 0 ? ' warn' : ''), flag);
      flags.appendChild(chip);
    });
  } else {
    const none = el('span', null, 'none — routine unknown sender');
    none.style.fontSize = '11px';
    none.style.color = 'var(--text-muted)';
    flags.appendChild(none);
  }
  lower.appendChild(flags);
  lower.appendChild(buildStructureBox());
  card.appendChild(lower);

  // --- actions
  const actions = el('div', 'rev-actions');
  actions.appendChild(el('span', 'queue-count', state.queue.length + ' in queue'));

  const skipButton = el('button', 'btn', 'Skip');
  skipButton.addEventListener('click', skip);
  actions.appendChild(skipButton);

  const confirmButton = el('button', 'btn btn-primary', 'Confirm');
  confirmButton.id = 'confirmBtn';
  confirmButton.disabled = true;
  confirmButton.addEventListener('click', confirmDecision);
  actions.appendChild(confirmButton);
  card.appendChild(actions);

  const error = el('div', 'error-note hidden');
  error.id = 'reviewError';
  card.appendChild(error);

  wdCheck.addEventListener('change', () => {
    state.wholeDomain = wdCheck.checked;
    paintAddress();
    updateMoveNote();
  });
}

/* The message body: the candidate's excerpt, and nothing else.
 *
 * Split on the de-fanged link form so those can be tinted, then append every
 * piece as a text node. The tinting is cosmetic; the text nodes are the point. */
function renderBody(box, text) {
  clear(box);
  const content = typeof text === 'string' ? text : '';
  if (!content.trim()) {
    const empty = el('span', null, '(no message text was captured for this candidate)');
    empty.style.color = 'var(--text-muted)';
    box.appendChild(empty);
    return;
  }
  content.split(DEFANG_RE).forEach((part, index) => {
    if (!part) return;
    // Odd indices are the captured link separators.
    if (index % 2 === 1) box.appendChild(el('span', 'defang', part));
    else box.appendChild(document.createTextNode(part));
  });
}

function buildStructureBox() {
  const box = el('div', 'struct-box');
  box.id = 'structBox';
  box.appendChild(el('div', 'mini-lbl', 'Known structure'));

  const text = document.createElement('textarea');
  text.id = 'structText';
  text.placeholder = 'paste a phrase from the body that identifies this shape';
  text.addEventListener('input', updateConfirm);
  box.appendChild(text);

  const toggle = el('div', 'sb-toggle');
  [['body', 'body match'], ['subject', 'subject match']].forEach(([key, label], index) => {
    const button = el('button', 'seg sbt' + (index === 0 ? ' active' : ''), label);
    button.dataset.sb = key;
    button.addEventListener('click', () => {
      state.subjectMatch = (key === 'subject');
      toggle.querySelectorAll('.sbt').forEach((other) => other.classList.remove('active'));
      button.classList.add('active');
    });
    toggle.appendChild(button);
  });
  box.appendChild(toggle);

  const dispositions = el('div', 'seg-h');
  [['allow', 'ALLOW'], ['block', 'BLOCK']].forEach(([key, label]) => {
    const button = el('button', 'seg ' + key, label);
    button.dataset.d = key;
    button.addEventListener('click', () => {
      state.disposition = key;
      dispositions.querySelectorAll('.seg').forEach((other) => other.classList.remove('active'));
      button.classList.add('active');
      updateConfirm();
    });
    dispositions.appendChild(button);
  });
  box.appendChild(dispositions);

  const tagRow = el('div', 'tag-row');
  const tags = document.createElement('input');
  tags.className = 'form-entry';
  tags.id = 'structTags';
  tags.placeholder = 'tags (optional)';
  tagRow.appendChild(tags);
  box.appendChild(tagRow);
  return box;
}

function pickList(button) {
  state.choice = button.dataset.c;
  document.querySelectorAll('.seg[data-c]').forEach((other) => other.classList.remove('active'));
  button.classList.add('active');

  const grey = state.choice === 'greylist';
  byId('structBox').classList.toggle('show', grey);
  byId('wdToggle').classList.toggle('hidden', grey);
  if (grey) {
    // The greylist keys on a domain regardless, so the whole-domain choice does
    // not apply -- and the box is cleared as well as ignored, so switching back
    // to WHITE cannot leave a ticked box that means nothing.
    state.wholeDomain = false;
    const check = byId('wdCheck');
    if (check) check.checked = false;
  }

  paintAddress();
  updateMoveNote();
  updateConfirm();
}

function paintAddress() {
  const bold = state.choice === 'greylist' || state.wholeDomain;
  byId('aDom').className = bold ? 'hl' : '';
  byId('aLocal').style.opacity = bold ? 0.5 : 1;
}

function updateMoveNote() {
  const current = state.queue[0];
  const note = byId('moveNote');
  if (!current || !note) return;
  const membership = current.membership;
  const domain = (current.sender && current.sender.domain) || '';
  if (membership && state.choice && membership.list !== state.choice) {
    note.textContent = '↳ ' + membership.key + ' is on the ' + membership.list
      + ' — confirming moves it to the ' + state.choice + '.';
  } else if (state.choice === 'greylist' && greylistTarget(current) !== domain) {
    // Says out loud where the shape is about to be written, which is not the
    // domain highlighted in the address above.
    note.textContent = '↳ ' + greylistTarget(current) + ' already covers '
      + domain + ' — the structure is catalogued there.';
  } else {
    note.textContent = '';
  }
}

function updateConfirm() {
  const button = byId('confirmBtn');
  if (!button) return;
  let ok = false;
  if (state.choice === 'whitelist' || state.choice === 'blacklist') {
    ok = true;
  } else if (state.choice === 'greylist') {
    const text = byId('structText');
    ok = !!text && text.value.trim() !== '' && !!state.disposition;
  }
  button.disabled = !ok;
}

function parseTags(value) {
  return String(value || '')
    .split(',')
    .map((tag) => tag.trim())
    .filter((tag) => tag !== '');
}

/* The domain a greylist decision keys on.
 *
 * A greylist entry covers its subdomains, so when the sender is already covered
 * by a listed parent domain the new shape belongs on THAT entry: keying on the
 * sending subdomain would add a second entry saying nothing the first did not.
 * Exactly the rule email_guard.propose applies when it stages a `new_structure`
 * candidate — "key on the listed domain, not the sending subdomain". */
function greylistTarget(card) {
  const membership = card.membership;
  if (membership && membership.list === 'greylist' && membership.scope === 'domain') {
    return membership.key;
  }
  return (card.sender && card.sender.domain) || '';
}

/* The decision for the card on screen, in the shape the applier consumes.
 *
 * White/black key on the address unless the reviewer asked for the whole
 * domain; the greylist always keys on a domain. That is the list schema
 * talking, not a UI preference. */
function buildDecision(current) {
  const address = (current.sender && current.sender.email) || '';
  const domain = (current.sender && current.sender.domain) || '';
  const decision = { candidate: current.id, action: state.choice };

  if (state.choice === 'greylist') {
    const phrase = byId('structText').value.trim();
    decision.entry = { domain: greylistTarget(current) };
    decision.structure = {
      name: phrase.slice(0, STRUCTURE_NAME_LIMIT),
      key_phrases: [state.subjectMatch ? SUBJECT_PREFIX + phrase : phrase],
      disposition: state.disposition === 'block' ? 'denied' : 'allowed',
      tags: parseTags(byId('structTags').value),
    };
  } else {
    decision.entry = state.wholeDomain ? { domain: domain } : { email: address };
  }
  return decision;
}

function describeDecision(current) {
  const domain = (current.sender && current.sender.domain) || '';
  const address = (current.sender && current.sender.email) || '';
  if (state.choice === 'greylist') {
    return 'greylisted ' + greylistTarget(current)
      + ' (' + (state.disposition === 'block' ? 'denied' : 'allowed') + ')';
  }
  const verb = state.choice === 'whitelist' ? 'whitelisted ' : 'blacklisted ';
  return verb + (state.wholeDomain ? domain : address);
}

function showReviewError(message) {
  const note = byId('reviewError');
  if (!note) return;
  note.textContent = message;
  note.classList.remove('hidden');
}

async function confirmDecision() {
  const current = state.queue[0];
  if (!current || !state.choice) return;

  const button = byId('confirmBtn');
  const description = describeDecision(current);
  const decision = buildDecision(current);
  button.disabled = true;

  try {
    await postJSON('/api/decisions', decision);
  } catch (err) {
    // The card stays exactly where it is: the applier is all-or-nothing, so a
    // rejected decision changed nothing and the reviewer can try again.
    showReviewError(err.message);
    button.disabled = false;
    return;
  }

  state.queue.shift();
  toast('→ ' + description);
  renderReview();
  // A list moved, so every other view of the lists is stale: the remaining
  // cards' membership lines and the List Data panel both re-read.
  await Promise.all([loadQueue().catch(() => {}), refreshList().catch(() => {})]);
  renderReview();
}

/* Skip: in memory, and nowhere else. */
function skip() {
  if (state.queue.length < 2) {
    toast('Nothing else in the queue to move on to');
    return;
  }
  state.queue.push(state.queue.shift());
  toast('Skipped — stays in queue');
  renderReview();
}

// --- list data -----------------------------------------------------------------

async function refreshList() {
  if (state.curList === 'unknown') {
    state.entries = [];
    renderList();
    return;
  }
  const payload = await getJSON('/api/lists/' + encodeURIComponent(state.curList));
  state.entries = payload.entries || [];
  renderList();
}

function renderList() {
  const scroll = byId('listScroll');
  const isGrey = state.curList === 'greylist';
  const isUnknown = state.curList === 'unknown';

  byId('listTitle').textContent = state.curList.charAt(0).toUpperCase() + state.curList.slice(1);
  byId('chartTitle').textContent = 'Recognitions · ' + state.curList;

  const target = byId('addTarget');
  clear(target);
  if (isUnknown) {
    target.appendChild(document.createTextNode('unknown senders are actioned in the '));
    target.appendChild(el('b', null, 'Review'));
    target.appendChild(document.createTextNode(' panel above'));
  } else {
    target.appendChild(document.createTextNode('adds to '));
    target.appendChild(el('b', null, state.curList));
  }
  byId('addForm').style.display = isUnknown ? 'none' : 'block';
  byId('addDisp').style.display = isGrey ? 'flex' : 'none';
  byId('addStructRow').style.display = isGrey ? 'flex' : 'none';
  byId('addInput').placeholder = isGrey ? '@domain.example' : 'name@address.example';

  clear(scroll);
  const rows = isUnknown ? unknownRows() : state.entries;
  if (!rows.length) {
    const empty = el('div', null, isUnknown ? 'no candidates awaiting review' : 'empty');
    empty.style.fontSize = '11px';
    empty.style.color = 'var(--text-muted)';
    empty.style.padding = '8px';
    scroll.appendChild(empty);
    return;
  }
  rows.forEach((entry) => scroll.appendChild(isGrey ? greyRow(entry) : plainRow(entry)));
}

/* The UNKNOWN tab is the review queue seen from the side: senders on no list,
 * counted and listed from the same candidates the Review panel is working
 * through. */
function unknownRows() {
  return state.queue
    .filter((card) => !card.membership)
    .map((card) => ({
      key: (card.sender && card.sender.email) || 'unknown',
      tags: [],
      structures: [],
    }));
}

function tagChips(entry) {
  const fragment = document.createDocumentFragment();
  (entry.tags || []).forEach((tag) => {
    fragment.appendChild(document.createTextNode(' '));
    fragment.appendChild(el('span', 'tag-mini', tag));
  });
  return fragment;
}

function plainRow(entry) {
  const item = el('div', 'list-item');
  item.appendChild(document.createTextNode(entry.key));
  item.appendChild(tagChips(entry));
  return item;
}

function greyRow(entry) {
  const item = el('div', 'list-item');
  const head = el('div', 'dom-head');
  head.appendChild(el('span', 'caret', '▶'));
  head.appendChild(el('span', null, entry.key));
  head.appendChild(tagChips(entry));

  const structures = el('div', 'struct-list');
  (entry.structures || []).forEach((structure) => {
    const row = el('div', 'struct-item');
    const denied = structure.disposition === 'denied';
    row.appendChild(el('span', 'pill ' + (denied ? 'block' : 'allow'), denied ? 'BLOCK' : 'ALLOW'));
    row.appendChild(document.createTextNode(structure.name));
    structures.appendChild(row);
  });
  if (!(entry.structures || []).length) {
    const none = el('div', 'struct-item', 'no catalogued structures — every shape reviews as new');
    structures.appendChild(none);
  }

  head.addEventListener('click', () => {
    head.classList.toggle('open');
    structures.classList.toggle('open');
  });

  item.appendChild(head);
  item.appendChild(structures);
  return item;
}

// --- add ----------------------------------------------------------------------

function showAddError(message) {
  const note = byId('addError');
  note.textContent = message || '';
  note.classList.toggle('hidden', !message);
}

/* What the reviewer typed, as a list entry.
 *
 * The greylist keys on a domain, so a full address typed into it is read as its
 * domain rather than rejected. Elsewhere a leading '@' (or no '@' at all) means
 * a domain, and anything else an address. */
function buildAddEntry(listName, raw) {
  const value = raw.trim();
  const tags = parseTags(byId('addTags').value);
  if (listName === 'greylist') {
    const at = value.lastIndexOf('@');
    return { domain: (at < 0 ? value : value.slice(at + 1)).trim(), tags: tags };
  }
  if (value.startsWith('@')) return { domain: value.slice(1).trim(), tags: tags };
  if (value.indexOf('@') < 0) return { domain: value, tags: tags };
  return { email: value, tags: tags };
}

async function submitAdd() {
  const listName = state.curList;
  if (LIST_NAMES.indexOf(listName) < 0) return;

  const raw = byId('addInput').value.trim();
  if (!raw) {
    showAddError('nothing to add — type an address or a domain');
    return;
  }

  const body = { entry: buildAddEntry(listName, raw) };
  if (listName === 'greylist') {
    const phrase = byId('addStruct').value.trim();
    if (phrase) {
      body.structure = {
        name: phrase.slice(0, STRUCTURE_NAME_LIMIT),
        key_phrases: [phrase],
        disposition: state.addDisposition === 'block' ? 'denied' : 'allowed',
        tags: parseTags(byId('addTags').value),
      };
    }
  }

  const button = byId('addConfirm');
  button.disabled = true;
  showAddError('');
  try {
    await postJSON('/api/lists/' + encodeURIComponent(listName) + '/add', body);
  } catch (err) {
    showAddError(err.message);
    button.disabled = false;
    return;
  }
  button.disabled = false;
  byId('addInput').value = '';
  byId('addStruct').value = '';
  byId('addTags').value = '';
  toast('Added to the ' + listName);
  // A manual add is a list change like any other -- the card on screen may have
  // just become a member of something.
  await Promise.all([refreshList().catch(() => {}), loadQueue().catch(() => {})]);
  renderReview();
}

// --- config (inert in Phase 1) -------------------------------------------------

/* Rendered, editable in memory, and saved nowhere. The dispatcher owns its own
 * config (`config/config.json`, the `dispatcher` section) and wiring this panel
 * to it is Phase 2 — so SAVE stays disabled rather than lying about it. */
function renderHooks() {
  const box = byId('hooks');
  clear(box);
  state.hooks.forEach((url, index) => {
    const row = el('div', 'hook-row');
    const input = document.createElement('input');
    input.className = 'form-entry';
    input.value = url;
    input.addEventListener('change', () => { state.hooks[index] = input.value; });
    const remove = el('button', 'icon-btn danger', '✕');
    remove.title = 'remove';
    remove.addEventListener('click', () => {
      state.hooks.splice(index, 1);
      renderHooks();
    });
    row.appendChild(input);
    row.appendChild(remove);
    box.appendChild(row);
  });
}

// --- wiring --------------------------------------------------------------------

function wireChrome() {
  const themeSelect = byId('themeSel');
  THEMES.forEach((theme) => {
    const option = document.createElement('option');
    option.value = theme;
    option.textContent = theme;
    themeSelect.appendChild(option);
  });
  themeSelect.value = 'midnight-dark';
  themeSelect.addEventListener('change', () => {
    document.documentElement.dataset.theme = themeSelect.value;
  });

  byId('fsSel').addEventListener('change', (event) => {
    document.documentElement.dataset.fs = event.target.value;
  });
}

function wireListPanel() {
  document.querySelectorAll('#listTabs .tab').forEach((tab) => {
    tab.addEventListener('click', () => {
      state.curList = tab.dataset.list;
      document.querySelectorAll('#listTabs .tab').forEach((other) => other.classList.remove('active'));
      tab.classList.add('active');
      refreshList().catch((err) => toast(err.message));
    });
  });

  byId('addDisp').querySelectorAll('.seg[data-d]').forEach((button) => {
    button.addEventListener('click', () => {
      state.addDisposition = button.dataset.d;
      byId('addDisp').querySelectorAll('.seg').forEach((other) => other.classList.remove('active'));
      button.classList.add('active');
    });
  });

  byId('addConfirm').addEventListener('click', () => { submitAdd(); });
  byId('addHook').addEventListener('click', () => {
    state.hooks.push('');
    renderHooks();
  });
}

// --- rules pack ----------------------------------------------------------------

/* The one live control on the Config panel. Everything else here is still a
 * Phase-2 placeholder, and SAVE stays disabled rather than lying about it.
 *
 * The console does not pull the rules itself: it asks the rules-updater
 * service, which is the only component with git and the only one that can write
 * the rules tree. So every outcome below is the updater's own result, passed
 * through unchanged. */

const RULES_OUTCOMES = {
  updated: (payload) => 'Updated to ' + shortSha(payload.new_commit) + '.',
  no_change: () => 'Already up to date — nothing to promote.',
  rejected: () => 'Rejected: the pulled pack failed validation. The current rules are still live.',
  busy: () => 'Another pull is already running. Nothing was changed.',
  error: (payload) => 'Could not pull: ' + (payload.message || 'unknown error'),
};

function shortSha(sha) {
  if (!sha) return 'unknown';
  return String(sha).slice(0, 12);
}

function whenText(stamp) {
  if (!stamp) return 'never';
  const parsed = new Date(stamp);
  return isNaN(parsed.getTime()) ? String(stamp) : parsed.toLocaleString();
}

function renderRulesStatus(status) {
  const box = byId('rulesStatus');
  clear(box);

  if (!status) {
    box.appendChild(el('div', null, 'Rules status unavailable.'));
    return;
  }

  const commit = el('div', null, '');
  commit.appendChild(el('b', null, shortSha(status.current_commit)));
  commit.appendChild(document.createTextNode(' on ' + (status.branch || 'main')));
  box.appendChild(commit);
  box.appendChild(el('div', null, 'Last pull: ' + whenText(status.last_pull_at)));

  if (status.last_status === 'rejected') {
    const warn = el('div', null, 'Last pull was rejected — running on the previous pack.');
    box.appendChild(warn);
  }
  (status.validation_errors || []).forEach((error) => {
    box.appendChild(el('div', null, '• ' + error));
  });
}

function showRulesError(message) {
  const note = byId('rulesError');
  note.textContent = message || '';
  note.classList.toggle('hidden', !message);
}

function showRulesOutcome(message) {
  const note = byId('rulesOutcome');
  note.textContent = message || '';
  note.classList.toggle('hidden', !message);
}

async function loadRulesStatus() {
  const status = await getJSON('/api/rules/status');
  state.rules = status;
  renderRulesStatus(status);
}

async function refreshRules() {
  const button = byId('refreshRules');
  button.disabled = true;
  showRulesError('');
  showRulesOutcome('Pulling…');

  try {
    const payload = await postJSON('/api/rules/refresh', {});
    const describe = RULES_OUTCOMES[payload.status];
    showRulesOutcome(describe ? describe(payload) : 'Finished: ' + payload.status);

    /* Validation errors belong next to the outcome, not in a toast: there can
     * be several, and they are the whole reason a pack was refused. */
    if (payload.status === 'rejected') {
      showRulesError((payload.validation_errors || []).join('; '));
    }
    (payload.warnings || []).forEach((warning) => toast('Signature feed: ' + warning));

    await loadRulesStatus().catch(() => {});
  } catch (err) {
    showRulesOutcome('');
    showRulesError(err.message);
  } finally {
    button.disabled = false;
  }
}

function wireRulesPanel() {
  byId('refreshRules').addEventListener('click', () => { refreshRules(); });
}

async function start() {
  wireChrome();
  wireListPanel();
  wireRulesPanel();
  renderHooks();
  renderReview();
  renderList();

  try {
    await loadQueue();
    renderReview();
  } catch (err) {
    showReviewError(err.message);
  }
  try {
    await refreshList();
  } catch (err) {
    toast(err.message);
  }
  /* Tolerant: a deployment that is not running the rules updater is a
   * legitimate one, and the rest of the console must still work. */
  try {
    await loadRulesStatus();
  } catch (err) {
    renderRulesStatus(null);
    showRulesError(err.message);
  }
}

start();
