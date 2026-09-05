'use strict';

// ---------------------------------------------------------------------------
// Podpis funkcji — wspolna postac dla pliku i dla bazy
// ---------------------------------------------------------------------------
//
// Zeby porownac "co mowi migracja" z "co jest w bazie", obie strony musza
// nazwac te sama funkcje tak samo. Postgres identyfikuje funkcje przez schemat,
// nazwe i TYPY argumentow wejsciowych — nie przez ich nazwy. Dlatego
//
//   public.refund_quota(p_user uuid, p_action text)   [z create]
//   public.refund_quota(uuid, text)                   [z grant]
//   proargtypes = {uuid, text}                             [z pg_proc]
//
// musza dac ten sam klucz: public.refund_quota(uuid,text).
//
// Argumenty OUT do podpisu NIE wchodza (nie ma ich w proargtypes). INOUT
// i VARIADIC wchodza.

// Aliasy sprowadzone do tego, co wypisuje pg_catalog.format_type().
const TYPE_ALIAS = new Map(Object.entries({
  int: 'integer', int4: 'integer',
  int2: 'smallint',
  int8: 'bigint',
  bool: 'boolean',
  varchar: 'character varying',
  char: 'character', bpchar: 'character',
  float4: 'real',
  float8: 'double precision', float: 'double precision',
  decimal: 'numeric',
  timestamptz: 'timestamp with time zone',
  timetz: 'time with time zone',
  timestamp: 'timestamp without time zone',
  time: 'time without time zone',
  serial: 'integer', serial4: 'integer', serial8: 'bigint', bigserial: 'bigint',
}));

// Slowa, po ktorych typ moze isc dalej niz jeden wyraz.
const MULTIWORD = {
  double: ['precision'],
  character: ['varying'],
  bit: ['varying'],
  timestamp: ['with', 'without'],
  time: ['with', 'without'],
};

const MODES = new Set(['in', 'out', 'inout', 'variadic']);

/** Czyta typ zaczynajacy sie na pozycji k. Zwraca null, jesli tam typu nie ma. */
function readType(toks, k) {
  if (!toks[k] || toks[k].t !== 'word') return null;
  let i = k;
  const parts = [];

  parts.push(toks[i].q ? toks[i].v : toks[i].v.toLowerCase());
  i++;
  while (toks[i] && toks[i].t === 'punct' && toks[i].v === '.' && toks[i + 1] && toks[i + 1].t === 'word') {
    parts.push('.', toks[i + 1].q ? toks[i + 1].v : toks[i + 1].v.toLowerCase());
    i += 2;
  }

  if (parts.length === 1 && !toks[k].q) {
    const base = parts[0];
    if (base === 'timestamp' || base === 'time') {
      let j = i;
      if (toks[j] && toks[j].t === 'punct' && toks[j].v === '(') j = skipParens(toks, j);
      if (toks[j] && toks[j].t === 'word' && (toks[j].v === 'with' || toks[j].v === 'without')
        && toks[j + 1] && toks[j + 1].v === 'time' && toks[j + 2] && toks[j + 2].v === 'zone') {
        parts.push(' ', toks[j].v, ' time zone');
        i = j + 3;
      }
    } else if (MULTIWORD[base] && toks[i] && toks[i].t === 'word' && MULTIWORD[base].includes(toks[i].v)) {
      parts.push(' ', toks[i].v);
      i++;
    }
  }

  // modyfikator dlugosci/precyzji — dla argumentow funkcji Postgres go ignoruje
  if (toks[i] && toks[i].t === 'punct' && toks[i].v === '(') i = skipParens(toks, i);

  // wymiary tablicy
  let dims = '';
  while (toks[i] && toks[i].t === 'punct' && toks[i].v === '[') {
    let j = i + 1;
    if (toks[j] && toks[j].t === 'num') j++;
    if (!toks[j] || toks[j].v !== ']') break;
    dims += '[]';
    i = j + 1;
  }

  return { type: normalizeType(parts.join('') + dims), next: i };
}

function skipParens(toks, i) {
  let depth = 0;
  for (; i < toks.length; i++) {
    if (toks[i].t !== 'punct') continue;
    if (toks[i].v === '(') depth++;
    else if (toks[i].v === ')') { depth--; if (depth === 0) return i + 1; }
  }
  return i;
}

const ARRAY_TAIL = /((\[\])+)$/;

function normalizeType(raw) {
  let t = String(raw).trim().replace(/\s+/g, ' ');
  let dims = '';
  const m = ARRAY_TAIL.exec(t);
  if (m) { dims = m[1]; t = t.slice(0, -dims.length); }
  const lower = t.toLowerCase();
  let bare = lower;
  for (const pfx of ['pg_catalog.', 'public.']) if (bare.startsWith(pfx)) bare = bare.slice(pfx.length);
  const mapped = TYPE_ALIAS.get(bare);
  return (mapped || bare) + dims;
}

/** Rozbija tokeny listy argumentow (to, co MIEDZY nawiasami) na typy podpisu. */
function argTypesFromTokens(toks) {
  const groups = splitTopLevel(toks, ',');
  const types = [];
  for (const g of groups) {
    let t = trimDefault(g);
    if (!t.length) continue;

    let mode = 'in';
    if (t[0].t === 'word' && !t[0].q && MODES.has(t[0].v) && t.length > 1) {
      mode = t[0].v;
      t = t.slice(1);
    }
    if (mode === 'out') continue; // nie wchodzi do podpisu

    // Czy pierwszy token to nazwa argumentu, czy juz typ? Rozstrzygamy proba:
    // jesli typ czytany od zera zjada CALA reszte, nazwy nie bylo.
    const whole = readType(t, 0);
    if (whole && whole.next === t.length) { types.push(whole.type); continue; }
    const after = readType(t, 1);
    if (after) { types.push(after.type); continue; }
    if (whole) { types.push(whole.type); continue; }
  }
  return types;
}

function trimDefault(toks) {
  for (let i = 0; i < toks.length; i++) {
    if (toks[i].t === 'word' && !toks[i].q && toks[i].v === 'default') return toks.slice(0, i);
    if (toks[i].t === 'punct' && toks[i].v === '=') return toks.slice(0, i);
  }
  return toks;
}

function splitTopLevel(toks, sep) {
  const out = [];
  let cur = [];
  let depth = 0;
  for (const tk of toks) {
    if (tk.t === 'punct') {
      if (tk.v === '(' || tk.v === '[') depth++;
      else if (tk.v === ')' || tk.v === ']') depth--;
      else if (tk.v === sep && depth === 0) { out.push(cur); cur = []; continue; }
    }
    cur.push(tk);
  }
  if (cur.length) out.push(cur);
  return out;
}

/** Czyta nazwe kwalifikowana: [schemat.]nazwa */
function readQualifiedName(toks, k) {
  if (!toks[k] || toks[k].t !== 'word') return null;
  const parts = [toks[k].q ? toks[k].v : toks[k].v.toLowerCase()];
  let i = k + 1;
  while (toks[i] && toks[i].t === 'punct' && toks[i].v === '.' && toks[i + 1] && toks[i + 1].t === 'word') {
    parts.push(toks[i + 1].q ? toks[i + 1].v : toks[i + 1].v.toLowerCase());
    i += 2;
  }
  const name = parts[parts.length - 1];
  const schema = parts.length > 1 ? parts[parts.length - 2] : null;
  return { schema, name, next: i };
}

/** Klucz porownania. argtypes === null znaczy "dowolne przeciazenie". */
function sigKey(schema, name, argtypes) {
  const s = schema || 'public';
  return argtypes === null ? s + '.' + name + '(*)' : s + '.' + name + '(' + argtypes.join(',') + ')';
}

function sigText(schema, name, argtypes) {
  const s = schema || 'public';
  return argtypes === null ? s + '.' + name + '(...)' : s + '.' + name + '(' + argtypes.join(', ') + ')';
}

module.exports = {
  readType, readQualifiedName, argTypesFromTokens, splitTopLevel,
  normalizeType, sigKey, sigText, skipParens,
};
