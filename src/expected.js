'use strict';

// ---------------------------------------------------------------------------
// Obraz OCZEKIWANY — odtworzony z migracji na dysku
// ---------------------------------------------------------------------------
//
// Migracje czytamy po kolei, w porzadku nazw plikow, i odgrywamy je na modelu
// uprawnien. Nie wykonujemy zadnego SQL — to czysta symulacja.
//
// MODEL UPRAWNIEN DO FUNKCJI, bo tu siedzi caly blad, ktory chcemy lapac:
//
//   Postgres przy CREATE FUNCTION nadaje EXECUTE roli `public` z automatu.
//   Kazda rola dziedziczy wtedy prawo wywolania PRZEZ `public` — service_role
//   takze, choc nikt mu nic jawnie nie nadal.
//
//   REVOKE ... FROM public zdejmuje to jednym ruchem WSZYSTKIM, ktorzy mieli
//   je tylko ta droga. Jesli po takim revoke nie ma grantu dla konkretnej roli,
//   funkcje moze wolac juz tylko jej wlasciciel.
//
// Dlatego revoke bez grantu nie jest literowka — jest zmiana stanu, ktora
// nasz model musi odwzorowac tak samo jak baza.

const fs = require('fs');
const path = require('path');
const { splitStatements } = require('./tokenizer');
const {
  readQualifiedName, argTypesFromTokens, splitTopLevel, sigKey, sigText, skipParens, readType,
} = require('./signature');
const { normalizeExpr } = require('./expr');

const OWNER = '__owner__'; // wlasciciel: jest zawsze, po obu stronach, nie porownujemy

/** Blad, po ktorym nie wolno wypisac raportu. Kod wyjscia 2, nie 0 i nie 1. */
function fatal(msg) {
  const e = new Error(msg);
  e.supadriftExit = 2;
  e.supadriftFatal = true;
  return e;
}

function buildExpected(migrationsDir, opts = {}) {
  const asOf = opts.asOf || null;
  const schemas = opts.schemas || ['public'];

  // ODPORNOSC. Ponizsze sprawdzenia sa krytyczne, a nie ostrzegawcze, i to jest
  // swiadoma decyzja. Narzedzie, ktore przy nieodczytanych migracjach wypisuje
  // "czysto", jest gorsze od zadnego: mowi, ze sprawdzilo, a nie sprawdzilo nic.
  // Wolimy awarie z kodem 2 niz zero z kodem 0.
  let all;
  try {
    all = fs.readdirSync(migrationsDir)
      .filter((f) => f.toLowerCase().endsWith('.sql'))
      .sort();
  } catch (e) {
    throw fatal('nie da sie odczytac katalogu migracji: ' + migrationsDir + '\n' + e.message);
  }

  if (all.length === 0) {
    throw fatal(
      'katalog nie zawiera ani jednego pliku .sql: ' + migrationsDir + '\n\n'
      + 'Pusty obraz oczekiwany porownany z baza dalby wynik, ktoremu nie wolno\n'
      + 'ufac, wiec supadrift woli sie tu zatrzymac. Sprawdz sciezke --migrations.'
    );
  }

  const files = asOf ? all.filter((f) => f.slice(0, asOf.length) <= asOf) : all;
  if (files.length === 0) {
    throw fatal(
      '--as-of ' + asOf + ' odsiewa WSZYSTKIE ' + all.length + ' migracji.\n'
      + 'Nie ma z czego zbudowac obrazu oczekiwanego.'
    );
  }

  const functions = new Map();
  const tables = new Map();
  const policies = new Map();
  const triggers = new Map();
  const eventTriggers = new Map();
  const notes = [];
  const stats = {
    statements: 0, creates: 0, drops: 0, grants: 0, revokes: 0, tables: 0, policies: 0,
  };

  const damaged = [];

  for (const file of files) {
    let sql;
    try {
      sql = fs.readFileSync(path.join(migrationsDir, file), 'utf8');
    } catch (e) {
      // EACCES, EISDIR, plik zniknal w trakcie — kazdy z nich znaczy, ze tej
      // migracji NIE PRZECZYTALISMY. Pominiecie jej po cichu falszowaloby wynik.
      damaged.push({ file, kind: 'nie-do-odczytania', text: e.code || e.message });
      continue;
    }

    // Bajt zerowy w pliku SQL znaczy, ze to nie jest tekst, ktory ktos napisal:
    // uciety zapis, zly kodek, plik binarny pod nazwa .sql.
    if (sql.indexOf(String.fromCharCode(0)) !== -1) {
      damaged.push({ file, kind: 'bajt-zerowy', text: 'plik zawiera bajt 0x00' });
      continue;
    }

    const issues = [];
    let stmts;
    try {
      stmts = splitStatements(sql, issues);
    } catch (e) {
      damaged.push({ file, kind: 'blad-tokenizacji', text: e.message });
      continue;
    }
    for (const it of issues) {
      damaged.push({
        file, kind: it.kind,
        text: it.line ? 'wiersz ' + it.line : 'na koncu pliku',
      });
    }

    for (const st of stmts) {
      stats.statements++;
      applyStatement(st, {
        file, sql, functions, tables, policies, triggers, eventTriggers, notes, stats, schemas,
      });
    }
  }

  if (damaged.length) {
    throw fatal(
      'nie udalo sie wiarygodnie odczytac ' + damaged.length + ' '
      + (damaged.length === 1 ? 'migracji' : 'migracji') + ':\n\n'
      + damaged.map((u) => '  ' + u.file + '  [' + u.kind + '] ' + u.text).join('\n')
      + '\n\nsupadrift NIE wypisze raportu na niepelnym obrazie. Zero rozjazdow\n'
      + 'przy nieprzeczytanej migracji znaczyloby "nie umiem sprawdzic", a nie\n'
      + '"czysto" — i tak wlasnie brzmi najgorszy mozliwy wynik tego narzedzia.'
    );
  }

  // Zostawiamy tylko interesujace nas schematy.
  for (const [k, f] of functions) if (!schemas.includes(f.schema)) functions.delete(k);
  for (const [k, t] of tables) if (!schemas.includes(t.schema)) tables.delete(k);
  for (const [k, p] of policies) if (!schemas.includes(p.schema)) policies.delete(k);
  for (const [k, tr] of triggers) if (!schemas.includes(tr.schema)) triggers.delete(k);

  return { functions, tables, policies, triggers, eventTriggers, notes, files, stats };
}

function applyStatement(st, ctx) {
  const t = st.tokens;
  const w = (i) => (t[i] && t[i].t === 'word' && !t[i].q ? t[i].v : null);
  const head = w(0);

  if (head === 'create') return onCreate(st, ctx);
  if (head === 'drop') {
    if (w(1) === 'owned') {
      ctx.notes.push(note(st, ctx, 'nieobslugiwane', 'DROP OWNED — moze usunac funkcje i uprawnienia'));
      return undefined;
    }
    return onDrop(st, ctx);
  }
  if (head === 'grant' || head === 'revoke') return onGrantRevoke(st, ctx);
  if (head === 'alter') return onAlter(st, ctx);
  if (head === 'do') return onDo(st, ctx);
  if (head === 'security' && w(1) === 'label') {
    ctx.notes.push(note(st, ctx, 'nieobslugiwane', 'SECURITY LABEL — nie modelowane'));
  }
  if (head === 'reassign') {
    ctx.notes.push(note(st, ctx, 'nieobslugiwane', 'REASSIGN OWNED — zmienia wlasciciela funkcji'));
  }
  return undefined;
}

function note(st, ctx, kind, text) {
  return { file: ctx.file, line: st.line, kind, text };
}

// --- CREATE FUNCTION --------------------------------------------------------

function onCreate(st, ctx) {
  const t = st.tokens;
  let i = 1;
  if (t[i] && t[i].v === 'or' && t[i + 1] && t[i + 1].v === 'replace') i += 2;
  while (t[i] && t[i].t === 'word' && !t[i].q
    && ['temp', 'temporary', 'global', 'local', 'unlogged'].includes(t[i].v)) i++;

  const kindWord = t[i] && t[i].t === 'word' && !t[i].q ? t[i].v : null;
  if (kindWord === 'table') return onCreateTable(st, ctx, i + 1);
  if (kindWord === 'policy') return onCreatePolicy(st, ctx, i + 1);
  if (kindWord === 'trigger') return onCreateTrigger(st, ctx, i + 1, false);
  if (kindWord === 'constraint' && t[i + 1] && t[i + 1].v === 'trigger') {
    return onCreateTrigger(st, ctx, i + 2, true);
  }
  if (kindWord === 'event' && t[i + 1] && t[i + 1].v === 'trigger') {
    return onCreateEventTrigger(st, ctx, i + 2);
  }
  if (kindWord !== 'function' && kindWord !== 'procedure') return;
  i++;

  const qn = readQualifiedName(t, i);
  if (!qn) return;
  i = qn.next;

  let argtypes = [];
  if (t[i] && t[i].t === 'punct' && t[i].v === '(') {
    const end = skipParens(t, i);
    argtypes = argTypesFromTokens(t.slice(i + 1, end - 1));
    i = end;
  }

  const schema = qn.schema || 'public';
  const key = sigKey(schema, qn.name, argtypes);
  const returns = readReturns(t, i);
  const body = readBody(t);
  const securityDefiner = findSeq(t, i, ['security', 'definer']) !== -1;
  const settings = readFunctionSettings(t, i);
  const searchPath = settings.has('search_path') ? settings.get('search_path').values : null;
  ctx.stats.creates++;

  const existing = ctx.functions.get(key);
  if (existing) {
    // CREATE OR REPLACE nie rusza uprawnien — Postgres zachowuje istniejacy ACL.
    // Ale ustawienia i tresc NADPISUJE, wiec te przepisujemy.
    existing.replacedIn.push(ctx.file);
    existing.declared = true;
    existing.returns = returns;
    existing.body = body;
    existing.securityDefiner = securityDefiner;
    existing.settings = settings;
    existing.searchPath = searchPath;
    return;
  }

  ctx.functions.set(key, {
    key,
    schema,
    name: qn.name,
    argtypes,
    text: sigText(schema, qn.name, argtypes),
    kind: kindWord,
    returns,
    body,
    securityDefiner,
    settings,
    searchPath,
    declared: true,
    createdIn: ctx.file,
    createdLine: st.line,
    replacedIn: [],
    owner: null,
    // Domyslny ACL po CREATE: wlasciciel + PUBLIC.
    acl: new Map([[OWNER, mkPriv()], ['public', mkPriv()]]),
    touched: [],
  });
}

function mkPriv(grantOption = false) {
  return { execute: true, grantOption };
}

/**
 * Typ zwracany. Potrzebny dla jednej rzeczy: funkcja zwracajaca `trigger`
 * albo `event_trigger` nie jest wolana wprost. Postgres sprawdza EXECUTE do niej
 * przy CREATE TRIGGER, a nie przy kazdym odpaleniu wyzwalacza — brak nadan
 * jest tam stanem normalnym i zgloszenie go byloby falszywym alarmem.
 */
function readReturns(t, from) {
  const idx = findWord(t, from, 'returns');
  if (idx === -1) return null;
  let k = idx + 1;
  if (t[k] && t[k].t === 'word' && !t[k].q && t[k].v === 'setof') k++;
  if (t[k] && t[k].t === 'word' && !t[k].q && t[k].v === 'table') return 'table';
  const rt = readType(t, k);
  return rt ? rt.type : null;
}

/**
 * Ustawienia przypiete do funkcji: SET nazwa = wartosc [, ...].
 * Interesuje nas glownie search_path, bo w funkcji SECURITY DEFINER decyduje
 * o tym, czyje obiekty zobaczy kod chodzacy z uprawnieniami wlasciciela.
 */
function readFunctionSettings(t, from) {
  const settings = new Map();
  let depth = 0;
  for (let i = from; i < t.length; i++) {
    if (t[i].t === 'punct') {
      if (t[i].v === '(') depth++;
      else if (t[i].v === ')') depth--;
      continue;
    }
    if (depth !== 0) continue;
    if (t[i].t !== 'word' || t[i].q || t[i].v !== 'set') continue;

    const nameTok = t[i + 1];
    if (!nameTok || nameTok.t !== 'word') continue;
    const name = nameTok.q ? nameTok.v : nameTok.v.toLowerCase();

    let k = i + 2;
    if (t[k] && ((t[k].t === 'punct' && t[k].v === '=') || (t[k].t === 'word' && t[k].v === 'to'))) {
      k++;
    } else if (t[k] && t[k].t === 'word' && t[k].v === 'from' && t[k + 1] && t[k + 1].v === 'current') {
      settings.set(name, { values: null, fromCurrent: true });
      i = k + 1;
      continue;
    } else {
      continue;
    }

    const values = [];
    for (;;) {
      const v = t[k];
      if (!v || (v.t !== 'word' && v.t !== 'str' && v.t !== 'num')) break;
      values.push(String(v.v).toLowerCase());
      k++;
      if (t[k] && t[k].t === 'punct' && t[k].v === ',') { k++; continue; }
      break;
    }
    if (values.length) settings.set(name, { values, fromCurrent: false });
    i = k - 1;
  }
  return settings;
}

/** Cialo funkcji — potrzebne wylacznie do zbudowania grafu wywolan w SQL. */
function readBody(t) {
  const d = t.find((x) => x.t === 'dollar');
  if (d) return d.v;
  const asIdx = findWord(t, 0, 'as');
  if (asIdx !== -1 && t[asIdx + 1] && t[asIdx + 1].t === 'str') return t[asIdx + 1].v;
  return null;
}

// --- TABELE: RLS i FORCE ----------------------------------------------------
//
// CREATE TABLE **nie wlacza** RLS. Tabela bez jawnego
// `alter table ... enable row level security` jest otwarta dla kazdego, kto ma
// do niej SELECT — a `anon` i `authenticated` maja go w Supabase z nadania na
// schemacie public. To dlatego brak tej jednej linii w migracji jest cichym
// otwarciem tabeli, a nie drobiazgiem stylistycznym.
//
// FORCE to osobna rzecz i osobno ja trzymamy: RLS domyslnie NIE dotyczy
// wlasciciela tabeli. Dopoki nie ma FORCE, polityki nie obowiazuja tego, kto
// tabele stworzyl — zwykle roli `postgres`, ktora chodzi w migracjach
// i w niejednym zadaniu utrzymaniowym.

function tableKey(schema, name) {
  return (schema || 'public') + '.' + name;
}

function onCreateTable(st, ctx, i) {
  const t = st.tokens;
  if (t[i] && t[i].v === 'if' && t[i + 1] && t[i + 1].v === 'not'
    && t[i + 2] && t[i + 2].v === 'exists') i += 3;

  const qn = readQualifiedName(t, i);
  if (!qn) return;
  const schema = qn.schema || 'public';
  const key = tableKey(schema, qn.name);
  ctx.stats.tables++;
  if (ctx.tables.has(key)) {
    ctx.tables.get(key).declared = true;
    return;
  }
  ctx.tables.set(key, {
    key, schema, name: qn.name,
    // CREATE TABLE nie wlacza RLS i nie ustawia FORCE. Zaden z tych stanow
    // nie bierze sie sam — musi stac w migracji jawnie.
    rls: false,
    force: false,
    declared: true,
    createdIn: ctx.file,
    createdLine: st.line,
    touched: [],
    ops: [],
  });
}

function ensureTable(ctx, schema, name) {
  const key = tableKey(schema, name);
  let tb = ctx.tables.get(key);
  if (!tb) {
    tb = {
      key, schema: schema || 'public', name,
      rls: false, force: false,
      declared: false, createdIn: null, createdLine: 0, touched: [], ops: [],
    };
    ctx.tables.set(key, tb);
  }
  return tb;
}

function onAlterTable(st, ctx, i) {
  const t = st.tokens;
  if (t[i] && t[i].v === 'if' && t[i + 1] && t[i + 1].v === 'exists') i += 2;
  if (t[i] && t[i].t === 'word' && t[i].v === 'only') i++;

  const qn = readQualifiedName(t, i);
  if (!qn) return;
  i = qn.next;
  if (t[i] && t[i].t === 'punct' && t[i].v === '*') i++;

  const schema = qn.schema || 'public';

  const ren = findSeq(t, i, ['rename', 'to']);
  if (ren !== -1) {
    const nn = readQualifiedName(t, ren + 2);
    if (nn) {
      const oldKey = tableKey(schema, qn.name);
      const old = ctx.tables.get(oldKey);
      if (old) {
        ctx.tables.delete(old.key);
        old.name = nn.name;
        old.key = tableKey(schema, nn.name);
        old.touched.push({ file: ctx.file, line: st.line, kind: 'rename' });
        ctx.tables.set(old.key, old);
      }
      // Polityki ida za tabela.
      for (const [pk, p] of [...ctx.policies]) {
        if (policyTableKey(p) !== oldKey) continue;
        ctx.policies.delete(pk);
        p.table = nn.name;
        p.key = policyKey(schema, nn.name, p.name);
        ctx.policies.set(p.key, p);
      }
    }
    return;
  }

  // ALTER TABLE ... ENABLE/DISABLE TRIGGER — wylaczony wyzwalacz istnieje,
  // ale nie odpala sie; z punktu widzenia dzialania to to samo co jego brak.
  if (alterTableTrigger(st, ctx, schema, qn.name, i)) return;

  // Kolejnosc ma znaczenie: NO FORCE zawiera w sobie FORCE.
  const enable = findSeq(t, i, ['enable', 'row', 'level', 'security']);
  const disable = findSeq(t, i, ['disable', 'row', 'level', 'security']);
  const noForce = findSeq(t, i, ['no', 'force', 'row', 'level', 'security']);
  const force = findSeq(t, i, ['force', 'row', 'level', 'security']);

  if (enable === -1 && disable === -1 && noForce === -1 && force === -1) return;

  const tb = ensureTable(ctx, schema, qn.name);
  if (enable !== -1) { tb.rls = true; tb.touched.push(mark(ctx, st, 'enable rls')); }
  if (disable !== -1) { tb.rls = false; tb.touched.push(mark(ctx, st, 'disable rls')); }
  if (noForce !== -1) { tb.force = false; tb.touched.push(mark(ctx, st, 'no force rls')); }
  else if (force !== -1) { tb.force = true; tb.touched.push(mark(ctx, st, 'force rls')); }
}

function mark(ctx, st, kind) {
  return { file: ctx.file, line: st.line, kind };
}

function onDropTable(st, ctx, i) {
  const t = st.tokens;
  if (t[i] && t[i].v === 'if' && t[i + 1] && t[i + 1].v === 'exists') i += 2;
  const list = readObjectList(t, i);
  for (const tgt of list.items) {
    const key = tableKey(tgt.schema || 'public', tgt.name);
    ctx.tables.delete(key);
    // Polityki znikaja razem z tabela — inaczej zostalyby jako duchy.
    for (const [pk, p] of ctx.policies) if (policyTableKey(p) === key) ctx.policies.delete(pk);
  }
}

// --- POLITYKI ---------------------------------------------------------------
//
// CREATE POLICY nazwa ON tabela [AS PERMISSIVE|RESTRICTIVE] [FOR polecenie]
//   [TO role] [USING (wyrazenie)] [WITH CHECK (wyrazenie)]
//
// Domyslne wartosci sa tu wazniejsze niz zwykle, bo prawie nikt ich nie pisze,
// a decyduja o zasiegu polityki:
//   AS   -> PERMISSIVE  (polityki sumuja sie przez OR, nie zawezaja)
//   FOR  -> ALL
//   TO   -> public      (czyli KAZDA rola, takze anon)

function policyTableKey(p) {
  return p.schema + '.' + p.table;
}

function policyKey(schema, table, name) {
  return schema + '.' + table + ':' + name;
}

function rawBetween(ctx, from, to) {
  if (!ctx.sql || !from || !to) return null;
  return ctx.sql.slice(from.pos, to.pos).trim();
}

function onCreatePolicy(st, ctx, i) {
  const t = st.tokens;
  if (!t[i] || t[i].t !== 'word') return;
  const name = t[i].q ? t[i].v : t[i].v;
  i++;
  if (!t[i] || t[i].t !== 'word' || t[i].v !== 'on') return;
  i++;
  const qn = readQualifiedName(t, i);
  if (!qn) return;
  i = qn.next;

  const schema = qn.schema || 'public';
  const pol = {
    key: policyKey(schema, qn.name, name),
    schema, table: qn.name, name,
    permissive: true,
    cmd: 'all',
    roles: ['public'],
    using: null, usingRaw: null,
    check: null, checkRaw: null,
    createdIn: ctx.file, line: st.line,
    declared: true,
  };
  readPolicyClauses(t, i, ctx, pol);
  ctx.stats.policies++;
  ctx.policies.set(pol.key, pol);
}

const POLICY_CLAUSE_STOP = ['using', 'with'];

function readPolicyClauses(t, i, ctx, pol) {
  while (i < t.length) {
    const tk = t[i];
    if (tk.t !== 'word' || tk.q) { i++; continue; }

    if (tk.v === 'as' && t[i + 1] && t[i + 1].t === 'word') {
      pol.permissive = t[i + 1].v !== 'restrictive';
      i += 2; continue;
    }
    if (tk.v === 'for' && t[i + 1] && t[i + 1].t === 'word') {
      pol.cmd = t[i + 1].v;
      i += 2; continue;
    }
    if (tk.v === 'rename' && t[i + 1] && t[i + 1].v === 'to') {
      i += 2; continue; // obsluzone osobno w onAlterPolicy
    }
    if (tk.v === 'to') {
      let end = i + 1;
      while (end < t.length && !(t[end].t === 'word' && !t[end].q
        && POLICY_CLAUSE_STOP.includes(t[end].v))) end++;
      const roles = readRoleList(t.slice(i + 1, end));
      if (roles.length) pol.roles = roles;
      i = end; continue;
    }
    if (tk.v === 'using' && t[i + 1] && t[i + 1].t === 'punct' && t[i + 1].v === '(') {
      const end = skipParens(t, i + 1);
      pol.using = normalizeExpr(t.slice(i + 2, end - 1));
      pol.usingRaw = rawBetween(ctx, t[i + 2], t[end - 1]);
      i = end; continue;
    }
    if (tk.v === 'with' && t[i + 1] && t[i + 1].t === 'word' && t[i + 1].v === 'check'
      && t[i + 2] && t[i + 2].t === 'punct' && t[i + 2].v === '(') {
      const end = skipParens(t, i + 2);
      pol.check = normalizeExpr(t.slice(i + 3, end - 1));
      pol.checkRaw = rawBetween(ctx, t[i + 3], t[end - 1]);
      i = end; continue;
    }
    i++;
  }
}

function onAlterPolicy(st, ctx, i) {
  const t = st.tokens;
  if (!t[i] || t[i].t !== 'word') return;
  const name = t[i].v;
  i++;
  if (!t[i] || t[i].v !== 'on') return;
  i++;
  const qn = readQualifiedName(t, i);
  if (!qn) return;
  i = qn.next;
  const schema = qn.schema || 'public';
  const key = policyKey(schema, qn.name, name);

  const ren = findSeq(t, i, ['rename', 'to']);
  if (ren !== -1 && t[ren + 2] && t[ren + 2].t === 'word') {
    const pol = ctx.policies.get(key);
    if (pol) {
      ctx.policies.delete(key);
      pol.name = t[ren + 2].v;
      pol.key = policyKey(schema, qn.name, pol.name);
      ctx.policies.set(pol.key, pol);
    }
    return;
  }

  let pol = ctx.policies.get(key);
  if (!pol) {
    pol = {
      key, schema, table: qn.name, name,
      permissive: true, cmd: 'all', roles: ['public'],
      using: null, usingRaw: null, check: null, checkRaw: null,
      createdIn: null, line: st.line, declared: false,
    };
    ctx.policies.set(key, pol);
  }
  readPolicyClauses(t, i, ctx, pol);
}

function onDropPolicy(st, ctx, i) {
  const t = st.tokens;
  if (t[i] && t[i].v === 'if' && t[i + 1] && t[i + 1].v === 'exists') i += 2;
  if (!t[i] || t[i].t !== 'word') return;
  const name = t[i].v;
  i++;
  if (!t[i] || t[i].v !== 'on') return;
  i++;
  const qn = readQualifiedName(t, i);
  if (!qn) return;
  ctx.policies.delete(policyKey(qn.schema || 'public', qn.name, name));
}

// --- DROP FUNCTION ----------------------------------------------------------

function onDrop(st, ctx) {
  const t = st.tokens;
  let i = 1;
  const kindWord = t[i] && t[i].t === 'word' ? t[i].v : null;
  if (kindWord === 'table') return onDropTable(st, ctx, i + 1);
  if (kindWord === 'policy') return onDropPolicy(st, ctx, i + 1);
  if (kindWord === 'trigger') return onDropTrigger(st, ctx, i + 1);
  if (kindWord === 'event' && t[i + 1] && t[i + 1].v === 'trigger') {
    return onDropEventTrigger(st, ctx, i + 2);
  }
  if (kindWord !== 'function' && kindWord !== 'procedure' && kindWord !== 'routine') return;
  i++;
  if (t[i] && t[i].v === 'if' && t[i + 1] && t[i + 1].v === 'exists') i += 2;

  const targets = readObjectList(t, i);
  for (const tgt of targets.items) {
    ctx.stats.drops++;
    for (const key of resolveKeys(ctx.functions, tgt)) ctx.functions.delete(key);
  }
}

// --- GRANT / REVOKE ---------------------------------------------------------

const PRIV_WORDS = new Set([
  'select', 'insert', 'update', 'delete', 'truncate', 'references', 'trigger',
  'create', 'connect', 'temporary', 'temp', 'usage', 'set', 'alter', 'maintain',
]);

function onGrantRevoke(st, ctx) {
  const t = st.tokens;
  const isGrant = t[0].v === 'grant';
  let i = 1;

  if (!isGrant && t[i] && t[i].v === 'grant' && t[i + 1] && t[i + 1].v === 'option' && t[i + 2] && t[i + 2].v === 'for') {
    i += 3;
  }

  // GRANT rola TO rola — czlonkostwo, nie uprawnienie do obiektu. Poznajemy
  // po tym, ze nie ma slowa ON.
  const onIdx = findWord(t, i, 'on');
  if (onIdx === -1) return;

  let execute = false;
  let sawOtherPriv = false;
  for (let k = i; k < onIdx; k++) {
    if (t[k].t !== 'word' || t[k].q) continue;
    if (t[k].v === 'execute') execute = true;
    else if (t[k].v === 'all') execute = true; // ALL [PRIVILEGES]
    else if (t[k].v === 'privileges') continue;
    else if (PRIV_WORDS.has(t[k].v)) sawOtherPriv = true;
  }

  i = onIdx + 1;
  const objWord = t[i] && t[i].t === 'word' && !t[i].q ? t[i].v : null;

  // GRANT ... ON ALL {FUNCTIONS|TABLES|SEQUENCES} IN SCHEMA x — hurtowo,
  // nie modelujemy. Musi byc sprawdzone PRZED gałezia tabel, bo inaczej
  // `on all tables in schema storage` zostaloby wzięte za tabele o nazwie "all".
  if (objWord === 'all' && t[i + 1] && t[i + 1].t === 'word'
    && ['functions', 'routines', 'procedures', 'tables', 'sequences'].includes(t[i + 1].v)) {
    ctx.notes.push(note(st, ctx, 'hurtowe',
      (isGrant ? 'GRANT' : 'REVOKE') + ' ON ALL ' + t[i + 1].v.toUpperCase()
      + ' IN SCHEMA — obejmuje funkcje, ale nie jest modelowane wprost'));
    return;
  }
  // Tabele. `ON TABLE t` oraz `ON t` (TABLE jest domyslnym rodzajem obiektu).
  const NON_TABLE = ['sequence', 'database', 'schema', 'domain', 'type',
    'language', 'foreign', 'large', 'tablespace', 'parameter'];
  if (objWord === 'table' || (objWord && !NON_TABLE.includes(objWord)
    && objWord !== 'function' && objWord !== 'procedure' && objWord !== 'routine')) {
    return onTableGrantRevoke(st, ctx, isGrant, onIdx, objWord === 'table' ? i + 1 : i);
  }

  if (objWord !== 'function' && objWord !== 'procedure' && objWord !== 'routine') {
    return; // sekwencja, schemat, baza — nie nasz zakres
  }
  if (!execute && sawOtherPriv) return;
  i++;

  const objs = readObjectList(t, i);
  i = objs.next;

  const kw = isGrant ? 'to' : 'from';
  const kwIdx = findWord(t, i, kw);
  if (kwIdx === -1) return;
  const roleEnd = findRoleListEnd(t, kwIdx + 1);
  const roles = readRoleList(t.slice(kwIdx + 1, roleEnd));
  const withGrantOption = isGrant && findSeq(t, roleEnd, ['with', 'grant', 'option']) !== -1;

  if (isGrant) ctx.stats.grants++; else ctx.stats.revokes++;

  for (const tgt of objs.items) {
    const keys = resolveKeys(ctx.functions, tgt);
    if (keys.length === 0) {
      // Uprawnienie do funkcji, ktorej CREATE nie ma w tym katalogu. Zapisujemy ja
      // mimo to — jesli nie ma jej takze w bazie, to jest rozjazd wart zgloszenia.
      const schema = tgt.schema || 'public';
      const key = sigKey(schema, tgt.name, tgt.argtypes);
      ctx.functions.set(key, {
        key, schema, name: tgt.name, argtypes: tgt.argtypes,
        text: sigText(schema, tgt.name, tgt.argtypes),
        kind: 'function',
        returns: null,
        body: null,
        securityDefiner: false,
        settings: new Map(),
        searchPath: null,
        declared: false,
        createdIn: null,
        createdLine: 0,
        replacedIn: [],
        owner: null,
        acl: new Map([[OWNER, mkPriv()], ['public', mkPriv()]]),
        touched: [],
      });
      if (tgt.argtypes === null) {
        ctx.notes.push(note(st, ctx, 'bez-podpisu',
          'uprawnienie do ' + tgt.name + ' bez listy argumentow — nie da sie wskazac przeciazenia'));
      }
      keys.push(key);
    }
    for (const key of keys) {
      const f = ctx.functions.get(key);
      if (!f) continue;
      for (const role of roles) {
        if (isGrant) f.acl.set(role, mkPriv(withGrantOption));
        else f.acl.delete(role);
      }
      f.touched.push({
        file: ctx.file, line: st.line,
        kind: isGrant ? 'grant' : 'revoke',
        roles: roles.slice(),
      });
    }
  }
}

// --- WYZWALACZE -------------------------------------------------------------
//
// Funkcje wyzwalaczy widzielismy juz wczesniej — ale sama funkcja niczego nie
// robi. Robi to PODPIECIE. `create trigger` moze zostac w jednym srodowisku
// i nie ma po nim sladu w niczym, co dotad sprawdzalismy: funkcja jest po obu
// stronach, uprawnienia sie zgadzaja, a wyzwalacz odpala sie tylko u jednego.
//
// Wyzwalacze zdarzeniowe (`create event trigger`) sa jeszcze gorsze, bo
// wymagaja superusera. Na Supabase rola `postgres`, ktora wykonuje
// `supabase db push`, superuserem NIE JEST — wiec takiego wyzwalacza nie da sie
// wdrozyc migracja i sila rzeczy zaklada sie go recznie. Dokladnie tak powstal
// `rls_guard` w sprawdzanym projekcie. To jest ta klasa rzeczy, ktora zyje
// wylacznie w jednym srodowisku i o ktorej repozytorium nie wie nic.

const TRIGGER_EVENTS = new Set(['insert', 'update', 'delete', 'truncate']);

function triggerKey(schema, table, name) {
  return schema + '.' + table + ':' + name;
}

function onCreateTrigger(st, ctx, i, isConstraint) {
  const t = st.tokens;
  if (!t[i] || t[i].t !== 'word') return;
  const name = t[i].v;
  i++;

  let timing = null;
  if (t[i] && t[i].t === 'word' && !t[i].q) {
    if (t[i].v === 'before') { timing = 'before'; i++; }
    else if (t[i].v === 'after') { timing = 'after'; i++; }
    else if (t[i].v === 'instead' && t[i + 1] && t[i + 1].v === 'of') { timing = 'instead of'; i += 2; }
  }

  const events = [];
  const updateColumns = [];
  for (;;) {
    if (!t[i] || t[i].t !== 'word' || t[i].q || !TRIGGER_EVENTS.has(t[i].v)) break;
    const ev = t[i].v;
    events.push(ev);
    i++;
    // UPDATE OF kol1, kol2 — zawezenie do kolumn. Pominiete dawaloby
    // "wyzwalacz jest w obu i taki sam", gdy w istocie odpala sie inaczej.
    if (ev === 'update' && t[i] && t[i].t === 'word' && !t[i].q && t[i].v === 'of') {
      i++;
      for (;;) {
        if (!t[i] || t[i].t !== 'word') break;
        updateColumns.push(t[i].q ? t[i].v : t[i].v.toLowerCase());
        i++;
        if (t[i] && t[i].t === 'punct' && t[i].v === ',') { i++; continue; }
        break;
      }
    }
    if (t[i] && t[i].t === 'word' && !t[i].q && t[i].v === 'or') { i++; continue; }
    break;
  }

  const onIdx = findWord(t, i, 'on');
  if (onIdx === -1) return;
  const qn = readQualifiedName(t, onIdx + 1);
  if (!qn) return;
  i = qn.next;
  const schema = qn.schema || 'public';

  // Domyslnie FOR EACH STATEMENT — Postgres tak przyjmuje, gdy nie napisano nic.
  let level = 'statement';
  const forIdx = findSeq(t, i, ['for']);
  if (forIdx !== -1) {
    let k = forIdx + 1;
    if (t[k] && t[k].v === 'each') k++;
    if (t[k] && t[k].t === 'word' && (t[k].v === 'row' || t[k].v === 'statement')) level = t[k].v;
  }

  let when = null;
  let whenRaw = null;
  const whenIdx = findWord(t, i, 'when');
  if (whenIdx !== -1 && t[whenIdx + 1] && t[whenIdx + 1].t === 'punct' && t[whenIdx + 1].v === '(') {
    const end = skipParens(t, whenIdx + 1);
    when = normalizeExpr(t.slice(whenIdx + 2, end - 1));
    whenRaw = rawBetween(ctx, t[whenIdx + 2], t[end - 1]);
  }

  const execIdx = findWord(t, i, 'execute');
  let fn = null;
  if (execIdx !== -1) {
    let k = execIdx + 1;
    if (t[k] && t[k].t === 'word' && (t[k].v === 'function' || t[k].v === 'procedure')) k++;
    const f = readQualifiedName(t, k);
    if (f) fn = (f.schema || 'public') + '.' + f.name;
  }

  const key = triggerKey(schema, qn.name, name);
  ctx.triggers.set(key, {
    key, schema, table: qn.name, name,
    timing, events, updateColumns, level,
    when, whenRaw, fn,
    constraint: !!isConstraint,
    enabled: 'O',
    createdIn: ctx.file, line: st.line,
  });
}

function onDropTrigger(st, ctx, i) {
  const t = st.tokens;
  if (t[i] && t[i].v === 'if' && t[i + 1] && t[i + 1].v === 'exists') i += 2;
  if (!t[i] || t[i].t !== 'word') return;
  const name = t[i].v;
  const onIdx = findWord(t, i + 1, 'on');
  if (onIdx === -1) return;
  const qn = readQualifiedName(t, onIdx + 1);
  if (!qn) return;
  ctx.triggers.delete(triggerKey(qn.schema || 'public', qn.name, name));
}

function onCreateEventTrigger(st, ctx, i) {
  const t = st.tokens;
  if (!t[i] || t[i].t !== 'word') return;
  const name = t[i].v;
  i++;
  const onIdx = findWord(t, i, 'on');
  if (onIdx === -1) return;
  const event = t[onIdx + 1] && t[onIdx + 1].t === 'word' ? t[onIdx + 1].v : null;

  const tags = [];
  const tagIdx = findSeq(t, onIdx, ['when', 'tag', 'in']);
  if (tagIdx !== -1 && t[tagIdx + 3] && t[tagIdx + 3].v === '(') {
    const end = skipParens(t, tagIdx + 3);
    for (const g of splitTopLevel(t.slice(tagIdx + 4, end - 1), ',')) {
      if (g[0] && g[0].t === 'str') tags.push(String(g[0].v).toUpperCase());
    }
  }

  const execIdx = findWord(t, onIdx, 'execute');
  let fn = null;
  if (execIdx !== -1) {
    let k = execIdx + 1;
    if (t[k] && t[k].t === 'word' && (t[k].v === 'function' || t[k].v === 'procedure')) k++;
    const f = readQualifiedName(t, k);
    if (f) fn = (f.schema || 'public') + '.' + f.name;
  }

  ctx.eventTriggers.set(name, {
    key: name, name, event, tags: tags.sort(), fn,
    enabled: 'O', createdIn: ctx.file, line: st.line,
  });
}

function onDropEventTrigger(st, ctx, i) {
  const t = st.tokens;
  if (t[i] && t[i].v === 'if' && t[i + 1] && t[i + 1].v === 'exists') i += 2;
  if (t[i] && t[i].t === 'word') ctx.eventTriggers.delete(t[i].v);
}

function onAlterEventTrigger(st, ctx, i) {
  const t = st.tokens;
  if (!t[i] || t[i].t !== 'word') return;
  const et = ctx.eventTriggers.get(t[i].v);
  if (!et) return;
  if (findWord(t, i, 'disable') !== -1) et.enabled = 'D';
  else if (findSeq(t, i, ['enable', 'replica']) !== -1) et.enabled = 'R';
  else if (findSeq(t, i, ['enable', 'always']) !== -1) et.enabled = 'A';
  else if (findWord(t, i, 'enable') !== -1) et.enabled = 'O';
}

/** ALTER TABLE t {ENABLE|DISABLE} [REPLICA|ALWAYS] TRIGGER {nazwa|ALL|USER} */
function alterTableTrigger(st, ctx, schema, table, i) {
  const t = st.tokens;
  const trigIdx = findWord(t, i, 'trigger');
  if (trigIdx === -1) return false;
  const disable = findWord(t, i, 'disable') !== -1;
  let state = 'O';
  if (disable) state = 'D';
  else if (findSeq(t, i, ['enable', 'replica']) !== -1) state = 'R';
  else if (findSeq(t, i, ['enable', 'always']) !== -1) state = 'A';

  const target = t[trigIdx + 1] && t[trigIdx + 1].t === 'word' ? t[trigIdx + 1].v : null;
  for (const [k, tr] of ctx.triggers) {
    if (tr.schema !== schema || tr.table !== table) continue;
    if (target === 'all' || target === 'user' || tr.name === target) tr.enabled = state;
  }
  return true;
}

// --- NADANIA NA TABELACH ----------------------------------------------------
//
// Rozni sie od funkcji dwoma rzeczami, i obie potrafia zmylic.
//
// 1. CREATE TABLE NIE nadaje niczego roli `public` — inaczej niz CREATE FUNCTION.
//    Za to w Supabase dziala ALTER DEFAULT PRIVILEGES, wiec nowa tabela dostaje
//    nadania z pg_default_acl. Linii bazowej nie da sie odczytac z migracji;
//    bierzemy ja z bazy przy porownaniu (patrz src/tablegrants.js).
//
// 2. Nadania KOLUMNOWE (`grant select (a, b) on table t to r`) nie siedza
//    w pg_class.relacl, tylko w pg_attribute.attacl. Model, ktory ich nie zna,
//    zglosilby "migracja nadaje select roli anon, a baza nie" przy kazdej
//    tabeli, ktora ich uzywa — czyli sklamalby akurat tam, gdzie uprawnienia
//    sa najstaranniej dobrane.
//
// REVOKE na poziomie tabeli zdejmuje TAKZE nadania kolumnowe: tak mowi
// dokumentacja Postgresa i tak to odgrywamy.

const TABLE_PRIVS = new Set([
  'select', 'insert', 'update', 'delete', 'truncate', 'references', 'trigger', 'maintain',
]);

/** Czyta liste uprawnien, razem z opcjonalnymi listami kolumn. */
function readPrivileges(t, from, to) {
  const items = [];
  let all = false;
  for (const grp of splitTopLevel(t.slice(from, to), ',')) {
    if (!grp.length) continue;
    let k = 0;
    if (grp[k].t !== 'word' || grp[k].q) continue;
    const name = grp[k].v;
    if (name === 'all') { all = true; continue; }
    if (name === 'privileges') continue;
    if (!TABLE_PRIVS.has(name)) continue;
    k++;
    let columns = null;
    if (grp[k] && grp[k].t === 'punct' && grp[k].v === '(') {
      const end = skipParens(grp, k);
      columns = splitTopLevel(grp.slice(k + 1, end - 1), ',')
        .map((g) => (g[0] && g[0].t === 'word' ? (g[0].q ? g[0].v : g[0].v.toLowerCase()) : null))
        .filter(Boolean);
    }
    items.push({ name, columns });
  }
  return { items, all };
}

function onTableGrantRevoke(st, ctx, isGrant, onIdx, objStart) {
  const t = st.tokens;
  const privStart = isGrant ? 1 : (t[1] && t[1].v === 'grant' ? 4 : 1);
  const { items, all } = readPrivileges(t, privStart, onIdx);
  if (!all && !items.length) return;

  const objs = readObjectList(t, objStart);
  const kw = isGrant ? 'to' : 'from';
  const kwIdx = findWord(t, objs.next, kw);
  if (kwIdx === -1) return;
  const roleEnd = findRoleListEnd(t, kwIdx + 1);
  const roles = readRoleList(t.slice(kwIdx + 1, roleEnd));
  if (!roles.length) return;

  for (const tgt of objs.items) {
    const tb = ensureTable(ctx, tgt.schema || 'public', tgt.name);
    tb.ops.push({
      op: isGrant ? 'grant' : 'revoke',
      all,
      privs: items.filter((x) => x.columns === null).map((x) => x.name),
      columnPrivs: items.filter((x) => x.columns !== null),
      roles,
      file: ctx.file,
      line: st.line,
    });
  }
}

// --- ALTER ------------------------------------------------------------------

function onAlter(st, ctx) {
  const t = st.tokens;
  const w = (i) => (t[i] && t[i].t === 'word' && !t[i].q ? t[i].v : null);

  if (w(1) === 'default' && w(2) === 'privileges') {
    ctx.notes.push(note(st, ctx, 'nieobslugiwane',
      'ALTER DEFAULT PRIVILEGES — zmienia uprawnienia funkcji tworzonych pozniej, nie jest modelowane'));
    return;
  }
  if (w(1) === 'table') return onAlterTable(st, ctx, 2);
  if (w(1) === 'policy') return onAlterPolicy(st, ctx, 2);
  if (w(1) === 'event' && w(2) === 'trigger') return onAlterEventTrigger(st, ctx, 3);
  if (w(1) !== 'function' && w(1) !== 'procedure' && w(1) !== 'routine') return;

  let i = 2;
  const qn = readQualifiedName(t, i);
  if (!qn) return;
  i = qn.next;
  let argtypes = null;
  if (t[i] && t[i].t === 'punct' && t[i].v === '(') {
    const end = skipParens(t, i);
    argtypes = argTypesFromTokens(t.slice(i + 1, end - 1));
    i = end;
  }
  const keys = resolveKeys(ctx.functions, { schema: qn.schema, name: qn.name, argtypes });

  // ALTER FUNCTION ... SET search_path = ... — druga droga do tego samego stanu
  // co SET w CREATE FUNCTION, wiec musi trafiac w to samo miejsce w modelu.
  const settings = readFunctionSettings(t, i);
  if (settings.size) {
    for (const key of keys) {
      const f = ctx.functions.get(key);
      if (!f) continue;
      for (const [name, val] of settings) f.settings.set(name, val);
      if (settings.has('search_path')) f.searchPath = settings.get('search_path').values;
    }
  }
  if (findSeq(t, i, ['reset', 'all']) !== -1) {
    for (const key of keys) {
      const f = ctx.functions.get(key);
      if (!f) continue;
      f.settings = new Map();
      f.searchPath = null;
    }
  }
  if (findSeq(t, i, ['security', 'definer']) !== -1) {
    for (const key of keys) if (ctx.functions.get(key)) ctx.functions.get(key).securityDefiner = true;
  }
  if (findSeq(t, i, ['security', 'invoker']) !== -1) {
    for (const key of keys) if (ctx.functions.get(key)) ctx.functions.get(key).securityDefiner = false;
  }

  const ownerIdx = findSeq(t, i, ['owner', 'to']);
  if (ownerIdx === -1) return;
  const owner = readRoleName(t, ownerIdx + 2);
  if (!owner) return;
  for (const key of keys) {
    const f = ctx.functions.get(key);
    if (f) f.owner = owner;
  }
}

function onDo(st, ctx) {
  const body = st.tokens.find((x) => x.t === 'dollar');
  if (!body) return;
  if (/(^|[^a-z_])(grant|revoke)([^a-z_]|$)/i.test(body.v)) {
    ctx.notes.push(note(st, ctx, 'nieobslugiwane',
      'blok DO zawiera GRANT/REVOKE — dynamiczny SQL nie jest odgrywany przez supadrift'));
  }
}

// --- pomocnicze -------------------------------------------------------------

function findWord(t, from, word) {
  let depth = 0;
  for (let i = from; i < t.length; i++) {
    if (t[i].t === 'punct') {
      if (t[i].v === '(') depth++;
      else if (t[i].v === ')') depth--;
      continue;
    }
    if (depth === 0 && t[i].t === 'word' && !t[i].q && t[i].v === word) return i;
  }
  return -1;
}

function findSeq(t, from, words) {
  for (let i = from; i + words.length <= t.length; i++) {
    let ok = true;
    for (let k = 0; k < words.length; k++) {
      const tk = t[i + k];
      if (!tk || tk.t !== 'word' || tk.q || tk.v !== words[k]) { ok = false; break; }
    }
    if (ok) return i;
  }
  return -1;
}

/** Lista obiektow: nazwa[(argumenty)] [, ...] */
function readObjectList(t, i) {
  const items = [];
  for (;;) {
    const qn = readQualifiedName(t, i);
    if (!qn) break;
    i = qn.next;
    let argtypes = null;
    if (t[i] && t[i].t === 'punct' && t[i].v === '(') {
      const end = skipParens(t, i);
      argtypes = argTypesFromTokens(t.slice(i + 1, end - 1));
      i = end;
    }
    items.push({ schema: qn.schema, name: qn.name, argtypes });
    if (t[i] && t[i].t === 'punct' && t[i].v === ',') { i++; continue; }
    break;
  }
  return { items, next: i };
}

const ROLE_STOP = new Set(['with', 'cascade', 'restrict', 'granted', 'by']);

function findRoleListEnd(t, i) {
  for (; i < t.length; i++) {
    if (t[i].t === 'word' && !t[i].q && ROLE_STOP.has(t[i].v)) return i;
  }
  return t.length;
}

function readRoleName(t, i) {
  if (!t[i]) return null;
  if (t[i].t === 'word' && !t[i].q && t[i].v === 'group') i++;
  if (!t[i] || t[i].t !== 'word') return null;
  return t[i].q ? t[i].v : t[i].v.toLowerCase();
}

function readRoleList(toks) {
  const out = [];
  for (const grp of splitTopLevel(toks, ',')) {
    const r = readRoleName(grp, 0);
    if (r) out.push(r);
  }
  return out;
}

/** Zamienia cel (nazwa + opcjonalne argumenty) na klucze istniejacych funkcji. */
function resolveKeys(functions, tgt) {
  const schema = tgt.schema || 'public';
  if (tgt.argtypes !== null) {
    const key = sigKey(schema, tgt.name, tgt.argtypes);
    return functions.has(key) ? [key] : [];
  }
  const out = [];
  for (const [k, f] of functions) if (f.schema === schema && f.name === tgt.name) out.push(k);
  return out;
}

module.exports = { buildExpected, OWNER };
