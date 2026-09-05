'use strict';

// ---------------------------------------------------------------------------
// Obraz RZECZYWISTY — odczytany z bazy
// ---------------------------------------------------------------------------
//
// Jedno zapytanie, stale, bez sklejania z czymkolwiek z zewnatrz. Nie ma tu
// interpolacji, wiec nie ma czego wstrzyknac. Filtrowanie schematow robimy
// po stronie JavaScriptu, zeby zapytanie moglo pozostac napisem stalym.
//
// CO CZYTAMY I DLACZEGO AKURAT TO
//   proargtypes  typy argumentow WEJSCIOWYCH — to one, a nie nazwy, tworza
//                tozsamosc funkcji w Postgresie; po nich laczymy z migracja
//   proacl       lista uprawnien; NULL znaczy "domyslne", czyli wlasciciel
//                plus EXECUTE dla `public` — i to NULL jest cala pulapka,
//                bo wyglada jak "brak uprawnien", a znaczy "dla wszystkich"
//   proowner     wlasciciel; jego wpis pomijamy przy porownaniu, bo po stronie
//                migracji nikt go nie zapisuje jawnie
//   pg_depend    odsiewamy funkcje nalezace do rozszerzen (deptype 'e') —
//                pgcrypto czy uuid-ossp nigdy nie beda w katalogu migracji
//                i zglaszanie ich jako rozjazd byloby samym halasem

const SYSTEM_SCHEMAS = new Set(['pg_catalog', 'information_schema', 'pg_toast']);

const FUNCTIONS_SQL = [
  'select',
  '  n.nspname as schema,',
  '  p.proname as name,',
  '  to_jsonb(coalesce(',
  '    (select array_agg(pg_catalog.format_type(u.t, null) order by u.o)',
  '       from unnest(p.proargtypes) with ordinality as u(t, o)),',
  "    array[]::text[])) as argtypes,",
  '  pg_catalog.pg_get_userbyid(p.proowner) as owner,',
  '  p.prokind::text as kind,',
  '  pg_catalog.format_type(p.prorettype, null) as returns,',
  '  p.prosrc as body,',
  '  p.prosecdef as security_definer,',
  '  to_jsonb(coalesce(p.proconfig, array[]::text[])) as config,',
  '  to_jsonb(coalesce(p.proacl::text[], array[]::text[])) as acl,',
  '  (p.proacl is null) as acl_is_default',
  'from pg_catalog.pg_proc p',
  'join pg_catalog.pg_namespace n on n.oid = p.pronamespace',
  "where p.prokind in ('f', 'p')",
  "  and n.nspname not in ('pg_catalog', 'information_schema', 'pg_toast')",
  '  and not exists (',
  '    select 1 from pg_catalog.pg_depend d',
  "    where d.classid = 'pg_catalog.pg_proc'::regclass",
  '      and d.objid = p.oid',
  "      and d.deptype = 'e')",
  'order by 1, 2, 3',
].join('\n');

// Tabele zwykle ('r') i partycjonowane ('p'). Widoki RLS nie dotyczy.
const TABLES_SQL = [
  'select',
  '  n.nspname as schema,',
  '  c.relname as name,',
  '  c.relrowsecurity as rls,',
  '  c.relforcerowsecurity as force_rls,',
  '  c.relkind::text as kind,',
  '  pg_catalog.pg_get_userbyid(c.relowner) as owner,',
  '  to_jsonb(coalesce(c.relacl::text[], array[]::text[])) as acl,',
  '  (c.relacl is null) as acl_is_default',
  'from pg_catalog.pg_class c',
  'join pg_catalog.pg_namespace n on n.oid = c.relnamespace',
  "where c.relkind in ('r', 'p')",
  "  and n.nspname not in ('pg_catalog', 'information_schema', 'pg_toast')",
  '  and not exists (',
  '    select 1 from pg_catalog.pg_depend d',
  "    where d.classid = 'pg_catalog.pg_class'::regclass",
  '      and d.objid = c.oid',
  "      and d.deptype = 'e')",
  'order by 1, 2',
].join('\n');

// polroles zawierajace OID 0 znaczy `public` — czyli KAZDA rola, takze anon.
// Zapisujemy to jawnie, bo pusty odbiorca latwo pomylic z brakiem odbiorcy.
const POLICIES_SQL = [
  'select',
  '  n.nspname as schema,',
  '  c.relname as table_name,',
  '  p.polname as name,',
  '  p.polcmd::text as cmd,',
  '  p.polpermissive as permissive,',
  '  to_jsonb(coalesce(',
  '    (select array_agg(',
  "       case when r = 0 then 'public' else pg_catalog.pg_get_userbyid(r) end",
  '       order by r)',
  '       from unnest(p.polroles) r),',
  "    array[]::text[])) as roles,",
  '  pg_catalog.pg_get_expr(p.polqual, p.polrelid) as using_expr,',
  '  pg_catalog.pg_get_expr(p.polwithcheck, p.polrelid) as check_expr',
  'from pg_catalog.pg_policy p',
  'join pg_catalog.pg_class c on c.oid = p.polrelid',
  'join pg_catalog.pg_namespace n on n.oid = c.relnamespace',
  "where n.nspname not in ('pg_catalog', 'information_schema', 'pg_toast')",
  'order by 1, 2, 3',
].join('\n');

const CMD_NAMES = { r: 'select', a: 'insert', w: 'update', d: 'delete', '*': 'all' };

// Nadania kolumnowe siedza osobno, w pg_attribute.attacl. Tabela, ktora ich
// uzywa, ma w relacl PUSTO dla tych rol — model bez tego zapytania zglaszalby
// przy niej rozjazd, ktorego nie ma.
const COLUMNS_SQL = [
  'select',
  '  n.nspname as schema,',
  '  c.relname as table_name,',
  '  a.attname as column_name,',
  '  to_jsonb(a.attacl::text[]) as acl',
  'from pg_catalog.pg_attribute a',
  'join pg_catalog.pg_class c on c.oid = a.attrelid',
  'join pg_catalog.pg_namespace n on n.oid = c.relnamespace',
  'where a.attacl is not null',
  "  and c.relkind in ('r', 'p')",
  "  and n.nspname not in ('pg_catalog', 'information_schema', 'pg_toast')",
  'order by 1, 2, 3',
].join('\n');

// Linia bazowa nowej tabeli. W Supabase ALTER DEFAULT PRIVILEGES jest ustawione
// poza migracjami, wiec swiezo utworzona tabela NIE startuje z pustym ACL.
// Bez tego kazda tabela wygladalaby na rozjechana.
const DEFAULT_ACL_SQL = [
  'select',
  "  coalesce(n.nspname, '') as schema,",
  '  pg_catalog.pg_get_userbyid(d.defaclrole) as owner,',
  '  d.defaclobjtype::text as objtype,',
  '  to_jsonb(coalesce(d.defaclacl::text[], array[]::text[])) as acl,',
  "  current_setting('server_version_num') as server_version",
  'from pg_catalog.pg_default_acl d',
  'left join pg_catalog.pg_namespace n on n.oid = d.defaclnamespace',
  "where d.defaclobjtype = 'r'",
].join('\n');

// WYZWALACZE.
//
// `not t.tgisinternal` jest tu warunkiem koniecznym, nie kosmetyka: Postgres
// zaklada wlasne, ukryte wyzwalacze dla KAZDEGO klucza obcego. Bez tego filtru
// raport tonalby w pozycjach typu "RI_ConstraintTrigger_c_12345", ktorych nikt
// nigdy nie napisze w migracji.
//
// tgtype to maska bitowa; dekodujemy ja w JavaScripcie (patrz decodeTgType),
// bo to czytelniejsze niż siedem wyrazen CASE w SQL.
const TRIGGERS_SQL = [
  'select',
  '  n.nspname as schema,',
  '  c.relname as table_name,',
  '  t.tgname as name,',
  '  t.tgtype::int as tgtype,',
  '  t.tgenabled::text as enabled,',
  "  fnn.nspname || '.' || p.proname as function_name,",
  '  to_jsonb(coalesce(',
  '    (select array_agg(a.attname order by u.ord)',
  '       from unnest(t.tgattr) with ordinality as u(num, ord)',
  '       join pg_catalog.pg_attribute a',
  '         on a.attrelid = t.tgrelid and a.attnum = u.num),',
  "    array[]::text[])) as update_columns,",
  '  pg_catalog.pg_get_expr(t.tgqual, t.tgrelid) as when_expr,',
  '  (t.tgconstraint <> 0) as is_constraint',
  'from pg_catalog.pg_trigger t',
  'join pg_catalog.pg_class c on c.oid = t.tgrelid',
  'join pg_catalog.pg_namespace n on n.oid = c.relnamespace',
  'join pg_catalog.pg_proc p on p.oid = t.tgfoid',
  'join pg_catalog.pg_namespace fnn on fnn.oid = p.pronamespace',
  'where not t.tgisinternal',
  "  and n.nspname not in ('pg_catalog', 'information_schema', 'pg_toast')",
  '  and not exists (',
  '    select 1 from pg_catalog.pg_depend d',
  "    where d.classid = 'pg_catalog.pg_trigger'::regclass",
  '      and d.objid = t.oid',
  "      and d.deptype = 'e')",
  'order by 1, 2, 3',
].join('\n');

// Wyzwalacze zdarzeniowe sa obiektem CALEJ BAZY, nie schematu — dlatego nie ma
// tu filtra po nspname i dlatego nie da sie ich przypisac do zadnej tabeli.
const EVENT_TRIGGERS_SQL = [
  'select',
  '  e.evtname as name,',
  '  e.evtevent as event,',
  '  e.evtenabled::text as enabled,',
  '  fnn.nspname as function_schema,',
  "  fnn.nspname || '.' || p.proname as function_name,",
  '  to_jsonb(coalesce(e.evttags, array[]::text[])) as tags',
  'from pg_catalog.pg_event_trigger e',
  'join pg_catalog.pg_proc p on p.oid = e.evtfoid',
  'join pg_catalog.pg_namespace fnn on fnn.oid = p.pronamespace',
  'where not exists (',
  '  select 1 from pg_catalog.pg_depend d',
  "  where d.classid = 'pg_catalog.pg_event_trigger'::regclass",
  '    and d.objid = e.oid',
  "    and d.deptype = 'e')",
  'order by 1',
].join('\n');

const { sigKey, sigText, normalizeType } = require('./signature');
const { normalizeExpr } = require('./expr');

/**
 * @param {{query: (sql:string)=>Promise<object[]>}} driver
 * @returns {Promise<{functions:Map<string,object>, schemasSeen:string[]}>}
 */
async function introspect(driver, opts = {}) {
  const schemas = opts.schemas || ['public'];
  const rows = await driver.query(FUNCTIONS_SQL);

  const functions = new Map();
  const schemasSeen = new Set();

  for (const row of rows) {
    const schema = String(row.schema);
    if (SYSTEM_SCHEMAS.has(schema)) continue;
    schemasSeen.add(schema);
    if (!schemas.includes(schema)) continue;

    const argtypes = asArray(row.argtypes).map((t) => normalizeType(t));
    const name = String(row.name);
    const key = sigKey(schema, name, argtypes);
    const owner = String(row.owner);

    functions.set(key, {
      key,
      schema,
      name,
      argtypes,
      text: sigText(schema, name, argtypes),
      kind: row.kind === 'p' ? 'procedure' : 'function',
      // Typ zwracany i cialo sluza wylacznie do odsiania wyzwalaczy i do grafu
      // wywolan. Cialo nigdy nie trafia do raportu — jest tresc z bazy, wiec
      // traktujemy je jak dane, nie jak cokolwiek do wypisania.
      returns: row.returns === null || row.returns === undefined ? null : String(row.returns),
      body: row.body === null || row.body === undefined ? null : String(row.body),
      owner,
      settings: parseProconfig(asArray(row.config)),
      searchPath: searchPathOf(asArray(row.config)),
      securityDefiner: row.security_definer === true || row.security_definer === 't',
      aclIsDefault: row.acl_is_default === true || row.acl_is_default === 't',
      acl: parseAclList(asArray(row.acl), owner, row.acl_is_default === true || row.acl_is_default === 't'),
    });
  }

  return { functions, schemasSeen: [...schemasSeen].sort() };
}

function asArray(v) {
  if (Array.isArray(v)) return v;
  if (v === null || v === undefined) return [];
  if (typeof v === 'string') {
    try {
      const p = JSON.parse(v);
      return Array.isArray(p) ? p : [];
    } catch {
      return [];
    }
  }
  return [];
}

/**
 * proacl to lista wpisow `odbiorca=uprawnienia/nadajacy`.
 * Pusty odbiorca oznacza role `public`. Znak X to EXECUTE, gwiazdka po nim
 * to WITH GRANT OPTION.
 */
function parseAclList(items, owner, isDefault) {
  const acl = new Map();
  if (isDefault || items.length === 0) {
    // NULL w proacl = uprawnienia domyslne: wlasciciel + EXECUTE dla `public`.
    acl.set('__owner__', { execute: true, grantOption: true, grantor: owner });
    acl.set('public', { execute: true, grantOption: false, grantor: owner });
    return acl;
  }
  for (const raw of items) {
    const e = parseAclItem(String(raw));
    if (!e) continue;
    const role = e.grantee === '' ? 'public' : e.grantee;
    const key = role === owner ? '__owner__' : role;
    acl.set(key, { execute: e.execute, grantOption: e.grantOption, grantor: e.grantor });
  }
  return acl;
}

/**
 * proconfig to tablica napisow "nazwa=wartosc". Dla search_path wartosc jest
 * lista schematow po przecinku, ktora Postgres zapisuje dokladnie tak, jak
 * zostala podana — z cudzyslowami wlacznie, jesli byly.
 */
function parseProconfig(items) {
  const out = new Map();
  for (const raw of items) {
    const s = String(raw);
    const eq = s.indexOf('=');
    if (eq === -1) continue;
    const name = s.slice(0, eq).trim().toLowerCase();
    out.set(name, { values: splitSettingValue(s.slice(eq + 1)), fromCurrent: false });
  }
  return out;
}

function splitSettingValue(v) {
  const out = [];
  let cur = '';
  let inQuotes = false;
  for (let i = 0; i < v.length; i++) {
    const c = v[i];
    if (c === '"') {
      if (inQuotes && v[i + 1] === '"') { cur += '"'; i++; continue; }
      inQuotes = !inQuotes;
      continue;
    }
    if (c === ',' && !inQuotes) { out.push(cur.trim().toLowerCase()); cur = ''; continue; }
    cur += c;
  }
  if (cur.trim()) out.push(cur.trim().toLowerCase());
  return out;
}

function searchPathOf(items) {
  const cfg = parseProconfig(items);
  return cfg.has('search_path') ? cfg.get('search_path').values : null;
}

function parseAclItem(s) {
  let i = 0;
  let grantee = '';
  if (s[0] === '"') {
    i = 1;
    for (; i < s.length; i++) {
      if (s[i] === '"') {
        if (s[i + 1] === '"') { grantee += '"'; i++; continue; }
        i++;
        break;
      }
      grantee += s[i];
    }
  } else {
    while (i < s.length && s[i] !== '=') { grantee += s[i]; i++; }
  }
  if (s[i] !== '=') return null;
  i++;
  const slash = s.lastIndexOf('/');
  const privs = slash === -1 ? s.slice(i) : s.slice(i, slash);
  const grantor = slash === -1 ? '' : s.slice(slash + 1).replace(/^"|"$/g, '');

  let execute = false;
  let grantOption = false;
  const named = new Set();
  for (let k = 0; k < privs.length; k++) {
    const ch = privs[k];
    if (ch === '*') continue;
    if (ch === 'X') {
      execute = true;
      if (privs[k + 1] === '*') grantOption = true;
    }
    const name = LETTER_TO_PRIV[ch];
    if (name) named.add(name);
  }
  return { grantee, execute, grantOption, grantor, privs: named };
}

const LETTER_TO_PRIV = {
  r: 'select', a: 'insert', w: 'update', d: 'delete',
  D: 'truncate', x: 'references', t: 'trigger', m: 'maintain',
  X: 'execute', U: 'usage', C: 'create', c: 'connect', T: 'temporary', s: 'set', A: 'alter_system',
};

const yes = (v) => v === true || v === 't' || v === 'true';

/** @returns {Promise<Map<string,object>>} */
async function introspectTables(driver, opts = {}) {
  const schemas = opts.schemas || ['public'];
  const rows = await driver.query(TABLES_SQL);

  const tables = new Map();
  for (const row of rows) {
    const schema = String(row.schema);
    if (SYSTEM_SCHEMAS.has(schema)) continue;
    if (!schemas.includes(schema)) continue;
    const name = String(row.name);
    const key = schema + '.' + name;
    tables.set(key, {
      key, schema, name,
      rls: yes(row.rls),
      force: yes(row.force_rls),
      partitioned: row.kind === 'p',
      owner: String(row.owner),
      acl: parseTableAcl(asArray(row.acl), String(row.owner)),
      aclIsDefault: yes(row.acl_is_default),
    });
  }
  return tables;
}

/** @returns {Promise<Map<string,object>>} */
async function introspectPolicies(driver, opts = {}) {
  const schemas = opts.schemas || ['public'];
  const rows = await driver.query(POLICIES_SQL);

  const policies = new Map();
  for (const row of rows) {
    const schema = String(row.schema);
    if (SYSTEM_SCHEMAS.has(schema)) continue;
    if (!schemas.includes(schema)) continue;

    const table = String(row.table_name);
    const name = String(row.name);
    const usingRaw = row.using_expr === null || row.using_expr === undefined
      ? null : String(row.using_expr);
    const checkRaw = row.check_expr === null || row.check_expr === undefined
      ? null : String(row.check_expr);

    policies.set(schema + '.' + table + ':' + name, {
      key: schema + '.' + table + ':' + name,
      schema, table, name,
      cmd: CMD_NAMES[row.cmd] || String(row.cmd),
      permissive: yes(row.permissive),
      roles: asArray(row.roles).map(String).sort(),
      using: normalizeExpr(usingRaw),
      usingRaw,
      check: normalizeExpr(checkRaw),
      checkRaw,
    });
  }
  return policies;
}

// Litery ACL Postgresa dla relacji.
const PRIV_LETTERS = {
  r: 'select', a: 'insert', w: 'update', d: 'delete',
  D: 'truncate', x: 'references', t: 'trigger', m: 'maintain',
};

/** @returns {Map<string, Set<string>>} rola -> zbior uprawnien */
function parseTableAcl(items, owner) {
  const acl = new Map();
  for (const raw of items) {
    const e = parseAclItem(String(raw));
    if (!e) continue;
    const role = e.grantee === '' ? 'public' : e.grantee;
    acl.set(role === owner ? '__owner__' : role, e.privs);
  }
  return acl;
}

async function introspectColumnAcls(driver, opts = {}) {
  const schemas = opts.schemas || ['public'];
  const rows = await driver.query(COLUMNS_SQL);
  // klucz: schema.tabela  ->  Map<kolumna, Map<rola, Set<priv>>>
  const out = new Map();
  for (const row of rows) {
    const schema = String(row.schema);
    if (!schemas.includes(schema)) continue;
    const tkey = schema + '.' + String(row.table_name);
    if (!out.has(tkey)) out.set(tkey, new Map());
    out.get(tkey).set(String(row.column_name), parseTableAcl(asArray(row.acl), null));
  }
  return out;
}

/** Klucz linii bazowej. Rozdzielamy znakiem, ktory nie moze wystapic w nazwie. */
function defaultAclKey(schema, owner) {
  return schema + String.fromCharCode(31) + owner;
}

async function introspectDefaultAcl(driver, opts = {}) {
  const rows = await driver.query(DEFAULT_ACL_SQL);
  const bySchemaOwner = new Map();
  let serverVersion = 0;
  for (const row of rows) {
    serverVersion = parseInt(row.server_version, 10) || serverVersion;
    const schema = String(row.schema || '');
    const owner = String(row.owner);
    bySchemaOwner.set(defaultAclKey(schema, owner), parseTableAcl(asArray(row.acl), owner));
  }
  return { bySchemaOwner, serverVersion };
}

// Maska bitowa tgtype, wprost z definicji Postgresa.
const TG_ROW = 1;
const TG_BEFORE = 2;
const TG_INSERT = 4;
const TG_DELETE = 8;
const TG_UPDATE = 16;
const TG_TRUNCATE = 32;
const TG_INSTEAD = 64;

function decodeTgType(tgtype) {
  const n = Number(tgtype) || 0;
  const events = [];
  if (n & TG_INSERT) events.push('insert');
  if (n & TG_UPDATE) events.push('update');
  if (n & TG_DELETE) events.push('delete');
  if (n & TG_TRUNCATE) events.push('truncate');
  return {
    timing: (n & TG_INSTEAD) ? 'instead of' : (n & TG_BEFORE) ? 'before' : 'after',
    level: (n & TG_ROW) ? 'row' : 'statement',
    events,
  };
}

async function introspectTriggers(driver, opts = {}) {
  const schemas = opts.schemas || ['public'];
  const rows = await driver.query(TRIGGERS_SQL);

  const triggers = new Map();
  for (const row of rows) {
    const schema = String(row.schema);
    if (SYSTEM_SCHEMAS.has(schema)) continue;
    if (!schemas.includes(schema)) continue;

    const table = String(row.table_name);
    const name = String(row.name);
    const key = schema + '.' + table + ':' + name;
    const d = decodeTgType(row.tgtype);
    const whenRaw = row.when_expr === null || row.when_expr === undefined
      ? null : String(row.when_expr);

    triggers.set(key, {
      key, schema, table, name,
      timing: d.timing,
      level: d.level,
      events: d.events,
      updateColumns: asArray(row.update_columns).map(String),
      fn: String(row.function_name),
      when: normalizeExpr(whenRaw),
      whenRaw,
      constraint: yes(row.is_constraint),
      enabled: String(row.enabled),
    });
  }
  return triggers;
}

// ZAKRES. Wyzwalacz zdarzeniowy jest obiektem CALEJ BAZY, nie schematu — i to
// wlasnie sprawia, ze latwo zapomniec go ograniczyc. Kazda inna kontrola pyta
// tylko o --schema; ta bez filtra zglaszala wyzwalacze platformy Supabase
// (pgrst_ddl_watch, issue_pg_cron_access i podobne), ktore stoja w KAZDYM
// projekcie i nigdy nie beda w cudzych migracjach.
//
// Zakresimy po schemacie funkcji, ktora wyzwalacz wola: jesli ta funkcja nie
// nalezy do schematu, ktory sprawdzamy, to i wyzwalacz nie jest nasz.
async function introspectEventTriggers(driver, opts = {}) {
  const schemas = opts.schemas || ['public'];
  const rows = await driver.query(EVENT_TRIGGERS_SQL);
  const out = new Map();
  for (const row of rows) {
    if (!schemas.includes(String(row.function_schema))) continue;
    const name = String(row.name);
    out.set(name, {
      key: name, name,
      event: String(row.event),
      tags: asArray(row.tags).map((x) => String(x).toUpperCase()).sort(),
      fn: String(row.function_name),
      enabled: String(row.enabled),
    });
  }
  return out;
}

module.exports = {
  introspect, introspectTables, introspectPolicies,
  introspectTriggers, introspectEventTriggers, decodeTgType,
  TRIGGERS_SQL, EVENT_TRIGGERS_SQL,
  introspectColumnAcls, introspectDefaultAcl,
  parseTableAcl, defaultAclKey, PRIV_LETTERS, COLUMNS_SQL, DEFAULT_ACL_SQL,
  FUNCTIONS_SQL, TABLES_SQL, POLICIES_SQL,
  parseAclItem, parseProconfig, searchPathOf,
};
