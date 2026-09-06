'use strict';

// Wyzwalacze.
//
// Znana odpowiedz jest w pierwszym tescie: `ensure_rls` istnieje w bazie
// i nie ma go w zadnej migracji, bo CREATE EVENT TRIGGER wymaga superusera
// i zaklada sie go recznie. To jest ta klasa rzeczy, ktora zyje wylacznie
// w jednym srodowisku — funkcja jest po obu stronach, uprawnienia sie zgadzaja,
// a podpiecia nie ma nigdzie w repozytorium.

const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const os = require('os');
const path = require('path');

const { buildExpected } = require('../src/expected');
const { introspectTriggers, introspectEventTriggers, decodeTgType } = require('../src/introspect');
const { compareTriggers, compareEventTriggers, total } = require('../src/compare');

const drv = (rows) => ({ query: async () => rows, close: async () => {} });

function expectedFrom(files) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'supadrift-tr-'));
  try {
    for (const [n, b] of Object.entries(files)) fs.writeFileSync(path.join(dir, n), b, 'utf8');
    return buildExpected(dir, { schemas: ['public'] });
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
}

// Maska tgtype: row=1 before=2 insert=4 delete=8 update=16 truncate=32 instead=64
const TG = { row: 1, before: 2, insert: 4, delete: 8, update: 16, truncate: 32, instead: 64 };
const mask = (...names) => names.reduce((n, x) => n | TG[x], 0);

const trg = (over) => Object.assign({
  schema: 'public', table_name: 't', name: 'trg',
  tgtype: mask('row', 'before', 'update'), enabled: 'O',
  function_name: 'public.set_updated_at', update_columns: [],
  when_expr: null, is_constraint: false,
}, over);

const evt = (over) => Object.assign({
  name: 'ensure_rls', event: 'ddl_command_end', enabled: 'O',
  // function_schema odwzorowuje kolumne, ktora zwraca EVENT_TRIGGERS_SQL —
  // po niej idzie zakresienie do --schema.
  function_schema: 'public',
  function_name: 'public.rls_auto_enable',
  tags: ['CREATE TABLE', 'CREATE TABLE AS', 'SELECT INTO'],
}, over);

async function check(files, trgRows, evtRows, allow) {
  const e = expectedFrom(files);
  const at = await introspectTriggers(drv(trgRows), { schemas: ['public'] });
  const ae = await introspectEventTriggers(drv(evtRows), { schemas: ['public'] });
  return {
    e,
    tab: compareTriggers(e.triggers, at, { allow }),
    ev: compareEventTriggers(e.eventTriggers, ae, { allow }),
  };
}

// --- ZNANA ODPOWIEDZ ---------------------------------------------------------

test('ensure_rls jest w bazie i nie ma go w zadnej migracji', async () => {
  const { e, ev } = await check(
    // Migracja tworzy sama FUNKCJE. Podpiecia nie ma i nie moze byc:
    // CREATE EVENT TRIGGER wymaga superusera.
    {
      '20260902120000_rls_auto_enable.sql':
        'create or replace function public.rls_auto_enable() returns event_trigger\n'
        + "language plpgsql security definer set search_path to 'pg_catalog', 'pg_temp'\n"
        + 'as $$ begin end; $$;',
    },
    [], [evt()]
  );

  assert.equal(e.eventTriggers.size, 0, 'zadna migracja nie zaklada wyzwalacza');
  assert.ok(e.functions.has('public.rls_auto_enable()'), 'ale funkcja JEST w migracjach');

  assert.equal(ev.onlyInDb.length, 1);
  assert.equal(ev.onlyInDb[0].text, 'event trigger ensure_rls');
  assert.equal(ev.onlyInDb[0].kind, 'zdarzeniowy');
  assert.equal(ev.onlyInDb[0].def.fn, 'public.rls_auto_enable');
  assert.equal(total(ev), 1, 'ma podniesc kod wyjscia');
});

test('allowManual przenosi go do osobnej listy, ale go nie ukrywa', async () => {
  const NOTHING = { '000_nic.sql': '-- katalog bez deklaracji, ale nie pusty' };
  const { ev } = await check(NOTHING, [], [evt()], ['ensure_rls']);
  assert.deepEqual(ev.onlyInDb, []);
  assert.equal(ev.manual.length, 1);
  assert.equal(ev.manual[0].text, 'event trigger ensure_rls');
  assert.equal(total(ev), 0, 'uzgodniony krok reczny nie wywraca CI');
});

// --- wyzwalacze tabelowe -----------------------------------------------------

test('siedem ksztaltow z prawdziwych migracji odtwarza sie bez rozjazdu', async () => {
  const files = {
    '001.sql': [
      'create trigger subscriptions_set_updated_at',
      '  before update on public.subscriptions',
      '  for each row execute function public.set_updated_at();',
      'create trigger subscriptions_grant_review_credits',
      '  after insert or update of status on public.subscriptions',
      '  for each row execute function public.grant_review_credits();',
      'create trigger reviews_replied_at',
      '  before insert or update on public.reviews',
      '  for each row execute function public.reviews_touch_replied_at();',
    ].join('\n'),
  };
  const rows = [
    trg({ table_name: 'subscriptions', name: 'subscriptions_set_updated_at' }),
    trg({
      table_name: 'subscriptions', name: 'subscriptions_grant_review_credits',
      tgtype: mask('row', 'insert', 'update'), // after = brak bitu before
      function_name: 'public.grant_review_credits', update_columns: ['status'],
    }),
    trg({
      table_name: 'reviews', name: 'reviews_replied_at',
      tgtype: mask('row', 'before', 'insert', 'update'),
      function_name: 'public.reviews_touch_replied_at',
    }),
  ];
  const { tab } = await check(files, rows, []);
  assert.equal(total(tab), 0);
});

test('kolejnosc zdarzen nie ma znaczenia', async () => {
  const { tab } = await check(
    {
      '001.sql': 'create trigger trg before update or insert on public.t\n'
        + '  for each row execute function public.set_updated_at();',
    },
    [trg({ tgtype: mask('row', 'before', 'insert', 'update') })], []
  );
  assert.equal(total(tab), 0);
});

test('inna funkcja to rozjazd', async () => {
  const { tab } = await check(
    {
      '001.sql': 'create trigger trg before update on public.t\n'
        + '  for each row execute function public.set_updated_at();',
    },
    [trg({ function_name: 'public.cos_innego' })], []
  );
  assert.equal(tab.different.length, 1);
  assert.deepEqual(tab.different[0].diffs, [
    { what: 'funkcja', inMigrations: 'public.set_updated_at', inDb: 'public.cos_innego', soft: false },
  ]);
});

test('UPDATE OF zawezone do kolumn jest porownywane', async () => {
  const { tab } = await check(
    {
      '001.sql': 'create trigger trg after update of status on public.t\n'
        + '  for each row execute function public.set_updated_at();',
    },
    [trg({ tgtype: mask('row', 'update'), update_columns: [] })], []
  );
  const d = tab.different[0].diffs.find((x) => x.what === 'UPDATE OF');
  assert.deepEqual([d.inMigrations, d.inDb], ['status', '(wszystkie)']);
});

test('before kontra after i row kontra statement', async () => {
  const { tab } = await check(
    {
      '001.sql': 'create trigger trg before update on public.t\n'
        + '  for each statement execute function public.set_updated_at();',
    },
    [trg({ tgtype: mask('row', 'update') })], []
  );
  const kinds = tab.different[0].diffs.map((x) => x.what).sort();
  assert.deepEqual(kinds, ['moment', 'poziom']);
});

test('brak FOR EACH znaczy STATEMENT, tak jak w Postgresie', async () => {
  const e = expectedFrom({
    '001.sql': 'create trigger trg before update on public.t execute function public.f();',
  });
  assert.equal(e.triggers.get('public.t:trg').level, 'statement');
});

test('wyzwalacz w migracji, ktorego nie ma w bazie', async () => {
  const { tab } = await check(
    {
      '001.sql': 'create trigger trg before update on public.t\n'
        + '  for each row execute function public.set_updated_at();',
    },
    [], []
  );
  assert.equal(tab.onlyInMigrations.length, 1);
  assert.equal(tab.onlyInMigrations[0].text, 'public.t :: trg');
});

test('drop trigger usuwa go z obrazu', async () => {
  const e = expectedFrom({
    '001.sql': 'create trigger trg before update on public.t for each row execute function public.f();',
    '002.sql': 'drop trigger if exists trg on public.t;',
  });
  assert.equal(e.triggers.size, 0);
});

test('ALTER TABLE ... DISABLE TRIGGER zmienia stan, a nie usuwa', async () => {
  const e = expectedFrom({
    '001.sql': 'create trigger trg before update on public.t for each row execute function public.f();',
    '002.sql': 'alter table public.t disable trigger trg;',
  });
  assert.equal(e.triggers.get('public.t:trg').enabled, 'D');
});

test('wylaczony w bazie, wlaczony w migracji to rozjazd', async () => {
  const { tab } = await check(
    {
      '001.sql': 'create trigger trg before update on public.t\n'
        + '  for each row execute function public.set_updated_at();',
    },
    [trg({ enabled: 'D' })], []
  );
  const d = tab.different[0].diffs.find((x) => x.what === 'stan');
  assert.deepEqual([d.inMigrations, d.inDb], ['wlaczony', 'WYLACZONY']);
});

test('klauzula WHEN: brak po jednej stronie jest twardy, inna tresc miekka', async () => {
  const a = await check(
    {
      '001.sql': 'create trigger trg before update on public.t for each row\n'
        + '  when (new.x is distinct from old.x) execute function public.f();',
    },
    [trg({ function_name: 'public.f', when_expr: null })], []
  );
  const d1 = a.tab.different[0].diffs.find((x) => x.what === 'WHEN');
  assert.equal(d1.soft, false);

  const b = await check(
    {
      '001.sql': 'create trigger trg before update on public.t for each row\n'
        + '  when (new.x is distinct from old.x) execute function public.f();',
    },
    [trg({ function_name: 'public.f', when_expr: '(new.y IS DISTINCT FROM old.y)' })], []
  );
  const d2 = b.tab.different[0].diffs.find((x) => x.what === 'WHEN — tresc');
  assert.equal(d2.soft, true);
});

// --- dekodowanie tgtype ------------------------------------------------------

test('tgtype dekoduje sie tak, jak koduje go Postgres', () => {
  assert.deepEqual(decodeTgType(mask('row', 'before', 'update')),
    { timing: 'before', level: 'row', events: ['update'] });
  assert.deepEqual(decodeTgType(mask('row', 'insert', 'update')),
    { timing: 'after', level: 'row', events: ['insert', 'update'] });
  assert.deepEqual(decodeTgType(mask('instead', 'row', 'delete')),
    { timing: 'instead of', level: 'row', events: ['delete'] });
  assert.deepEqual(decodeTgType(mask('truncate')),
    { timing: 'after', level: 'statement', events: ['truncate'] });
});

// --- wyzwalacze zdarzeniowe --------------------------------------------------

test('event trigger z migracji jest czytany razem z tagami', () => {
  const e = expectedFrom({
    '001.sql': "create event trigger ensure_rls on ddl_command_end\n"
      + "  when tag in ('CREATE TABLE', 'SELECT INTO')\n"
      + '  execute function public.rls_auto_enable();',
  });
  const t = e.eventTriggers.get('ensure_rls');
  assert.equal(t.event, 'ddl_command_end');
  assert.deepEqual(t.tags, ['CREATE TABLE', 'SELECT INTO']);
  assert.equal(t.fn, 'public.rls_auto_enable');
});

test('rozny zestaw tagow to rozjazd', async () => {
  const { ev } = await check(
    {
      '001.sql': "create event trigger ensure_rls on ddl_command_end\n"
        + "  when tag in ('CREATE TABLE') execute function public.rls_auto_enable();",
    },
    [], [evt()]
  );
  const d = ev.different[0].diffs.find((x) => x.what === 'TAG');
  assert.deepEqual([d.inMigrations, d.inDb], ['CREATE TABLE', 'CREATE TABLE, CREATE TABLE AS, SELECT INTO']);
});

test('drop i alter event trigger sa czytane', () => {
  const a = expectedFrom({
    '001.sql': 'create event trigger e on ddl_command_end execute function public.f();',
    '002.sql': 'drop event trigger if exists e;',
  });
  assert.equal(a.eventTriggers.size, 0);

  const b = expectedFrom({
    '001.sql': 'create event trigger e on ddl_command_end execute function public.f();',
    '002.sql': 'alter event trigger e disable;',
  });
  assert.equal(b.eventTriggers.get('e').enabled, 'D');
});

// --- BYL BLAD: wyzwalacze zdarzeniowe nie byly zakresione --------------------
//
// Wyzwalacz zdarzeniowy jest obiektem calej bazy, wiec latwo zapomniec, ze
// ograniczenie do --schema tez go dotyczy. Bez tego filtra kazdy projekt
// Supabase zglaszal szesc wlasnych wyzwalaczy platformy (pgrst_ddl_watch,
// issue_pg_cron_access i podobne) jako "jest w bazie, nie ma w migracji".

const PLATFORM_TRIGGERS = [
  ['pgrst_ddl_watch', 'extensions.pgrst_ddl_watch'],
  ['pgrst_drop_watch', 'extensions.pgrst_drop_watch'],
  ['issue_pg_cron_access', 'extensions.grant_pg_cron_access'],
  ['issue_pg_graphql_access', 'extensions.grant_pg_graphql_access'],
  ['issue_pg_net_access', 'extensions.grant_pg_net_access'],
  ['issue_graphql_placeholder', 'extensions.set_graphql_placeholder'],
].map(([name, fn]) => ({
  name, event: 'ddl_command_end', enabled: 'O',
  function_schema: 'extensions', function_name: fn, tags: [],
}));

const OURS = {
  name: 'rls_guard', event: 'ddl_command_end', enabled: 'O',
  function_schema: 'public', function_name: 'public.enforce_rls',
  tags: ['CREATE TABLE'],
};

test('wyzwalacze platformy Supabase sa poza zakresem schematu public', async () => {
  const ae = await introspectEventTriggers(drv(PLATFORM_TRIGGERS.concat([OURS])), { schemas: ['public'] });
  assert.deepEqual([...ae.keys()], ['rls_guard'],
    'szesc wyzwalaczy platformy wolajacych funkcje z extensions nie ma prawa sie zglosic');
});

test('ten sam wyzwalacz JEST widziany, gdy sprawdzamy schemat jego funkcji', async () => {
  const ae = await introspectEventTriggers(drv(PLATFORM_TRIGGERS), { schemas: ['extensions'] });
  assert.equal(ae.size, 6, 'filtr ma zakresic, a nie ukrywac na stale');
});

test('zakres wyzwalaczy zdarzeniowych idzie za schematem funkcji, nie za nazwa', async () => {
  const ae = await introspectEventTriggers(drv([OURS]), { schemas: ['inny_schemat'] });
  assert.equal(ae.size, 0);
});
