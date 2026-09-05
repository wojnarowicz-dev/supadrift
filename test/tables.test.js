'use strict';

// Tabele: RLS i FORCE.
//
// Sedno jest w pierwszym tescie. CREATE TABLE nie wlacza RLS — Postgres zostawia
// tabele otwarta. Migracja, ktora tworzy tabele i nie mowi
// `enable row level security`, opisuje wiec tabele BEZ ochrony, nawet jesli
// w produkcyjnej bazie ochrona jest (bo ktos wlaczyl ja recznie albo zrobil to
// wyzwalacz zdarzeniowy). Swieze srodowisko dostanie wtedy tabele otwarta.

const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const os = require('os');
const path = require('path');

const { buildExpected } = require('../src/expected');
const { introspectTables } = require('../src/introspect');
const { compareTables, total } = require('../src/compare');

const fakeDriver = (rows) => ({ query: async () => rows, close: async () => {} });

const row = (name, over) => Object.assign({
  schema: 'public', name, rls: false, force_rls: false, kind: 'r', owner: 'postgres',
}, over);

function dirWith(files) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'supadrift-tab-'));
  for (const [n, b] of Object.entries(files)) fs.writeFileSync(path.join(dir, n), b, 'utf8');
  return dir;
}

async function analyze(files, rows) {
  const dir = dirWith(files);
  try {
    const expected = buildExpected(dir, { schemas: ['public'] });
    const actual = await introspectTables(fakeDriver(rows), { schemas: ['public'] });
    return { expected, actual, result: compareTables(expected.tables, actual) };
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
}

test('CREATE TABLE bez enable row level security znaczy tabela BEZ RLS', async () => {
  const { expected } = await analyze(
    { '001.sql': 'create table public.t (id uuid primary key, x text);' }, []
  );
  const t = expected.tables.get('public.t');
  assert.equal(t.rls, false, 'Postgres nie wlacza RLS przy tworzeniu tabeli');
  assert.equal(t.force, false);
});

test('brak enable w migracji przy wlaczonym RLS w bazie to rozjazd', async () => {
  const { result } = await analyze(
    { '001.sql': 'create table public.t (id uuid primary key);' },
    [row('t', { rls: true })]
  );
  assert.equal(result.different.length, 1);
  assert.deepEqual(result.different[0].flags, [{ flag: 'rls', inMigrations: false, inDb: true }]);
});

test('enable row level security jest odczytywane', async () => {
  const { result, expected } = await analyze(
    {
      '001.sql': 'create table public.t (id uuid primary key);\n'
        + 'alter table public.t enable row level security;',
    },
    [row('t', { rls: true })]
  );
  assert.equal(expected.tables.get('public.t').rls, true);
  assert.equal(total(result), 0);
});

test('FORCE i NO FORCE — NO FORCE nie moze byc czytane jako FORCE', async () => {
  const a = await analyze(
    {
      '001.sql': 'create table public.t (id uuid);\n'
        + 'alter table public.t enable row level security;\n'
        + 'alter table public.t force row level security;',
    },
    [row('t', { rls: true, force_rls: true })]
  );
  assert.equal(a.expected.tables.get('public.t').force, true);
  assert.equal(total(a.result), 0);

  const b = await analyze(
    {
      '001.sql': 'create table public.t (id uuid);\n'
        + 'alter table public.t enable row level security;\n'
        + 'alter table public.t force row level security;',
      '002.sql': 'alter table public.t no force row level security;',
    },
    [row('t', { rls: true, force_rls: true })]
  );
  assert.equal(b.expected.tables.get('public.t').force, false, 'NO FORCE musi wygrac');
  assert.deepEqual(b.result.different[0].flags, [{ flag: 'force', inMigrations: false, inDb: true }]);
});

test('disable row level security cofa wczesniejsze enable', async () => {
  const { expected } = await analyze(
    {
      '001.sql': 'create table public.t (id uuid);\nalter table public.t enable row level security;',
      '002.sql': 'alter table public.t disable row level security;',
    },
    []
  );
  assert.equal(expected.tables.get('public.t').rls, false);
});

test('cialo funkcji ze srednikami nie myli parsera tabel', async () => {
  const sql = [
    'create table public.t (id uuid primary key);',
    'create function public.f() returns trigger language plpgsql as $$',
    'begin',
    "  alter table public.udawana enable row level security;",
    '  return new;',
    'end;',
    '$$;',
    'alter table public.t enable row level security;',
  ].join('\n');
  const { expected } = await analyze({ '001.sql': sql }, []);
  assert.deepEqual([...expected.tables.keys()], ['public.t'],
    'ALTER TABLE w ciele funkcji nie jest instrukcja migracji');
  assert.equal(expected.tables.get('public.t').rls, true);
});

test('rename przenosi stan RLS na nowa nazwe', async () => {
  const { expected } = await analyze(
    {
      '001.sql': 'create table public.stara (id uuid);\n'
        + 'alter table public.stara enable row level security;',
      '002.sql': 'alter table public.stara rename to nowa;',
    },
    []
  );
  assert.equal(expected.tables.has('public.stara'), false);
  assert.equal(expected.tables.get('public.nowa').rls, true);
});

test('drop table usuwa tabele z obrazu', async () => {
  const { expected } = await analyze(
    {
      '001.sql': 'create table public.t (id uuid);',
      '002.sql': 'drop table if exists public.t;',
    },
    []
  );
  assert.equal(expected.tables.size, 0);
});

test('trzy kategorie dla tabel', async () => {
  const { result } = await analyze(
    {
      '001.sql': 'create table public.tylko_w_plikach (id uuid);\n'
        + 'alter table public.tylko_w_plikach enable row level security;',
    },
    [row('tylko_w_bazie', { rls: false })]
  );
  assert.equal(result.onlyInMigrations.length, 1);
  assert.equal(result.onlyInMigrations[0].text, 'public.tylko_w_plikach');
  assert.equal(result.onlyInDb.length, 1);
  assert.equal(result.onlyInDb[0].text, 'public.tylko_w_bazie');
  assert.equal(result.onlyInDb[0].rls, false);
  assert.equal(result.different.length, 0);
});

test('alter table na tabeli spoza katalogu tez jest widziany', async () => {
  const { expected } = await analyze(
    { '001.sql': 'alter table public.obca enable row level security;' }, []
  );
  const t = expected.tables.get('public.obca');
  assert.equal(t.declared, false, 'brak CREATE w tym katalogu');
  assert.equal(t.rls, true);
});
