'use strict';

// Nadania na tabelach i kolumnach.
//
// Kazdy z tych testow odpowiada bledowi, ktory ta kontrola popelnila, zanim
// zostala skonfrontowana z prawdziwa baza. Kolejno: pusta linia bazowa,
// nadania kolumnowe brane za tabelaryczne, oraz "on all tables in schema"
// czytane jako tabela o nazwie "all".

const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const os = require('os');
const path = require('path');

const { buildExpected } = require('../src/expected');
const {
  introspectTables, introspectColumnAcls, introspectDefaultAcl,
} = require('../src/introspect');
const { compareTableGrants, replay, allPrivsFor } = require('../src/tablegrants');

const drv = (rows) => ({ query: async () => rows, close: async () => {} });

function dirWith(files) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'supadrift-tg-'));
  for (const [n, b] of Object.entries(files)) fs.writeFileSync(path.join(dir, n), b, 'utf8');
  return dir;
}

function expectedFrom(files) {
  const dir = dirWith(files);
  try {
    return buildExpected(dir, { schemas: ['public'] });
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
}

// Linia bazowa zawezona, dokladnie taka jak w sprawdzanym projekcie:
// nowa tabela dostaje Dxtm dla anon/authenticated/service_role, bez SELECT.
const DEFAULTS = [{
  schema: 'public', owner: 'postgres', objtype: 'r',
  acl: ['postgres=arwdDxtm/postgres', 'anon=Dxtm/postgres',
    'authenticated=Dxtm/postgres', 'service_role=Dxtm/postgres'],
  server_version: '170006',
}];

const tab = (name, acl) => ({
  schema: 'public', name, rls: true, force_rls: false, kind: 'r',
  owner: 'postgres', acl, acl_is_default: false,
});

async function analyze(files, tableRows, columnRows = []) {
  const e = expectedFrom(files);
  const at = await introspectTables(drv(tableRows), { schemas: ['public'] });
  const ac = await introspectColumnAcls(drv(columnRows), { schemas: ['public'] });
  const da = await introspectDefaultAcl(drv(DEFAULTS));
  return { e, findings: compareTableGrants(e.tables, at, ac, da, {}) };
}

// --- linia bazowa ------------------------------------------------------------

test('linia bazowa z pg_default_acl jest uzywana, a nie pusty ACL', async () => {
  // Migracja tworzy tabele i odbiera dostep anon/authenticated. service_role
  // nie jest tu wymieniony ANI RAZU — a mimo to ma w bazie Dxtm z domyslnych
  // uprawnien. Model bez linii bazowej zglosilby tu rozjazd, ktorego nie ma.
  const { findings } = await analyze(
    {
      '001.sql': 'create table public.rate_limits (id uuid);\n'
        + 'revoke all on table public.rate_limits from anon, authenticated;',
    },
    [tab('rate_limits', ['postgres=arwdDxtm/postgres', 'service_role=Dxtm/postgres'])]
  );
  assert.deepEqual(findings, []);
});

test('brak linii bazowej w bazie daje rozjazd, bo tam service_role juz nie ma', async () => {
  const { findings } = await analyze(
    {
      '001.sql': 'create table public.rate_limits (id uuid);\n'
        + 'revoke all on table public.rate_limits from anon, authenticated;',
    },
    [tab('rate_limits', ['postgres=arwdDxtm/postgres'])]
  );
  assert.equal(findings.length, 1);
  assert.deepEqual(findings[0].roles, [{
    role: 'service_role',
    inMigrations: 'maintain, references, trigger, truncate',
    inDb: '(nic)',
  }]);
});

test('grant all dokłada do linii bazowej pelny zestaw', async () => {
  const { findings } = await analyze(
    {
      '001.sql': 'create table public.t (id uuid);\n'
        + 'revoke all on table public.t from anon, authenticated;\n'
        + 'grant all on table public.t to service_role;',
    },
    [tab('t', ['postgres=arwdDxtm/postgres', 'service_role=arwdDxtm/postgres'])]
  );
  assert.deepEqual(findings, []);
});

test('MAINTAIN wchodzi do ALL dopiero od Postgresa 17', () => {
  assert.ok(allPrivsFor(170006).includes('maintain'));
  assert.ok(!allPrivsFor(160004).includes('maintain'));
});

// --- nadania kolumnowe -------------------------------------------------------

test('grant select (kolumny) nie jest nadaniem na tabeli', async () => {
  // reviews: revoke all od anon/authenticated, potem sam SELECT na kolumnach.
  // W relacl NIE MA wtedy anon ani authenticated — i tak ma byc.
  const cols = ['id', 'author', 'body'];
  const { findings } = await analyze(
    {
      '001.sql': 'create table public.reviews (id uuid, author text, body text);\n'
        + 'revoke all on table public.reviews from anon, authenticated;\n'
        + 'grant select (id, author, body) on table public.reviews to anon, authenticated;\n'
        + 'grant all on table public.reviews to service_role;',
    },
    [tab('reviews', ['postgres=arwdDxtm/postgres', 'service_role=arwdDxtm/postgres'])],
    cols.map((c) => ({
      schema: 'public', table_name: 'reviews', column_name: c,
      acl: ['anon=r/postgres', 'authenticated=r/postgres'],
    }))
  );
  assert.deepEqual(findings, []);
});

test('brakujaca kolumna w bazie jest zgloszona z nazwa kolumny', async () => {
  const { findings } = await analyze(
    {
      '001.sql': 'create table public.reviews (id uuid, tajne text);\n'
        + 'revoke all on table public.reviews from anon, authenticated;\n'
        + 'grant select (id, tajne) on table public.reviews to anon;',
    },
    [tab('reviews', ['postgres=arwdDxtm/postgres', 'service_role=Dxtm/postgres'])],
    [{ schema: 'public', table_name: 'reviews', column_name: 'id', acl: ['anon=r/postgres'] }]
  );
  assert.equal(findings.length, 1);
  assert.deepEqual(findings[0].columns, [
    { column: 'tajne', role: 'anon', inMigrations: 'select', inDb: '(nic)' },
  ]);
});

test('nadanie kolumnowe w bazie, o ktorym migracje nie wiedza, jest zgloszone', async () => {
  const { findings } = await analyze(
    {
      '001.sql': 'create table public.reviews (id uuid, tajne text);\n'
        + 'revoke all on table public.reviews from anon, authenticated;',
    },
    [tab('reviews', ['postgres=arwdDxtm/postgres', 'service_role=Dxtm/postgres'])],
    [{ schema: 'public', table_name: 'reviews', column_name: 'tajne', acl: ['anon=r/postgres'] }]
  );
  assert.equal(findings.length, 1);
  assert.deepEqual(findings[0].columns, [
    { column: 'tajne', role: 'anon', inMigrations: '(nic)', inDb: 'select' },
  ]);
});

test('revoke all na tabeli zdejmuje takze nadania kolumnowe', () => {
  const ops = [
    { op: 'grant', all: false, privs: [], roles: ['anon'], columnPrivs: [{ name: 'select', columns: ['a'] }] },
    { op: 'revoke', all: true, privs: [], roles: ['anon'], columnPrivs: [] },
  ];
  const out = replay(ops, new Map(), 170006);
  assert.equal(out.columns.size, 0, 'dokumentacja Postgresa: revoke na tabeli zdejmuje kolumny');
});

test('kolejnosc migracji decyduje: revoke, potem grant kolumnowy, zostaje grant', () => {
  const ops = [
    { op: 'revoke', all: true, privs: [], roles: ['anon'], columnPrivs: [] },
    { op: 'grant', all: false, privs: [], roles: ['anon'], columnPrivs: [{ name: 'select', columns: ['a'] }] },
  ];
  const out = replay(ops, new Map(), 170006);
  assert.deepEqual([...out.columns.get('a').get('anon')], ['select']);
});

// --- czytanie skladni --------------------------------------------------------

test('grant bez slowa TABLE tez jest nadaniem na tabeli', async () => {
  const e = expectedFrom({
    '001.sql': 'create table public.t (id uuid);\ngrant select on public.t to anon;',
  });
  const ops = e.tables.get('public.t').ops;
  assert.equal(ops.length, 1);
  assert.deepEqual(ops[0].privs, ['select']);
  assert.deepEqual(ops[0].roles, ['anon']);
});

test('ON ALL TABLES IN SCHEMA nie tworzy tabeli o nazwie "all"', async () => {
  const e = expectedFrom({
    '001.sql': 'revoke all on all tables in schema storage from anon, authenticated;',
  });
  assert.deepEqual([...e.tables.keys()], [], 'zadnej tabeli, a juz na pewno nie public.all');
  assert.equal(e.notes.filter((n) => n.kind === 'hurtowe').length, 1,
    'ale musi zostac odnotowane, bo obejmuje tabele');
});

test('lista uprawnien i lista rol sa czytane w calosci', async () => {
  const e = expectedFrom({
    '001.sql': 'create table public.t (id uuid);\n'
      + 'grant select, insert, update on table public.t to anon, authenticated, service_role;',
  });
  const op = e.tables.get('public.t').ops[0];
  assert.deepEqual(op.privs.sort(), ['insert', 'select', 'update']);
  assert.deepEqual(op.roles, ['anon', 'authenticated', 'service_role']);
});

test('czesciowy revoke zdejmuje tylko wskazane uprawnienia', async () => {
  const { findings } = await analyze(
    {
      '001.sql': 'create table public.t (id uuid);\n'
        + 'grant all on table public.t to service_role;\n'
        + 'revoke select, insert, update, delete on table public.t from service_role;\n'
        + 'revoke all on table public.t from anon, authenticated;',
    },
    [tab('t', ['postgres=arwdDxtm/postgres', 'service_role=Dxtm/postgres'])]
  );
  assert.deepEqual(findings, [], 'zostaja truncate, references, trigger, maintain');
});

test('grant/revoke na funkcji nie trafia do modelu tabel', async () => {
  const e = expectedFrom({
    '001.sql': 'create function public.f() returns void as $$ begin end; $$;\n'
      + 'revoke all on function public.f() from public;\n'
      + 'grant execute on function public.f() to service_role;',
  });
  assert.equal(e.tables.size, 0);
});
