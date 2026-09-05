'use strict';

// Test odtwarza bezposrednio blad, dla ktorego supadrift powstal:
// revoke bez grantu w migracji 20260901130000, naprawiony dopiero w 20260901150000.

const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const os = require('os');
const path = require('path');

const { buildExpected, OWNER } = require('../src/expected');
const { introspect, parseAclItem } = require('../src/introspect');
const { compare, total } = require('../src/compare');
const { assertReadOnly } = require('../src/db/readonly');
const { argTypesFromTokens } = require('../src/signature');
const { tokenize } = require('../src/tokenizer');

// --- katalog migracji udajacy prawdziwy --------------------------------------

const FILES = {
  '20260829130000_rate_limits.sql': [
    'create or replace function public.take_rate_slot(',
    '  p_user uuid, p_action text, p_window_seconds integer, p_max integer)',
    'returns boolean language plpgsql security definer as $$',
    'begin',
    '  insert into public.rate_limits(user_id, action) values (p_user, p_action);',
    '  return true;',
    'end;',
    '$$;',
    'revoke all on function public.take_rate_slot(uuid, text, integer, integer)',
    '  from public, anon, authenticated;',
    'grant execute on function public.take_rate_slot(uuid, text, integer, integer)',
    '  to service_role;',
  ].join('\n'),

  // Migracja z bledem: revoke jest, grantu nie ma.
  '20260901130000_rate_limit_release.sql': [
    'create or replace function public.release_rate_slot(p_user uuid, p_action text)',
    'returns void language plpgsql security definer as $$',
    'begin',
    '  update public.rate_limits set hits = greatest(0, hits - 1);',
    'end;',
    '$$;',
    'revoke all on function public.release_rate_slot(uuid, text)',
    '  from public, anon, authenticated;',
  ].join('\n'),

  // Naprawa.
  '20260901150000_release_rate_slot_grant.sql': [
    'revoke all     on function public.release_rate_slot(uuid, text)',
    '                 from public, anon, authenticated;',
    'grant  execute on function public.release_rate_slot(uuid, text)',
    '                 to service_role;',
  ].join('\n'),
};

function fixtureDir() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'supadrift-test-'));
  for (const [name, body] of Object.entries(FILES)) {
    fs.writeFileSync(path.join(dir, name), body, 'utf8');
  }
  return dir;
}

// Baza: stan dzisiejszy, czyli JUZ PO naprawie — obie funkcje maja grant.
const DB_ROWS = [
  {
    schema: 'public', name: 'take_rate_slot',
    argtypes: ['uuid', 'text', 'integer', 'integer'],
    owner: 'postgres', kind: 'f', security_definer: true,
    acl: ['postgres=X/postgres', 'service_role=X/postgres'], acl_is_default: false,
  },
  {
    schema: 'public', name: 'release_rate_slot',
    argtypes: ['uuid', 'text'],
    owner: 'postgres', kind: 'f', security_definer: true,
    acl: ['postgres=X/postgres', 'service_role=X/postgres'], acl_is_default: false,
  },
];

const fakeDriver = (rows) => ({ query: async () => rows, close: async () => {} });

async function run(asOf) {
  const dir = fixtureDir();
  try {
    const expected = buildExpected(dir, { asOf, schemas: ['public'] });
    const actual = await introspect(fakeDriver(DB_ROWS), { schemas: ['public'] });
    return { expected, actual, result: compare(expected.functions, actual.functions) };
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
}

// --- znana odpowiedz ---------------------------------------------------------

test('stan sprzed naprawy: revoke bez grantu daje rozjazd na release_rate_slot', async () => {
  const { result } = await run('20260901140000');

  assert.equal(total(result), 1, 'dokladnie jeden rozjazd');
  assert.equal(result.different.length, 1);

  const d = result.different[0];
  assert.equal(d.text, 'public.release_rate_slot(uuid, text)');
  assert.deepEqual(d.roles, [{ role: 'service_role', kind: 'brak-w-migracji' }]);

  // wskazanie na wlasciwy plik i wlasciwa linie
  const last = d.touched[d.touched.length - 1];
  assert.equal(last.file, '20260901130000_rate_limit_release.sql');
  assert.equal(last.kind, 'revoke');
});

test('kontrola negatywna: po naprawie zero rozjazdow', async () => {
  const { result } = await run(null);
  assert.equal(total(result), 0);
  assert.deepEqual(result.different, []);
  assert.deepEqual(result.onlyInDb, []);
  assert.deepEqual(result.onlyInMigrations, []);
});

test('zdrowa siostra take_rate_slot milczy w obu przebiegach', async () => {
  for (const asOf of ['20260901140000', null]) {
    const { result } = await run(asOf);
    const hits = [...result.different, ...result.onlyInDb, ...result.onlyInMigrations]
      .filter((x) => x.text.includes('take_rate_slot'));
    assert.deepEqual(hits, [], 'take_rate_slot ma komplet revoke+grant, nie ma prawa sie zglosic');
  }
});

test('revoke z samej migracji faktycznie zdejmuje public z modelu', async () => {
  const { expected } = await run('20260901140000');
  const f = expected.functions.get('public.release_rate_slot(uuid,text)');
  assert.ok(f);
  const roles = [...f.acl.keys()].filter((r) => r !== OWNER);
  assert.deepEqual(roles, [], 'po revoke od public nie zostaje NIKT poza wlascicielem');
});

// --- trzy kategorie ----------------------------------------------------------

test('kategoria: jest w migracji, nie ma w bazie', async () => {
  const dir = fixtureDir();
  try {
    const expected = buildExpected(dir, { schemas: ['public'] });
    const actual = await introspect(fakeDriver([DB_ROWS[0]]), { schemas: ['public'] });
    const result = compare(expected.functions, actual.functions);
    assert.equal(result.onlyInMigrations.length, 1);
    assert.equal(result.onlyInMigrations[0].text, 'public.release_rate_slot(uuid, text)');
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('kategoria: jest w bazie, nie ma w migracji', async () => {
  const dir = fixtureDir();
  try {
    const expected = buildExpected(dir, { schemas: ['public'] });
    const extra = DB_ROWS.concat([{
      schema: 'public', name: 'nieznana_funkcja', argtypes: [],
      owner: 'postgres', kind: 'f', security_definer: false,
      acl: [], acl_is_default: true,
    }]);
    const actual = await introspect(fakeDriver(extra), { schemas: ['public'] });
    const result = compare(expected.functions, actual.functions);
    assert.equal(result.onlyInDb.length, 1);
    assert.equal(result.onlyInDb[0].text, 'public.nieznana_funkcja()');
    assert.deepEqual(result.onlyInDb[0].roles, ['public'], 'proacl NULL znaczy EXECUTE dla public');
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

// --- szczegoly ---------------------------------------------------------------

test('podpis laczy sie mimo roznych zapisow argumentow', () => {
  assert.deepEqual(argTypesFromTokens(tokenize('p_user uuid, p_action text')), ['uuid', 'text']);
  assert.deepEqual(argTypesFromTokens(tokenize('uuid, text')), ['uuid', 'text']);
  assert.deepEqual(argTypesFromTokens(tokenize('p_a int, p_b timestamptz')),
    ['integer', 'timestamp with time zone']);
  assert.deepEqual(argTypesFromTokens(tokenize('out p_x int, p_y text')), ['text'],
    'argument OUT nie wchodzi do podpisu');
});

test('proacl: pusty odbiorca to rola public, gwiazdka to opcja nadawania', () => {
  const bez = (x) => ({ grantee: x.grantee, execute: x.execute, grantOption: x.grantOption, grantor: x.grantor });
  assert.deepEqual(bez(parseAclItem('=X/postgres')),
    { grantee: '', execute: true, grantOption: false, grantor: 'postgres' });
  assert.deepEqual(bez(parseAclItem('service_role=X*/postgres')),
    { grantee: 'service_role', execute: true, grantOption: true, grantor: 'postgres' });
  assert.equal(parseAclItem('anon=r/postgres').execute, false);
  assert.deepEqual([...parseAclItem('service_role=arwdDxtm/postgres').privs].sort(),
    ['delete', 'insert', 'maintain', 'references', 'select', 'trigger', 'truncate', 'update']);
});

test('create or replace nie kasuje wczesniejszych nadan', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'supadrift-cor-'));
  try {
    fs.writeFileSync(path.join(dir, '001.sql'),
      'create function public.g() returns void as $$ begin end; $$;\n'
      + 'revoke all on function public.g() from public;\n'
      + 'grant execute on function public.g() to service_role;\n');
    fs.writeFileSync(path.join(dir, '002.sql'),
      'create or replace function public.g() returns void as $$ begin end; $$;\n');
    const e = buildExpected(dir, { schemas: ['public'] });
    const f = e.functions.get('public.g()');
    assert.deepEqual([...f.acl.keys()].filter((r) => r !== OWNER), ['service_role']);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('to, czego parser nie modeluje, jest zgloszone, a nie przemilczane', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'supadrift-notes-'));
  try {
    fs.writeFileSync(path.join(dir, '001.sql'),
      'alter default privileges in schema public grant execute on functions to service_role;\n'
      + 'grant execute on all functions in schema public to service_role;\n'
      + 'do $$ begin execute (select 1); grant execute on function public.h() to anon; end; $$;\n');
    const e = buildExpected(dir, { schemas: ['public'] });
    const kinds = e.notes.map((n) => n.kind).sort();
    assert.deepEqual(kinds, ['hurtowe', 'nieobslugiwane', 'nieobslugiwane']);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

// --- bezpieczenstwo ----------------------------------------------------------

test('bramka odrzuca wszystko, co nie jest pojedynczym SELECT-em', () => {
  const bad = [
    'grant execute on function public.f() to anon',
    'create function x() returns void as $$ $$',
    'drop function public.f()',
    'update pg_proc set proname = 1',
    'select 1; drop table t',
    'do $$ begin end $$',
  ];
  for (const sql of bad) assert.throws(() => assertReadOnly(sql), undefined, sql);
  assert.doesNotThrow(() => assertReadOnly('select 1 from pg_catalog.pg_proc'));
});

test('poswiadczenie w argumencie zatrzymuje program', () => {
  const { refuseCredentialsInArgv } = require('../src/secrets');
  assert.throws(() => refuseCredentialsInArgv(['--db-url', 'postgresql://u:p@h/db']));
  assert.throws(() => refuseCredentialsInArgv(['--key=sb_secret_abcdef']));
  assert.doesNotThrow(() => refuseCredentialsInArgv(['--via-cli', '--only', 'rate_slot']));
});

test('zaciemnianie usuwa haslo z adresu i tokeny', () => {
  const { registerSecret, redact } = require('../src/secrets');
  registerSecret('postgresql://supadrift_ro:TajneHaslo123@db.example.supabase.co:5432/postgres');
  const out = redact('blad: nie mozna polaczyc z postgresql://supadrift_ro:TajneHaslo123@db.example.supabase.co:5432/postgres (haslo TajneHaslo123)');
  assert.ok(!out.includes('TajneHaslo123'), out);
});
