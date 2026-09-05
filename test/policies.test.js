'use strict';

// Polityki oraz tabelowy odpowiednik kontroli zamiaru.
//
// Najtrudniejsza rzecz jest tu jedna i nie jest nia skladnia: Postgres NIE
// przechowuje tekstu wyrazenia, tylko drzewo, i odtwarza tekst po swojemu.
// Porownanie napis do napisu zglaszaloby rozjazd przy kazdej polityce.
// Pierwszy blok testow pilnuje, zeby normalizacja zdejmowala to, co Postgres
// dokłada sam, i ANI TROCHE wiecej.

const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const os = require('os');
const path = require('path');

const { buildExpected } = require('../src/expected');
const { introspectPolicies, introspectTables } = require('../src/introspect');
const { comparePolicies, compareTables, total } = require('../src/compare');
const { checkRlsWithoutPolicy } = require('../src/intent');
const { normalizeExpr } = require('../src/expr');

const fakeDriver = (rows) => ({ query: async () => rows, close: async () => {} });

function dirWith(files) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'supadrift-pol-'));
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

const polRow = (over) => Object.assign({
  schema: 'public', table_name: 't', name: 'p', cmd: 'r', permissive: true,
  roles: ['authenticated'], using_expr: null, check_expr: null,
}, over);

// --- normalizacja wyrazen ----------------------------------------------------

test('normalizacja zdejmuje to, co dokłada pg_get_expr', () => {
  const pary = [
    ['(select auth.uid()) = user_id', '(( SELECT auth.uid() AS uid) = user_id)'],
    ['auth.uid() = user_id', '(auth.uid() = user_id)'],
    ['user_id = (select auth.uid())', '(user_id = ( SELECT auth.uid() AS uid))'],
    ['true', 'true'],
  ];
  for (const [mig, db] of pary) {
    assert.equal(normalizeExpr(mig), normalizeExpr(db), mig);
  }
});

test('normalizacja NIE zaciera prawdziwej roznicy', () => {
  assert.notEqual(normalizeExpr('status = 1'), normalizeExpr('status = 2'));
  assert.notEqual(normalizeExpr('a = user_id'), normalizeExpr('b = user_id'));
  assert.notEqual(normalizeExpr('true'), normalizeExpr('false'));
  assert.notEqual(
    normalizeExpr('(select auth.uid()) = user_id'),
    normalizeExpr('(select auth.uid()) = owner_id')
  );
});

// --- czytanie CREATE POLICY --------------------------------------------------

test('domyslne wartosci sa czytane tak, jak robi to Postgres', () => {
  const e = expectedFrom({ '001.sql': 'create policy p on public.t using (true);' });
  const p = e.policies.get('public.t:p');
  assert.equal(p.cmd, 'all', 'brak FOR znaczy ALL');
  assert.deepEqual(p.roles, ['public'], 'brak TO znaczy public, czyli kazda rola');
  assert.equal(p.permissive, true, 'brak AS znaczy PERMISSIVE');
  assert.equal(p.check, null);
});

test('pelna postac z cudzyslowem, wieloma rolami i with check', () => {
  const sql = [
    'create policy "reviews_write_own"',
    '  on public.reviews',
    '  as restrictive',
    '  for update',
    '  to anon, authenticated',
    '  using ((select auth.uid()) = user_id)',
    '  with check ((select auth.uid()) = user_id);',
  ].join('\n');
  const p = expectedFrom({ '001.sql': sql }).policies.get('public.reviews:reviews_write_own');
  assert.ok(p);
  assert.equal(p.permissive, false);
  assert.equal(p.cmd, 'update');
  assert.deepEqual(p.roles, ['anon', 'authenticated']);
  assert.equal(p.using, normalizeExpr('(( SELECT auth.uid() AS uid) = user_id)'));
  assert.equal(p.check, normalizeExpr('(( SELECT auth.uid() AS uid) = user_id)'));
  assert.match(p.usingRaw, /auth\.uid/);
});

test('drop policy if exists + create policy — wzorzec z tych migracji', () => {
  const e = expectedFrom({
    '001.sql': 'create policy "x" on public.t for select to authenticated using (a = 1);',
    '002.sql': 'drop policy if exists "x" on public.t;\n'
      + 'create policy "x" on public.t for select to authenticated using (a = 2);',
  });
  assert.equal(e.policies.size, 1);
  assert.equal(e.policies.get('public.t:x').using, normalizeExpr('a = 2'));
});

test('drop policy bez ponownego create usuwa polityke', () => {
  const e = expectedFrom({
    '001.sql': 'create policy "x" on public.t using (true);',
    '002.sql': 'drop policy "x" on public.t;',
  });
  assert.equal(e.policies.size, 0);
});

test('drop table zabiera ze soba polityki', () => {
  const e = expectedFrom({
    '001.sql': 'create table public.t (id uuid);\n'
      + 'create policy "x" on public.t using (true);',
    '002.sql': 'drop table public.t;',
  });
  assert.equal(e.policies.size, 0);
  assert.equal(e.tables.size, 0);
});

test('rename tabeli przenosi polityki', () => {
  const e = expectedFrom({
    '001.sql': 'create table public.stara (id uuid);\n'
      + 'create policy "x" on public.stara using (true);',
    '002.sql': 'alter table public.stara rename to nowa;',
  });
  assert.deepEqual([...e.policies.keys()], ['public.nowa:x']);
});

test('CREATE POLICY w ciele funkcji nie jest instrukcja migracji', () => {
  const sql = [
    'create function public.f() returns void language plpgsql as $$',
    'begin',
    "  execute 'create policy udawana on public.t using (true)';",
    'end;',
    '$$;',
  ].join('\n');
  assert.equal(expectedFrom({ '001.sql': sql }).policies.size, 0);
});

// --- porownanie --------------------------------------------------------------

async function cmp(files, rows, opts) {
  const e = expectedFrom(files);
  const a = await introspectPolicies(fakeDriver(rows), { schemas: ['public'] });
  return { e, a, result: comparePolicies(e.policies, a, opts) };
}

test('polityka zapisana inaczej, ale znaczaca to samo, nie jest rozjazdem', async () => {
  const { result } = await cmp(
    { '001.sql': 'create policy "p" on public.t for select to authenticated using ((select auth.uid()) = user_id);' },
    [polRow({ using_expr: '(( SELECT auth.uid() AS uid) = user_id)' })]
  );
  assert.equal(total(result), 0);
});

test('inna rola to twardy rozjazd', async () => {
  const { result } = await cmp(
    { '001.sql': 'create policy "p" on public.t for select to authenticated using (true);' },
    [polRow({ roles: ['anon', 'authenticated'], using_expr: 'true' })]
  );
  assert.equal(result.different.length, 1);
  const d = result.different[0].diffs.find((x) => x.what === 'role');
  assert.deepEqual([d.inMigrations, d.inDb], ['authenticated', 'anon, authenticated']);
  assert.equal(d.soft, false);
});

test('inne polecenie i inny rodzaj to twarde rozjazdy', async () => {
  const { result } = await cmp(
    { '001.sql': 'create policy "p" on public.t as restrictive for update to authenticated using (true);' },
    [polRow({ cmd: 'r', permissive: true, using_expr: 'true' })]
  );
  const kinds = result.different[0].diffs.map((x) => x.what).sort();
  assert.deepEqual(kinds, ['polecenie', 'rodzaj']);
});

test('brak WITH CHECK po jednej stronie to twardy rozjazd, nie miekki', async () => {
  const { result } = await cmp(
    { '001.sql': 'create policy "p" on public.t for select to authenticated using (true) with check (true);' },
    [polRow({ using_expr: 'true', check_expr: null })]
  );
  const d = result.different[0].diffs;
  assert.equal(d.length, 1);
  assert.equal(d[0].what, 'WITH CHECK');
  assert.equal(d[0].soft, false);
  assert.deepEqual([d[0].inMigrations, d[0].inDb], ['jest', 'brak']);
});

test('rozna tresc wyrazenia jest zgloszona jako miekka', async () => {
  const { result } = await cmp(
    { '001.sql': 'create policy "p" on public.t for select to authenticated using (status = 1);' },
    [polRow({ using_expr: '(status = 2)' })]
  );
  const d = result.different[0].diffs[0];
  assert.equal(d.what, 'USING — tresc');
  assert.equal(d.soft, true);
});

test('--no-policy-expr wycisza sama tresc, a reszta zostaje', async () => {
  const { result } = await cmp(
    { '001.sql': 'create policy "p" on public.t for select to authenticated using (status = 1);' },
    [polRow({ using_expr: '(status = 2)' })],
    { compareExpr: false }
  );
  assert.equal(total(result), 0);
});

test('trzy kategorie dla polityk', async () => {
  const { result } = await cmp(
    { '001.sql': 'create policy "tylko_w_plikach" on public.t using (true);' },
    [polRow({ name: 'tylko_w_bazie', using_expr: 'true' })]
  );
  assert.equal(result.onlyInMigrations.length, 1);
  assert.equal(result.onlyInDb.length, 1);
  assert.equal(result.different.length, 0);
});

// --- RLS bez polityk ---------------------------------------------------------

async function bare(files, tableRows, polRows, allow) {
  const e = expectedFrom(files);
  const at = await introspectTables(fakeDriver(tableRows), { schemas: ['public'] });
  const ap = await introspectPolicies(fakeDriver(polRows), { schemas: ['public'] });
  return checkRlsWithoutPolicy(e.tables, at, e.policies, ap, { allow });
}

const tabRow = (name, over) => Object.assign({
  schema: 'public', name, rls: true, force_rls: false, kind: 'r', owner: 'postgres',
}, over);

test('RLS wlaczone i zero polityk zglasza sie po obu stronach', async () => {
  const f = await bare(
    {
      '001.sql': 'create table public.rate_limits (id uuid);\n'
        + 'alter table public.rate_limits enable row level security;',
    },
    [tabRow('rate_limits')], []
  );
  assert.equal(f.length, 1);
  assert.equal(f[0].text, 'public.rate_limits');
  assert.equal(f[0].where, 'w obu');
});

test('tabela z polityka milczy', async () => {
  const f = await bare(
    {
      '001.sql': 'create table public.t (id uuid);\n'
        + 'alter table public.t enable row level security;\n'
        + 'create policy "p" on public.t for select to authenticated using (true);',
    },
    [tabRow('t')], [polRow({ using_expr: 'true' })]
  );
  assert.deepEqual(f, []);
});

test('tabela bez RLS nie jest przypadkiem tej kontroli', async () => {
  const f = await bare(
    { '001.sql': 'create table public.t (id uuid);' },
    [tabRow('t', { rls: false })], []
  );
  assert.deepEqual(f, []);
});

test('lista wyjatkow wycisza, i przyjmuje nazwe z schematem albo bez', async () => {
  const files = {
    '001.sql': 'create table public.rate_limits (id uuid);\n'
      + 'alter table public.rate_limits enable row level security;',
  };
  for (const wpis of ['public.rate_limits', 'rate_limits', 'PUBLIC.RATE_LIMITS']) {
    const f = await bare(files, [tabRow('rate_limits')], [], [wpis]);
    assert.deepEqual(f, [], 'wyjatek podany jako ' + wpis);
  }
});

test('wyjatek nie wycisza INNEJ tabeli w tym samym stanie', async () => {
  const f = await bare(
    {
      '001.sql': 'create table public.rate_limits (id uuid);\n'
        + 'alter table public.rate_limits enable row level security;\n'
        + 'create table public.nowa (id uuid);\n'
        + 'alter table public.nowa enable row level security;',
    },
    [tabRow('rate_limits'), tabRow('nowa')], [], ['public.rate_limits']
  );
  assert.equal(f.length, 1);
  assert.equal(f[0].text, 'public.nowa', 'nowa tabela w tym stanie musi sie odezwac sama');
});

test('FORCE jest odnotowany, bo zmienia zasieg domkniecia', async () => {
  const f = await bare(
    {
      '001.sql': 'create table public.t (id uuid);\n'
        + 'alter table public.t enable row level security;\n'
        + 'alter table public.t force row level security;',
    },
    [tabRow('t', { force_rls: true })], []
  );
  assert.equal(f[0].force, true);
});

test('polityka tylko w bazie: brak polityk widoczny jest juz tylko w migracjach', async () => {
  const f = await bare(
    {
      '001.sql': 'create table public.t (id uuid);\n'
        + 'alter table public.t enable row level security;',
    },
    [tabRow('t')], [polRow({ using_expr: 'true' })]
  );
  assert.equal(f.length, 1);
  assert.equal(f[0].where, 'w migracjach');
});
