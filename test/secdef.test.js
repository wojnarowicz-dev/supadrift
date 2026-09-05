'use strict';

// SECURITY DEFINER a search_path.
//
// Kluczowy przypadek to trzeci test: `set search_path = public` WYGLADA na
// domkniete, a nie jest — pg_temp jest przeszukiwany dla nazw relacji jako
// pierwszy, dopoki nie wymieni sie go jawnie. To jest ta roznica, ktora
// odrozniala dwie funkcje w sprawdzanym projekcie od trzynastu pozostalych.

const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const os = require('os');
const path = require('path');

const { buildExpected } = require('../src/expected');
const { introspect } = require('../src/introspect');
const { compare } = require('../src/compare');
const { checkSecurityDefiner, classify } = require('../src/secdef');

const drv = (rows) => ({ query: async () => rows, close: async () => {} });

function expectedFrom(files) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'supadrift-sd-'));
  try {
    for (const [n, b] of Object.entries(files)) fs.writeFileSync(path.join(dir, n), b, 'utf8');
    return buildExpected(dir, { schemas: ['public'] });
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
}

const row = (name, over) => Object.assign({
  schema: 'public', name, argtypes: [], owner: 'postgres', kind: 'f',
  returns: 'void', body: '', security_definer: true,
  config: ['search_path=public, pg_temp'],
  acl: ['postgres=X/postgres', 'service_role=X/postgres'], acl_is_default: false,
}, over);

async function check(files, rows, allow) {
  const e = expectedFrom(files);
  const a = await introspect(drv(rows), { schemas: ['public'] });
  return {
    e, a,
    findings: checkSecurityDefiner(e.functions, a.functions, { allow }),
    drift: compare(e.functions, a.functions),
  };
}

const fn = (name, opts) => 'create function public.' + name + '() returns void\n'
  + 'language plpgsql\n'
  + (opts.definer === false ? '' : 'security definer\n')
  + (opts.sp ? 'set search_path = ' + opts.sp + '\n' : '')
  + 'as $$ begin end; $$;\n'
  + 'revoke all on function public.' + name + '() from public;\n'
  + 'grant execute on function public.' + name + '() to service_role;\n';

// --- klasyfikacja ------------------------------------------------------------

test('sama klasyfikacja', () => {
  assert.equal(classify(null), 'brak-search-path');
  assert.equal(classify([]), 'brak-search-path');
  assert.equal(classify(['public']), 'bez-pg_temp');
  assert.equal(classify(['pg_catalog']), 'bez-pg_temp');
  assert.equal(classify(['pg_temp', 'public']), 'pg_temp-nie-na-koncu');
  assert.equal(classify(['public', 'pg_temp']), null);
  assert.equal(classify(['pg_catalog', 'pg_temp']), null);
});

// --- co jest zgloszeniem -----------------------------------------------------

test('search_path = public wyglada na domkniete, a nie jest', async () => {
  const { findings } = await check(
    { '001.sql': fn('take_rate_slot', { sp: 'public' }) },
    [row('take_rate_slot', { config: ['search_path=public'] })]
  );
  assert.equal(findings.length, 1);
  assert.equal(findings[0].kind, 'bez-pg_temp');
  assert.equal(findings[0].where, 'w obu');
  assert.deepEqual(findings[0].suggestion.values, ['public', 'pg_temp']);
});

test('brak search_path w ogole jest zglaszany ostrzej i idzie pierwszy', async () => {
  const { findings } = await check(
    {
      '001.sql': fn('bez', {}) + fn('z_public', { sp: 'public' })
        + fn('ok1', { sp: 'public, pg_temp' }) + fn('ok2', { sp: 'public, pg_temp' }),
    },
    [
      row('bez', { config: [] }),
      row('z_public', { config: ['search_path=public'] }),
      row('ok1'), row('ok2'),
    ]
  );
  assert.equal(findings.length, 2);
  assert.equal(findings[0].text, 'public.bez()', 'brak ustawienia przed niepelnym');
  assert.equal(findings[0].kind, 'brak-search-path');
  assert.deepEqual(findings[0].suggestion.values, ['public', 'pg_temp']);
  assert.match(findings[0].suggestion.why, /SECURITY DEFINER w tym zestawie/);
});

test('poprawka nie podstawia cudzego schematu pod funkcje z innym search_path', async () => {
  // rls_auto_enable ma pg_catalog. Wiekszosc ma public, pg_temp. Poprawka MUSI
  // brzmiec "pg_catalog, pg_temp", bo inaczej zmienialaby znaczenie funkcji.
  const { findings } = await check(
    {
      '001.sql': fn('a', { sp: 'public, pg_temp' }) + fn('b', { sp: 'public, pg_temp' })
        + fn('rls_auto_enable', { sp: "'pg_catalog'" }),
    },
    [
      row('a'), row('b'),
      row('rls_auto_enable', { config: ['search_path=pg_catalog'] }),
    ]
  );
  assert.equal(findings.length, 1);
  assert.equal(findings[0].text, 'public.rls_auto_enable()');
  assert.deepEqual(findings[0].suggestion.values, ['pg_catalog', 'pg_temp']);
  assert.match(findings[0].suggestion.why, /istniejacej listy/);
});

test('pg_temp nie na koncu tez jest zgloszeniem', async () => {
  const { findings } = await check(
    { '001.sql': fn('f', { sp: 'pg_temp, public' }) },
    [row('f', { config: ['search_path=pg_temp, public'] })]
  );
  assert.equal(findings[0].kind, 'pg_temp-nie-na-koncu');
  assert.deepEqual(findings[0].suggestion.values, ['public', 'pg_temp']);
});

// --- czego NIE zglaszamy -----------------------------------------------------

test('komplet public, pg_temp milczy', async () => {
  const { findings } = await check(
    { '001.sql': fn('f', { sp: 'public, pg_temp' }) },
    [row('f')]
  );
  assert.deepEqual(findings, []);
});

test('SECURITY INVOKER nie jest przypadkiem tej kontroli', async () => {
  const { findings } = await check(
    { '001.sql': fn('set_updated_at', { definer: false, sp: 'public' }) },
    [row('set_updated_at', { security_definer: false, config: ['search_path=public'] })]
  );
  assert.deepEqual(findings, [],
    'funkcja chodzi z uprawnieniami wolajacego, podstawienie nic mu nie daje');
});

test('lista wyjatkow wycisza, nazwa albo pelny podpis', async () => {
  const files = { '001.sql': fn('cron_only', { sp: 'public' }) };
  const rows = [row('cron_only', { config: ['search_path=public'] })];
  assert.equal((await check(files, rows)).findings.length, 1);
  for (const wpis of ['cron_only', 'public.cron_only', 'public.cron_only()']) {
    assert.deepEqual((await check(files, rows, [wpis])).findings, [], 'wyjatek: ' + wpis);
  }
});

// --- czytanie skladni --------------------------------------------------------

test('wartosci w apostrofach czytane tak samo jak gole', async () => {
  const e = expectedFrom({ '001.sql': fn('f', { sp: "'public', 'pg_temp'" }) });
  assert.deepEqual(e.functions.get('public.f()').searchPath, ['public', 'pg_temp']);
});

test('SET ... TO ... czytane tak samo jak SET ... = ...', async () => {
  const e = expectedFrom({
    '001.sql': 'create function public.f() returns void language plpgsql\n'
      + 'security definer set search_path to public, pg_temp as $$ begin end; $$;',
  });
  assert.deepEqual(e.functions.get('public.f()').searchPath, ['public', 'pg_temp']);
});

test('ALTER FUNCTION ... SET search_path trafia w to samo miejsce', async () => {
  const e = expectedFrom({
    '001.sql': fn('f', { sp: 'public' }),
    '002.sql': 'alter function public.f() set search_path = public, pg_temp;',
  });
  assert.deepEqual(e.functions.get('public.f()').searchPath, ['public', 'pg_temp']);
});

test('CREATE OR REPLACE nadpisuje ustawienia, bo tak robi Postgres', async () => {
  const e = expectedFrom({
    '001.sql': fn('f', { sp: 'public, pg_temp' }),
    '002.sql': 'create or replace function public.f() returns void language plpgsql\n'
      + 'security definer set search_path = public as $$ begin end; $$;',
  });
  assert.deepEqual(e.functions.get('public.f()').searchPath, ['public'],
    'podmiana ciala bez pg_temp cofa domkniecie i musi byc widoczna');
});

test('search_path w ciele funkcji nie jest ustawieniem funkcji', async () => {
  const e = expectedFrom({
    '001.sql': 'create function public.f() returns void language plpgsql security definer\n'
      + "set search_path = public, pg_temp as $$ begin execute 'set search_path = zle'; end; $$;",
  });
  assert.deepEqual(e.functions.get('public.f()').searchPath, ['public', 'pg_temp']);
});

// --- rozjazd plikow z baza ---------------------------------------------------

test('rozny search_path miedzy migracja a baza to rozjazd', async () => {
  const { drift } = await check(
    { '001.sql': fn('f', { sp: 'public, pg_temp' }) },
    [row('f', { config: ['search_path=public'] })]
  );
  assert.equal(drift.different.length, 1);
  assert.deepEqual(drift.different[0].attrs, [
    { what: 'search_path', inMigrations: 'public, pg_temp', inDb: 'public' },
  ]);
});

test('zmiana SECURITY DEFINER na INVOKER miedzy plikami a baza to rozjazd', async () => {
  const { drift } = await check(
    { '001.sql': fn('f', { sp: 'public, pg_temp' }) },
    [row('f', { security_definer: false })]
  );
  assert.deepEqual(drift.different[0].attrs, [
    { what: 'SECURITY DEFINER', inMigrations: 'definer', inDb: 'invoker' },
  ]);
});

test('funkcja tylko z grantem w migracjach nie jest porownywana co do atrybutow', async () => {
  const { drift } = await check(
    { '001.sql': 'grant execute on function public.obca() to service_role;' },
    [row('obca', { config: ['search_path=public'] })]
  );
  // Nadania porownujemy dalej — to jest sedno narzedzia. Ale search_path
  // i SECURITY DEFINER nie, bo bez CREATE w katalogu nie wiemy, co migracja
  // o nich mowi, a zgadywanie dawaloby zgloszenie przy kazdej takiej funkcji.
  assert.equal(drift.different.length, 1);
  assert.deepEqual(drift.different[0].attrs, []);
  assert.ok(drift.different[0].roles.length > 0);
});
