'use strict';

// SARIF 2.1.0.
//
// Plik jest sprawdzany OFICJALNYM SCHEMATEM OASIS (ajv), a nie ogladany okiem.
// Schemat lezy w test/fixtures/sarif-schema-2.1.0.json, zeby testy chodzily
// bez sieci.
//
// Poza schematem sprawdzamy jeszcze wymagania GitHub code scanning, ktorych
// schemat NIE wymusza, a bez ktorych alert nie powstanie albo powstanie bez
// kotwicy: sciezki wzgledne z ukosnikami w przod, startLine >= 1, level
// z dozwolonego zbioru, poprawny ruleIndex.

const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const os = require('os');
const path = require('path');

const Ajv = require('ajv-draft-04');  // schemat OASIS jest w draft-04
const addFormats = require('ajv-formats');

const { buildExpected } = require('../src/expected');
const { introspect, introspectTables, introspectPolicies, introspectTriggers, introspectEventTriggers } = require('../src/introspect');
const { compare, compareTables, comparePolicies, compareTriggers, compareEventTriggers } = require('../src/compare');
const { checkOwnerOnly, checkRlsWithoutPolicy } = require('../src/intent');
const { checkSecurityDefiner } = require('../src/secdef');
const { buildSarif, zebrane } = require('../src/sarif');
const { RULES } = require('../src/rules');

const SCHEMA = JSON.parse(
  fs.readFileSync(path.join(__dirname, 'fixtures', 'sarif-schema-2.1.0.json'), 'utf8')
);

function walidator() {
  const ajv = new Ajv({ allErrors: true, strict: false });
  addFormats(ajv);
  return ajv.compile(SCHEMA);
}

const drv = (rows) => ({ query: async () => rows, close: async () => {} });

// Migracje i baza dobrane tak, zeby odpalic MOZLIWIE WIELE regul naraz.
const MIGRACJE = {
  '20260101000000_start.sql': [
    'create table public.t (id uuid primary key, tajne text);',
    'alter table public.t enable row level security;',
    'revoke all on table public.t from anon, authenticated;',
    'create policy "t_select" on public.t for select to authenticated using (a = 1);',
    'create table public.bez_polityk (id uuid);',
    'alter table public.bez_polityk enable row level security;',
    '',
    'create function public.martwa() returns void language plpgsql',
    'security definer set search_path = public',
    'as $$ begin end; $$;',
    'revoke all on function public.martwa() from public, anon, authenticated;',
    '',
    'create function public.brakuje_w_bazie() returns void language plpgsql as $$ begin end; $$;',
    '',
    'create function public.zdrowa() returns void language plpgsql',
    'security definer set search_path = public, pg_temp',
    'as $$ begin end; $$;',
    'revoke all on function public.zdrowa() from public;',
    'grant execute on function public.zdrowa() to service_role;',
    '',
    'create trigger t_touch before update on public.t',
    '  for each row execute function public.zdrowa();',
  ].join('\n'),
};

const fnRow = (name, over) => Object.assign({
  schema: 'public', name, argtypes: [], owner: 'postgres', kind: 'f',
  returns: 'void', body: '', security_definer: true, config: ['search_path=public'],
  acl: ['postgres=X/postgres'], acl_is_default: false,
}, over);

async function zbudujKontekst() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'supadrift-sarif-'));
  for (const [n, b] of Object.entries(MIGRACJE)) fs.writeFileSync(path.join(dir, n), b, 'utf8');

  const e = buildExpected(dir, { schemas: ['public'] });

  const a = await introspect(drv([
    // rozjazd nadania: baza ma service_role, migracje nie
    fnRow('martwa', { acl: ['postgres=X/postgres', 'service_role=X/postgres'] }),
    // rozjazd search_path: migracje "public, pg_temp", baza "public"
    fnRow('zdrowa', { acl: ['postgres=X/postgres', 'service_role=X/postgres'] }),
    // funkcja tylko w bazie
    fnRow('tylko_w_bazie', { config: [], security_definer: false, acl_is_default: true, acl: [] }),
  ]), { schemas: ['public'] });

  const at = await introspectTables(drv([
    // RLS wylaczone w bazie, wlaczone w migracji
    { schema: 'public', name: 't', rls: false, force_rls: false, kind: 'r', owner: 'postgres', acl: [], acl_is_default: true },
    { schema: 'public', name: 'bez_polityk', rls: true, force_rls: false, kind: 'r', owner: 'postgres', acl: [], acl_is_default: true },
    { schema: 'public', name: 'tylko_w_bazie', rls: false, force_rls: false, kind: 'r', owner: 'postgres', acl: [], acl_is_default: true },
  ]), { schemas: ['public'] });

  const ap = await introspectPolicies(drv([
    // inna rola niz w migracji + inna tresc
    { schema: 'public', table_name: 't', name: 't_select', cmd: 'r', permissive: true, roles: ['anon'], using_expr: '(a = 2)', check_expr: null },
  ]), { schemas: ['public'] });

  const atr = await introspectTriggers(drv([]), { schemas: ['public'] });
  const aev = await introspectEventTriggers(drv([
    { name: 'ensure_rls', event: 'ddl_command_end', enabled: 'O',
      function_schema: 'public', function_name: 'public.zdrowa', tags: [] },
  ]));

  const ctx = {
    result: compare(e.functions, a.functions),
    intent: checkOwnerOnly(e.functions, a.functions, {}),
    secdef: checkSecurityDefiner(e.functions, a.functions, {}),
    tableResult: compareTables(e.tables, at),
    tableGrants: null,
    policyResult: comparePolicies(e.policies, ap),
    triggerResult: compareTriggers(e.triggers, atr, {}),
    eventTriggerResult: compareEventTriggers(e.eventTriggers, aev, {}),
    rlsIntent: checkRlsWithoutPolicy(e.tables, at, e.policies, ap, {}),
    expectedInfo: e,
    actualInfo: { functions: a.functions, tables: at, policies: ap },
    target: '(test)',
    options: { migrationsDir: dir, schemas: ['public'], asOf: null },
  };
  return { ctx, dir };
}

// --- schemat -----------------------------------------------------------------

test('dokument przechodzi oficjalny schemat SARIF 2.1.0', async () => {
  const { ctx, dir } = await zbudujKontekst();
  try {
    const { doc, zgloszen } = buildSarif(ctx, {
      baseDir: dir, migrationsDir: dir, version: '0.1.0',
    });
    assert.ok(zgloszen > 0, 'test bez zgloszen nie sprawdzilby niczego');

    const sprawdz = walidator();
    const ok = sprawdz(doc);
    if (!ok) {
      const opis = sprawdz.errors.slice(0, 8)
        .map((e) => '  ' + e.instancePath + ' ' + e.message).join('\n');
      assert.fail('dokument NIE przechodzi schematu:\n' + opis);
    }
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('walidator faktycznie odrzuca dokument niezgodny — kontrola negatywna', () => {
  const sprawdz = walidator();
  assert.equal(sprawdz({ version: '2.1.0' }), false, 'brak runs musi byc odrzucony');
  assert.equal(sprawdz({ version: '1.0.0', runs: [] }), false, 'zla wersja musi byc odrzucona');
  assert.equal(sprawdz({ version: '2.1.0', runs: [{}] }), false, 'run bez tool musi byc odrzucony');
});

// --- wymagania GitHub code scanning ------------------------------------------

test('wymagania GitHuba, ktorych schemat nie wymusza', async () => {
  const { ctx, dir } = await zbudujKontekst();
  try {
    const { doc } = buildSarif(ctx, { baseDir: dir, migrationsDir: dir, version: '0.1.0' });
    const run = doc.runs[0];

    assert.equal(doc.version, '2.1.0');
    assert.equal(run.tool.driver.name, 'supadrift');
    assert.ok(run.tool.driver.rules.length > 0);

    for (const r of run.results) {
      assert.equal(r.level, 'note', 'poziom ma byc note, nigdy error — patrz README');
      assert.ok(r.message.text.length > 0);
      assert.ok(r.partialFingerprints.supadriftKey, 'bez odcisku GitHub gubi alerty przy przesunieciu linii');

      const reg = run.tool.driver.rules[r.ruleIndex];
      assert.ok(reg, 'ruleIndex musi wskazywac istniejaca regule');
      assert.equal(reg.id, r.ruleId, 'ruleIndex i ruleId musza wskazywac to samo');

      const loc = r.locations[0].physicalLocation;
      const uri = loc.artifactLocation.uri;
      assert.ok(!path.isAbsolute(uri), 'sciezka bezwzgledna: GitHub jej nie dopasuje (' + uri + ')');
      assert.ok(!uri.includes('\\'), 'ukosnik wsteczny w URI: ' + uri);
      assert.ok(!uri.startsWith('..'), 'sciezka poza repozytorium: ' + uri);
      assert.ok(loc.region.startLine >= 1, 'startLine musi byc >= 1');
    }
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('kazda regula w katalogu ma komplet opisow i unikalny identyfikator', () => {
  const widziane = new Set();
  for (const r of RULES) {
    assert.match(r.id, /^supadrift\/[a-z-]+$/, 'id: ' + r.id);
    assert.ok(!widziane.has(r.id), 'powtorzony id: ' + r.id);
    widziane.add(r.id);
    assert.ok(r.name && /^[A-Za-z]+$/.test(r.name), 'name ma byc w PascalCase: ' + r.id);
    assert.ok(r.short && r.short.length > 10 && !r.short.includes('\n'),
      'shortDescription ma byc jedna linia: ' + r.id);
    assert.ok(r.full && r.full.length > r.short.length,
      'fullDescription ma tlumaczyc wiecej niz short: ' + r.id);
  }
});

test('obiekt bez pliku zrodlowego dostaje kotwice i mowi o tym wprost', async () => {
  const { ctx, dir } = await zbudujKontekst();
  try {
    const { doc } = buildSarif(ctx, { baseDir: dir, migrationsDir: dir, version: '0.1.0' });
    const bezPliku = doc.runs[0].results.filter((r) => /nie ma jej w zadnej migracji|nie ma go w zadnej migracji/.test(r.message.text));
    assert.ok(bezPliku.length > 0, 'scenariusz ma zawierac obiekty tylko z bazy');
    for (const r of bezPliku) {
      assert.match(r.message.text, /kotwica\s+wskazuje najnowsza migracje/,
        'kotwica zastepcza musi byc nazwana wprost, zeby nikt nie czytal jej jako miejsca bledu');
    }
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('zgloszenia w SARIF i w raporcie pochodza z jednej funkcji', async () => {
  // zebrane() jest zrodlem dla obu wyjsc — dzieki temu nie moga sie rozjechac.
  const { ctx, dir } = await zbudujKontekst();
  try {
    const lista = zebrane(ctx);
    const { doc } = buildSarif(ctx, { baseDir: dir, migrationsDir: dir, version: '0.1.0' });
    assert.equal(doc.runs[0].results.length, lista.length);
    assert.deepEqual(
      doc.runs[0].results.map((r) => r.ruleId).sort(),
      lista.map((z) => z.ruleId).sort()
    );
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('odciski sa stabilne miedzy przebiegami i rozne dla roznych zgloszen', async () => {
  const a = await zbudujKontekst();
  const b = await zbudujKontekst();
  try {
    const dA = buildSarif(a.ctx, { baseDir: a.dir, migrationsDir: a.dir, version: '0.1.0' }).doc;
    const dB = buildSarif(b.ctx, { baseDir: b.dir, migrationsDir: b.dir, version: '0.1.0' }).doc;
    const fp = (d) => d.runs[0].results.map((r) => r.partialFingerprints.supadriftKey);
    assert.deepEqual(fp(dA), fp(dB), 'ten sam stan musi dac te same odciski');
    assert.equal(new Set(fp(dA)).size, fp(dA).length, 'odciski musza byc rozne miedzy zgloszeniami');
  } finally {
    fs.rmSync(a.dir, { recursive: true, force: true });
    fs.rmSync(b.dir, { recursive: true, force: true });
  }
});
