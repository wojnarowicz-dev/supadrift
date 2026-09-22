'use strict';

// Co zdjely przelaczniki --allow-*, i czy to widac w podsumowaniu.
//
// DLACZEGO OSOBNY PLIK. Trzy kontrole maja liste wyjatkow i kazda ma ja po
// swojemu: --allow-owner-only (funkcje zamkniete swiadomie), --allow-no-policy
// (tabele z RLS bez polityk), --allow-search-path (SECURITY DEFINER z takim
// search_path, jaki ma byc). Wszystkie trzy filtrowaly swoje pozycje przez
// `continue` i NIE liczyly ich. Zdjeta pozycja przestawala istniec.
//
// To jest dokladnie ta roznica, dla ktorej pole `summary` powstalo: "nie ma
// takich przypadkow" i "sa, ktos je obejrzal i odlozyl" musza byc rozne
// liczby. Czwarty przelacznik, --allow-manual, robil to dobrze od poczatku —
// przenosi wyzwalacze na liste `manual`, ktora widac — wiec trzy pozostale
// milczaly obok jednego, ktory mowil, i nikt tego nie porownal.
//
// KRYTERIUM: dla kazdej z trzech kontroli ta sama rzecz, raz bez wyjatku i raz
// z wyjatkiem, musi dac zgloszenie mniej i odlozona pozycje wiecej. Suma jest
// stala — nic nie znika.

const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const os = require('os');
const path = require('path');

const { buildExpected } = require('../src/expected');
const { introspect, introspectTables, introspectPolicies } = require('../src/introspect');
const { checkOwnerOnly, checkRlsWithoutPolicy } = require('../src/intent');
const { checkSecurityDefiner } = require('../src/secdef');

const drv = (rows) => ({ query: async () => rows, close: async () => {} });

function expectedFrom(files) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'supadrift-expl-'));
  try {
    for (const [n, b] of Object.entries(files)) fs.writeFileSync(path.join(dir, n), b, 'utf8');
    return buildExpected(dir, { schemas: ['public'] });
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
}

const fnRow = (over) => Object.assign({
  schema: 'public', name: 'f', argtypes: [], owner: 'postgres', kind: 'f',
  returns: 'void', body: '', security_definer: true,
  acl: ['postgres=X/postgres'], acl_is_default: false,
}, over);

const tabRow = (name, over) => Object.assign({
  schema: 'public', name, rls: true, force_rls: false, kind: 'r', owner: 'postgres',
}, over);

// Jedno zdanie o kazdej kontroli: to samo wejscie, raz bez listy wyjatkow
// i raz z nia.
const para = async (bez, z) => ({ bez: await bez(), z: await z() });

test('--allow-owner-only: zdjeta funkcja jest policzona, nie zgubiona', async () => {
  const sql = [
    'create function public.tylko_cron() returns void language plpgsql as $$ begin end; $$;',
    'revoke all on function public.tylko_cron() from public, anon, authenticated;',
  ].join('\n');
  const rows = [fnRow({ name: 'tylko_cron' })];

  const run = async (allow) => {
    const e = expectedFrom({ '001.sql': sql });
    const a = await introspect(drv(rows), { schemas: ['public'] });
    return checkOwnerOnly(e.functions, a.functions, { allow });
  };
  const { bez, z } = await para(() => run([]), () => run(['tylko_cron']));

  assert.equal(bez.length, 1, 'bez wyjatku: jedno zgloszenie');
  assert.deepEqual(bez.setAside, [], 'bez wyjatku nic nie odlozono');

  assert.equal(z.length, 0, 'z wyjatkiem: zero zgloszen');
  assert.equal(z.setAside.length, 1, 'z wyjatkiem: jedna pozycja odlozona');
  assert.equal(z.setAside[0].key, bez[0].key, 'odlozono dokladnie to zgloszenie');
  assert.equal(z.length + z.setAside.length, bez.length, 'suma sie zgadza — nic nie znika');
});

test('--allow-no-policy: zdjeta tabela jest policzona, nie zgubiona', async () => {
  const files = {
    '001.sql': 'create table public.rate_limits (id uuid);\n'
      + 'alter table public.rate_limits enable row level security;',
  };
  const run = async (allow) => {
    const e = expectedFrom(files);
    const at = await introspectTables(drv([tabRow('rate_limits')]), { schemas: ['public'] });
    const ap = await introspectPolicies(drv([]), { schemas: ['public'] });
    return checkRlsWithoutPolicy(e.tables, at, e.policies, ap, { allow });
  };
  const { bez, z } = await para(() => run([]), () => run(['rate_limits']));

  assert.equal(bez.length, 1);
  assert.deepEqual(bez.setAside, []);
  assert.equal(z.length, 0);
  assert.equal(z.setAside.length, 1);
  assert.equal(z.setAside[0].key, bez[0].key);
});

test('--allow-search-path: zdjeta funkcja jest policzona, nie zgubiona', async () => {
  const sql = 'create function public.g() returns void\n'
    + 'language plpgsql\nsecurity definer\n'
    + 'as $$ begin end; $$;\n'
    + 'revoke all on function public.g() from public;\n'
    + 'grant execute on function public.g() to service_role;\n';
  const rows = [fnRow({
    name: 'g', config: null,
    acl: ['postgres=X/postgres', 'service_role=X/postgres'],
  })];

  const run = async (allow) => {
    const e = expectedFrom({ '001.sql': sql });
    const a = await introspect(drv(rows), { schemas: ['public'] });
    return checkSecurityDefiner(e.functions, a.functions, { allow });
  };
  const { bez, z } = await para(() => run([]), () => run(['g']));

  assert.equal(bez.length, 1);
  assert.deepEqual(bez.setAside, []);
  assert.equal(z.length, 0);
  assert.equal(z.setAside.length, 1);
  assert.equal(z.setAside[0].key, bez[0].key);
});

// TABLICA MA ZOSTAC TABLICA. Pozycje odlozone wisza na niej jako wlasciwosc
// NIEPRZELICZALNA, i to nie jest ozdoba: przez te trzy tablice przechodzi
// JSON.stringify w --json i assert.deepEqual w czterech plikach testow. Gdyby
// wlasciwosc byla przeliczalna, ksztalt wyjscia JSON zmienilby sie kazdemu,
// kto je czyta maszynowo, a to jest cena, ktorej ta poprawka nie warta.
test('odlozone pozycje nie zmieniaja ksztaltu tablicy ani JSON-a', async () => {
  const sql = [
    'create function public.tylko_cron() returns void language plpgsql as $$ begin end; $$;',
    'revoke all on function public.tylko_cron() from public, anon, authenticated;',
  ].join('\n');
  const e = expectedFrom({ '001.sql': sql });
  const a = await introspect(drv([fnRow({ name: 'tylko_cron' })]), { schemas: ['public'] });
  const z = checkOwnerOnly(e.functions, a.functions, { allow: ['tylko_cron'] });

  assert.ok(Array.isArray(z));
  assert.equal(JSON.stringify(z), '[]', 'JSON widzi pusta tablice');
  assert.deepEqual(z, [], 'deepEqual wobec [] nadal przechodzi');
  assert.equal(Object.keys(z).length, 0, 'zadnego przeliczalnego klucza');
  assert.equal(z.setAside.length, 1, 'a policzone jest mimo to');
});
