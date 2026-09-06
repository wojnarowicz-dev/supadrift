'use strict';

// Odpornosc: co robi supadrift, gdy wejscie jest zepsute.
//
// KRYTERIUM JEST JEDNO I NIE MA OD NIEGO WYJATKU:
//   padnij glosno albo przejdz. NIGDY nie zwracaj po cichu zera.
//
// "Czysto" przy nieodczytanych migracjach to najgorszy mozliwy wynik tego
// narzedzia — mowi czlowiekowi, ze sprawdzil, podczas gdy nie sprawdzil nic.
// Dlatego kazdy scenariusz jest uruchamiany DWA RAZY: raz uszkodzony, raz
// healthyDir. Zdrowy przebieg dowodzi, ze fraza "CZYSTO" i code 0 w ogole potrafia
// sie tu pojawic — bez tego test uszkodzonego przypadku nic nie znaczy, bo
// przechodzilby takze wtedy, gdyby narzedzie nie dzialalo w ogole.

const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { spawnSync } = require('child_process');

const { buildExpected } = require('../src/expected');
const BIN = path.join(__dirname, '..', 'bin', 'supadrift.js');

const HEALTHY = [
  'create function public.f() returns void language plpgsql as $$',
  'begin',
  '  update public.t set a = 1;',
  'end;',
  '$$;',
  'revoke all on function public.f() from public;',
  'grant execute on function public.f() to service_role;',
].join('\n');

function dirWith(files) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'supadrift-odp-'));
  for (const [n, b] of Object.entries(files)) fs.writeFileSync(path.join(dir, n), b, 'utf8');
  return dir;
}

/** Uruchamia buildExpected i mowi, czy threw glosno. */
function attempt(dir, opts) {
  try {
    const e = buildExpected(dir, Object.assign({ schemas: ['public'] }, opts));
    return { threw: false, functionCount: e.functions.size, fileCount: e.files.length };
  } catch (err) {
    return { threw: true, code: err.supadriftExit, fatal: !!err.supadriftFatal, msg: err.message };
  }
}

/**
 * Sedno testu: pair uszkodzony/healthyDir na tym samym ksztalcie wejscia.
 * Uszkodzony MUSI paść. Zdrowy MUSI przejsc — inaczej nie wiemy, czy
 * pierwsza polowa cokolwiek udowodnila.
 */
function pair(scenario, makeBroken, makeHealthy, opts) {
  const dU = makeBroken();
  const dZ = makeHealthy();
  try {
    const u = attempt(dU, opts);
    const z = attempt(dZ, opts);

    assert.equal(u.threw, true, scenario + ': uszkodzone wejscie MUSI paść, a nie zwrocic wynik');
    assert.equal(u.code, 2, scenario + ': code wyjscia ma byc 2 (blad), nie 0 ani 1');
    assert.equal(u.fatal, true, scenario + ': ma byc oznaczone jako blad krytyczny');

    assert.equal(z.threw, false, scenario + ': ZDROWE wejscie musi przejsc — inaczej test nic nie dowodzi');
    assert.ok(z.functionCount > 0, scenario + ': healthyDir przebieg ma faktycznie cos odczytac');
    return u;
  } finally {
    fs.rmSync(dU, { recursive: true, force: true });
    fs.rmSync(dZ, { recursive: true, force: true });
  }
}

// --- scenariusze -------------------------------------------------------------

test('urwane cytowanie dolarowe: pada, a nie udaje, ze przeczytalo funkcje', () => {
  const u = pair('urwane $$',
    () => dirWith({ '001.sql': 'create function public.f() returns void as $$\nbegin\n  update t set a = 1;\n' }),
    () => dirWith({ '001.sql': HEALTHY }));
  assert.match(u.msg, /niedomkniete-cytowanie-dolarowe/);
});

test('urwany literal tekstowy: pada', () => {
  const u = pair('urwany literal',
    () => dirWith({ '001.sql': HEALTHY + "\ncomment on function public.f() is 'nigdy nie domkniete" }),
    () => dirWith({ '001.sql': HEALTHY }));
  assert.match(u.msg, /niedomkniety-literal/);
});

test('urwany komentarz blokowy: pada', () => {
  const u = pair('urwany komentarz',
    () => dirWith({ '001.sql': '/* opis, ktory sie nie konczy\n' + HEALTHY }),
    () => dirWith({ '001.sql': '/* opis, ktory sie konczy */\n' + HEALTHY }));
  assert.match(u.msg, /niedomkniety-komentarz-blokowy/);
});

test('niezbilansowane nawiasy: pada', () => {
  const u = pair('nawiasy',
    () => dirWith({ '001.sql': HEALTHY + '\ncreate table public.t (id uuid, x text' }),
    () => dirWith({ '001.sql': HEALTHY + '\ncreate table public.t (id uuid, x text);' }));
  assert.match(u.msg, /niezbilansowane-nawiasy/);
});

test('plik binarny pod nazwa .sql: pada na bajcie zerowym', () => {
  const u = pair('bajt zerowy',
    () => dirWith({ '001.sql': 'create function public.f()' + String.fromCharCode(0) + ' returns void;' }),
    () => dirWith({ '001.sql': HEALTHY }));
  assert.match(u.msg, /bajt-zerowy/);
});

test('pusty dirWith: pada, zamiast wypisac czysto', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'supadrift-odp-'));
  const healthyDir = dirWith({ '001.sql': HEALTHY });
  try {
    const u = attempt(dir);
    const z = attempt(healthyDir);
    assert.equal(u.threw, true, 'pusty dirWith nie ma prawa dac wyniku');
    assert.equal(u.code, 2);
    assert.match(u.msg, /ani jednego pliku \.sql/);
    assert.equal(z.threw, false, 'healthyDir dirWith musi przejsc');
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
    fs.rmSync(healthyDir, { recursive: true, force: true });
  }
});

test('dirWith nie istnieje: pada', () => {
  const missing = path.join(os.tmpdir(), 'supadrift-nie-ma-' + Date.now());
  const u = attempt(missing);
  assert.equal(u.threw, true);
  assert.equal(u.code, 2);
  assert.match(u.msg, /nie da sie odczytac katalogu/);
});

test('plik .sql nie do odczytania: pada, a nie pomija po cichu', () => {
  // Katalog pod nazwa pliku .sql daje EISDIR — deterministyczny odpowiednik
  // braku uprawnien, dzialajacy tak samo na kazdym systemie.
  const u = pair('nie do odczytania',
    () => {
      const d = dirWith({ '001.sql': HEALTHY });
      fs.mkdirSync(path.join(d, '002_nieczytelny.sql'));
      return d;
    },
    () => dirWith({ '001.sql': HEALTHY, '002_czytelny.sql': 'grant execute on function public.f() to anon;' }));
  assert.match(u.msg, /nie-do-odczytania/);
});

test('--as-of odsiewajacy wszystko: pada, zamiast porownywac pusty obraz', () => {
  const dir = dirWith({ '20260101000000_a.sql': HEALTHY });
  try {
    const u = attempt(dir, { asOf: '20250101000000' });
    const z = attempt(dir, { asOf: '20270101000000' });
    assert.equal(u.threw, true);
    assert.match(u.msg, /odsiewa WSZYSTKIE/);
    assert.equal(z.threw, false, 'sensowny --as-of musi dzialac');
    assert.ok(z.functionCount > 0);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

// --- przez wiersz polecen: code wyjscia i missing frazy "CZYSTO" ------------------

function run(args) {
  return spawnSync(process.execPath, [BIN, ...args], {
    encoding: 'utf8',
    timeout: 30000,
    // Katalog bez .env i bez supadrift.json: inaczej test czytalby files
    // dewelopera i przechodzilby albo padal zaleznie od jego maszyny.
    cwd: os.tmpdir(),
    env: Object.assign({}, process.env, { SUPADRIFT_DB_URL: undefined }),
  });
}

test('uszkodzony dirWith: code 2 i ani slowa o czystosci', () => {
  const broken = dirWith({ '001.sql': 'create function public.f() as $$ begin' });
  try {
    const r = run(['--migrations', broken]);
    const out = (r.stdout || '') + (r.stderr || '');
    assert.equal(r.status, 2, 'code wyjscia ma byc 2');
    assert.ok(!/CZYSTO/.test(out), 'slowo CZYSTO nie ma prawa paść przy nieodczytanym wejsciu');
    assert.ok(!/rozjazd functionCount\s*:\s*0/.test(out), 'zero rozjazdow tez nie');
    assert.match(out, /niedomkniete-cytowanie-dolarowe/);
  } finally {
    fs.rmSync(broken, { recursive: true, force: true });
  }
});

test('adres bazy nie do sparsowania: code 2, nie code 0', () => {
  const healthy = dirWith({ '001.sql': HEALTHY });
  try {
    const r = spawnSync(process.execPath, [BIN, '--migrations', healthy], {
      encoding: 'utf8',
      timeout: 30000,
      cwd: os.tmpdir(),
      env: Object.assign({}, process.env, { SUPADRIFT_DB_URL: 'to-nie-jest-adres' }),
    });
    const out = (r.stdout || '') + (r.stderr || '');
    assert.equal(r.status, 2);
    assert.ok(!/CZYSTO/.test(out));
  } finally {
    fs.rmSync(healthy, { recursive: true, force: true });
  }
});

test('uciety supadrift.json: code 2, nie code 0', () => {
  const dir = dirWith({ '001.sql': HEALTHY });
  try {
    fs.writeFileSync(path.join(dir, 'supadrift.json'), '{ "allowManual": ["ensure_rls"');
    const r = spawnSync(process.execPath, [BIN, '--migrations', dir, '--config', path.join(dir, 'supadrift.json')], {
      encoding: 'utf8',
      timeout: 30000,
      cwd: os.tmpdir(),
      env: Object.assign({}, process.env, { SUPADRIFT_DB_URL: undefined }),
    });
    const out = (r.stdout || '') + (r.stderr || '');
    assert.equal(r.status, 2);
    assert.ok(!/CZYSTO/.test(out));
    assert.match(out, /niepoprawny JSON|blad JSON na pozycji/);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('kontrola dodatnia: zdrowe wejscie DOCHODZI do proby polaczenia', () => {
  // Bez tego wszystkie testy wyzej przechodzilyby takze wtedy, gdyby supadrift
  // padal zawsze i wszedzie. Tu ma dojsc az do warstwy polaczenia i dopiero
  // tam zglosic missing adresu.
  const healthy = dirWith({ '001.sql': HEALTHY });
  try {
    const r = run(['--migrations', healthy]);
    const out = (r.stdout || '') + (r.stderr || '');
    assert.equal(r.status, 2);
    assert.match(out, /Brak adresu polaczenia/,
      'zdrowe migracje maja przejsc parsowanie i dojsc do polaczenia');
    assert.ok(!/niedomkniete|bajt-zerowy|ani jednego pliku/.test(out));
  } finally {
    fs.rmSync(healthy, { recursive: true, force: true });
  }
});
