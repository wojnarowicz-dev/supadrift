'use strict';

// Odpornosc: co robi supadrift, gdy wejscie jest zepsute.
//
// KRYTERIUM JEST JEDNO I NIE MA OD NIEGO WYJATKU:
//   padnij glosno albo przejdz. NIGDY nie zwracaj po cichu zera.
//
// "Czysto" przy nieodczytanych migracjach to najgorszy mozliwy wynik tego
// narzedzia — mowi czlowiekowi, ze sprawdzil, podczas gdy nie sprawdzil nic.
// Dlatego kazdy scenariusz jest uruchamiany DWA RAZY: raz uszkodzony, raz
// zdrowy. Zdrowy przebieg dowodzi, ze fraza "CZYSTO" i kod 0 w ogole potrafia
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

const ZDROWA = [
  'create function public.f() returns void language plpgsql as $$',
  'begin',
  '  update public.t set a = 1;',
  'end;',
  '$$;',
  'revoke all on function public.f() from public;',
  'grant execute on function public.f() to service_role;',
].join('\n');

function katalog(pliki) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'supadrift-odp-'));
  for (const [n, b] of Object.entries(pliki)) fs.writeFileSync(path.join(dir, n), b, 'utf8');
  return dir;
}

/** Uruchamia buildExpected i mowi, czy padlo glosno. */
function proba(dir, opts) {
  try {
    const e = buildExpected(dir, Object.assign({ schemas: ['public'] }, opts));
    return { padlo: false, funkcji: e.functions.size, plikow: e.files.length };
  } catch (err) {
    return { padlo: true, kod: err.supadriftExit, fatal: !!err.supadriftFatal, msg: err.message };
  }
}

/**
 * Sedno testu: para uszkodzony/zdrowy na tym samym ksztalcie wejscia.
 * Uszkodzony MUSI paść. Zdrowy MUSI przejsc — inaczej nie wiemy, czy
 * pierwsza polowa cokolwiek udowodnila.
 */
function para(nazwaScenariusza, zbudujUszkodzony, zbudujZdrowy, opts) {
  const dU = zbudujUszkodzony();
  const dZ = zbudujZdrowy();
  try {
    const u = proba(dU, opts);
    const z = proba(dZ, opts);

    assert.equal(u.padlo, true, nazwaScenariusza + ': uszkodzone wejscie MUSI paść, a nie zwrocic wynik');
    assert.equal(u.kod, 2, nazwaScenariusza + ': kod wyjscia ma byc 2 (blad), nie 0 ani 1');
    assert.equal(u.fatal, true, nazwaScenariusza + ': ma byc oznaczone jako blad krytyczny');

    assert.equal(z.padlo, false, nazwaScenariusza + ': ZDROWE wejscie musi przejsc — inaczej test nic nie dowodzi');
    assert.ok(z.funkcji > 0, nazwaScenariusza + ': zdrowy przebieg ma faktycznie cos odczytac');
    return u;
  } finally {
    fs.rmSync(dU, { recursive: true, force: true });
    fs.rmSync(dZ, { recursive: true, force: true });
  }
}

// --- scenariusze -------------------------------------------------------------

test('urwane cytowanie dolarowe: pada, a nie udaje, ze przeczytalo funkcje', () => {
  const u = para('urwane $$',
    () => katalog({ '001.sql': 'create function public.f() returns void as $$\nbegin\n  update t set a = 1;\n' }),
    () => katalog({ '001.sql': ZDROWA }));
  assert.match(u.msg, /niedomkniete-cytowanie-dolarowe/);
});

test('urwany literal tekstowy: pada', () => {
  const u = para('urwany literal',
    () => katalog({ '001.sql': ZDROWA + "\ncomment on function public.f() is 'nigdy nie domkniete" }),
    () => katalog({ '001.sql': ZDROWA }));
  assert.match(u.msg, /niedomkniety-literal/);
});

test('urwany komentarz blokowy: pada', () => {
  const u = para('urwany komentarz',
    () => katalog({ '001.sql': '/* opis, ktory sie nie konczy\n' + ZDROWA }),
    () => katalog({ '001.sql': '/* opis, ktory sie konczy */\n' + ZDROWA }));
  assert.match(u.msg, /niedomkniety-komentarz-blokowy/);
});

test('niezbilansowane nawiasy: pada', () => {
  const u = para('nawiasy',
    () => katalog({ '001.sql': ZDROWA + '\ncreate table public.t (id uuid, x text' }),
    () => katalog({ '001.sql': ZDROWA + '\ncreate table public.t (id uuid, x text);' }));
  assert.match(u.msg, /niezbilansowane-nawiasy/);
});

test('plik binarny pod nazwa .sql: pada na bajcie zerowym', () => {
  const u = para('bajt zerowy',
    () => katalog({ '001.sql': 'create function public.f()' + String.fromCharCode(0) + ' returns void;' }),
    () => katalog({ '001.sql': ZDROWA }));
  assert.match(u.msg, /bajt-zerowy/);
});

test('pusty katalog: pada, zamiast wypisac czysto', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'supadrift-odp-'));
  const zdrowy = katalog({ '001.sql': ZDROWA });
  try {
    const u = proba(dir);
    const z = proba(zdrowy);
    assert.equal(u.padlo, true, 'pusty katalog nie ma prawa dac wyniku');
    assert.equal(u.kod, 2);
    assert.match(u.msg, /ani jednego pliku \.sql/);
    assert.equal(z.padlo, false, 'zdrowy katalog musi przejsc');
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
    fs.rmSync(zdrowy, { recursive: true, force: true });
  }
});

test('katalog nie istnieje: pada', () => {
  const brak = path.join(os.tmpdir(), 'supadrift-nie-ma-' + Date.now());
  const u = proba(brak);
  assert.equal(u.padlo, true);
  assert.equal(u.kod, 2);
  assert.match(u.msg, /nie da sie odczytac katalogu/);
});

test('plik .sql nie do odczytania: pada, a nie pomija po cichu', () => {
  // Katalog pod nazwa pliku .sql daje EISDIR — deterministyczny odpowiednik
  // braku uprawnien, dzialajacy tak samo na kazdym systemie.
  const u = para('nie do odczytania',
    () => {
      const d = katalog({ '001.sql': ZDROWA });
      fs.mkdirSync(path.join(d, '002_nieczytelny.sql'));
      return d;
    },
    () => katalog({ '001.sql': ZDROWA, '002_czytelny.sql': 'grant execute on function public.f() to anon;' }));
  assert.match(u.msg, /nie-do-odczytania/);
});

test('--as-of odsiewajacy wszystko: pada, zamiast porownywac pusty obraz', () => {
  const dir = katalog({ '20260101000000_a.sql': ZDROWA });
  try {
    const u = proba(dir, { asOf: '20250101000000' });
    const z = proba(dir, { asOf: '20270101000000' });
    assert.equal(u.padlo, true);
    assert.match(u.msg, /odsiewa WSZYSTKIE/);
    assert.equal(z.padlo, false, 'sensowny --as-of musi dzialac');
    assert.ok(z.funkcji > 0);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

// --- przez wiersz polecen: kod wyjscia i brak frazy "CZYSTO" ------------------

function uruchom(args) {
  return spawnSync(process.execPath, [BIN, ...args], {
    encoding: 'utf8',
    timeout: 30000,
    // Katalog bez .env i bez supadrift.json: inaczej test czytalby pliki
    // dewelopera i przechodzilby albo padal zaleznie od jego maszyny.
    cwd: os.tmpdir(),
    env: Object.assign({}, process.env, { SUPADRIFT_DB_URL: undefined }),
  });
}

test('uszkodzony katalog: kod 2 i ani slowa o czystosci', () => {
  const zly = katalog({ '001.sql': 'create function public.f() as $$ begin' });
  try {
    const r = uruchom(['--migrations', zly]);
    const out = (r.stdout || '') + (r.stderr || '');
    assert.equal(r.status, 2, 'kod wyjscia ma byc 2');
    assert.ok(!/CZYSTO/.test(out), 'slowo CZYSTO nie ma prawa paść przy nieodczytanym wejsciu');
    assert.ok(!/rozjazd funkcji\s*:\s*0/.test(out), 'zero rozjazdow tez nie');
    assert.match(out, /niedomkniete-cytowanie-dolarowe/);
  } finally {
    fs.rmSync(zly, { recursive: true, force: true });
  }
});

test('adres bazy nie do sparsowania: kod 2, nie kod 0', () => {
  const dobry = katalog({ '001.sql': ZDROWA });
  try {
    const r = spawnSync(process.execPath, [BIN, '--migrations', dobry], {
      encoding: 'utf8',
      timeout: 30000,
      cwd: os.tmpdir(),
      env: Object.assign({}, process.env, { SUPADRIFT_DB_URL: 'to-nie-jest-adres' }),
    });
    const out = (r.stdout || '') + (r.stderr || '');
    assert.equal(r.status, 2);
    assert.ok(!/CZYSTO/.test(out));
  } finally {
    fs.rmSync(dobry, { recursive: true, force: true });
  }
});

test('uciety supadrift.json: kod 2, nie kod 0', () => {
  const dir = katalog({ '001.sql': ZDROWA });
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
  // tam zglosic brak adresu.
  const dobry = katalog({ '001.sql': ZDROWA });
  try {
    const r = uruchom(['--migrations', dobry]);
    const out = (r.stdout || '') + (r.stderr || '');
    assert.equal(r.status, 2);
    assert.match(out, /Brak adresu polaczenia/,
      'zdrowe migracje maja przejsc parsowanie i dojsc do polaczenia');
    assert.ok(!/niedomkniete|bajt-zerowy|ani jednego pliku/.test(out));
  } finally {
    fs.rmSync(dobry, { recursive: true, force: true });
  }
});
