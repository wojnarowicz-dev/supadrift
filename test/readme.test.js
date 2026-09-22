'use strict';

// Czy strona mowi prawde o narzedziu.
//
// TEGO NIE BYLO W OGOLE. Trzy siostrzane narzedzia maja warstwe, ktora
// wykonuje kazde polecenie pokazane w README i porownuje wynik z tym, co
// strona obiecuje. Tutaj nie bylo nic — a README to jedyna rzecz, ktora
// czlowiek czyta PRZED uruchomieniem czegokolwiek.
//
// ZACZYNAMY OD NAJPIERWSZEJ LINII, KTORA KTOKOLWIEK WPISUJE: `npx supadrift`.
// Zla nazwa pakietu wysyla czytelnika do cudzego pakietu albo donikad, i zaden
// przebieg lokalny tego nie pokaze — bo lokalnie nazwa pakietu nie jest w ogole
// uzywana.
//
// CZEGO TA WARSTWA NIE ROBI: nie uruchamia polecen, ktore potrzebuja ZYWEJ
// bazy. To narzedzie porownuje migracje z prawdziwym Postgresem, wiec
// wiekszosc przykladow ze strony wymaga polaczenia, ktorego test nie ma prawa
// zakladac. Sprawdzane jest to, co da sie sprawdzic bez bazy, i jest to
// napisane wprost, zeby nikt nie wzial tej warstwy za pelne pokrycie.

const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const path = require('path');
const { spawnSync } = require('child_process');

const ROOT = path.join(__dirname, '..');
const BIN = path.join(ROOT, 'bin', 'supadrift.js');
const pkg = JSON.parse(fs.readFileSync(path.join(ROOT, 'package.json'), 'utf8'));

const PAGES = ['README.md', 'README.pl.md']
  .filter((f) => fs.existsSync(path.join(ROOT, f)));

// `npx <nazwa>` — nazwa pakietu i to, co po niej stoi.
const NPX = /\bnpx\s+([a-z0-9@._-]+)([^\n`]*)/gi;

function npxLines(text) {
  return [...text.matchAll(NPX)].map((m) => ({
    pkg: m[1],
    // KROPKA NA KONCU BYWA ARGUMENTEM, NIE INTERPUNKCJA. Kropka przyklejona do
    // slowa konczy zdanie; kropka stojaca sama to katalog. Pomylenie tych
    // dwoch rzeczy w siostrzanym narzedziu sprawilo, ze bramka uruchamiala
    // gola podkomende, dostawala kod 2 i nazywala to przejsciem.
    rest: (m[2] || '')
      .replace(/(?<=[A-Za-z0-9])[.,;:]$/, '')
      .replace(/[,;:]$/, '')
      .trim(),
  }));
}

test('kazda strona ma linie npx', () => {
  assert.ok(PAGES.length > 0, 'nie ma zadnego README');
  for (const page of PAGES) {
    const lines = npxLines(fs.readFileSync(path.join(ROOT, page), 'utf8'));
    assert.ok(lines.length > 0, page + ': ani jednej linii npx');
  }
});

test('npx na stronie nazywa TEN pakiet', () => {
  for (const page of PAGES) {
    const lines = npxLines(fs.readFileSync(path.join(ROOT, page), 'utf8'));
    for (const l of lines) {
      assert.equal(l.pkg.replace(/@.*$/, ''), pkg.name,
        page + ': strona mowi "npx ' + l.pkg + '", a pakiet nazywa sie ' + pkg.name);
    }
  }
});

test('nazwa z npx jest kluczem w bin', () => {
  const binNames = Object.keys(pkg.bin || {});
  assert.ok(binNames.includes(pkg.name),
    'npx znajdzie pakiet i nie bedzie mial czego uruchomic; bin: ' + binNames.join(', '));
});

// PRZELACZNIKI Z LINII npx MUSZA ISTNIEC. Nie uruchamiamy calego porownania —
// to potrzebuje bazy — ale nieznany przelacznik narzedzie odrzuca od razu, bez
// laczenia sie z czymkolwiek, i to wystarczy, zeby zlapac zardzewialy przyklad.
test('przelaczniki z linii npx sa znane narzedziu', () => {
  for (const page of PAGES) {
    const lines = npxLines(fs.readFileSync(path.join(ROOT, page), 'utf8'));
    for (const l of lines) {
      const flags = l.rest.split(/\s+/).filter((a) => a.startsWith('--'));
      for (const flag of flags) {
        const r = spawnSync(process.execPath, [BIN, flag, '--migrations', __dirname],
          { cwd: ROOT, encoding: 'utf8', timeout: 60000,
            env: Object.assign({}, process.env, { SUPADRIFT_DB_URL: '' }) });
        const out = (r.stdout || '') + (r.stderr || '');
        assert.ok(!/nieznany przelacznik|unknown option|Nieznana opcja/i.test(out),
          page + ': ' + flag + ' — narzedzie go nie zna: ' + out.slice(0, 120));
      }
    }
  }
});
