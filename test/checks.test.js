'use strict';

// Zbior kontroli: jeden fakt w kodzie, i kazde zdanie mierzone wobec niego.
//
// DLACZEGO TO POWSTALO. Zbior kontroli byl wypisany recznie w trzech
// miejscach, ktore czyta czlowiek, zanim czemukolwiek tu zaufa: tabela
// „Scope" na obu stronach, przelaczniki `--no-*` w pomocy i bezimienna
// tablica osmiu nazw zmiennych w bin/supadrift.js, ktora liczy, ile kontroli
// wylaczono. Nic ich ze sobą nie zestawiało.
//
// Kontrola dopisana bez wiersza w tabeli to kontrola, o ktorej nikt nie wie,
// ze chodzi. Wiersz bez kontroli to obietnica, ktorej nic nie spelnia.
// A `notApplicable` bylo trzecia reczna kopia tej samej listy.
//
// To jest ten sam ksztalt, ktory znalazl sie w looks-clean: naglowek
// polecenia obiecywal wezszy zbior niz wiersz bezposrednio pod nim, a dwie
// bramki stały zielone nad sprzecznością, bo żadna nie zestawiała ich ze
// sobą. Naprawa jest ta sama: NIE porownywac dwoch napisow ze soba, tylko
// kazdy napis z KODEM. src/checks.js jest faktem, tabela i pomoc sa
// twierdzeniami o nim.

const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const path = require('path');
const { spawnSync } = require('child_process');

const { CHECKS, CHECK_FLAGS, switchedOff } = require('../src/checks');

const ROOT = path.join(__dirname, '..');
const CLI = path.join(ROOT, 'bin', 'supadrift.js');

const help = () => {
  const r = spawnSync(process.execPath, [CLI, '--help'], { encoding: 'utf8', maxBuffer: 1e9 });
  return (r.stdout || '') + (r.stderr || '');
};

// Wiersze tabeli „Scope": pierwsza komorka to nazwa kontroli.
function scopeRows(page, heading) {
  const lines = fs.readFileSync(path.join(ROOT, page), 'utf8').split(/\r?\n/);
  const at = lines.findIndex((l) => l.trim() === heading);
  assert.notEqual(at, -1, page + ': nie ma naglowka ' + heading);
  const rows = [];
  for (let i = at + 1; i < lines.length; i++) {
    const l = lines[i];
    if (!/^\s*\|/.test(l)) { if (rows.length) break; else continue; }
    const cells = l.trim().replace(/^\||\|$/g, '').split('|').map((c) => c.trim());
    if (/^-+$/.test(cells[0].replace(/:/g, ''))) continue;      // linia oddzielajaca
    rows.push(cells[0].replace(/`/g, ''));
  }
  return rows;
}

test('kazda kontrola ma wiersz w tabeli Scope na obu stronach', () => {
  for (const [page, heading, lang] of [
    ['README.md', '## Scope', 'en'],
    ['README.pl.md', '## Zakres', 'pl'],
  ]) {
    const rows = scopeRows(page, heading);
    // eventTriggerResult dzieli nazwe z triggerResult — jeden wiersz na NAZWE,
    // bo tak to czyta czlowiek: „wyzwalacze" to jedna pozycja tabeli.
    const names = [...new Set(CHECKS.map((c) => c[lang]))];
    const missing = names.filter((n) => !rows.some((r) => r === n));
    assert.deepEqual(missing, [], page + ': tabela nie wymienia: ' + missing.join(', '));
  }
});

test('kazdy przelacznik --no-* z listy kontroli jest w pomocy', () => {
  const h = help();
  const missing = CHECK_FLAGS.filter((f) => !h.includes(f));
  assert.deepEqual(missing, [], 'pomoc nie oferuje: ' + missing.join(', '));
});

// W DRUGA STRONE, i to jest ta polowa, ktorej brak przepuscil pierwotna wade.
// Bramka sprawdzajaca tylko „czy kazda kontrola ma napis" przechodzi nad
// napisem, za ktorym nie stoi zadna kontrola.
test('kazdy przelacznik --no-* z pomocy wylacza istniejaca kontrole', () => {
  const h = help();
  const inHelp = [...new Set([...h.matchAll(/^\s+(--no-[a-z-]+)/gm)].map((m) => m[1]))];
  // --no-policy-expr i --no-fix nie wylaczaja KONTROLI: pierwszy zwęża
  // porownanie polityk, drugi tylko nie drukuje migracji naprawczej.
  const NOT_A_CHECK = { '--no-policy-expr': 'zawezenie porownania, nie kontrola', '--no-fix': 'tylko wydruk' };
  const orphans = inHelp.filter((f) => !CHECK_FLAGS.includes(f) && !NOT_A_CHECK[f]);
  assert.deepEqual(orphans, [], 'pomoc oferuje przelaczniki bez kontroli: ' + orphans.join(', '));
});

test('nieDotyczy liczy kontrole, nie pozycje', () => {
  const wszystkie = {};
  for (const c of CHECKS) wszystkie[c.key] = [];
  assert.equal(switchedOff(wszystkie), 0, 'nic nie wylaczone');

  const bezTabel = { ...wszystkie, tableResult: null };
  assert.equal(switchedOff(bezTabel), 1, '--no-tables to JEDNA kontrola');

  // --no-triggers zdejmuje dwie kontrole, i tak ma byc liczone: wyzwalacze
  // tabelowe i zdarzeniowe to dwa rozne porownania pod jednym przelacznikiem.
  const bezWyzwalaczy = { ...wszystkie, triggerResult: null, eventTriggerResult: null };
  assert.equal(switchedOff(bezWyzwalaczy), 2, '--no-triggers to dwie kontrole');

  const nic = {};
  assert.equal(switchedOff(nic), CHECKS.length, 'brak wyniku liczy sie jak wylaczona');
});
