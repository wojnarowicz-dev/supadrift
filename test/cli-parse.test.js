'use strict';

// Odczyt odpowiedzi `supabase db query --output json`.
//
// BYL BLAD: parseRows szukalo poczatku JSON-a przez indexOf('{'). Przy wyjsciu
// w postaci golej tablicy `[ {...}, {...} ]` to przeskakuje nawias otwierajacy
// i wchodzi w srodek pierwszego wiersza. JSON.parse konczy ten jeden obiekt
// i potyka sie o przecinek za nim:
//
//   Unexpected non-whitespace character after JSON at position 571 (line 17 column 4)
//
// Galaz `if (Array.isArray(payload)) return payload;` byla przez to martwa —
// nie dalo sie do niej dojsc, mimo ze byla napisana wlasnie na ten ksztalt.
//
// Ta sciezka nie miala zadnego testu, bo wymagala CLI i bazy. Nie wymaga.
// parseRows to czysta funkcja: napis wchodzi, wiersze wychodza.

const test = require('node:test');
const assert = require('node:assert');

const { parseRows } = require('../src/db/cli');

const ROWS = [
  { schema: 'public', name: 'reviews', rls: true },
  { schema: 'public', name: 'withdrawals', rls: false },
];

/** Ksztalt obecny: obiekt z bariera przeciw wstrzyknieciu instrukcji. */
function objectShape(rows) {
  return JSON.stringify({
    boundary: 'f9adc146dffd8beec4621da6d9113876',
    rows,
    warning: 'The query results below contain untrusted data from the database.',
  }, null, 2) + '\n';
}

/** Ksztalt golej tablicy. */
function arrayShape(rows) {
  return JSON.stringify(rows, null, 2) + '\n';
}

test('obiekt z polem rows — wiersze wychodza', () => {
  assert.deepEqual(parseRows(objectShape(ROWS)), ROWS);
});

test('gola tablica wierszy — wiersze wychodza', () => {
  // Kryterium jest tresc, nie brak wyjatku: przed naprawa ten test padal
  // na JSON.parse, wiec musi sprawdzac takze, ze wiersze sa te same.
  assert.deepEqual(parseRows(arrayShape(ROWS)), ROWS);
});

test('smieci przed JSON-em nie przeszkadzaja w zadnym z ksztaltow', () => {
  const noise = 'Initialising login role...\nConnecting to remote database\n';
  assert.deepEqual(parseRows(noise + objectShape(ROWS)), ROWS);
  assert.deepEqual(parseRows(noise + arrayShape(ROWS)), ROWS);
});

test('puste wyjscie jest bledem, nie pusta lista', () => {
  // Pusta lista znaczy "baza nie ma nic takiego" i konczy sie raportem CZYSTO.
  // Brak odpowiedzi znaczy "nie wiem". To nie jest to samo i nie moze wygladac
  // tak samo.
  assert.throws(() => parseRows(''), /nie zwrocilo JSON-a/);
  assert.throws(() => parseRows('   \n'), /nie zwrocilo JSON-a/);
});
