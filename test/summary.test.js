'use strict';

// Cztery stany i kod wyjscia, ktory z nich wynika.
//
// DLACZEGO OSOBNO OD RESZTY. Pelny przebieg tego narzedzia potrzebuje ZYWEJ
// bazy: porownuje migracje z uprawnieniami, ktore naprawde obowiazuja. Kazdy
// ksztalt podsumowania da sie wiec zobaczyc tylko wtedy, gdy ma sie baze w
// tym stanie — a regula, ktora z podsumowania wyprowadza kod wyjscia, musi
// byc sprawdzalna bez niej. Wiec jest pytana wprost, podsumowaniami
// wypisanymi tutaj, a nie wyprodukowanymi przez przebieg.
//
// PIERWSZY WIERSZ JEST TYM, PO CO TO POWSTALO. "Nie dalem rady polaczyc sie
// z baza" nie jest tym samym co "uprawnienia sie zgadzaja", i roznica miedzy
// nimi to jedna liczba, ktora czyta budowanie.

const test = require('node:test');
const assert = require('node:assert');

const { summaryOf, exitCodeFor } = require('../src/summary');

const S = (parts) => summaryOf(parts);

test('nie dalo sie polaczyc i nic nie bylo do decyzji: code 2', () => {
  assert.equal(exitCodeFor(S({ couldNotBeRead: 1 }), {}), 2);
});

test('nie dalo sie odczytac czesci, ale cos zglosil: nie 2, bo odpowiedz stoi', () => {
  assert.equal(exitCodeFor(S({ actionable: 3, couldNotBeRead: 1 }), {}), 1);
});

test('rozjazdy sa: code 1', () => {
  assert.equal(exitCodeFor(S({ actionable: 3 }), {}), 1);
});

test('czysto: code 0', () => {
  assert.equal(exitCodeFor(S({ actionable: 0, explained: 4, notApplicable: 2 }), {}), 0);
});

// --sarif oddaje wynik do zakladki Security, a nie do wyniku budowania.
// Pierwsze zetkniecie z narzedziem, ktore wywraca budowanie, jest ostatnim.
test('--sarif: rozjazdy nie wywracaja budowania', () => {
  assert.equal(exitCodeFor(S({ actionable: 3 }), { sarif: true }), 0);
});

// ...ale brak odczytu nadal wywraca, bo to nie jest znalezisko tylko brak
// odpowiedzi, i zadna zakladka tego nie zastapi.
test('--sarif: brak odczytu nadal daje 2', () => {
  assert.equal(exitCodeFor(S({ couldNotBeRead: 1 }), { sarif: true }), 2);
});

// WYJASNIONE I NIE-DOTYCZY NIGDY NIE ZAPALAJA NICZEGO. Wyzwalacz zdjety przez
// --allow-manual i kontrola wylaczona przez --no-tables to odpowiedzi, nie
// praca do wykonania.
test('wyjasnione i nieDotyczy nie zmieniaja kodu', () => {
  assert.equal(exitCodeFor(S({ explained: 9, notApplicable: 5 }), {}), 0);
});

test('pole ma zawsze te same cztery liczby plus rozbicie', () => {
  const s = S({ actionable: 1, explained: 2, notApplicable: 3, couldNotBeRead: 4 });
  assert.deepEqual(Object.keys(s).sort(),
    ['actionable', 'explained', 'notApplicable', 'unreachable', 'unreachableIs'].sort());
  assert.equal(s.unreachable, 4);
  // Rozbicie istnieje nawet tu, gdzie jest calym unreachable: w said-vs-done
  // te dwie polowy sie roznia, a to samo pole musi znaczyc to samo we
  // wszystkich czterech narzedziach.
  assert.deepEqual(s.unreachableIs, { aQuestionForAPerson: 0, couldNotBeRead: 4 });
});
