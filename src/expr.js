'use strict';

// ---------------------------------------------------------------------------
// Porownywanie wyrazen polityk
// ---------------------------------------------------------------------------
//
// PROBLEM. Postgres nie przechowuje tekstu, ktory napisales. Przechowuje drzewo
// i odtwarza z niego tekst na zadanie. To, co wroci, prawie nigdy nie jest tym,
// co poszlo:
//
//   w migracji        (select auth.uid()) = user_id
//   pg_get_expr()     (( SELECT auth.uid() AS uid) = user_id)
//
// Doszly nawiasy obejmujace calosc i alias kolumny w podzapytaniu. Porownanie
// napis do napisu zglaszaloby tu rozjazd przy KAZDEJ polityce i utopilo sygnal
// w halasie — a narzedzie, ktore zglasza wszystko, nie zglasza niczego.
//
// CO ROBIMY. Obie strony sprowadzamy do strumienia tokenow i zdejmujemy dwie
// rzeczy, ktore Postgres dokłada sam:
//   1. nawiasy obejmujace cale wyrazenie,
//   2. aliasy listy select (`as cos` tuz przed `)`, `,` albo `from`).
//
// CZEGO TO NIE ZALATWIA — i mowimy o tym wprost w raporcie. Postgres przepisuje
// tez rzutowania (`cast(x as text)` -> `(x)::text`), rozwija nazwy operatorow
// i domyka nazwy schematow. Roznica w tresci wyrazenia jest wiec sygnalem
// "spojrz na to okiem", a nie dowodem rozjazdu. Sama obecnosc albo brak USING
// i WITH CHECK jest juz twarda: tego Postgres nie dokłada ani nie gubi.

const { tokenize } = require('./tokenizer');

/** Zdejmuje nawiasy obejmujace cale wyrazenie, tyle razy, ile trzeba. */
function stripOuterParens(toks) {
  let t = toks;
  for (;;) {
    if (t.length < 2) return t;
    const first = t[0];
    const last = t[t.length - 1];
    if (first.t !== 'punct' || first.v !== '(' || last.t !== 'punct' || last.v !== ')') return t;
    let depth = 0;
    let matchesLast = true;
    for (let i = 0; i < t.length; i++) {
      if (t[i].t !== 'punct') continue;
      if (t[i].v === '(') depth++;
      else if (t[i].v === ')') {
        depth--;
        if (depth === 0 && i !== t.length - 1) { matchesLast = false; break; }
      }
    }
    if (!matchesLast) return t;
    t = t.slice(1, -1);
  }
}

/** Usuwa aliasy listy select, ktore pg_get_expr() dopisuje sam. */
function dropSelectAliases(toks) {
  const out = [];
  for (let i = 0; i < toks.length; i++) {
    const tk = toks[i];
    const next = toks[i + 1];
    const after = toks[i + 2];
    const isAlias = tk.t === 'word' && !tk.q && tk.v === 'as'
      && next && next.t === 'word'
      && (after === undefined
        || (after.t === 'punct' && (after.v === ')' || after.v === ','))
        || (after.t === 'word' && !after.q && after.v === 'from'));
    if (isAlias) { i++; continue; }
    out.push(tk);
  }
  return out;
}

function render(toks) {
  return toks.map((tk) => {
    if (tk.t === 'word') return tk.q ? '"' + tk.v + '"' : tk.v;
    if (tk.t === 'str') return "'" + tk.v + "'";
    if (tk.t === 'dollar') return '$$' + tk.v + '$$';
    return tk.v;
  }).join(' ');
}

/** @param {string|Array} input tekst wyrazenia albo gotowe tokeny */
function normalizeExpr(input) {
  if (input === null || input === undefined) return null;
  const toks = typeof input === 'string' ? tokenize(input) : input;
  return render(stripOuterParens(dropSelectAliases(stripOuterParens(toks))));
}

module.exports = { normalizeExpr, stripOuterParens, dropSelectAliases, render };
