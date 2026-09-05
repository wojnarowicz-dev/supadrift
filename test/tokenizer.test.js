'use strict';

const test = require('node:test');
const assert = require('node:assert');
const { tokenize, splitStatements } = require('../src/tokenizer');

const words = (st) => st.tokens.map((t) => (t.t === 'dollar' ? '<$>' : t.v)).join(' ');

test('cialo plpgsql pelne srednikow nie rozbija instrukcji', () => {
  const sql = [
    'create or replace function public.f() returns void language plpgsql as $$',
    'begin',
    '  update t set a = 1;',
    '  update t set b = 2;',
    'end;',
    '$$;',
    'revoke all on function public.f() from public;',
  ].join('\n');
  const st = splitStatements(sql);
  assert.equal(st.length, 2, 'naiwny split po sredniku dalby 5');
  assert.match(words(st[0]), /^create or replace function public \. f \( \)/);
  assert.match(words(st[1]), /^revoke all on function/);
});

test('znacznik dolarowy z nazwa', () => {
  const sql = 'create function f() as $body$ begin; end; $body$; select 1;';
  const st = splitStatements(sql);
  assert.equal(st.length, 2);
});

test('$1 to parametr pozycyjny, nie poczatek cytowania', () => {
  const toks = tokenize('select $1; select $2;');
  const dollars = toks.filter((t) => t.t === 'dollar');
  assert.equal(dollars.length, 0);
  assert.equal(splitStatements('select $1; select $2;').length, 2);
});

test('srednik w komentarzu liniowym i blokowym nie dzieli', () => {
  const sql = 'select 1 -- ; nie tutaj\n/* ani ; tutaj */ ; select 2;';
  assert.equal(splitStatements(sql).length, 2);
});

test('komentarz blokowy zagniezdza sie, tak jak w Postgresie', () => {
  const sql = '/* zewnetrzny /* wewnetrzny ; */ nadal komentarz ; */ select 1;';
  const st = splitStatements(sql);
  assert.equal(st.length, 1);
  assert.equal(words(st[0]), 'select 1');
});

test('srednik w literale i w identyfikatorze w cudzyslowie nie dzieli', () => {
  assert.equal(splitStatements("select 'a;b'; select 2;").length, 2);
  assert.equal(splitStatements('select "kol;umna"; select 2;').length, 2);
});

test('podwojony apostrof zamyka sie poprawnie', () => {
  const st = splitStatements("select 'to '' nie koniec ; wciaz literal'; select 2;");
  assert.equal(st.length, 2);
});

test("E'...' traktuje odwrotny ukosnik jako ucieczke", () => {
  const bs = String.fromCharCode(92);
  const st = splitStatements("select E'" + bs + "'; ' ; select 2;");
  assert.equal(st.length, 2);
});

test('identyfikator w cudzyslowie zachowuje wielkosc liter, zwykly nie', () => {
  const toks = tokenize('SELECT "MojaKolumna" FROM T');
  assert.equal(toks[0].v, 'select');
  assert.equal(toks[1].v, 'MojaKolumna');
  assert.equal(toks[1].q, true);
  assert.equal(toks[3].v, 't');
});

test('niedomkniete cytowanie dolarowe nie zapetla sie', () => {
  const st = splitStatements('create function f() as $$ begin; end;');
  assert.equal(st.length, 1);
});
