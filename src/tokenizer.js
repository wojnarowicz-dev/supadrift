'use strict';

// ---------------------------------------------------------------------------
// Tokenizer SQL
// ---------------------------------------------------------------------------
//
// PO CO WLASNY, A NIE PARSER DRZEWA. GRANT i REVOKE to plaskie, regularne DDL —
// pelne drzewo skladniowe nic tu nie dodaje, a kosztuje zaleznosc i gramatyke,
// ktora trzeba utrzymywac razem z kazda wersja Postgresa.
//
// Jedyna pulapka jest jedna i konkretna: CYTOWANIE DOLAROWE. Cialo funkcji
// plpgsql stoi miedzy $$ a $$ i jest pelne srednikow. Naiwne `sql.split(';')`
// rozcina takie cialo na kawalki i wszystko dalej jest juz zgadywaniem.
// Dlatego dzielenie na instrukcje idzie po TOKENACH, nie po znakach.
//
// Poza $$ obslugujemy jeszcze to, co realnie wystepuje w migracjach:
//   --  komentarz do konca wiersza
//   /* */ komentarz blokowy — w Postgresie ZAGNIEZDZALNY, inaczej niz w C
//   '...'   z podwojeniem ''    E'...' z odwrotnym ukosnikiem
//   "..."   identyfikator z podwojeniem ""
//   $1      parametr pozycyjny — NIE jest poczatkiem cytowania dolarowego

const IDENT_START = /[A-Za-z_\u0080-\uFFFF]/;
const IDENT_CHAR = /[A-Za-z0-9_\u0080-\uFFFF]/;
const DIGIT = /[0-9]/;

// $$ albo $tag$ — ale nie $1
const DOLLAR_TAG = /^\$([A-Za-z_\u0080-\uFFFF][A-Za-z0-9_\u0080-\uFFFF]*)?\$/;

/**
 * @typedef {{t:'word'|'str'|'dollar'|'num'|'punct', v:string, q?:boolean, pos:number, line:number}} Token
 * `word` bez cudzyslowu jest zawsze male literami (SQL jest niewrazliwy na
 * wielkosc). `q:true` znaczy "byl w cudzyslowie" — wtedy v zachowuje wielkosc
 * i nie jest slowem kluczowym.
 */

/**
 * @param {string} sql
 * @param {object[]} [issues] zbiera uszkodzenia pliku; patrz uwaga nizej
 * @returns {Token[]}
 *
 * USZKODZENIA. Tokenizer jest z zalozenia wyrozumialy — na urwanym pliku nie
 * wywala sie, tylko dochodzi do konca. To dobre dla odpornosci i FATALNE dla
 * zaufania: plik uciety w polowie ciala funkcji dawalby "funkcje", zero uwag
 * i raport "czysto". Dlatego kazde niedomkniecie ladu je w `issues`, a warstwa
 * wyzej robi z tego blad krytyczny. Cichy brak odczytu jest gorszy niz awaria.
 */
function tokenize(sql, issues = []) {
  /** @type {Token[]} */
  const out = [];
  const n = sql.length;
  let i = 0;
  let line = 1;

  while (i < n) {
    const c = sql[i];

    if (c === '\n') { line++; i++; continue; }
    if (c === ' ' || c === '\t' || c === '\r' || c === '\f' || c === '\v') { i++; continue; }

    // komentarz do konca wiersza
    if (c === '-' && sql[i + 1] === '-') {
      const e = sql.indexOf('\n', i);
      i = e === -1 ? n : e;
      continue;
    }

    // komentarz blokowy, zagniezdzalny
    if (c === '/' && sql[i + 1] === '*') {
      const startLine = line;
      let depth = 1;
      let j = i + 2;
      while (j < n && depth > 0) {
        if (sql[j] === '/' && sql[j + 1] === '*') { depth++; j += 2; }
        else if (sql[j] === '*' && sql[j + 1] === '/') { depth--; j += 2; }
        else { if (sql[j] === '\n') line++; j++; }
      }
      if (depth > 0) {
        issues.push({ kind: 'niedomkniety-komentarz-blokowy', line: startLine });
      }
      i = j;
      continue;
    }

    // cytowanie dolarowe — cala rzecz, dla ktorej ten plik istnieje
    if (c === '$') {
      const m = DOLLAR_TAG.exec(sql.slice(i, i + 256));
      if (m) {
        const tag = m[0];
        const startLine = line;
        const bodyStart = i + tag.length;
        const end = sql.indexOf(tag, bodyStart);
        if (end === -1) {
          issues.push({ kind: 'niedomkniete-cytowanie-dolarowe', line: startLine, tag });
        }
        const stop = end === -1 ? n : end + tag.length;
        for (let k = i; k < stop; k++) if (sql[k] === '\n') line++;
        out.push({ t: 'dollar', v: sql.slice(bodyStart, end === -1 ? n : end), pos: i, line: startLine });
        i = stop;
        continue;
      }
      // $1, $2 — parametr pozycyjny
      if (DIGIT.test(sql[i + 1] || '')) {
        let j = i + 1;
        while (j < n && DIGIT.test(sql[j])) j++;
        out.push({ t: 'num', v: sql.slice(i, j), pos: i, line });
        i = j;
        continue;
      }
      out.push({ t: 'punct', v: '$', pos: i, line });
      i++;
      continue;
    }

    // literaly z prefiksem: E'...' (ukosniki), B'...', X'...', U&'...'
    if (/[eEbBxX]/.test(c) && sql[i + 1] === "'") {
      const r = readQuoted(sql, i + 1, "'", /[eE]/.test(c), line, issues);
      out.push({ t: 'str', v: r.value, pos: i, line });
      line = r.line; i = r.next;
      continue;
    }
    if (/[uU]/.test(c) && sql[i + 1] === '&' && (sql[i + 2] === "'" || sql[i + 2] === '"')) {
      const q = sql[i + 2];
      const r = readQuoted(sql, i + 2, q, false, line, issues);
      out.push({ t: q === "'" ? 'str' : 'word', v: r.value, q: q === '"', pos: i, line });
      line = r.line; i = r.next;
      continue;
    }

    if (c === "'") {
      const r = readQuoted(sql, i, "'", false, line, issues);
      out.push({ t: 'str', v: r.value, pos: i, line });
      line = r.line; i = r.next;
      continue;
    }

    if (c === '"') {
      const r = readQuoted(sql, i, '"', false, line, issues);
      out.push({ t: 'word', v: r.value, q: true, pos: i, line });
      line = r.line; i = r.next;
      continue;
    }

    if (DIGIT.test(c)) {
      let j = i;
      while (j < n && /[0-9.eE+\-]/.test(sql[j])) {
        // wykladnik: + i - tylko zaraz po e/E
        if ((sql[j] === '+' || sql[j] === '-') && !/[eE]/.test(sql[j - 1])) break;
        j++;
      }
      out.push({ t: 'num', v: sql.slice(i, j), pos: i, line });
      i = j;
      continue;
    }

    if (IDENT_START.test(c)) {
      let j = i;
      while (j < n && IDENT_CHAR.test(sql[j])) j++;
      out.push({ t: 'word', v: sql.slice(i, j).toLowerCase(), pos: i, line });
      i = j;
      continue;
    }

    out.push({ t: 'punct', v: c, pos: i, line });
    i++;
  }

  return out;
}

const BSLASH = String.fromCharCode(92);

function readQuoted(sql, start, quote, backslash, line, issues = []) {
  const n = sql.length;
  let i = start + 1;
  let value = '';
  let ln = line;
  while (i < n) {
    const c = sql[i];
    if (c === '\n') ln++;
    if (backslash && c === BSLASH && i + 1 < n) { value += sql[i + 1]; i += 2; continue; }
    if (c === quote) {
      if (sql[i + 1] === quote) { value += quote; i += 2; continue; } // podwojenie
      i++;
      return { value, next: i, line: ln };
    }
    value += c;
    i++;
  }
  // Doszlismy do konca pliku bez zamykajacego cudzyslowu — plik jest urwany.
  issues.push({
    kind: quote === "'" ? 'niedomkniety-literal' : 'niedomkniety-identyfikator',
    line,
  });
  return { value, next: n, line: ln };
}

/**
 * Dzieli strumien tokenow na instrukcje po sredniku na poziomie zerowym.
 * @returns {{tokens:Token[], line:number, start:number, end:number}[]}
 */
function splitStatements(sql, issues = []) {
  const toks = tokenize(sql, issues);
  const out = [];
  let cur = [];
  let depth = 0;

  for (const tk of toks) {
    if (tk.t === 'punct') {
      if (tk.v === '(') depth++;
      else if (tk.v === ')') depth = Math.max(0, depth - 1);
      else if (tk.v === ';' && depth === 0) {
        if (cur.length) out.push(mk(cur, tk.pos + 1));
        cur = [];
        continue;
      }
    }
    cur.push(tk);
  }
  if (depth !== 0) issues.push({ kind: 'niezbilansowane-nawiasy', line: 0, depth });
  if (cur.length) out.push(mk(cur, sql.length));

  function mk(tokens, end) {
    return { tokens, line: tokens[0].line, start: tokens[0].pos, end };
  }
  return out;
}

module.exports = { tokenize, splitStatements };
