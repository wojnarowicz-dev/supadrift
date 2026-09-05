'use strict';

// ---------------------------------------------------------------------------
// Bramka "tylko odczyt"
// ---------------------------------------------------------------------------
//
// supadrift nigdy nie tworzy, nie zmienia, nie nadaje i nie usuwa. Zeby to
// bylo wlasnoscia programu, a nie obietnica w README, kazde zapytanie
// przechodzi przez ta funkcje, zanim trafi do sterownika. Nie ma sciezki
// obok — oba sterowniki wolaja ja w swoim query().
//
// Sprawdzenie jest celowo tepe: dopuszczamy wylacznie pojedyncze SELECT.
// Zadnych CTE zapisujacych, zadnych srednikow, zadnego DO. Zapytania, ktore
// supadrift wysyla, sa napisami stalymi w tym repozytorium, wiec ta bramka
// nie ma prawa nikomu przeszkadzac — a lapie kazda przyszla nieuwage.

const FORBIDDEN = [
  'insert', 'update', 'delete', 'truncate', 'merge',
  'create', 'alter', 'drop', 'grant', 'revoke', 'comment',
  'copy', 'call', 'do', 'vacuum', 'analyze', 'cluster', 'reindex',
  'refresh', 'lock', 'notify', 'listen', 'security',
];

function assertReadOnly(sql) {
  const text = String(sql);

  if (!/^\s*select\b/i.test(text)) {
    throw new Error('supadrift wysyla wylacznie SELECT; odrzucono zapytanie zaczynajace sie inaczej');
  }
  // Jeden srednik na koncu jest w porzadku, wiecej niz jedna instrukcja nie.
  if (/;\s*\S/.test(text)) {
    throw new Error('supadrift wysyla jedna instrukcje na raz; odrzucono zapytanie z wieloma instrukcjami');
  }
  // Slowa modyfikujace poza literalami i cudzyslowami.
  const stripped = text
    .replace(/'(?:[^']|'')*'/g, "''")
    .replace(/"(?:[^"]|"")*"/g, '""');
  for (const word of FORBIDDEN) {
    const re = new RegExp('(^|[^A-Za-z_])' + word + '([^A-Za-z_]|$)', 'i');
    if (re.test(stripped)) {
      throw new Error('supadrift nie wysyla zapytan zawierajacych slowo ' + word.toUpperCase());
    }
  }
  return text;
}

module.exports = { assertReadOnly, FORBIDDEN };
