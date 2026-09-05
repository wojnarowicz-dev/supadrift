'use strict';

// ---------------------------------------------------------------------------
// SECURITY DEFINER a search_path
// ---------------------------------------------------------------------------
//
// Funkcja SECURITY DEFINER chodzi z uprawnieniami wlasciciela. To znaczy, ze
// kazda nazwa, ktorej nie napisano w niej z kwalifikacja schematu, jest szukana
// po search_path OBOWIAZUJACYM W CZASIE WYWOLANIA — a ten ustawia wolajacy,
// jesli funkcja nie przybije go sobie sama. Wolajacy podstawia wtedy wlasny
// schemat przed public i jego `quota_usage` albo jego `now()` wykonuje sie
// z uprawnieniami wlasciciela funkcji.
//
// Stad `set search_path = ...` w definicji. I stad DRUGA polowa tej reguly,
// o ktorej latwo zapomniec:
//
//   PG_TEMP MUSI BYC NA LISCIE, I MUSI BYC OSTATNI.
//
// Schemat tymczasowy jest przeszukiwany dla nazw RELACJI jako PIERWSZY, o ile
// nie wymieniono go jawnie. Kazdy uzytkownik moze w swoim pg_temp zalozyc
// tabele o dowolnej nazwie. `set search_path = public` nie chroni wiec przed
// niczym w zakresie tabel: pg_temp nadal idzie przed public. Dopiero wpisanie
// `pg_temp` na koncu listy przesuwa go na koniec kolejnosci.
//
// To dokladnie ta roznica:
//   set search_path = public              <- pg_temp NADAL pierwszy
//   set search_path = public, pg_temp     <- pg_temp ostatni, tak ma byc
//
// Kwalifikowanie nazw w ciele (public.quota_usage) zamyka te droge osobno
// i dobrze, gdy jest — ale nie zwalnia z ustawienia, bo wystarczy jedna
// niekwalifikowana nazwa dopisana pol roku pozniej.
//
// CZEGO NIE ZGLASZAMY. Funkcji SECURITY INVOKER. Chodza z uprawnieniami
// wolajacego, wiec podstawienie nie daje napastnikowi niczego, czego by juz
// nie mial.

const HYGIENE = {
  BRAK: 'brak-search-path',
  BEZ_PG_TEMP: 'bez-pg_temp',
  PG_TEMP_NIE_OSTATNI: 'pg_temp-nie-na-koncu',
};

function classify(searchPath) {
  if (!searchPath || searchPath.length === 0) return HYGIENE.BRAK;
  const idx = searchPath.indexOf('pg_temp');
  if (idx === -1) return HYGIENE.BEZ_PG_TEMP;
  if (idx !== searchPath.length - 1) return HYGIENE.PG_TEMP_NIE_OSTATNI;
  return null;
}

function fmt(searchPath) {
  if (!searchPath || !searchPath.length) return '(nie ustawiony)';
  return searchPath.join(', ');
}

/**
 * Poprawka jest liczona osobno dla kazdej funkcji, a nie brana z wiekszosci:
 * funkcji, ktora ma juz `search_path = pg_catalog`, nie wolno "naprawic" na
 * `public, pg_temp` — to byloby podstawienie innego schematu pod jej nazwy.
 * Wiekszosc sluzy tylko tam, gdzie nie ma czego uzupelnic.
 */
function suggestFor(searchPath, majority) {
  if (searchPath && searchPath.length) {
    const withoutTemp = searchPath.filter((s) => s !== 'pg_temp');
    return { values: withoutTemp.concat(['pg_temp']), why: 'dopisane pg_temp na koncu istniejacej listy' };
  }
  if (majority) return { values: majority.values, why: majority.why };
  return { values: ['public', 'pg_temp'], why: 'ustawienie zalecane w dokumentacji Postgresa' };
}

/** Najczestszy poprawny search_path wsrod pozostalych funkcji SECURITY DEFINER. */
function majorityPattern(functions, skipKey) {
  const counts = new Map();
  for (const f of functions.values()) {
    if (f.key === skipKey) continue;
    if (!f.securityDefiner) continue;
    if (classify(f.searchPath) !== null) continue;
    const k = f.searchPath.join(', ');
    counts.set(k, (counts.get(k) || 0) + 1);
  }
  let best = null;
  for (const [k, n] of counts) if (!best || n > best.n) best = { k, n };
  if (!best) return null;
  return {
    values: best.k.split(', '),
    why: best.n + ' ' + plural(best.n, 'inna funkcja', 'inne funkcje', 'innych funkcji')
      + ' SECURITY DEFINER w tym zestawie ma dokladnie takie ustawienie',
  };
}

function plural(n, one, few, many) {
  if (n === 1) return one;
  const t = n % 10;
  const h = n % 100;
  if (t >= 2 && t <= 4 && !(h >= 12 && h <= 14)) return few;
  return many;
}

/**
 * @param {Map} expected obraz z migracji
 * @param {Map} actual   obraz z bazy
 * @param {{allow?:string[]}} opts
 */
function checkSecurityDefiner(expected, actual, opts = {}) {
  const allow = new Set((opts.allow || []).map((s) => s.toLowerCase()));
  const findings = [];

  for (const key of [...new Set([...expected.keys(), ...actual.keys()])].sort()) {
    const e = expected.get(key);
    const a = actual.get(key);
    const ref = a || e;

    const secdefInMigrations = !!e && e.securityDefiner === true;
    const secdefInDb = !!a && a.securityDefiner === true;
    if (!secdefInMigrations && !secdefInDb) continue;

    const inMigrations = secdefInMigrations ? classify(e.searchPath) : null;
    const inDb = secdefInDb ? classify(a.searchPath) : null;
    if (inMigrations === null && inDb === null) continue;

    if (allow.has(ref.key.toLowerCase())
      || allow.has((ref.schema + '.' + ref.name).toLowerCase())
      || allow.has(ref.name.toLowerCase())) continue;

    const base = a && secdefInDb ? a.searchPath : (e ? e.searchPath : null);
    const suggestion = suggestFor(base, majorityPattern(expected, key) || majorityPattern(actual, key));

    findings.push({
      key,
      text: ref.text,
      kind: inDb || inMigrations,
      inMigrations,
      inDb,
      where: inMigrations && inDb ? 'w obu' : inMigrations ? 'w migracjach' : 'w bazie',
      searchPathInMigrations: e && secdefInMigrations ? fmt(e.searchPath) : null,
      searchPathInDb: a && secdefInDb ? fmt(a.searchPath) : null,
      declaredIn: e ? e.createdIn : null,
      declaredLine: e ? (e.createdLine || 1) : 1,
      suggestion,
    });
  }

  // Brak ustawienia jest gorszy niz niepelne, wiec idzie pierwszy.
  const rank = (f) => (f.kind === HYGIENE.BRAK ? 0 : f.kind === HYGIENE.BEZ_PG_TEMP ? 1 : 2);
  findings.sort((x, y) => rank(x) - rank(y) || (x.key < y.key ? -1 : 1));
  return findings;
}

module.exports = { checkSecurityDefiner, classify, suggestFor, majorityPattern, HYGIENE, fmt };
