'use strict';

// ---------------------------------------------------------------------------
// Kontrola zamiaru: funkcja, ktorej nie ma kto wolac
// ---------------------------------------------------------------------------
//
// Porownanie plikow z baza ma jedna slepa plamke i jest ona akurat tam, gdzie
// boli najbardziej: NIE ZOBACZY BLEDU, W KTORYM PLIKI I BAZA MYLA SIE TAK SAMO.
// W dniu, w ktorym migracja 20240115120000 weszla na produkcje, baza byla z nia
// zgodna co do znaku. Rozjazd wynosil zero. Funkcja byla martwa.
//
// Ta kontrola nie porownuje niczego z niczym. Patrzy na jeden obraz i pyta:
// czy po tych uprawnieniach zostal ktokolwiek, kto moze te funkcje wywolac?
//
//   REVOKE ... FROM public zdejmuje EXECUTE wszystkim, ktorzy mieli je tylko
//   przez role `public` — a przy tworzeniu funkcji maja je tak wszyscy.
//   Jesli po takim revoke nie ma zadnego GRANT EXECUTE, zostaje sam wlasciciel.
//   Zaden klient Supabase nie laczy sie jako wlasciciel: edge functions chodza
//   jako service_role, przegladarka jako anon albo authenticated. Funkcja jest
//   wiec wywolywalna przez nikogo — i nikt tego nie zglosi, bo z punktu widzenia
//   bazy uprawnienia sa dokladnie takie, jakie kazano ustawic.
//
// KIEDY TO NIE JEST BLAD — i dlatego tego nie zglaszamy:
//
//   1. Funkcja wyzwalacza (`returns trigger`, `returns event_trigger`).
//      Postgres sprawdza EXECUTE do niej przy CREATE TRIGGER, a nie przy kazdym
//      odpaleniu. Brak nadan jest tam stanem normalnym.
//   2. Funkcja wolana wylacznie z ciala innej funkcji SECURITY DEFINER nalezacej
//      do tego samego wlasciciela. W trakcie takiego wywolania biezacym
//      uzytkownikiem JEST wlasciciel, wiec sprawdzenie przechodzi. To swiadomy
//      i poprawny wzorzec, wiec zglaszamy go osobno i slabiej.
//   3. Funkcja wpisana wprost na liste wyjatkow (--allow-owner-only).
//
// Reszta jest podejrzana i warta zdania w raporcie.

const { OWNER } = require('./expected');
const { withSetAside } = require('./summary');

const TRIGGER_RETURNS = new Set(['trigger', 'event_trigger', 'pg_catalog.trigger']);

function nonOwnerRoles(acl) {
  if (!acl) return [];
  const out = [];
  for (const [r, p] of acl) {
    if (r === OWNER) continue;
    if (p && p.execute === false) continue;
    out.push(r);
  }
  return out.sort();
}

function isTriggerFn(...fns) {
  for (const f of fns) {
    if (f && f.returns && TRIGGER_RETURNS.has(String(f.returns).toLowerCase())) return true;
  }
  return false;
}

/**
 * Kto w tym zestawie funkcji wola funkcje o podanej nazwie z ciala SQL.
 * Dopasowanie jest po nazwie plus nawias — nie rozrozniamy przeciazen, bo do
 * oceny "czy ktos ja w ogole wola" to wystarcza, a przestrzelenie w te strone
 * kosztuje najwyzej lagodniejsze zgloszenie zamiast ostrego.
 */
function buildCallers(functions) {
  const byName = new Map();
  for (const f of functions.values()) {
    if (!byName.has(f.name)) byName.set(f.name, []);
    byName.get(f.name).push(f);
  }

  const callers = new Map(); // nazwa -> [{text, securityDefiner, owner}]
  for (const caller of functions.values()) {
    if (!caller.body) continue;
    for (const name of byName.keys()) {
      if (name === caller.name) continue;
      // Wywolanie moze byc kwalifikowane schematem (public.f()) albo gole (f()).
      // Kwalifikator dopuszczamy dowolny — nie rozrozniamy schematow, bo do
      // pytania "czy ktos ja w ogole wola z SQL" to wystarcza.
      const re = new RegExp(
        '(^|[^A-Za-z0-9_.])([A-Za-z_][A-Za-z0-9_]*\\s*\\.\\s*)?' + escapeRe(name) + '\\s*\\(',
        'i'
      );
      if (!re.test(caller.body)) continue;
      if (!callers.has(name)) callers.set(name, []);
      callers.get(name).push(caller);
    }
  }
  return callers;
}

function escapeRe(s) {
  return String(s).replace(/[.*+?^${}()|[\]\\]/g, (c) => '\\' + c);
}

/**
 * Rola, ktora najpewniej powinna dostac EXECUTE. Nie zgadujemy z powietrza:
 * patrzymy na sasiadki. Najpierw na funkcje utworzone w tym samym pliku
 * migracji, potem na caly zestaw. Dokladnie tak rozpoznaje sie ten blad recznie
 * — "siostra z tej samej rodziny ma komplet, tej brakuje drugiej polowy pary".
 */
function suggestRole(fn, functions) {
  const tally = (pred) => {
    const counts = new Map();
    for (const other of functions.values()) {
      if (other.key === fn.key) continue;
      if (!pred(other)) continue;
      for (const r of nonOwnerRoles(other.acl)) {
        if (r === 'public') continue;
        counts.set(r, (counts.get(r) || 0) + 1);
      }
    }
    let best = null;
    for (const [r, n] of counts) if (!best || n > best.n) best = { role: r, n };
    return best;
  };

  if (fn.createdIn) {
    const same = tally((o) => o.createdIn === fn.createdIn);
    if (same) return { role: same.role, why: 'inna funkcja z tego samego pliku migracji' };
  }
  const any = tally(() => true);
  if (any) return { role: any.role, why: 'najczestsza rola w tym zestawie migracji' };
  return null;
}

/**
 * @param {Map} expected obraz z migracji
 * @param {Map} actual   obraz z bazy
 * @param {{allow?:string[]}} opts
 */
function checkOwnerOnly(expected, actual, opts = {}) {
  const allow = new Set((opts.allow || []).map((s) => s.toLowerCase()));
  // CO ZDJELA LISTA WYJATKOW. Bez tego zdjeta pozycja przestawala istniec
  // i pole `explained` nie mialo jej z czego policzyc — patrz withSetAside
  // w src/summary.js.
  const setAside = [];
  const callersInMigrations = buildCallers(expected);
  const callersInDb = buildCallers(actual);

  const findings = [];
  const keys = new Set([...expected.keys(), ...actual.keys()]);

  for (const key of [...keys].sort()) {
    const e = expected.get(key);
    const a = actual.get(key);
    const ref = a || e;

    const deadInMigrations = !!e && nonOwnerRoles(e.acl).length === 0;
    const deadInDb = !!a && nonOwnerRoles(a.acl).length === 0;
    if (!deadInMigrations && !deadInDb) continue;

    if (isTriggerFn(e, a)) continue;
    if (allowed(allow, ref)) {
      setAside.push({ key, text: ref.text, why: '--allow-owner-only' });
      continue;
    }

    const callers = dedupe([
      ...(callersInMigrations.get(ref.name) || []),
      ...(callersInDb.get(ref.name) || []),
    ]);
    // Wolajaca SECURITY DEFINER tego samego wlasciciela usprawiedliwia brak nadan.
    const definerCallers = callers.filter((c) => c.securityDefiner === true);

    findings.push({
      key,
      text: ref.text,
      owner: a ? a.owner : null,
      inMigrations: deadInMigrations,
      inDb: deadInDb,
      where: deadInMigrations && deadInDb ? 'w obu'
        : deadInMigrations ? 'w migracjach' : 'w bazie',
      declaredIn: e ? e.createdIn : null,
      declaredLine: e ? (e.createdLine || 1) : 1,
      touched: e ? e.touched : [],
      callers: callers.map((c) => c.text),
      excusedByDefinerCaller: definerCallers.length > 0,
      suggestion: e ? suggestRole(e, expected) : null,
    });
  }

  // Najgorszy przypadek pierwszy: martwa po obu stronach i nikt jej nie wola z SQL.
  const rank = (f) => (f.excusedByDefinerCaller ? 2 : 0) + (f.where === 'w obu' ? 0 : 1);
  findings.sort((x, y) => rank(x) - rank(y) || (x.key < y.key ? -1 : 1));
  return withSetAside(findings, setAside);
}

function allowed(allow, fn) {
  return allow.has(fn.key.toLowerCase())
    || allow.has((fn.schema + '.' + fn.name).toLowerCase())
    || allow.has(fn.name.toLowerCase());
}

function dedupe(list) {
  const seen = new Set();
  const out = [];
  for (const x of list) {
    if (seen.has(x.key)) continue;
    seen.add(x.key);
    out.push(x);
  }
  return out;
}

// ---------------------------------------------------------------------------
// Kontrola zamiaru dla tabel: RLS wlaczone, zero polityk
// ---------------------------------------------------------------------------
//
// To ten sam ksztalt bledu co przy funkcjach, tylko o pietro wyzej. Wlaczenie
// RLS bez zadnej polityki NIE jest bledem skladni ani rozjazdem — jest stanem,
// w ktorym tabela przestaje byc widoczna dla wszystkich rol podlegajacych RLS.
// Zostaja tylko role z BYPASSRLS (w Supabase: service_role) i wlasciciel, jesli
// nie ma FORCE.
//
// I TERAZ RZECZ NAJWAZNIEJSZA: te dwa przypadki wygladaja identycznie —
//
//   a) tabela CELOWO wylacznie dla service_role, np. kolejka zdarzen,
//      do ktorej siega tylko funkcja brzegowa;
//   b) ktos wlaczyl RLS i zapomnial dopisac polityke.
//
// Zadne zapytanie do bazy ich nie rozroznia, bo roznica siedzi w zamiarze,
// a nie w katalogu. Dlatego jedynym uczciwym rozwiazaniem jest lista wyjatkow:
// tabele z (a) wpisuje sie raz do konfiguracji i przestaja sie odzywac, a kazda
// nowa tabela w tym stanie zglasza sie sama. Cisza znaczy wtedy "sprawdzone
// i zamierzone", a nie "nie umiem sprawdzic".

function checkRlsWithoutPolicy(expectedTables, actualTables, expectedPolicies, actualPolicies, opts = {}) {
  const allow = new Set((opts.allow || []).map((s) => s.toLowerCase()));
  const setAside = [];                                 // jak wyzej

  const countBy = (policies) => {
    const n = new Map();
    for (const p of policies.values()) {
      const k = p.schema + '.' + p.table;
      n.set(k, (n.get(k) || 0) + 1);
    }
    return n;
  };
  const inMig = countBy(expectedPolicies);
  const inDb = countBy(actualPolicies);

  const findings = [];
  for (const key of [...new Set([...expectedTables.keys(), ...actualTables.keys()])].sort()) {
    const e = expectedTables.get(key);
    const a = actualTables.get(key);

    const bareInMigrations = !!e && e.rls === true && !(inMig.get(key) > 0);
    const bareInDb = !!a && a.rls === true && !(inDb.get(key) > 0);
    if (!bareInMigrations && !bareInDb) continue;

    const short = key.includes('.') ? key.slice(key.indexOf('.') + 1) : key;
    if (allow.has(key.toLowerCase()) || allow.has(short.toLowerCase())) {
      setAside.push({ key, text: key, why: '--allow-no-policy' });
      continue;
    }

    findings.push({
      key,
      text: key,
      inMigrations: bareInMigrations,
      inDb: bareInDb,
      where: bareInMigrations && bareInDb ? 'w obu'
        : bareInMigrations ? 'w migracjach' : 'w bazie',
      force: a ? a.force : (e ? e.force : false),
      owner: a ? a.owner : null,
      declaredIn: e ? e.createdIn : null,
      declaredLine: e ? (e.createdLine || 1) : 1,
    });
  }
  return withSetAside(findings, setAside);
}

module.exports = {
  checkOwnerOnly, checkRlsWithoutPolicy, nonOwnerRoles, buildCallers, suggestRole,
};
