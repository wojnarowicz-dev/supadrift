'use strict';

// ---------------------------------------------------------------------------
// Porownanie w trzech kategoriach
// ---------------------------------------------------------------------------
//
//   1. jest w migracji, nie ma w bazie   — migracja nie zostala wdrozona
//   2. jest w bazie, nie ma w migracji   — ktos zmienil baze recznie
//   3. jest w obu, ale inaczej           — tu siedza prawdziwe bledy
//
// Trzecia kategoria jest najwazniejsza i najmniej widoczna. Pierwsza i druga
// rzucaja sie w oczy przy najblizszym odtworzeniu srodowiska. Trzecia potrafi
// zyc miesiacami: kod dziala, testy przechodza, a jedna rola ma o jedno
// uprawnienie za malo albo za duzo.
//
// WLASCICIEL. Wpisu wlasciciela nie porownujemy. Postgres wpisuje go do ACL
// z automatu przy tworzeniu funkcji, a zadna migracja go nie nadaje jawnie —
// porownywanie tego dawaloby rozjazd przy kazdej funkcji i utopilo sygnal.
// Wyjatek: jesli migracja jawnie nadaje uprawnienie roli, ktora jest
// wlascicielem, to porownujemy, bo wtedy jest co porownywac.

const { OWNER } = require('./expected');

function compare(expected, actual, opts = {}) {
  const ignoreRoles = new Set(opts.ignoreRoles || []);

  const onlyInMigrations = [];
  const onlyInDb = [];
  const different = [];

  const keys = new Set([...expected.keys(), ...actual.keys()]);

  for (const key of [...keys].sort()) {
    const e = expected.get(key);
    const a = actual.get(key);

    if (e && !a) {
      onlyInMigrations.push({
        key, text: e.text,
        declaredIn: e.createdIn,
        declaredLine: e.createdLine || 1,
        declared: e.declared,
        roles: rolesOf(e.acl, ignoreRoles),
      });
      continue;
    }
    if (!e && a) {
      onlyInDb.push({
        key, text: a.text,
        owner: a.owner,
        securityDefiner: a.securityDefiner,
        roles: rolesOf(a.acl, ignoreRoles),
      });
      continue;
    }

    const roleDiffs = diffAcl(e, a, ignoreRoles);
    const attrDiffs = diffAttrs(e, a);
    if (roleDiffs.length || attrDiffs.length) {
      different.push({
        key, text: a.text,
        owner: a.owner,
        declaredIn: e.createdIn,
        declaredLine: e.createdLine || 1,
        touched: e.touched,
        roles: roleDiffs,
        attrs: attrDiffs,
      });
    }
  }

  return { onlyInMigrations, onlyInDb, different };
}

function rolesOf(acl, ignoreRoles) {
  return [...acl.keys()]
    .filter((r) => r !== OWNER && !ignoreRoles.has(r))
    .sort();
}

function diffAcl(e, a, ignoreRoles) {
  // Wlasciciela pomijamy, chyba ze migracja nadaje mu uprawnienie z nazwy.
  const ownerNamedInMigration = e.acl.has(a.owner);

  const expRoles = new Map();
  for (const [r, p] of e.acl) {
    if (r === OWNER) continue;
    if (ignoreRoles.has(r)) continue;
    if (r === a.owner && !ownerNamedInMigration) continue;
    expRoles.set(r, p);
  }

  const actRoles = new Map();
  for (const [r, p] of a.acl) {
    if (r === OWNER) {
      if (ownerNamedInMigration) actRoles.set(a.owner, p);
      continue;
    }
    if (ignoreRoles.has(r)) continue;
    if (!p.execute) continue; // wpis bez EXECUTE nas nie dotyczy
    actRoles.set(r, p);
  }

  const out = [];
  for (const r of new Set([...expRoles.keys(), ...actRoles.keys()])) {
    const inMig = expRoles.has(r) && expRoles.get(r).execute;
    const inDb = actRoles.has(r);
    if (inMig && !inDb) {
      out.push({ role: r, kind: 'brak-w-bazie' });
    } else if (!inMig && inDb) {
      out.push({ role: r, kind: 'brak-w-migracji' });
    } else if (inMig && inDb) {
      const go1 = !!expRoles.get(r).grantOption;
      const go2 = !!actRoles.get(r).grantOption;
      if (go1 !== go2) {
        out.push({ role: r, kind: 'inna-opcja-nadawania', inMigrations: go1, inDb: go2 });
      }
    }
  }
  out.sort((x, y) => (x.role < y.role ? -1 : x.role > y.role ? 1 : 0));
  return out;
}

/**
 * Wlasnosci funkcji poza lista uprawnien. Porownujemy je TYLKO wtedy, gdy
 * w migracjach faktycznie widzielismy CREATE — jesli katalog zawiera sam grant
 * do funkcji utworzonej gdzie indziej, to nie wiemy, co migracja o niej mowi,
 * i udawanie, ze wiemy, dawaloby falszywe zgloszenia.
 */
function diffAttrs(e, a) {
  const out = [];
  if (!e.declared) return out;

  if (e.securityDefiner !== undefined && e.securityDefiner !== a.securityDefiner) {
    out.push({
      what: 'SECURITY DEFINER',
      inMigrations: e.securityDefiner ? 'definer' : 'invoker',
      inDb: a.securityDefiner ? 'definer' : 'invoker',
    });
  }

  const ep = e.searchPath ? e.searchPath.join(', ') : null;
  const ap = a.searchPath ? a.searchPath.join(', ') : null;
  if (ep !== ap) {
    out.push({
      what: 'search_path',
      inMigrations: ep === null ? '(nie ustawiony)' : ep,
      inDb: ap === null ? '(nie ustawiony)' : ap,
    });
  }
  return out;
}

function total(result) {
  return result.onlyInMigrations.length + result.onlyInDb.length + result.different.length;
}

// --- tabele: RLS i FORCE ----------------------------------------------------
//
// Te same trzy kategorie, ale porownujemy dwa znaczniki zamiast listy rol.
// Roznica w RLS jest powazniejsza niz w FORCE i tak ja opisujemy: wylaczone RLS
// znaczy "kazdy, kto ma SELECT, widzi wszystkie wiersze", a brak FORCE znaczy
// "polityki nie dotycza wlasciciela tabeli".

function compareTables(expected, actual) {
  const onlyInMigrations = [];
  const onlyInDb = [];
  const different = [];

  for (const key of [...new Set([...expected.keys(), ...actual.keys()])].sort()) {
    const e = expected.get(key);
    const a = actual.get(key);

    if (e && !a) {
      onlyInMigrations.push({
        key, text: key, declaredIn: e.createdIn, declaredLine: e.createdLine || 1,
        declared: e.declared, rls: e.rls, force: e.force,
      });
      continue;
    }
    if (!e && a) {
      onlyInDb.push({ key, text: key, owner: a.owner, rls: a.rls, force: a.force, partitioned: a.partitioned });
      continue;
    }

    const flags = [];
    if (e.rls !== a.rls) flags.push({ flag: 'rls', inMigrations: e.rls, inDb: a.rls });
    if (e.force !== a.force) flags.push({ flag: 'force', inMigrations: e.force, inDb: a.force });
    if (flags.length) {
      different.push({
        key, text: key, owner: a.owner, declaredIn: e.createdIn,
        declaredLine: e.createdLine || 1, touched: e.touched, flags,
      });
    }
  }

  return { onlyInMigrations, onlyInDb, different };
}

// --- polityki ---------------------------------------------------------------
//
// Twardo porownujemy to, czego Postgres nie przepisuje: polecenie, rodzaj
// (permissive/restrictive), liste rol oraz sama OBECNOSC albo brak USING
// i WITH CHECK. Tresc wyrazenia porownujemy po normalizacji i oznaczamy
// osobno — patrz src/expr.js po powod.

function comparePolicies(expected, actual, opts = {}) {
  const compareExpr = opts.compareExpr !== false;

  const onlyInMigrations = [];
  const onlyInDb = [];
  const different = [];

  for (const key of [...new Set([...expected.keys(), ...actual.keys()])].sort()) {
    const e = expected.get(key);
    const a = actual.get(key);

    if (e && !a) {
      onlyInMigrations.push({
        key, text: describePolicy(e), table: e.schema + '.' + e.table,
        declaredIn: e.createdIn, cmd: e.cmd, roles: e.roles, def: e,
      });
      continue;
    }
    if (!e && a) {
      onlyInDb.push({
        key, text: describePolicy(a), table: a.schema + '.' + a.table,
        cmd: a.cmd, roles: a.roles, permissive: a.permissive,
      });
      continue;
    }

    const diffs = [];
    if (e.cmd !== a.cmd) diffs.push({ what: 'polecenie', inMigrations: e.cmd, inDb: a.cmd, soft: false });
    if (e.permissive !== a.permissive) {
      diffs.push({
        what: 'rodzaj',
        inMigrations: e.permissive ? 'permissive' : 'restrictive',
        inDb: a.permissive ? 'permissive' : 'restrictive',
        soft: false,
      });
    }
    const er = [...e.roles].sort().join(', ');
    const ar = [...a.roles].sort().join(', ');
    if (er !== ar) diffs.push({ what: 'role', inMigrations: er, inDb: ar, soft: false });

    for (const [clause, ek, ak] of [['USING', 'using', 'using'], ['WITH CHECK', 'check', 'check']]) {
      const eHas = e[ek] !== null;
      const aHas = a[ak] !== null;
      if (eHas !== aHas) {
        diffs.push({
          what: clause, inMigrations: eHas ? 'jest' : 'brak', inDb: aHas ? 'jest' : 'brak', soft: false,
        });
      } else if (eHas && aHas && compareExpr && e[ek] !== a[ak]) {
        diffs.push({
          what: clause + ' — tresc',
          inMigrations: e[ek + 'Raw'] || e[ek],
          inDb: a[ak + 'Raw'] || a[ak],
          soft: true,
        });
      }
    }

    if (diffs.length) {
      different.push({
        key, text: describePolicy(a), table: a.schema + '.' + a.table,
        declaredIn: e.createdIn, diffs, def: e,
      });
    }
  }

  return { onlyInMigrations, onlyInDb, different };
}

function describePolicy(p) {
  return p.schema + '.' + p.table + ' :: "' + p.name + '"';
}

// --- wyzwalacze -------------------------------------------------------------
//
// Funkcja wyzwalacza to nie to samo co wyzwalacz. Funkcja moze byc po obu
// stronach, z identycznymi uprawnieniami, a PODPIECIE istniec tylko w jednym
// srodowisku — i wtedy nie odpala sie u nikogo innego. Dlatego to jest osobna
// kontrola, a nie szczegol tamtej.
//
// `allow` przenosi pozycje z listy rozjazdow do osobnej listy "poza migracjami,
// swiadomie". NIE ucisza jej: wyzwalacz zdarzeniowy zakladany recznie, bo
// wymaga superusera, ma byc widoczny w kazdym raporcie — inaczej za pol roku
// nikt nie bedzie pamietal, ze swieze srodowisko go nie dostaje.

const TRIGGER_FIELDS = [
  ['fn', 'funkcja'],
  ['timing', 'moment'],
  ['level', 'poziom'],
];

function compareTriggers(expected, actual, opts = {}) {
  const allow = new Set((opts.allow || []).map((s) => s.toLowerCase()));
  const compareExpr = opts.compareExpr !== false;

  const onlyInMigrations = [];
  const onlyInDb = [];
  const different = [];
  const manual = [];

  const allowed = (t) => allow.has(t.key.toLowerCase()) || allow.has(t.name.toLowerCase());

  for (const key of [...new Set([...expected.keys(), ...actual.keys()])].sort()) {
    const e = expected.get(key);
    const a = actual.get(key);

    if (e && !a) {
      onlyInMigrations.push({ key, text: describeTrigger(e), declaredIn: e.createdIn, def: e });
      continue;
    }
    if (!e && a) {
      const row = { key, text: describeTrigger(a), def: a, kind: 'tabelowy' };
      if (allowed(a)) manual.push(row); else onlyInDb.push(row);
      continue;
    }

    const diffs = [];
    for (const [f, label] of TRIGGER_FIELDS) {
      if (e[f] !== a[f]) diffs.push({ what: label, inMigrations: e[f], inDb: a[f], soft: false });
    }
    const ev = (x) => [...x.events].sort().join(', ');
    if (ev(e) !== ev(a)) diffs.push({ what: 'zdarzenia', inMigrations: ev(e), inDb: ev(a), soft: false });
    const uc = (x) => [...x.updateColumns].sort().join(', ') || '(wszystkie)';
    if (uc(e) !== uc(a)) diffs.push({ what: 'UPDATE OF', inMigrations: uc(e), inDb: uc(a), soft: false });
    if (e.enabled !== a.enabled) {
      diffs.push({
        what: 'stan', inMigrations: enabledText(e.enabled), inDb: enabledText(a.enabled), soft: false,
      });
    }
    if ((e.when !== null) !== (a.when !== null)) {
      diffs.push({
        what: 'WHEN', inMigrations: e.when === null ? 'brak' : 'jest',
        inDb: a.when === null ? 'brak' : 'jest', soft: false,
      });
    } else if (e.when !== null && compareExpr && e.when !== a.when) {
      diffs.push({
        what: 'WHEN — tresc', inMigrations: e.whenRaw || e.when, inDb: a.whenRaw || a.when, soft: true,
      });
    }

    if (diffs.length) {
      different.push({ key, text: describeTrigger(a), declaredIn: e.createdIn, diffs, def: e });
    }
  }

  return { onlyInMigrations, onlyInDb, different, manual };
}

function compareEventTriggers(expected, actual, opts = {}) {
  const allow = new Set((opts.allow || []).map((s) => s.toLowerCase()));
  const onlyInMigrations = [];
  const onlyInDb = [];
  const different = [];
  const manual = [];

  for (const key of [...new Set([...expected.keys(), ...actual.keys()])].sort()) {
    const e = expected.get(key);
    const a = actual.get(key);

    if (e && !a) {
      onlyInMigrations.push({ key, text: describeEventTrigger(e), declaredIn: e.createdIn, def: e });
      continue;
    }
    if (!e && a) {
      const row = { key, text: describeEventTrigger(a), def: a, kind: 'zdarzeniowy' };
      if (allow.has(a.name.toLowerCase())) manual.push(row); else onlyInDb.push(row);
      continue;
    }

    const diffs = [];
    if (e.fn !== a.fn) diffs.push({ what: 'funkcja', inMigrations: e.fn, inDb: a.fn, soft: false });
    if (e.event !== a.event) diffs.push({ what: 'zdarzenie', inMigrations: e.event, inDb: a.event, soft: false });
    const tg = (x) => x.tags.join(', ') || '(wszystkie)';
    if (tg(e) !== tg(a)) diffs.push({ what: 'TAG', inMigrations: tg(e), inDb: tg(a), soft: false });
    if (e.enabled !== a.enabled) {
      diffs.push({
        what: 'stan', inMigrations: enabledText(e.enabled), inDb: enabledText(a.enabled), soft: false,
      });
    }
    if (diffs.length) {
      different.push({ key, text: describeEventTrigger(a), declaredIn: e.createdIn, diffs, def: e });
    }
  }

  return { onlyInMigrations, onlyInDb, different, manual };
}

function enabledText(code) {
  return { O: 'wlaczony', D: 'WYLACZONY', R: 'tylko replika', A: 'zawsze' }[code] || String(code);
}

function describeTrigger(t) {
  return t.schema + '.' + t.table + ' :: ' + t.name;
}

function describeEventTrigger(t) {
  return 'event trigger ' + t.name;
}

module.exports = {
  compare, compareTables, comparePolicies, compareTriggers, compareEventTriggers,
  enabledText, total,
};
