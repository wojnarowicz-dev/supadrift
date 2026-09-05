'use strict';

// ---------------------------------------------------------------------------
// Wyjscie SARIF 2.1.0
// ---------------------------------------------------------------------------
//
// PO CO. Raport w terminalu trzeba pamietac uruchomic. Adnotacja przy linii
// w pull requeście odzywa sie sama. To cala roznica.
//
// PODZBIOR, NIE CALY STANDARD. SARIF ma duzo wiecej pol, niz GitHub code
// scanning czyta. Emitujemy to, co GitHub faktycznie wykorzystuje — reszta
// tylko powiekszalaby plik i dawala zludzenie, ze cos znaczy.
//
// SCIEZKI. `artifactLocation.uri` MUSI byc wzgledny wobec korzenia repozytorium
// i pisany ukosnikami w przod, inaczej GitHub nie dopasuje go do pliku i alert
// powstanie bez kotwicy. Stad --sarif-base.
//
// KOTWICA DLA OBIEKTOW, KTORYCH NIE MA W MIGRACJACH. Zgloszenie "jest w bazie,
// nie ma w migracji" z definicji nie ma pliku zrodlowego. GitHub nie pokaze
// alertu bez lokalizacji, wiec kotwiczymy takie zgloszenia na NAJNOWSZEJ
// migracji, w pierwszym wierszu, i mowimy o tym wprost w tresci komunikatu.
// Kotwica jest wskazaniem miejsca w zestawie migracji, a nie twierdzeniem,
// ze blad siedzi w tamtym pliku.

const path = require('path');
const crypto = require('crypto');
const { RULES, rule } = require('./rules');
const { total } = require('./compare');

const SCHEMA = 'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json';

// Wszystko jest `note`. Uzasadnienie w README, sekcja "W CI".
const POZIOM = 'note';

function ile(n, jeden, kilka, wiele) {
  if (n === 1) return n + ' ' + jeden;
  const t = n % 10;
  const h = n % 100;
  return n + ' ' + (t >= 2 && t <= 4 && !(h >= 12 && h <= 14) ? kilka : wiele);
}

/** Ostatnie miejsce w migracjach, ktore ruszalo ten obiekt. */
function zTouched(touched) {
  if (!touched || !touched.length) return null;
  const t = touched[touched.length - 1];
  return t.file ? { file: t.file, line: t.line || 1 } : null;
}

/**
 * Zbiera wszystkie zgloszenia do jednej plaskiej listy.
 * `file` moze byc null — wtedy kotwica trafia na najnowsza migracje.
 */
function zebrane(ctx) {
  const w = [];
  const liczby = {
    funkcji: ctx.expectedInfo.functions.size,
    tabel: ctx.expectedInfo.tables.size,
    polityk: ctx.expectedInfo.policies.size,
    wyzwalaczy: ctx.expectedInfo.triggers.size,
  };
  const pop = (n, jeden, kilka, wiele) => '  (sprawdzono ' + ile(n, jeden, kilka, wiele) + ')';

  const dodaj = (ruleId, key, msg, loc) => {
    w.push({ ruleId, key, message: msg, file: loc ? loc.file : null, line: loc ? loc.line : 1 });
  };

  // --- funkcje ---------------------------------------------------------------
  for (const d of ctx.result.different) {
    const loc = zTouched(d.touched) || (d.declaredIn ? { file: d.declaredIn, line: d.declaredLine || 1 } : null);
    for (const r of d.roles) {
      const co = r.kind === 'brak-w-bazie'
        ? 'migracje nadaja EXECUTE roli ' + r.role + ', w bazie tego nadania nie ma'
        : r.kind === 'brak-w-migracji'
          ? 'baza ma EXECUTE dla roli ' + r.role + ', w migracjach tego nadania nie ma'
          : 'rola ' + r.role + ' rozni sie opcja WITH GRANT OPTION';
      dodaj('supadrift/function-grant-drift', d.key + '|' + r.role,
        d.text + ' — ' + co + '.' + pop(liczby.funkcji, 'funkcje', 'funkcje', 'funkcji'), loc);
    }
    for (const a of d.attrs || []) {
      dodaj('supadrift/function-attribute-drift', d.key + '|' + a.what,
        d.text + ' — ' + a.what + ': migracje "' + a.inMigrations + '", baza "' + a.inDb + '".', loc);
    }
  }
  for (const d of ctx.result.onlyInMigrations) {
    dodaj('supadrift/function-missing-in-db', d.key,
      d.text + ' — jest w migracjach, nie ma jej w bazie.',
      d.declaredIn ? { file: d.declaredIn, line: d.declaredLine || 1 } : null);
  }
  for (const d of ctx.result.onlyInDb) {
    dodaj('supadrift/function-missing-in-migrations', d.key,
      d.text + ' — jest w bazie (wlasciciel ' + d.owner + '), nie ma jej w zadnej migracji.', null);
  }
  for (const f of ctx.intent || []) {
    const loc = zTouched(f.touched) || (f.declaredIn ? { file: f.declaredIn, line: f.declaredLine || 1 } : null);
    const podp = f.suggestion && !f.excusedByDefinerCaller
      ? ' Brakujaca polowa pary najpewniej: grant execute on function ' + f.text
        + ' to ' + f.suggestion.role + ';'
      : '';
    dodaj('supadrift/function-unreachable', f.key,
      f.text + ' — po revoke nie zostalo zadne nadanie EXECUTE (martwa: ' + f.where + ').'
      + podp, loc);
  }
  for (const f of ctx.secdef || []) {
    dodaj('supadrift/security-definer-search-path', f.key,
      f.text + ' — ' + f.kind + ' (' + f.where + '). Poprawka: alter function '
      + f.text + ' set search_path = ' + f.suggestion.values.join(', ') + ';',
      f.declaredIn ? { file: f.declaredIn, line: f.declaredLine || 1 } : null);
  }

  // --- tabele ----------------------------------------------------------------
  if (ctx.tableResult) {
    for (const d of ctx.tableResult.different) {
      const loc = zTouched(d.touched) || (d.declaredIn ? { file: d.declaredIn, line: d.declaredLine || 1 } : null);
      for (const f of d.flags) {
        const nazwa = f.flag === 'rls' ? 'ROW LEVEL SECURITY' : 'FORCE ROW LEVEL SECURITY';
        dodaj('supadrift/table-rls-drift', d.key + '|' + f.flag,
          d.text + ' — ' + nazwa + ': migracje ' + (f.inMigrations ? 'wlaczone' : 'wylaczone')
          + ', baza ' + (f.inDb ? 'wlaczone' : 'wylaczone') + '.'
          + pop(liczby.tabel, 'tabele', 'tabele', 'tabel'), loc);
      }
    }
    for (const d of ctx.tableResult.onlyInMigrations) {
      dodaj('supadrift/table-missing-in-db', d.key,
        d.text + ' — jest w migracjach, nie ma jej w bazie.',
        d.declaredIn ? { file: d.declaredIn, line: d.declaredLine || 1 } : null);
    }
    for (const d of ctx.tableResult.onlyInDb) {
      dodaj('supadrift/table-missing-in-migrations', d.key,
        d.text + ' — jest w bazie (RLS ' + (d.rls ? 'wlaczone' : 'WYLACZONE')
        + '), nie ma jej w zadnej migracji.', null);
    }
  }
  for (const d of ctx.tableGrants || []) {
    const loc = d.declaredIn ? { file: d.declaredIn, line: d.declaredLine || 1 } : null;
    for (const r of d.roles) {
      dodaj('supadrift/table-grant-drift', d.key + '|' + r.role,
        d.text + ' — rola ' + r.role + ': migracje [' + r.inMigrations + '], baza ['
        + r.inDb + '].', loc);
    }
    for (const c of d.columns) {
      dodaj('supadrift/table-grant-drift', d.key + '|' + c.column + '|' + c.role,
        d.text + ', kolumna ' + c.column + ', rola ' + c.role
        + ': migracje [' + c.inMigrations + '], baza [' + c.inDb + '].', loc);
    }
  }
  for (const f of ctx.rlsIntent || []) {
    dodaj('supadrift/rls-without-policy', f.key,
      f.text + ' — RLS wlaczone przy zerze polityk (' + f.where + '); FORCE '
      + (f.force ? 'wlaczone' : 'wylaczone') + '. Jesli tak ma byc, dopisz tabele '
      + 'do allowNoPolicy w supadrift.json.',
      f.declaredIn ? { file: f.declaredIn, line: f.declaredLine || 1 } : null);
  }

  // --- polityki --------------------------------------------------------------
  if (ctx.policyResult) {
    for (const d of ctx.policyResult.different) {
      const loc = d.def && d.def.createdIn ? { file: d.def.createdIn, line: d.def.line || 1 } : null;
      for (const f of d.diffs) {
        dodaj('supadrift/policy-drift', d.key + '|' + f.what,
          d.text + ' — ' + f.what + ': migracje "' + f.inMigrations + '", baza "' + f.inDb + '".'
          + (f.soft ? ' Postgres przepisuje wyrazenia po swojemu, wiec ta roznica moze byc '
            + 'tylko innym zapisem tego samego.' : '')
          + pop(liczby.polityk, 'polityke', 'polityki', 'polityk'), loc);
      }
    }
    for (const d of ctx.policyResult.onlyInMigrations) {
      dodaj('supadrift/policy-missing-in-db', d.key,
        d.text + ' — ' + d.cmd + ' dla ' + d.roles.join(', ') + '; jest w migracjach, nie ma w bazie.',
        d.def && d.def.createdIn ? { file: d.def.createdIn, line: d.def.line || 1 } : null);
    }
    for (const d of ctx.policyResult.onlyInDb) {
      dodaj('supadrift/policy-missing-in-migrations', d.key,
        d.text + ' — ' + d.cmd + ' dla ' + d.roles.join(', ') + '; jest w bazie, nie ma w migracjach.',
        null);
    }
  }

  // --- wyzwalacze ------------------------------------------------------------
  for (const res of [ctx.triggerResult, ctx.eventTriggerResult]) {
    if (!res) continue;
    for (const d of res.different) {
      const loc = d.def && d.def.createdIn ? { file: d.def.createdIn, line: d.def.line || 1 } : null;
      for (const f of d.diffs) {
        dodaj('supadrift/trigger-drift', d.key + '|' + f.what,
          d.text + ' — ' + f.what + ': migracje "' + f.inMigrations + '", baza "' + f.inDb + '".'
          + pop(liczby.wyzwalaczy, 'wyzwalacz', 'wyzwalacze', 'wyzwalaczy'), loc);
      }
    }
    for (const d of res.onlyInMigrations) {
      dodaj('supadrift/trigger-missing-in-db', d.key,
        d.text + ' — jest w migracjach, nie ma go w bazie; funkcja istnieje, ale nic jej nie wola.',
        d.def && d.def.createdIn ? { file: d.def.createdIn, line: d.def.line || 1 } : null);
    }
    for (const d of res.onlyInDb) {
      dodaj('supadrift/trigger-missing-in-migrations', d.key,
        d.text + ' [' + d.kind + '] — jest w bazie, nie ma go w zadnej migracji; '
        + 'swieze srodowisko go nie dostanie.', null);
    }
  }

  return w;
}

function odcisk(ruleId, key) {
  // Rozdzielamy znakiem, ktory nie moze wystapic ani w id reguly, ani w kluczu
  // obiektu — inaczej dwa rozne zgloszenia moglyby dac ten sam odcisk.
  return crypto.createHash('sha256')
    .update(ruleId + String.fromCharCode(31) + key)
    .digest('hex')
    .slice(0, 16);
}

/**
 * @param {object} ctx kontekst raportu
 * @param {{baseDir:string, migrationsDir:string, version:string}} opts
 * @returns {{doc:object, ostrzezenia:string[], zgloszen:number}}
 */
function buildSarif(ctx, opts) {
  const znalezione = zebrane(ctx);
  const ostrzezenia = [];

  // Kotwica zastepcza: najnowsza migracja, wiersz 1.
  const pliki = ctx.expectedInfo.files || [];
  const zastepcza = pliki.length ? pliki[pliki.length - 1] : null;

  const uzyte = [];
  const indeks = new Map();
  for (const z of znalezione) {
    if (!indeks.has(z.ruleId)) {
      indeks.set(z.ruleId, uzyte.length);
      uzyte.push(rule(z.ruleId));
    }
  }

  const wzgledny = (plik) => {
    const abs = path.resolve(opts.migrationsDir, plik);
    const rel = path.relative(opts.baseDir, abs).split(path.sep).join('/');
    if (rel.startsWith('..')) {
      ostrzezenia.push('sciezka poza katalogiem bazowym, GitHub jej nie dopasuje: ' + rel);
    }
    return rel;
  };

  const results = znalezione.map((z) => {
    const bezPliku = !z.file;
    const plik = z.file || zastepcza;
    const tekst = bezPliku
      ? z.message + ' Ten obiekt nie ma pliku zrodlowego w migracjach — kotwica '
        + 'wskazuje najnowsza migracje w zestawie, a nie miejsce bledu.'
      : z.message;

    const wynik = {
      ruleId: z.ruleId,
      ruleIndex: indeks.get(z.ruleId),
      level: POZIOM,
      message: { text: tekst },
      partialFingerprints: { supadriftKey: odcisk(z.ruleId, z.key) },
    };
    if (plik) {
      wynik.locations = [{
        physicalLocation: {
          artifactLocation: { uri: wzgledny(plik) },
          region: { startLine: Math.max(1, z.line || 1) },
        },
      }];
    }
    return wynik;
  });

  const doc = {
    $schema: SCHEMA,
    version: '2.1.0',
    runs: [{
      tool: {
        driver: {
          name: 'supadrift',
          version: opts.version,
          informationUri: 'https://github.com/',
          rules: uzyte.map((r) => ({
            id: r.id,
            name: r.name,
            shortDescription: { text: r.short },
            fullDescription: { text: r.full },
            defaultConfiguration: { level: POZIOM },
          })),
        },
      },
      automationDetails: { id: 'supadrift/' + (ctx.options.schemas || ['public']).join('+') },
      results,
    }],
  };

  return { doc, ostrzezenia, zgloszen: results.length };
}

module.exports = { buildSarif, zebrane, RULES, total };
