'use strict';

// ---------------------------------------------------------------------------
// Raport i gotowa migracja naprawcza
// ---------------------------------------------------------------------------
//
// supadrift NIE STOSUJE naprawy. Wypisuje ja do wklejenia. Roznica jest
// zasadnicza: narzedzie, ktore samo poprawia uprawnienia w bazie, musi miec
// prawo je zmieniac — a wtedy przestaje byc narzedziem tylko do odczytu
// i staje sie kolejna rzecza, ktora moze zepsuc produkcje o trzeciej w nocy.
//
// W raporcie ani w migracji naprawczej nie ma zadnego poswiadczenia. Adres
// bazy pokazujemy jako sam host i nazwe bazy, bez uzytkownika i bez hasla.

const ROLE_OK = /^[a-z_][a-z0-9_$]*$/;

function q(role) {
  return ROLE_OK.test(role) ? role : '"' + role.replace(/"/g, '""') + '"';
}

const { enabledText, total } = require('./compare');

const RULE = '-'.repeat(74);

function renderReport(ctx) {
  const { result, expectedInfo, actualInfo, target, options } = ctx;
  const L = [];

  L.push('supadrift — rozjazd migracji i bazy');
  L.push(RULE);
  L.push('migracje : ' + options.migrationsDir);
  L.push('           ' + expectedInfo.files.length + ' plikow, '
    + expectedInfo.functions.size + ' funkcji, ' + expectedInfo.stats.grants + ' grant / '
    + expectedInfo.stats.revokes + ' revoke'
    + (options.asOf ? '   [stan na ' + options.asOf + ']' : ''));
  L.push('baza     : ' + target);
  L.push('           ' + actualInfo.functions.size + ' funkcji w schemacie '
    + options.schemas.join(', '));
  const tbl = ctx.tableResult;
  if (tbl) {
    L.push('           ' + ctx.expectedInfo.tables.size + ' tabel w migracjach, '
      + ctx.actualInfo.tables.size + ' w bazie');
  }
  if (ctx.policyResult) {
    L.push('           ' + ctx.expectedInfo.policies.size + ' polityk w migracjach, '
      + ctx.actualInfo.policies.size + ' w bazie');
  }
  // Ta linia jest jedynym miejscem, z ktorego czytelnik wie, CO zostalo
  // sprawdzone. Jesli kontrola sie wykonala, ma tu byc wymieniona — inaczej
  // "czysto" znaczy mniej, niz sie wydaje.
  const zakres = ['funkcje — EXECUTE (grant / revoke)'];
  if (ctx.intent) zakres.push('kontrola zamiaru');
  if (ctx.secdef) zakres.push('SECURITY DEFINER — search_path');
  if (tbl) zakres.push('tabele — RLS i FORCE');
  if (ctx.tableGrants) zakres.push('nadania na tabelach i kolumnach');
  if (ctx.policyResult) zakres.push('polityki');
  if (ctx.rlsIntent) zakres.push('RLS bez polityk');
  if (ctx.triggerResult) zakres.push('wyzwalacze tabelowe i zdarzeniowe');
  L.push('zakres   : ' + zakres.length + ' kontrol');
  for (const z of zakres) L.push('           - ' + z);
  L.push('');

  const n = result.onlyInMigrations.length + result.onlyInDb.length + result.different.length;
  const intent = ctx.intent || [];
  const nt = tbl ? tbl.onlyInMigrations.length + tbl.onlyInDb.length + tbl.different.length : 0;
  const pl = ctx.policyResult;
  const np = pl ? pl.onlyInMigrations.length + pl.onlyInDb.length + pl.different.length : 0;
  const bareCount = (ctx.rlsIntent || []).length;
  const sdCount = (ctx.secdef || []).length;
  const tgCount = (ctx.tableGrants || []).length;
  const trCount = (ctx.triggerResult ? total(ctx.triggerResult) : 0)
    + (ctx.eventTriggerResult ? total(ctx.eventTriggerResult) : 0);
  const manCount = (ctx.triggerResult ? ctx.triggerResult.manual.length : 0)
    + (ctx.eventTriggerResult ? ctx.eventTriggerResult.manual.length : 0);

  if (n === 0 && intent.length === 0 && nt === 0 && np === 0 && bareCount === 0 && sdCount === 0 && tgCount === 0 && trCount === 0) {
    L.push('CZYSTO.');
    L.push('');
    L.push('Kazda funkcja z migracji istnieje w bazie i ma kogo, kto moze ja');
    L.push('wywolac; nadania EXECUTE zgadzaja sie co do roli.');
    if (tbl) L.push('RLS i FORCE na tabelach sa takie same po obu stronach.');
    if (pl) L.push('Polityki zgadzaja sie co do polecenia, rol i tresci wyrazen.');
    if (ctx.secdef) L.push('Kazda funkcja SECURITY DEFINER ma search_path z pg_temp na koncu.');
    if (ctx.tableGrants) L.push('Nadania na tabelach i kolumnach zgadzaja sie co do uprawnienia.');
    if (ctx.triggerResult) {
      L.push('Wyzwalacze sa po obu stronach te same'
        + (manCount ? ' (poza uzgodnionymi krokami recznymi, nizej).' : '.'));
    }
  } else {
    L.push('rozjazd funkcji            : ' + n);
    if (ctx.intent) L.push('nie ma kto wolac           : ' + intent.length);
    if (ctx.secdef) L.push('search_path bez pg_temp    : ' + sdCount);
    if (tbl) L.push('rozjazd tabel RLS/FORCE    : ' + nt);
    if (ctx.tableGrants) L.push('rozjazd nadan na tabelach  : ' + tgCount);
    if (pl) L.push('rozjazd polityk            : ' + np);
    if (ctx.rlsIntent) L.push('RLS bez zadnej polityki    : ' + bareCount);
    if (ctx.triggerResult) L.push('rozjazd wyzwalaczy         : ' + trCount);
  }
  L.push('');

  section(L, 'JEST W OBU, ALE INACZEJ', result.different.length, () => {
    for (const d of result.different) {
      L.push('  ' + d.text);
      for (const r of d.roles) {
        if (r.kind === 'brak-w-bazie') {
          L.push('      ' + pad(q(r.role)) + ' migracja nadaje EXECUTE, w bazie tego nadania NIE MA');
        } else if (r.kind === 'brak-w-migracji') {
          L.push('      ' + pad(q(r.role)) + ' baza ma EXECUTE, w migracjach tego nadania NIE MA');
        } else {
          L.push('      ' + pad(q(r.role)) + ' WITH GRANT OPTION: migracja ' + yn(r.inMigrations)
            + ', baza ' + yn(r.inDb));
        }
      }
      for (const at of d.attrs || []) {
        L.push('      ' + at.what);
        L.push('          migracje: ' + at.inMigrations);
        L.push('          baza    : ' + at.inDb);
      }
      const last = lastTouch(d.touched);
      if (last) L.push('      ostatnia zmiana uprawnien w migracjach: ' + last);
      else if (d.declaredIn) L.push('      utworzona w: ' + d.declaredIn);
      L.push('');
    }
  });

  section(L, 'JEST W MIGRACJI, NIE MA W BAZIE', result.onlyInMigrations.length, () => {
    for (const d of result.onlyInMigrations) {
      L.push('  ' + d.text);
      L.push('      ' + (d.declared
        ? 'utworzona w migracji ' + d.declaredIn + ', w bazie jej nie ma'
        : 'migracje nadaja jej uprawnienia, ale nigdzie jej nie tworza'));
      if (d.roles.length) L.push('      wg migracji EXECUTE dla: ' + d.roles.join(', '));
      L.push('');
    }
  });

  section(L, 'JEST W BAZIE, NIE MA W MIGRACJI', result.onlyInDb.length, () => {
    for (const d of result.onlyInDb) {
      L.push('  ' + d.text);
      L.push('      wlasciciel: ' + d.owner
        + (d.securityDefiner ? ', SECURITY DEFINER' : '')
        + '; EXECUTE dla: ' + (d.roles.length ? d.roles.join(', ') : '(nikt poza wlascicielem)'));
      L.push('');
    }
  });

  section(L, 'NIE MA KTO WOLAC', intent.length, () => {
    L.push('Po revoke od `public` nie zostalo zadne nadanie EXECUTE. Funkcje moze');
    L.push('wywolac wylacznie jej wlasciciel, a zaden klient Supabase nim nie jest:');
    L.push('edge functions chodza jako service_role, przegladarka jako anon albo');
    L.push('authenticated. To NIE jest rozjazd — pliki i baza moga sie tu zgadzac');
    L.push('co do znaku i obie byc w bledzie.');
    L.push('');
    for (const f of intent) {
      L.push('  ' + f.text + '     martwa: ' + f.where);
      if (f.owner) L.push('      poza wlascicielem (' + f.owner + ') EXECUTE nie ma nikt');
      else L.push('      poza wlascicielem EXECUTE nie ma nikt');

      const rev = lastRevoke(f.touched);
      if (rev) L.push('      revoke bez pary: ' + rev);
      else if (f.declaredIn) L.push('      utworzona w: ' + f.declaredIn);

      if (f.excusedByDefinerCaller) {
        L.push('      wolana z SECURITY DEFINER: ' + f.callers.join(', '));
        L.push('      przy takim wywolaniu biezacym uzytkownikiem jest wlasciciel,');
        L.push('      wiec brak nadan moze byc zamierzony — sprawdz i, jesli tak,');
        L.push('      dopisz ja do --allow-owner-only');
      } else if (f.callers.length) {
        L.push('      wolana z: ' + f.callers.join(', '));
      } else {
        L.push('      zadna inna funkcja SQL jej nie wola — wolajacy jest poza baza');
        L.push('      (edge function, klient), a on nie jest wlascicielem');
      }

      if (f.suggestion && !f.excusedByDefinerCaller) {
        L.push('      brakujaca polowa pary najpewniej brzmi:');
        L.push('        grant execute on function ' + f.text + ' to ' + q(f.suggestion.role) + ';');
        L.push('      (podpowiedz z: ' + f.suggestion.why + ')');
      }
      L.push('');
    }
  });

  if (tbl) {
    section(L, 'TABELE — JEST W OBU, ALE INACZEJ', tbl.different.length, () => {
      for (const d of tbl.different) {
        L.push('  ' + d.text);
        for (const f of d.flags) {
          if (f.flag === 'rls') {
            L.push('      ROW LEVEL SECURITY   migracje: ' + onoff(f.inMigrations)
              + '   baza: ' + onoff(f.inDb));
            if (!f.inMigrations && f.inDb) {
              L.push('      Swieze srodowisko postawione z tych migracji dostanie te tabele');
              L.push('      BEZ RLS. W Supabase anon i authenticated maja SELECT na schemacie');
              L.push('      public, wiec bylaby otwarta dla kazdego.');
            } else if (f.inMigrations && !f.inDb) {
              L.push('      Migracje kaza wlaczyc RLS, a w bazie jest wylaczone —');
              L.push('      ta tabela jest teraz otwarta na produkcji.');
            }
          } else {
            L.push('      FORCE ROW LEVEL SECURITY   migracje: ' + onoff(f.inMigrations)
              + '   baza: ' + onoff(f.inDb));
            L.push('      Bez FORCE polityki nie dotycza wlasciciela tabeli (' + (d.owner || 'wlasciciela') + ').');
          }
        }
        if (d.declaredIn) L.push('      utworzona w: ' + d.declaredIn);
        L.push('');
      }
    });

    section(L, 'TABELE — JEST W MIGRACJI, NIE MA W BAZIE', tbl.onlyInMigrations.length, () => {
      for (const d of tbl.onlyInMigrations) {
        L.push('  ' + d.text);
        L.push('      ' + (d.declared ? 'utworzona w migracji ' + d.declaredIn : 'migracje ja zmieniaja, ale nigdzie nie tworza')
          + '; wg migracji RLS ' + onoff(d.rls) + ', FORCE ' + onoff(d.force));
        L.push('');
      }
    });

    section(L, 'TABELE — JEST W BAZIE, NIE MA W MIGRACJI', tbl.onlyInDb.length, () => {
      for (const d of tbl.onlyInDb) {
        L.push('  ' + d.text);
        L.push('      wlasciciel: ' + d.owner + '; RLS ' + onoff(d.rls) + ', FORCE ' + onoff(d.force));
        if (!d.rls) L.push('      RLS wylaczone i tabeli nie ma w migracjach — sprawdz ja jako pierwsza');
        L.push('');
      }
    });
  }

  const tg = ctx.tableGrants || [];
  section(L, 'TABELE — NADANIA', tg.length, () => {
    L.push('Uwaga na linie bazowa: CREATE TABLE nie nadaje niczego roli `public`,');
    L.push('ale ALTER DEFAULT PRIVILEGES w Supabase nadaje cos nowym tabelom mimo');
    L.push('to, i tego nie widac w migracjach. supadrift czyta ta linie z bazy');
    L.push('(pg_default_acl) i dopiero od niej odgrywa grant/revoke z plikow.');
    L.push('');
    for (const d of tg) {
      L.push('  ' + d.text);
      if (d.baseline.length) L.push('      linia bazowa nowej tabeli: ' + d.baseline.join('; '));
      for (const r of d.roles) {
        L.push('      rola ' + r.role);
        L.push('          migracje: ' + r.inMigrations);
        L.push('          baza    : ' + r.inDb);
      }
      for (const c of d.columns) {
        L.push('      kolumna ' + c.column + ', rola ' + c.role);
        L.push('          migracje: ' + c.inMigrations);
        L.push('          baza    : ' + c.inDb);
      }
      if (d.declaredIn) L.push('      utworzona w: ' + d.declaredIn);
      L.push('');
    }
  });

  const pol = ctx.policyResult;
  if (pol) {
    section(L, 'POLITYKI — JEST W OBU, ALE INACZEJ', pol.different.length, () => {
      for (const d of pol.different) {
        L.push('  ' + d.text);
        for (const f of d.diffs) {
          L.push('      ' + f.what);
          L.push('          migracje: ' + f.inMigrations);
          L.push('          baza    : ' + f.inDb);
          if (f.soft) {
            L.push('          (Postgres przepisuje wyrazenia po swojemu — ta roznica moze');
            L.push('           byc tylko innym zapisem tego samego. Spojrz okiem.)');
          }
        }
        if (d.declaredIn) L.push('      utworzona w: ' + d.declaredIn);
        L.push('');
      }
    });

    section(L, 'POLITYKI — JEST W MIGRACJI, NIE MA W BAZIE', pol.onlyInMigrations.length, () => {
      for (const d of pol.onlyInMigrations) {
        L.push('  ' + d.text);
        L.push('      ' + d.cmd + ' dla ' + d.roles.join(', ')
          + (d.declaredIn ? '; utworzona w ' + d.declaredIn : ''));
        L.push('      Na produkcji tej polityki NIE MA — jesli tabela ma RLS,');
        L.push('      to znaczy, ze te dane sa teraz niedostepne dla tych rol.');
        L.push('');
      }
    });

    section(L, 'POLITYKI — JEST W BAZIE, NIE MA W MIGRACJI', pol.onlyInDb.length, () => {
      for (const d of pol.onlyInDb) {
        L.push('  ' + d.text);
        L.push('      ' + d.cmd + ' dla ' + d.roles.join(', ')
          + (d.permissive ? ', permissive' : ', restrictive'));
        L.push('      Swieze srodowisko jej nie dostanie — dostep bedzie tam wezszy');
        L.push('      niz na produkcji.');
        L.push('');
      }
    });
  }

  const trg = ctx.triggerResult;
  const evt = ctx.eventTriggerResult;
  if (trg || evt) {
    const both = (f) => [...(trg ? trg[f] : []), ...(evt ? evt[f] : [])];

    section(L, 'WYZWALACZE — JEST W BAZIE, NIE MA W MIGRACJI', both('onlyInDb').length, () => {
      L.push('Funkcja wyzwalacza to nie to samo co wyzwalacz. Funkcja moze byc po obu');
      L.push('stronach i miec te same uprawnienia, a PODPIECIE istniec tylko tutaj —');
      L.push('wtedy swieze srodowisko dostanie funkcje, ktorej nic nie wola.');
      L.push('');
      for (const d of both('onlyInDb')) {
        L.push('  ' + d.text + '   [' + d.kind + ']');
        L.push('      ' + describeDef(d.def));
        if (d.kind === 'zdarzeniowy') {
          L.push('      CREATE EVENT TRIGGER wymaga superusera, wiec `supabase db push`');
          L.push('      (rola postgres) go NIE zalozy. Jesli zostal zalozony recznie i tak');
          L.push('      ma byc, wpisz go do allowManual w supadrift.json razem z powodem —');
          L.push('      bedzie wtedy wypisywany osobno, jako znany krok reczny.');
        }
        L.push('');
      }
    });

    section(L, 'WYZWALACZE — JEST W MIGRACJI, NIE MA W BAZIE', both('onlyInMigrations').length, () => {
      for (const d of both('onlyInMigrations')) {
        L.push('  ' + d.text);
        L.push('      ' + describeDef(d.def));
        if (d.declaredIn) L.push('      utworzony w: ' + d.declaredIn);
        L.push('      Migracja go zaklada, w bazie go nie ma — funkcja sie nie odpala.');
        L.push('');
      }
    });

    section(L, 'WYZWALACZE — JEST W OBU, ALE INACZEJ', both('different').length, () => {
      for (const d of both('different')) {
        L.push('  ' + d.text);
        for (const f of d.diffs) {
          L.push('      ' + f.what);
          L.push('          migracje: ' + f.inMigrations);
          L.push('          baza    : ' + f.inDb);
          if (f.soft) L.push('          (Postgres przepisuje wyrazenia — moze byc tylko inny zapis)');
        }
        if (d.declaredIn) L.push('      utworzony w: ' + d.declaredIn);
        L.push('');
      }
    });

    const man = both('manual');
    if (man.length) {
      L.push('POZA MIGRACJAMI, SWIADOMIE  (' + man.length + ')');
      L.push(RULE);
      L.push('Ponizsze sa w bazie, nie ma ich w migracjach i jest to uzgodnione');
      L.push('(allowManual w supadrift.json). Nie licza sie do kodu wyjscia, ale sa');
      L.push('wypisywane w kazdym raporcie: swieze srodowisko ich NIE DOSTANIE,');
      L.push('dopoki ktos nie wykona kroku recznego.');
      L.push('');
      for (const d of man) {
        L.push('  ' + d.text + '   [' + d.kind + ']');
        L.push('      ' + describeDef(d.def));
        L.push('');
      }
    }
  }

  const sd = ctx.secdef || [];
  section(L, 'SECURITY DEFINER BEZ PELNEGO SEARCH_PATH', sd.length, () => {
    L.push('Funkcja SECURITY DEFINER chodzi z uprawnieniami wlasciciela, wiec kazda');
    L.push('nazwa bez kwalifikacji schematu jest szukana po search_path — a ten');
    L.push('ustawia WOLAJACY, jesli funkcja nie przybije go sobie sama.');
    L.push('');
    L.push('Druga polowa reguly, o ktorej latwo zapomniec: pg_temp musi byc NA LISCIE');
    L.push('i musi byc OSTATNI. Schemat tymczasowy jest przeszukiwany dla nazw relacji');
    L.push('jako PIERWSZY, dopoki nie wymieni sie go jawnie — a zalozyc w nim tabele');
    L.push('o dowolnej nazwie moze kazdy uzytkownik.');
    L.push('');
    L.push('    set search_path = public              <- pg_temp NADAL pierwszy');
    L.push('    set search_path = public, pg_temp     <- pg_temp ostatni, tak ma byc');
    L.push('');
    for (const f of sd) {
      L.push('  ' + f.text + '     ' + f.kind + ' (' + f.where + ')');
      if (f.searchPathInMigrations !== null) L.push('      migracje: ' + f.searchPathInMigrations);
      if (f.searchPathInDb !== null) L.push('      baza    : ' + f.searchPathInDb);
      if (f.declaredIn) L.push('      utworzona w: ' + f.declaredIn);
      L.push('      poprawka:');
      L.push('        alter function ' + f.text + ' set search_path = '
        + f.suggestion.values.join(', ') + ';');
      L.push('      (' + f.suggestion.why + ')');
      L.push('');
    }
  });

  const bare = ctx.rlsIntent || [];
  section(L, 'TABELE Z RLS, ALE BEZ ZADNEJ POLITYKI', bare.length, () => {
    L.push('RLS wlaczone i zero polityk znaczy, ze tabela jest dostepna wylacznie');
    L.push('dla rol z BYPASSRLS (w Supabase: service_role)' );
    L.push('Czasem dokladnie o to chodzi. Jesli tak — wpisz tabele na liste');
    L.push('wyjatkow (allowNoPolicy w supadrift.json albo --allow-no-policy),');
    L.push('zeby cisza w tym miejscu znaczyla "sprawdzone", a nie "przeoczone".');
    L.push('');
    for (const f of bare) {
      L.push('  ' + f.text + '     bez polityk: ' + f.where);
      L.push('      FORCE ' + onoff(f.force)
        + (f.force ? ' — nie siega tam nawet wlasciciel' : ' — wlasciciel (' + (f.owner || 'postgres') + ') siega mimo RLS'));
      if (f.declaredIn) L.push('      utworzona w: ' + f.declaredIn);
      L.push('');
    }
  });

  // Indeks wedlug regul. Pochodzi z TEJ SAMEJ funkcji co wyjscie SARIF
  // (src/sarif.js, zebrane()), wiec oba wyjscia nie moga sie rozjechac —
  // a identyfikator, ktory tu widzisz, jest tym, ktorego szukasz w zakladce
  // Security i ktory da sie wkleic w grep.
  let indeks = [];
  try {
    indeks = require('./sarif').zebrane(ctx);
  } catch { indeks = []; }
  if (indeks.length) {
    L.push('ZGLOSZENIA WEDLUG REGUL  (' + indeks.length + ')');
    L.push(RULE);
    const wg = new Map();
    for (const z of indeks) {
      if (!wg.has(z.ruleId)) wg.set(z.ruleId, []);
      wg.get(z.ruleId).push(z);
    }
    for (const [id, lista] of [...wg].sort()) {
      L.push('  ' + id + '   (' + lista.length + ')');
      for (const z of lista) {
        L.push('      ' + (z.file ? z.file + ':' + z.line : '(brak pliku w migracjach)'));
      }
    }
    L.push('');
  }

  if (expectedInfo.notes.length) {
    L.push('CZEGO SUPADRIFT NIE ODCZYTAL Z MIGRACJI');
    L.push(RULE);
    L.push('Ponizsze instrukcje moga wplywac na uprawnienia funkcji, a nie sa');
    L.push('odwzorowane w modelu. Dopoki tu cokolwiek stoi, "czysto" znaczy');
    L.push('"czysto poza tym".');
    L.push('');
    for (const nt of expectedInfo.notes) {
      L.push('  ' + nt.file + ':' + nt.line + '  [' + nt.kind + '] ' + nt.text);
    }
    L.push('');
  }

  return L.join('\n');
}

function section(L, title, count, body) {
  if (!count) return;
  L.push(title + '  (' + count + ')');
  L.push(RULE);
  body();
}

function pad(s) {
  return (s + '                    ').slice(0, Math.max(16, s.length + 1));
}

function yn(b) { return b ? 'tak' : 'nie'; }

function onoff(b) { return b ? 'WLACZONE' : 'wylaczone'; }

function plural(n, one, few, many) {
  if (n === 1) return one;
  const t = n % 10;
  const h = n % 100;
  if (t >= 2 && t <= 4 && !(h >= 12 && h <= 14)) return few;
  return many;
}

function lastTouch(touched) {
  if (!touched || !touched.length) return null;
  const t = touched[touched.length - 1];
  return t.file + ':' + t.line + ' (' + t.kind + ' ' + t.roles.join(', ') + ')';
}

function lastRevoke(touched) {
  if (!touched) return null;
  for (let i = touched.length - 1; i >= 0; i--) {
    if (touched[i].kind === 'revoke') {
      return touched[i].file + ':' + touched[i].line + ' (od ' + touched[i].roles.join(', ') + ')';
    }
  }
  return null;
}

// --- migracja naprawcza -----------------------------------------------------

function renderFix(ctx) {
  const { result, options } = ctx;
  const L = [];
  const stamp = timestamp();

  L.push('-- ' + '='.repeat(74));
  L.push('-- Migracja naprawcza wygenerowana przez supadrift');
  L.push('-- ' + stamp + '   zakres: funkcje, EXECUTE');
  L.push('-- ' + '='.repeat(74));
  L.push('--');
  L.push('-- KIERUNEK. Ponizsze polecenia doprowadzaja BAZE do stanu, ktory opisuja');
  L.push('-- MIGRACJE — bo to migracje sa w repozytorium i to one odtworza kazde');
  L.push('-- nastepne srodowisko.');
  L.push('--');
  L.push('-- Zanim wkleisz: przy kazdym rozjazdzie sa dwie mozliwe prawdy. Albo baza');
  L.push('-- odjechala i trzeba ja cofnac (to robi ten plik), albo to migracje sa');
  L.push('-- niepelne i brakujaca linie trzeba DOPISAC DO NOWEJ MIGRACJI, zamiast');
  L.push('-- zdejmowac uprawnienie z bazy. Wybor nalezy do czlowieka, dlatego');
  L.push('-- supadrift niczego sam nie stosuje.');
  L.push('--');
  L.push('-- Nazwa pliku do zapisania:');
  L.push('--   supabase/migrations/' + stamp + '_supadrift_fix.sql');
  L.push('-- ' + '='.repeat(74));
  L.push('');

  let wrote = false;

  for (const d of result.different) {
    const add = d.roles.filter((r) => r.kind === 'brak-w-bazie');
    const del = d.roles.filter((r) => r.kind === 'brak-w-migracji');
    const go = d.roles.filter((r) => r.kind === 'inna-opcja-nadawania');
    if (!add.length && !del.length && !go.length) continue;
    wrote = true;

    L.push('-- ' + '-'.repeat(70));
    L.push('-- ' + d.text);
    const last = lastTouch(d.touched);
    if (last) L.push('-- ostatnia zmiana uprawnien w migracjach: ' + last);
    L.push('-- ' + '-'.repeat(70));
    for (const r of add) {
      L.push('grant execute on function ' + d.text + ' to ' + q(r.role) + ';');
    }
    for (const r of del) {
      L.push('-- baza ma to nadanie, migracje go nie znaja. Jesli bylo zamierzone,');
      L.push('-- NIE wykonuj ponizszej linii — dopisz zamiast tego grant do migracji.');
      L.push('revoke execute on function ' + d.text + ' from ' + q(r.role) + ';');
    }
    for (const r of go) {
      if (r.inMigrations) {
        L.push('grant execute on function ' + d.text + ' to ' + q(r.role) + ' with grant option;');
      } else {
        L.push('revoke grant option for execute on function ' + d.text + ' from ' + q(r.role) + ';');
        L.push('grant execute on function ' + d.text + ' to ' + q(r.role) + ';');
      }
    }
    L.push('');
  }

  for (const d of result.onlyInMigrations) {
    wrote = true;
    L.push('-- ' + '-'.repeat(70));
    L.push('-- BRAK W BAZIE: ' + d.text);
    L.push('-- Tresci funkcji nie da sie odtworzyc z samych uprawnien. Najpewniej');
    L.push('-- migracja ' + (d.declaredIn || '(nieznana)') + ' nie zostala wdrozona.');
    L.push('-- Sprawdz `supabase migration list` i wdroz brakujaca migracje,');
    L.push('-- zamiast tworzyc funkcje recznie.');
    L.push('-- ' + '-'.repeat(70));
    L.push('');
  }

  for (const d of result.onlyInDb) {
    wrote = true;
    L.push('-- ' + '-'.repeat(70));
    L.push('-- BRAK W MIGRACJACH: ' + d.text);
    L.push('-- Ta funkcja istnieje w bazie, ale nie powstala z zadnej migracji');
    L.push('-- w tym katalogu, wiec swieze srodowisko jej nie dostanie.');
    L.push('-- Wlasciwa naprawa to DOPISANIE jej do migracji. Usuniecie ponizej');
    L.push('-- jest zakomentowane celowo — odkomentuj tylko, jesli wiesz, ze to');
    L.push('-- pozostalosc.');
    L.push('-- drop function ' + d.text + ';');
    L.push('-- ' + '-'.repeat(70));
    L.push('');
  }

  const tbl = ctx.tableResult;
  if (tbl) {
    for (const d of tbl.different) {
      wrote = true;
      L.push('-- ' + '-'.repeat(70));
      L.push('-- TABELA: ' + d.text);
      L.push('-- ' + '-'.repeat(70));
      for (const f of d.flags) {
        if (f.flag === 'rls') {
          if (f.inMigrations) L.push('alter table ' + d.text + ' enable row level security;');
          else {
            L.push('-- Baza ma RLS, migracje o nim nie mowia. Wylaczenie go na produkcji');
            L.push('-- OTWIERA te tabele. Wlasciwa naprawa jest prawie zawsze odwrotna:');
            L.push('-- dopisz `enable row level security` do nowej migracji.');
            L.push('-- alter table ' + d.text + ' disable row level security;');
          }
        } else if (f.inMigrations) {
          L.push('alter table ' + d.text + ' force row level security;');
        } else {
          L.push('-- alter table ' + d.text + ' no force row level security;');
        }
      }
      L.push('');
    }
    for (const d of tbl.onlyInDb) {
      wrote = true;
      L.push('-- ' + '-'.repeat(70));
      L.push('-- TABELA W BAZIE, NIE W MIGRACJACH: ' + d.text
        + '   (RLS ' + onoff(d.rls) + ', FORCE ' + onoff(d.force) + ')');
      L.push('-- Swieze srodowisko jej nie dostanie. Dopisz ja do migracji.');
      L.push('-- ' + '-'.repeat(70));
      L.push('');
    }
    for (const d of tbl.onlyInMigrations) {
      wrote = true;
      L.push('-- ' + '-'.repeat(70));
      L.push('-- TABELA W MIGRACJACH, NIE W BAZIE: ' + d.text);
      L.push('-- Najpewniej migracja ' + (d.declaredIn || '(nieznana)') + ' nie zostala wdrozona.');
      L.push('-- ' + '-'.repeat(70));
      L.push('');
    }
  }

  for (const kind of ['triggerResult', 'eventTriggerResult']) {
    const res = ctx[kind];
    if (!res) continue;
    for (const d of [...res.different, ...res.onlyInMigrations]) {
      if (!d.def) continue;
      wrote = true;
      L.push('-- ' + '-'.repeat(70));
      L.push('-- WYZWALACZ: ' + d.text);
      if (d.diffs) for (const f of d.diffs) L.push('-- ' + f.what + ': migracje=' + f.inMigrations + ' baza=' + f.inDb);
      L.push('-- Ponizsze odtwarza podpiecie Z MIGRACJI.');
      L.push('-- ' + '-'.repeat(70));
      L.push(renderTrigger(d.def));
      L.push('');
    }
    for (const d of res.onlyInDb) {
      wrote = true;
      L.push('-- ' + '-'.repeat(70));
      L.push('-- WYZWALACZ W BAZIE, NIE W MIGRACJACH: ' + d.text);
      L.push('-- ' + describeDef(d.def));
      L.push('-- Swieze srodowisko go nie dostanie. Wlasciwa naprawa to dopisanie go');
      L.push('-- do migracji — a jesli sie nie da (event trigger wymaga superusera),');
      L.push('-- to udokumentowanie kroku recznego i wpisanie do allowManual.');
      L.push('-- ' + '-'.repeat(70));
      L.push('');
    }
  }

  const pol = ctx.policyResult;
  if (pol) {
    for (const d of [...pol.different, ...pol.onlyInMigrations]) {
      if (!d.def) continue;
      wrote = true;
      L.push('-- ' + '-'.repeat(70));
      L.push('-- POLITYKA: ' + d.text);
      if (d.diffs) for (const f of d.diffs) L.push('-- ' + f.what + ': migracje=' + f.inMigrations + ' baza=' + f.inDb);
      L.push('-- Ponizsze odtwarza definicje Z MIGRACJI. Jesli to baza ma racje,');
      L.push('-- nie wykonuj tego — popraw migracje.');
      L.push('-- ' + '-'.repeat(70));
      L.push(renderPolicy(d.def));
      L.push('');
    }
    for (const d of pol.onlyInDb) {
      wrote = true;
      L.push('-- ' + '-'.repeat(70));
      L.push('-- POLITYKA W BAZIE, NIE W MIGRACJACH: ' + d.text);
      L.push('-- ' + d.cmd + ' dla ' + d.roles.join(', ') + '. Swieze srodowisko jej nie dostanie.');
      L.push('-- Wlasciwa naprawa to dopisanie jej do migracji, nie usuniecie.');
      L.push('-- drop policy if exists "' + d.text.split('"')[1] + '" on ' + d.table + ';');
      L.push('-- ' + '-'.repeat(70));
      L.push('');
    }
  }

  for (const d of ctx.tableGrants || []) {
    wrote = true;
    L.push('-- ' + '-'.repeat(70));
    L.push('-- NADANIA: ' + d.text);
    L.push('-- Ponizsze doprowadza baze do stanu opisanego przez migracje.');
    L.push('-- ' + '-'.repeat(70));
    for (const r2 of d.roles) {
      L.push('revoke all on table ' + d.text + ' from ' + q(r2.role) + ';');
      if (r2.inMigrations !== '(nic)') {
        L.push('grant ' + r2.inMigrations + ' on table ' + d.text + ' to ' + q(r2.role) + ';');
      }
    }
    for (const c of d.columns) {
      if (c.inMigrations !== '(nic)') {
        L.push('grant ' + c.inMigrations + ' (' + c.column + ') on table ' + d.text + ' to ' + q(c.role) + ';');
      } else {
        L.push('revoke ' + c.inDb + ' (' + c.column + ') on table ' + d.text + ' from ' + q(c.role) + ';');
      }
    }
    L.push('');
  }

  for (const f of ctx.secdef || []) {
    wrote = true;
    L.push('-- ' + '-'.repeat(70));
    L.push('-- SEARCH_PATH: ' + f.text + '   (' + f.kind + ', ' + f.where + ')');
    if (f.searchPathInDb !== null) L.push('-- w bazie teraz: ' + f.searchPathInDb);
    L.push('-- ' + f.suggestion.why);
    L.push('-- Zmienia SAMO ustawienie: nie rusza ciala, podpisu, wlasciciela ani nadan.');
    L.push('-- Pamietaj, ze CREATE OR REPLACE w migracji NADPISUJE ustawienia — jesli');
    L.push('-- ta funkcja bedzie kiedys podmieniana, poprawka musi trafic takze tam.');
    L.push('-- ' + '-'.repeat(70));
    L.push('alter function ' + f.text + ' set search_path = ' + f.suggestion.values.join(', ') + ';');
    L.push('');
  }

  for (const f of ctx.rlsIntent || []) {
    wrote = true;
    L.push('-- ' + '-'.repeat(70));
    L.push('-- RLS BEZ POLITYK: ' + f.text + '   (' + f.where + ')');
    L.push('-- Dwie mozliwe prawdy, obie wygladaja w bazie tak samo:');
    L.push('--   a) tak ma byc — tabela wylacznie dla service_role. Wtedy dopisz ja');
    L.push('--      do supadrift.json:  "allowNoPolicy": ["' + f.text + '"]');
    L.push('--   b) ktos zapomnial polityki. Wtedy napisz ja i dodaj migracja.');
    L.push('-- supadrift nie zgadnie, ktora z nich jest prawdziwa.');
    L.push('-- ' + '-'.repeat(70));
    L.push('');
  }

  for (const f of ctx.intent || []) {
    wrote = true;
    L.push('-- ' + '-'.repeat(70));
    L.push('-- NIE MA KTO WOLAC: ' + f.text + '   (martwa: ' + f.where + ')');
    const rev = lastRevoke(f.touched);
    if (rev) L.push('-- revoke bez pary: ' + rev);
    if (f.excusedByDefinerCaller) {
      L.push('-- UWAGA: wolana z SECURITY DEFINER (' + f.callers.join(', ') + '), wiec brak');
      L.push('-- nadan moze byc zamierzony. Sprawdz, zanim cokolwiek nadasz.');
    } else if (!f.callers.length) {
      L.push('-- Zadna funkcja SQL jej nie wola, wiec wolajacy jest poza baza i NIE jest');
      L.push('-- wlascicielem. Sprawdz, jaka rola laczy sie wolajacy, i nadaj EXECUTE jej.');
    }
    L.push('-- ' + '-'.repeat(70));
    if (f.suggestion && !f.excusedByDefinerCaller) {
      L.push('-- Podpowiedz z: ' + f.suggestion.why + '. POTWIERDZ ja, zanim wykonasz.');
      L.push('grant execute on function ' + f.text + ' to ' + q(f.suggestion.role) + ';');
    } else {
      L.push('-- grant execute on function ' + f.text + ' to <rola>;');
    }
    L.push('');
  }

  if (!wrote) {
    L.push('-- Nie ma czego naprawiac: supadrift nie znalazl ani rozjazdu,');
    L.push('-- ani funkcji, ktorej nie ma kto wolac.');
    L.push('');
  }

  return L.join('\n');
}

function describeDef(d) {
  if (!d) return '';
  if (d.event) {
    return 'on ' + d.event
      + (d.tags && d.tags.length ? ' when tag in (' + d.tags.join(', ') + ')' : '')
      + '  ->  ' + d.fn + '()'
      + (d.enabled && d.enabled !== 'O' ? '   [' + enabledText(d.enabled) + ']' : '');
  }
  return (d.timing || '') + ' ' + (d.events || []).join(' or ')
    + (d.updateColumns && d.updateColumns.length ? ' of ' + d.updateColumns.join(', ') : '')
    + ' for each ' + (d.level || '') + '  ->  ' + d.fn + '()'
    + (d.enabled && d.enabled !== 'O' ? '   [' + enabledText(d.enabled) + ']' : '');
}

function renderTrigger(d) {
  if (d.event) {
    return 'drop event trigger if exists ' + d.name + ';\n'
      + 'create event trigger ' + d.name + ' on ' + d.event
      + (d.tags && d.tags.length
        ? '\n  when tag in (' + d.tags.map((x) => "'" + x + "'").join(', ') + ')' : '')
      + '\n  execute function ' + d.fn + '();';
  }
  return 'drop trigger if exists ' + d.name + ' on ' + d.schema + '.' + d.table + ';\n'
    + 'create trigger ' + d.name + '\n'
    + '  ' + d.timing + ' ' + d.events.join(' or ')
    + (d.updateColumns && d.updateColumns.length ? ' of ' + d.updateColumns.join(', ') : '')
    + ' on ' + d.schema + '.' + d.table + '\n'
    + '  for each ' + d.level
    + (d.whenRaw ? '\n  when (' + d.whenRaw + ')' : '')
    + '\n  execute function ' + d.fn + '();';
}

function renderPolicy(p) {
  const tbl = p.schema + '.' + p.table;
  const L = [
    'drop policy if exists "' + p.name + '" on ' + tbl + ';',
    'create policy "' + p.name + '"',
    '  on ' + tbl,
  ];
  if (!p.permissive) L.push('  as restrictive');
  if (p.cmd && p.cmd !== 'all') L.push('  for ' + p.cmd);
  L.push('  to ' + p.roles.map(q).join(', '));
  if (p.usingRaw || p.using) L.push('  using (' + (p.usingRaw || p.using) + ')');
  if (p.checkRaw || p.check) L.push('  with check (' + (p.checkRaw || p.check) + ')');
  return L.join('\n') + ';';
}

function timestamp(d = new Date()) {
  const p = (x, n = 2) => String(x).padStart(n, '0');
  return d.getUTCFullYear() + p(d.getUTCMonth() + 1) + p(d.getUTCDate())
    + p(d.getUTCHours()) + p(d.getUTCMinutes()) + p(d.getUTCSeconds());
}

module.exports = { renderReport, renderFix, timestamp };
