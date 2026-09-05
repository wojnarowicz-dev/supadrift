'use strict';

// ---------------------------------------------------------------------------
// Katalog regul
// ---------------------------------------------------------------------------
//
// Identyfikatory powstaly razem z wyjsciem SARIF, bo wczesniej ich nie bylo —
// raport tekstowy nazywal sekcje zdaniem po polsku i tyle. To za malo w dwoch
// miejscach naraz: SARIF wymaga `ruleId`, a czlowiek szukajacy w logu CI
// potrzebuje czegos, co da sie wkleic w grep.
//
// Dlatego ten sam identyfikator idzie do OBU wyjsc: do SARIF-a jako `ruleId`
// i do raportu tekstowego w nawiasie kwadratowym przy kazdym zgloszeniu.
// Rozjazd miedzy nimi bylby dokladnie tym rodzajem bledu, ktory to narzedzie
// ma lapac u innych.
//
// POZIOM. Wszystko jest `note`, nigdy `error` — patrz README, sekcja "W CI".
// Krotko: czesc zgloszen to twarde fakty z katalogu, ale czesc (tresc wyrazen
// polityk, klauzula WHEN, kontrole zamiaru) wymaga decyzji czlowieka, a alert,
// ktory blokuje, zostaje wylaczony po tygodniu i wtedy nie zglasza juz nic.

const RULES = [
  {
    id: 'supadrift/function-grant-drift',
    name: 'FunctionGrantDrift',
    short: 'Nadanie EXECUTE do funkcji rozni sie miedzy migracja a baza.',
    full: 'Migracje i baza nie zgadzaja sie co do tego, ktora rola moze wywolac '
      + 'te funkcje. Postgres nadaje EXECUTE roli `public` przy tworzeniu kazdej '
      + 'funkcji, a REVOKE od `public` zabiera je wszystkim, ktorzy mieli je tylko '
      + 'ta droga — dlatego brakujaca polowa pary revoke/grant nie jest literowka, '
      + 'tylko zmiana stanu. Swieze srodowisko dostanie uprawnienia takie, jakie '
      + 'opisuja pliki, a nie takie, jakie sa dzis na produkcji.',
  },
  {
    id: 'supadrift/function-attribute-drift',
    name: 'FunctionAttributeDrift',
    short: 'search_path albo SECURITY DEFINER funkcji rozni sie miedzy migracja a baza.',
    full: 'Sama definicja funkcji rozni sie w rzeczy, ktora decyduje o jej '
      + 'uprawnieniach: czy chodzi z uprawnieniami wlasciciela (SECURITY DEFINER), '
      + 'albo po jakiej sciezce szuka nazw (search_path). Najczestsza przyczyna to '
      + 'niewdrozona migracja albo CREATE OR REPLACE, ktory nadpisal ustawienie.',
  },
  {
    id: 'supadrift/function-missing-in-db',
    name: 'FunctionMissingInDatabase',
    short: 'Funkcja jest w migracjach, nie ma jej w bazie.',
    full: 'Migracja tworzy te funkcje, a w bazie jej nie ma. Zwykle znaczy to, ze '
      + 'migracja nie zostala wdrozona na tym srodowisku.',
  },
  {
    id: 'supadrift/function-missing-in-migrations',
    name: 'FunctionMissingInMigrations',
    short: 'Funkcja jest w bazie, nie ma jej w zadnej migracji.',
    full: 'Funkcja istnieje w bazie, ale nie powstala z zadnego pliku w katalogu '
      + 'migracji — najpewniej zalozono ja recznie. Swieze srodowisko postawione '
      + 'z tego repozytorium jej NIE DOSTANIE.',
  },
  {
    id: 'supadrift/function-unreachable',
    name: 'FunctionUnreachable',
    short: 'Po REVOKE nie zostalo zadne nadanie EXECUTE — funkcje moze wolac tylko wlasciciel.',
    full: 'To NIE jest rozjazd: pliki i baza moga zgadzac sie tu co do znaku i obie '
      + 'byc w bledzie. REVOKE od `public` bez pary GRANT zostawia funkcje dostepna '
      + 'wylacznie dla wlasciciela, a zaden klient Supabase nim nie jest — edge '
      + 'functions chodza jako service_role, przegladarka jako anon albo '
      + 'authenticated. Funkcje wyzwalaczy sa z tej kontroli wylaczone, bo Postgres '
      + 'sprawdza do nich EXECUTE przy CREATE TRIGGER, a nie przy odpaleniu.',
  },
  {
    id: 'supadrift/security-definer-search-path',
    name: 'SecurityDefinerSearchPath',
    short: 'Funkcja SECURITY DEFINER nie ma pg_temp na koncu search_path.',
    full: 'Funkcja SECURITY DEFINER rozwiazuje nazwy z uprawnieniami wlasciciela, '
      + 'wiec search_path musi byc przybity w definicji. Druga polowa reguly bywa '
      + 'pomijana: pg_temp musi byc NA LISCIE i na jej koncu. Schemat tymczasowy '
      + 'jest przeszukiwany dla nazw relacji jako PIERWSZY, dopoki nie wymieni sie '
      + 'go jawnie, a zalozyc w nim tabele o dowolnej nazwie moze kazdy uzytkownik. '
      + '`set search_path = public` zostawia wiec pg_temp przed public; dopiero '
      + '`set search_path = public, pg_temp` przesuwa go na koniec.',
  },
  {
    id: 'supadrift/table-rls-drift',
    name: 'TableRlsDrift',
    short: 'ROW LEVEL SECURITY albo FORCE rozni sie miedzy migracja a baza.',
    full: 'CREATE TABLE nie wlacza RLS. Tabela, ktorej migracja nie mowi jawnie '
      + '`enable row level security`, jest w opisie repozytorium OTWARTA, nawet '
      + 'jesli na produkcji ochrona jest — a w Supabase anon i authenticated maja '
      + 'SELECT na schemacie public. FORCE jest osobna sprawa: bez niego polityki '
      + 'nie dotycza wlasciciela tabeli.',
  },
  {
    id: 'supadrift/table-missing-in-db',
    name: 'TableMissingInDatabase',
    short: 'Tabela jest w migracjach, nie ma jej w bazie.',
    full: 'Migracja tworzy te tabele, a w bazie jej nie ma — zwykle niewdrozona migracja.',
  },
  {
    id: 'supadrift/table-missing-in-migrations',
    name: 'TableMissingInMigrations',
    short: 'Tabela jest w bazie, nie ma jej w zadnej migracji.',
    full: 'Tabela istnieje w bazie, ale nie powstala z zadnej migracji w tym '
      + 'katalogu. Swieze srodowisko jej nie dostanie.',
  },
  {
    id: 'supadrift/table-grant-drift',
    name: 'TableGrantDrift',
    short: 'Nadania na tabeli albo na kolumnie roznia sie miedzy migracja a baza.',
    full: 'Uprawnienia do tabeli lub do pojedynczych kolumn nie zgadzaja sie. '
      + 'Linia bazowa liczona jest z pg_default_acl, bo w Supabase ALTER DEFAULT '
      + 'PRIVILEGES nadaje cos nowym tabelom poza migracjami. Nadania kolumnowe '
      + 'siedza w pg_attribute.attacl, nie w pg_class.relacl.',
  },
  {
    id: 'supadrift/rls-without-policy',
    name: 'RlsWithoutPolicy',
    short: 'RLS wlaczone przy zerze polityk — tabela dostepna tylko dla rol z BYPASSRLS.',
    full: 'Dwa calkiem rozne przypadki wygladaja w katalogu identycznie: tabela '
      + 'CELOWO zamknieta dla wszystkich poza service_role, oraz tabela, przy '
      + 'ktorej ktos wlaczyl RLS i zapomnial polityki. Roznica siedzi w zamiarze, '
      + 'wiec rozstrzyga ja lista wyjatkow allowNoPolicy w supadrift.json.',
  },
  {
    id: 'supadrift/policy-drift',
    name: 'PolicyDrift',
    short: 'Polityka rozni sie miedzy migracja a baza.',
    full: 'Polecenie, rodzaj (permissive/restrictive), lista rol albo obecnosc '
      + 'USING/WITH CHECK nie zgadzaja sie. Sama TRESC wyrazenia porownywana jest '
      + 'po normalizacji i oznaczana osobno: Postgres nie przechowuje tekstu, ktory '
      + 'napisales, tylko drzewo, i odtwarza z niego tekst po swojemu — roznica '
      + 'w samej tresci bywa wiec tylko innym zapisem tego samego.',
  },
  {
    id: 'supadrift/policy-missing-in-db',
    name: 'PolicyMissingInDatabase',
    short: 'Polityka jest w migracjach, nie ma jej w bazie.',
    full: 'Migracja zaklada te polityke, a w bazie jej nie ma. Jesli tabela ma RLS, '
      + 'znaczy to, ze dane sa teraz niedostepne dla rol, ktore ta polityka mial obejmowac.',
  },
  {
    id: 'supadrift/policy-missing-in-migrations',
    name: 'PolicyMissingInMigrations',
    short: 'Polityka jest w bazie, nie ma jej w zadnej migracji.',
    full: 'Polityka istnieje w bazie i nie ma jej w migracjach — swieze srodowisko '
      + 'bedzie mialo dostep WEZSZY niz produkcja.',
  },
  {
    id: 'supadrift/trigger-drift',
    name: 'TriggerDrift',
    short: 'Wyzwalacz rozni sie miedzy migracja a baza.',
    full: 'Funkcja, moment, zdarzenia, lista kolumn przy UPDATE OF, poziom albo '
      + 'stan wlaczenia nie zgadzaja sie miedzy plikami a baza.',
  },
  {
    id: 'supadrift/trigger-missing-in-db',
    name: 'TriggerMissingInDatabase',
    short: 'Wyzwalacz jest w migracjach, nie ma go w bazie.',
    full: 'Migracja zaklada to podpiecie, a w bazie go nie ma — funkcja wyzwalacza '
      + 'istnieje, ale nic jej nie wola.',
  },
  {
    id: 'supadrift/trigger-missing-in-migrations',
    name: 'TriggerMissingInMigrations',
    short: 'Wyzwalacz jest w bazie, nie ma go w zadnej migracji.',
    full: 'Funkcja wyzwalacza to nie to samo co wyzwalacz. Samo PODPIECIE istnieje '
      + 'tylko w tej bazie — swieze srodowisko go nie dostanie. Dotyczy to zwlaszcza '
      + 'wyzwalaczy zdarzeniowych: CREATE EVENT TRIGGER wymaga superusera, wiec '
      + '`supabase db push` ich nie zalozy i sila rzeczy powstaja recznie.',
  },
];

const BY_ID = new Map(RULES.map((r) => [r.id, r]));

function rule(id) {
  const r = BY_ID.get(id);
  if (!r) throw new Error('nieznana regula: ' + id);
  return r;
}

module.exports = { RULES, BY_ID, rule };
