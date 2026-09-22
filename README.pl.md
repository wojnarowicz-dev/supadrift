# supadrift

[English](README.md) · **Polski**

supadrift porównuje **uprawnienia**, które opisują Twoje migracje SQL, z tymi,
które faktycznie obowiązują w bazie Supabase: `grant` i `revoke` na funkcjach,
polityki RLS, `search_path` w funkcjach `SECURITY DEFINER` oraz nadania na
tabelach i kolumnach.

To inna warstwa niż porównywanie schematu. **Atlas**, **pg-schema-diff**
i **Liquibase** porównują *strukturę* — tabele, kolumny, indeksy, ograniczenia,
widoki. supadrift porównuje *kto ma prawo co zrobić*. Inne pytanie, inna
odpowiedź — patrz [Czego supadrift nie robi](#czego-supadrift-nie-robi).

Tej warstwy uprawnień nie sprawdza dziś z plikami nikt. Security Advisor
w Supabase patrzy **tylko na bazę**. Narzędzia w rodzaju `pgrls` patrzą **tylko
na pliki**. Rozjazd między jednym a drugim jest realnym błędem i nie zgłasza go
nic:

> Migracja `20240115120000` miała `revoke` bez `grant execute` dla
> `service_role`. Funkcja `refund_quota` nie wykonała się ani razu od
> wdrożenia. Baza była „poprawna" (uprawnienia dokładnie takie, jakie kazano),
> pliki były „poprawne" (revoke stoi tam, gdzie miał stać), a funkcja była
> martwa. Naprawiła to dopiero migracja `20240115140000`, znaleziona ręcznie.

## Co się zmieniło w 0.2.0

**Jeśli uruchamiasz to w CI, przeczytaj ten wiersz.** Kody wyjścia **nie**
zmieniły znaczenia i jest to celowe: `2` już znaczyło „nie dałem rady
sprawdzić", a `1` — „są rozjazdy". Nowe jest to, że maszyna widzi ten sam
stan bez czytania prozy — oraz że **`--json` wreszcie wypisuje treść, gdy
przebieg pada**. Wcześniej dawał kod wyjścia i pusty strumień, więc czytelnik
samego pliku nie odróżniał „nie dało się sprawdzić" od „w ogóle nie ruszyło".

```json
{
  "summary": { "actionable": 0, "explained": 0, "notApplicable": 0,
               "unreachable": 1,
               "unreachableIs": { "aQuestionForAPerson": 0, "couldNotBeRead": 1 } },
  "error": "..."
}
```

Każdy udany przebieg niesie te same cztery liczby, na ekranie i w JSON-ie.

**`1` jest tu stanowe i to jest odstępstwo od pozostałych narzędzi.**
Tamte zgłaszają to, co NOWE, bo każde trzyma migawkę poprzedniego przebiegu.
To nie trzyma żadnej — porównuje migracje z żywą bazą i nie ma z czym
różnicować. Zrobienie go różnicowym oznaczałoby zmyślenie bazy porównań;
uciszenie go domyślnie odebrałoby mu jedyne, co dziś umie powiedzieć
budowaniu. Więc rozjazdy dalej psują budowanie, dokładnie jak w 0.1.x.

**Czego te cztery liczby nie liczą.** `notApplicable` liczy KONTROLE
wyłączone przez `--no-tables` i podobne, nie pozycje — wyłączenie kontroli
zdejmuje opinię, nie znalezisko. `explained` liczy to, co zdjęły **wszystkie
cztery** listy `--allow-*`, plus to, czego migracje nie modelują.

Pozostałe trzy listy zdejmowały swoje pozycje bez liczenia ich, więc „nie ma
takich przypadków” i „są, ktoś je obejrzał i odłożył” docierały do budowania
jako ta sama liczba. W projekcie, dla którego to narzędzie powstało, było to
sześć tabel, każda z akapitem uzasadnienia wpisanym obok w `supadrift.json`,
a pole mówiło dwa. Teraz mówi osiem — i przebieg wypisuje ich nazwy, na
ekranie i pod `setAside` w JSON-ie, bo liczba, za którą nic nie stoi, jest
prośbą o zaufanie.

## Uruchomienie bez instalowania

```
npx supadrift --via-cli
```

Node 18 albo nowszy, uruchamiane z katalogu projektu Supabase zalinkowanego
w Supabase CLI — ta droga nie wymaga żadnego hasła. Bez CLI adres bazy wkładasz
do `SUPADRIFT_DB_URL` albo do `.env`; nigdy nie przyjmujemy go argumentem, bo
argumenty trafiają do historii powłoki. supadrift wyłącznie czyta.

---

## Czego supadrift nie robi

Nie porównuje kolumn, typów, indeksów ani ograniczeń. Nie powie Ci, że kolumna
zmieniła typ, że brakuje indeksu albo że rozjechało się ograniczenie `check`. Do
tego istnieją dojrzałe narzędzia — **Atlas**, **pg-schema-diff**, **Liquibase** —
i to nie jest próba zastąpienia żadnego z nich.

Są **komplementarne, nie konkurencyjne**. Używanie obu naraz jest sensownym
ustawieniem: porównywarka schematu pilnuje struktury, supadrift pilnuje warstwy
uprawnień. Łapią inne błędy i żadne nie zastępuje drugiego.

Trzy prawdziwe wady, które to narzędzie znalazło w bazie swojego autora,
pokazują ten podział na konkretach:

| znalezisko | czym było | czy zgłosiłaby to porównywarka schematu? |
|---|---|---|
| `revoke` bez pary `grant` | rozjazd uprawnień: baza nadawała `EXECUTE` roli `service_role`, migracje nie | **nie** — obiekt istnieje po obu stronach i strukturalnie jest identyczny |
| funkcja obecna w bazie, nieobecna w żadnej migracji | brakujący obiekt schematu | **tak** — dokładnie do tego służą |
| `SECURITY DEFINER` bez `pg_temp` w `search_path` | w ogóle nie rozjazd: pliki i baza się zgadzały | **nie** — porównywarka zestawia dwie strony, a tu obie mówiły to samo |

Trzeci wiersz jest tym, przy którym warto się zatrzymać. **Nic, co działa przez
porównywanie dwóch stanów, nie może tego zgłosić**, bo nie było czego porównać:
obie strony mówiły to samo i obie były w błędzie. Po to właśnie kontrole zamiaru
stoją obok kontroli rozjazdu — i dlatego narzędzie do uprawnień nie może być
funkcją doklejoną do porównywarki schematu.

## Połączenie

**Tę sekcję czytaj pierwszą.** Narzędzie, które trzeba wpuścić do produkcyjnej
bazy, ma obowiązek powiedzieć od razu, co z tą bazą robi.

### 1. Wyłącznie odczyt

supadrift nigdy nie wykonuje `create`, `alter`, `grant`, `revoke` ani `drop`.
Nie jest to obietnica w dokumentacji — jest to własność programu, wymuszona
w trzech miejscach naraz:

- `src/db/readonly.js` przepuszcza **wyłącznie pojedyncze `SELECT`**. Każde
  zapytanie przechodzi przez tę bramkę, zanim trafi do sterownika; obie ścieżki
  połączenia jej używają i nie ma drogi obok.
- Zapytania, które supadrift wysyła, są **napisami stałymi** w tym repozytorium
  (`src/introspect.js`). Nie ma interpolacji, więc nie ma czego wstrzyknąć.
- Połączenie bezpośrednie ustawia sesję na `read only` i opakowuje odczyt
  w transakcję `BEGIN READ ONLY` zamykaną przez `ROLLBACK`.

Migracji naprawczej supadrift **nie stosuje**. Wypisuje ją do wklejenia.
Narzędzie, które samo poprawia uprawnienia, musiałoby mieć prawo je zmieniać —
a wtedy przestaje być narzędziem tylko do odczytu i staje się kolejną rzeczą,
która może zepsuć produkcję.

### 2. Klucz i adres — tylko ze zmiennej środowiskowej albo z `.env`

Nigdy z argumentu wiersza poleceń. supadrift **odmawia startu**, gdy zobaczy
w `argv` adres połączenia, klucz serwisowy albo token — nie ostrzega, tylko
kończy z kodem 2.

Powód: argument nie jest prywatny. Ląduje w historii powłoki
(`~/.bash_history`, `ConsoleHost_history.txt`), w logu CI, w `ps` widocznym dla
każdego użytkownika maszyny i w komunikacie o błędzie, który człowiek wkleja
potem do zgłoszenia. Ostrzeżenie, które da się przewinąć, nie chroni niczego:
klucz jest już wtedy w historii.

```powershell
$env:SUPADRIFT_DB_URL = "postgresql://supadrift_ro:HASLO@..."
supadrift
```

```bash
export SUPADRIFT_DB_URL="postgresql://supadrift_ro:HASLO@..."
supadrift
```

Czytane zmienne, w tej kolejności: `SUPADRIFT_DB_URL`, `SUPABASE_DB_URL`,
`DATABASE_URL`. Jeśli żadnej nie ma w środowisku, supadrift szuka ich w `.env`
w bieżącym katalogu (albo w pliku wskazanym przez `--env-file`).

### 3. Klucz nie trafia na wyjście

Ani do raportu, ani do wygenerowanej migracji, ani do komunikatu o błędzie.
Każde wyjście — także `--json` i treść zapisywana przez `--fix` — przechodzi
przez `redact()` z `src/secrets.js`, które usuwa zarejestrowany adres, samo
hasło z adresu oraz wszystko o kształcie `sb_secret_*`, `sbp_*` i JWT.
Adres bazy pokazywany jest jako sam host i nazwa bazy, bez użytkownika i hasła.

Poza `redact()` stoją jeszcze trzy rzeczy, każda zamykająca inną drogę ucieczki:

- **`process.on('uncaughtException')` i `('unhandledRejection')`** w `bin/supadrift.js`
  oraz `client.on('error')` w `src/db/pg.js`. Błąd, który wybuchnie poza łańcuchem
  obietnic — zdarzenie z gniazda, zerwana sesja, timer — Node wypisałby jako surowy
  obiekt razem ze stosem i **ominął `redact()`**. Te trzy słuchacze istnieją po to,
  żeby taka droga nie istniała.
- **Nierozpoznany argument nie jest odbijany.** Wypisywana jest sama nazwa opcji;
  argument bez nazwy kwitowany jest `(tresc pominieta)`. Nierozpoznanym argumentem
  bywa hasło wklejone omyłkowo w złe miejsce, a komunikat o błędzie idzie do logu
  CI, którego historia powłoki nie obejmuje.
- **Podproces `supabase` nie dostaje adresu bazy.** `src/db/cli.js` wycina
  `SUPADRIFT_DB_URL`, `SUPABASE_DB_URL`, `DATABASE_URL`, `PGPASSWORD`, `PGPASSFILE`
  i `PGSERVICE` ze środowiska przekazywanego binarce, która ich nie potrzebuje —
  chodzi własnym tokenem. Inaczej hasło byłoby widoczne w `ps` dla każdego
  użytkownika maszyny.

**Co jednak wychodzi i wychodzić ma: nazwa hosta.** Raport pisze, z czym się
połączył, a przy Supabase host zawiera identyfikator projektu
(`db.<ref>.supabase.co`); pokazuje go też komunikat systemowy przy błędzie DNS.
Jest to zamierzone — raport, który nie mówi, jaką bazę sprawdził, jest bezwartościowy.
Jeśli wynik ma trafić do logu oglądanego przez kogoś postronnego, użyj
**`--hide-target`**: host i `ref` (także ten z nazwy użytkownika puli `rola.<ref>`)
zostają zarejestrowane jako sekrety i znikają z **całego** wyjścia, a w ich miejsce
wchodzi ośmioznakowy, nieodwracalny odcisk, po którym nadal odróżnisz dwa przebiegi.

Znanym ograniczeniem jest próg długości: `registerSecret()` rejestruje hasło od
czterech znaków wzwyż. Krótsze nie jest rejestrowane jako osobny ciąg, bo
zamieniałoby przypadkowe słowa w raporcie na `[USUNIETE]`; wzorzec
`://uzytkownik:haslo@` przechwytuje je mimo to.

### 4. Rola tylko do odczytu — nie potrzebujesz klucza serwisowego

Wszystko, co supadrift czyta, to katalogi systemowe: `pg_proc`, `pg_class`,
`pg_namespace`, `pg_depend`, `pg_policy`, `pg_attribute`, `pg_default_acl`,
`pg_trigger` i `pg_event_trigger`. Dla pierwszych pięciu sprawdzone wprost na
żywym projekcie: każdy ma w ACL wpis `=r/…`, czyli `SELECT` dla roli `public`,
a `has_table_privilege('anon', …, 'SELECT')` zwraca dla nich prawdę. Pozostałe
to katalogi tej samej klasy, z tym samym domyślnym nadaniem. Rola dla supadrift **nie potrzebuje więc żadnego nadania poza `CONNECT`** —
nie musi widzieć ani jednego wiersza z Twoich danych.

W SQL Editorze w Supabase:

```sql
-- Hasło wygeneruj długie i losowe; nie wpisuj go tu z palca.
create role supadrift_ro with login password 'WKLEJ_DLUGIE_LOSOWE_HASLO';

grant connect on database postgres to supadrift_ro;

-- Bez uprawnień do tworzenia czegokolwiek i bez dziedziczenia ról.
alter role supadrift_ro nosuperuser nocreatedb nocreaterole noinherit;

-- Dodatkowa warstwa: domyślnie każda transakcja tej roli jest tylko do odczytu.
alter role supadrift_ro set default_transaction_read_only = on;
```

Ta rola nie ma żadnych uprawnień do obiektów, więc nie ma w bazie niczego, co
mogłaby zapisać ani odczytać poza katalogami systemowymi. `default_transaction_read_only`
jest dodatkiem, nie granicą — klient może je nadpisać; granicą jest brak nadań.

Adres połączenia weź z panelu Supabase (**Connect**) i podmień w nim użytkownika
i hasło na te powyżej. Rola własna działa na połączeniu bezpośrednim
(`db.<ref>.supabase.co:5432`) i na puli sesyjnej
(`aws-0-<region>.pooler.supabase.com:5432`, użytkownik `supadrift_ro.<ref>`).
Jeśli Twoja sieć nie ma IPv6, użyj puli.

Używaj portu **5432** (tryb sesyjny), nie 6543. W trybie transakcyjnym
`SET SESSION` nie musi przetrwać między zapytaniami, a supadrift na nim polega.

Cofnięcie dostępu, gdy będzie już niepotrzebny:

```sql
drop role supadrift_ro;
```

#### TLS: weryfikacja zostaje włączona

Pula Supabase przedstawia certyfikat podpisany własnym CA, którego nie ma
w magazynie zaufania Node'a. Przy włączonej weryfikacji połączenie kończy się
błędem `self-signed certificate in certificate chain` — **zanim hasło w ogóle
pójdzie w eter**.

Właściwą odpowiedzią jest wskazanie tego CA, a nie wyłączenie sprawdzania.
Certyfikat pobierz z panelu (**Settings → Database → SSL Configuration**)
i podaj supadriftowi jego ścieżkę:

```
SUPADRIFT_SSL_CA=C:/Users/ktos/supadrift/supabase-ca.crt
```

Weryfikacja zostaje **włączona** — zmienia się tylko kotwica zaufania. Brakujący
plik albo plik, który nie jest PEM-em, to błąd krytyczny z kodem 2; supadrift nie
wróci po cichu do ustawień domyślnych.

`SUPADRIFT_SSL_NO_VERIFY=1` zostaje jako ostatnia deska ratunku. Wyłącza
uwierzytelnienie serwera, więc połączenie przestaje bronić przed podstawieniem
się pod Twoją bazę. Celowo **nie ma na to przełącznika** w wierszu poleceń.

### 5. Ścieżka bez żadnego hasła

Jeśli masz zalinkowany projekt w Supabase CLI, supadrift może czytać bazę przez
niego i wtedy **nie widzi żadnego poświadczenia**:

```bash
supadrift --via-cli
```

Wygodne, ale nie minimalne: CLI używa własnego tokenu do Management API, a ten
token jest silny. Do stałego użycia, a zwłaszcza do CI, lepsza jest rola tylko
do odczytu z punktu 4.

---

## Szybki start

Z klonu. Po instalacji z rejestru `pg` przychodzi razem z paczką, a polecenie
to `supadrift` — albo `npx supadrift`, jak na górze tej strony.

```bash
cd supadrift
npm install                      # tylko po to, by mieć `pg`; przy --via-cli niepotrzebne
node bin/supadrift.js --help
```

Z katalogu projektu Supabase (supadrift sam znajdzie `supabase/migrations`):

```bash
node bin/supadrift.js --via-cli
```

Albo wskazując katalog i łącząc się bezpośrednio:

```bash
export SUPADRIFT_DB_URL="postgresql://supadrift_ro:...@..."
node bin/supadrift.js --migrations ../moj-projekt/supabase/migrations
```

Kody wyjścia: **0** czysto, **1** znaleziono rozjazd, **2** błąd. Nadaje się
do CI bez owijania.

---

## Co robi, krok po kroku

1. **Czyta migracje** z katalogu, po kolei, w porządku nazw plików, i odgrywa
   je na modelu uprawnień. Nie wykonuje przy tym żadnego SQL.
2. **Odpytuje bazę** — `pg_proc`, `pg_namespace`, `pg_depend` — o stan
   rzeczywisty.
3. **Porównuje w trzech kategoriach:**
   - jest w migracji, nie ma w bazie — migracja nie została wdrożona;
   - jest w bazie, nie ma w migracji — ktoś zmienił bazę ręcznie, a świeże
     środowisko tego nie dostanie;
   - **jest w obu, ale inaczej** — tu siedzą prawdziwe błędy. Pierwsze dwie
     kategorie rzucają się w oczy przy najbliższym odtworzeniu środowiska.
     Trzecia potrafi żyć miesiącami: kod działa, testy przechodzą, a jedna rola
     ma o jedno uprawnienie za mało.
4. **Wypisuje raport i gotową migrację naprawczą** do wklejenia. Nie stosuje jej.

Do tego dochodzi **kontrola zamiaru**, która nie porównuje niczego z niczym —
opisana niżej, bo powstała z osobnego powodu.

## Zakres

| co | co sprawdza |
|---|---|
| funkcje i procedury | czy istnieją, kto ma do nich `EXECUTE`, `SECURITY DEFINER`, `search_path` |
| kontrola zamiaru | czy funkcję ma kto wywołać |
| `SECURITY DEFINER` | czy `search_path` ma `pg_temp`, i czy na końcu |
| tabele | `ROW LEVEL SECURITY` i `FORCE ROW LEVEL SECURITY` |
| nadania na tabelach | uprawnienia per rola, w tym **kolumnowe** |
| polityki | polecenie, rodzaj, role, `USING`, `WITH CHECK` |
| wyzwalacze | tabelowe (`pg_trigger`) i zdarzeniowe (`pg_event_trigger`) |
| kontrola zamiaru dla tabel | RLS włączone przy zerze polityk |

Wszystko w schemacie `public` (albo w tym, który podasz przez `--schema`).

### Funkcje: EXECUTE

Model uprawnień odwzorowuje to, co naprawdę robi Postgres, bo tam siedzi cały
błąd, który chcemy łapać:

- `CREATE FUNCTION` nadaje `EXECUTE` roli **`public`** z automatu. Każda rola
  dziedziczy wtedy prawo wywołania *przez* `public` — `service_role` też, choć
  nikt mu nic jawnie nie nadał.
- `REVOKE ... FROM public` zdejmuje to **wszystkim**, którzy mieli je tylko tą
  drogą. Jeśli po takim revoke nie ma jawnego grantu, funkcję może wołać już
  tylko jej właściciel.
- `proacl = NULL` w bazie nie znaczy „brak uprawnień", tylko „domyślne", czyli
  właściciel **plus `EXECUTE` dla `public`". Wygląda jak jedno, znaczy drugie.
- `CREATE OR REPLACE` **nie** zeruje nadań — supadrift też ich nie zeruje.

Wpisu właściciela nie porównujemy: Postgres dopisuje go do ACL sam, a żadna
migracja nie nadaje go jawnie. Porównywanie tego dawałoby rozjazd przy każdej
funkcji i utopiłoby sygnał.

Funkcje należące do rozszerzeń (`pg_depend.deptype = 'e'`, np. `pgcrypto`) są
odsiewane — nigdy nie będzie ich w katalogu migracji i zgłaszanie ich byłoby
samym hałasem.

### Kontrola zamiaru: funkcja, której nie ma kto wołać

Porównanie plików z bazą ma jedną ślepą plamkę i jest ona akurat tam, gdzie boli
najbardziej: **nie zobaczy błędu, w którym pliki i baza mylą się tak samo.**
W dniu, w którym migracja `20240115120000` weszła na produkcję, baza była z nią
zgodna co do znaku. Rozjazd wynosił zero. Funkcja była martwa.

Ta kontrola nie porównuje niczego z niczym. Patrzy na jeden obraz — osobno na
migracje, osobno na bazę — i pyta: czy po tych uprawnieniach został ktokolwiek,
kto może tę funkcję wywołać? Jeśli po `revoke` od `public` nie ma żadnego
`grant execute`, zostaje sam właściciel, a żaden klient Supabase nim nie jest.
Raport mówi wtedy, gdzie funkcja jest martwa: `w migracjach`, `w bazie`
albo — najgorzej — `w obu`.

Podpowiada też brakującą połowę pary, i nie zgaduje jej z powietrza: patrzy na
sąsiadki. Najpierw na funkcje utworzone w tym samym pliku migracji, potem na
cały zestaw. Dokładnie tak rozpoznaje się ten błąd ręcznie.

**Czego ta kontrola nie zgłasza**, bo brak nadań jest tam stanem normalnym:

- Funkcje wyzwalaczy (`returns trigger`, `returns event_trigger`). Postgres
  sprawdza `EXECUTE` do nich przy `CREATE TRIGGER`, a nie przy każdym odpaleniu.
- Funkcje wołane z ciała innej funkcji `SECURITY DEFINER`. W trakcie takiego
  wywołania bieżącym użytkownikiem **jest** właściciel, więc sprawdzenie
  przechodzi. To świadomy wzorzec, więc zgłaszamy go osobno, słabiej i z powodem.
- Funkcje wpisane na listę wyjątków `--allow-owner-only` — dla tych, które
  naprawdę mają być dostępne tylko dla właściciela (zadania `pg_cron` i podobne).

Wyłącza się przez `--no-intent`.

### `SECURITY DEFINER` a `search_path`

Funkcja `SECURITY DEFINER` chodzi z uprawnieniami właściciela, więc każda nazwa
napisana w niej bez kwalifikacji schematu jest szukana po `search_path`
obowiązującym **w czasie wywołania** — a ten ustawia wołający, jeśli funkcja nie
przybije go sobie sama. Stąd `set search_path = ...` w definicji.

I stąd druga połowa reguły, o której najłatwiej zapomnieć:

```
set search_path = public              <- pg_temp NADAL pierwszy
set search_path = public, pg_temp     <- pg_temp ostatni, tak ma być
```

Schemat tymczasowy jest przeszukiwany dla nazw **relacji** jako pierwszy, dopóki
nie wymieni się go jawnie — a założyć w nim tabelę o dowolnej nazwie może każdy
użytkownik. `set search_path = public` nie zamyka więc tej drogi; dopiero
wpisanie `pg_temp` na końcu listy przesuwa go na koniec kolejności.

Kontrola rozróżnia trzy stany: `brak-search-path` (najgorszy, zgłaszany
pierwszy), `bez-pg_temp` i `pg_temp-nie-na-koncu`.

Poprawka jest liczona **osobno dla każdej funkcji**, a nie brana z większości.
Funkcji, która ma `search_path = pg_catalog`, nie wolno „naprawić" na
`public, pg_temp` — to podstawiłoby pod jej nazwy inny schemat. Większość służy
tylko tam, gdzie nie ma czego uzupełnić, i wtedy raport mówi, ilu innym
funkcjom `SECURITY DEFINER` ją zawdzięcza.

Funkcje `SECURITY INVOKER` nie są przypadkiem tej kontroli: chodzą
z uprawnieniami wołającego, więc podstawienie nie daje mu niczego, czego by już
nie miał. Wyłącza się przez `--no-secdef`, wycisza przez `--allow-search-path`.

### Tabele: RLS i FORCE

Dwie rzeczy, obie łatwe do przeoczenia:

- **`CREATE TABLE` nie włącza RLS.** Migracja, która tworzy tabelę i nie mówi
  `alter table ... enable row level security`, opisuje tabelę **bez ochrony** —
  nawet jeśli w produkcyjnej bazie ochrona jest, bo ktoś włączył ją ręcznie albo
  zrobił to wyzwalacz zdarzeniowy. Świeże środowisko dostanie wtedy tabelę
  otwartą, a w Supabase `anon` i `authenticated` mają `SELECT` na schemacie
  `public`.
- **RLS domyślnie nie dotyczy właściciela tabeli.** Dopóki nie ma
  `FORCE ROW LEVEL SECURITY`, polityki nie obowiązują tego, kto tabelę stworzył —
  zwykle roli `postgres`, która chodzi w migracjach i w niejednym zadaniu
  utrzymaniowym. Dlatego `FORCE` jest trzymany i porównywany osobno od `RLS`.

Parser rozumie `enable` / `disable`, `force` / `no force` (w tej kolejności —
`no force` zawiera w sobie `force`), `rename to` oraz `drop table`. Tabele
należące do rozszerzeń są odsiewane tak samo jak funkcje.

Wyłącza się przez `--no-tables`.

### Nadania na tabelach i kolumnach

Trzy rzeczy odróżniają to od nadań na funkcjach i każda z nich, pominięta, daje
zgłoszenia, których nie ma. Wszystkie trzy wyszły dopiero w zderzeniu
z prawdziwą bazą.

**1. Linia bazowa nie jest pusta.** `CREATE FUNCTION` nadaje `EXECUTE` roli
`public`; `CREATE TABLE` nie nadaje nic — ale w Supabase działa
`ALTER DEFAULT PRIVILEGES`, ustawione poza migracjami. Nowa tabela dostaje więc
nadania, o których w katalogu migracji nie ma ani słowa. Tej linii bazowej nie
da się zgadnąć z plików, więc supadrift czyta ją z `pg_default_acl` i dopiero od
niej odgrywa `grant`/`revoke`. Raport pokazuje ją przy każdym zgłoszeniu, żeby
było widać, od czego liczy.

**2. Nadania kolumnowe są w `pg_attribute.attacl`, nie w `pg_class.relacl`.**
`grant select (a, b) on table t to anon` zostawia `relacl` **bez** `anon`. Model,
który tego nie czyta, zgłasza „migracja nadaje SELECT roli anon, a baza nie" —
czyli kłamie akurat przy tabeli, w której uprawnienia dobrano najstaranniej.

**3. `REVOKE` na poziomie tabeli zdejmuje także nadania kolumnowe.** Tak mówi
dokumentacja Postgresa i tak to jest odgrywane, w kolejności plików migracji.

`ALL` zależy od wersji serwera: `MAINTAIN` doszedł w Postgresie 17, więc na
starszym `grant all` nie obejmuje go i doliczanie tworzyłoby rozjazd przy każdej
tabeli. supadrift czyta `server_version_num` i liczy `ALL` dla tego serwera.

Wyłącza się przez `--no-grants`.

### Wyzwalacze

**Funkcja wyzwalacza to nie to samo co wyzwalacz.** Funkcja może być po obu
stronach, z identycznymi uprawnieniami, a samo **podpięcie** istnieć tylko
w jednym środowisku — i wtedy nie odpala się u nikogo innego. Żadna z wcześniej
opisanych kontroli tego nie widzi.

Porównywane twardo: funkcja, moment (`before`/`after`/`instead of`), zdarzenia
(kolejność nie ma znaczenia), `UPDATE OF` z listą kolumn, poziom
(`row`/`statement`), stan (włączony/wyłączony/replika) oraz obecność `WHEN`.
Treść `WHEN` — miękko, z tego samego powodu co wyrażenia polityk.

Filtr `not tgisinternal` jest tu warunkiem koniecznym, nie kosmetyką: Postgres
zakłada własne, ukryte wyzwalacze dla **każdego klucza obcego**. Bez tego raport
tonąłby w pozycjach `RI_ConstraintTrigger_c_12345`, których nikt nigdy nie
napisze w migracji.

**Wyzwalacze zdarzeniowe są osobnym przypadkiem i najgorszym.** `CREATE EVENT
TRIGGER` wymaga superusera, a rola `postgres`, która wykonuje `supabase db push`,
superuserem na Supabase **nie jest**. Takiego wyzwalacza nie da się więc wdrożyć
migracją i siłą rzeczy zakłada się go ręcznie — po czym repozytorium nie wie
o nim nic, a świeże środowisko go nie dostaje.

Dla tego przypadku jest `allowManual`. **Nie ucisza** pozycji, tylko przenosi ją
do osobnej sekcji „POZA MIGRACJAMI, ŚWIADOMIE": nie liczy się do kodu wyjścia,
ale jest wypisywana w każdym raporcie. Wyzwalacz zakładany ręcznie ma być
widoczny zawsze — inaczej za pół roku nikt nie będzie pamiętał, że nowe
środowisko wymaga dodatkowego kroku.

Wyłącza się przez `--no-triggers`.

### Polityki

Twardo porównywane jest to, czego Postgres nie przepisuje: polecenie
(`for select` / `insert` / …), rodzaj (`permissive` / `restrictive`), lista ról
oraz sama **obecność albo brak** `USING` i `WITH CHECK`. Domyślne wartości są tu
ważniejsze niż zwykle, bo prawie nikt ich nie pisze, a decydują o zasięgu:
brak `AS` znaczy `PERMISSIVE` (polityki sumują się przez OR, nie zawężają),
brak `FOR` znaczy `ALL`, brak `TO` znaczy **`public`, czyli każda rola, także
`anon`**.

Treść wyrażeń to osobna sprawa i warto wiedzieć dlaczego. **Postgres nie
przechowuje tekstu, który napisałeś** — przechowuje drzewo i odtwarza z niego
tekst na żądanie:

```
w migracji      (select auth.uid()) = user_id
pg_get_expr()   (( SELECT auth.uid() AS uid) = user_id)
```

Doszły nawiasy obejmujące całość i alias kolumny w podzapytaniu. Porównanie
napis do napisu zgłaszałoby rozjazd przy **każdej** polityce — a narzędzie, które
zgłasza wszystko, nie zgłasza niczego. Dlatego obie strony sprowadzamy do
strumienia tokenów i zdejmujemy dokładnie te dwie rzeczy, które Postgres dokłada
sam (`src/expr.js`).

Czego to nie załatwia i co jest napisane wprost w raporcie: Postgres przepisuje
też rzutowania (`cast(x as text)` → `(x)::text`), rozwija nazwy operatorów
i domyka schematy. Różnica w samej treści wyrażenia jest więc sygnałem
**„spójrz na to okiem"**, a nie dowodem rozjazdu — i jest tak oznaczona.
Obecność lub brak klauzuli pozostaje twarda. `--no-policy-expr` wyłącza samo
porównywanie treści, resztę zostawia.

Wyłącza się przez `--no-policies`.

### Kontrola zamiaru dla tabel: RLS bez żadnej polityki

Ten sam kształt błędu co przy funkcjach, piętro wyżej. RLS włączone i zero
polityk znaczy, że tabela jest dostępna wyłącznie dla ról z `BYPASSRLS`
(w Supabase: `service_role`) i — jeśli nie ma `FORCE` — dla właściciela.

I teraz rzecz najważniejsza: **dwa całkiem różne przypadki wyglądają w bazie
identycznie.** Tabela celowo zamknięta dla wszystkich poza `service_role` i tabela,
przy której ktoś włączył RLS i zapomniał polityki, mają w katalogu ten sam zapis.
Żadne zapytanie ich nie rozróżni, bo różnica siedzi w zamiarze.

Dlatego jedynym uczciwym rozwiązaniem jest lista wyjątków. Tabele zamknięte
świadomie wpisuje się raz i przestają się odzywać; każda **nowa** tabela w tym
stanie zgłosi się sama. Cisza znaczy wtedy „sprawdzone i zamierzone", a nie
„przeoczone".

## Listy wyjątków — `supadrift.json`

Wyjątek jest faktem o projekcie, a nie o jednym uruchomieniu, więc jego miejsce
jest w repozytorium obok migracji, a nie w historii powłoki. supadrift szuka
`supadrift.json` w bieżącym katalogu, a potem w katalogu projektu Supabase (tym,
w którym leży `supabase/`); można też wskazać go przez `--config`.

```json
{
  "allowNoPolicy": [
    "public.quota_usage"
  ],
  "allowOwnerOnly": [
    "public.tylko_dla_cron()"
  ],
  "allowSearchPath": [],
  "allowManual": ["rls_guard"],
  "ignoreRoles": []
}
```

Klucze zaczynające się od `$` są ignorowane — to miejsce na powód, dla którego
wyjątek istnieje. Wyjątek bez uzasadnienia po pół roku jest nie do odróżnienia
od przeoczenia.

**W tym pliku nie wolno trzymać poświadczeń.** supadrift ich stąd nie czyta —
adres i klucz biorą się wyłącznie ze zmiennej środowiskowej albo z `.env`.

## Co znaczy „czysto"

Brak zgłoszeń ma znaczyć „sprawdziłem i się zgadza", a nie „nie umiem
sprawdzić". Dlatego:

- Wszystko, czego parser **nie odwzorował**, ląduje w raporcie w osobnej sekcji
  „Czego supadrift nie odczytał z migracji" — `ALTER DEFAULT PRIVILEGES`,
  `GRANT ... ON ALL FUNCTIONS IN SCHEMA`, `GRANT`/`REVOKE` wewnątrz bloku
  `DO $$`, `SECURITY LABEL`, `REASSIGN OWNED`. Dopóki tam cokolwiek stoi,
  „czysto" znaczy „czysto poza tym".
- Uprawnienie nadane funkcji, której `CREATE` nie ma w katalogu, też jest
  odnotowane, a nie przemilczane.

- Treść wyrażeń w politykach jest porównywana po normalizacji i **oznaczona jako
  miękka**. Raport mówi wprost, że różnica może być tylko innym zapisem tego
  samego. Nie udajemy pewności, której nie ma.

### Padnij głośno albo przejdź — nigdy nie zwracaj po cichu zera

Najgorszy możliwy wynik tego narzędzia to **„czysto" przy nieodczytanym
wejściu**: mówi człowiekowi, że sprawdził, podczas gdy nie sprawdził nic.
Dlatego następujące sytuacje są **błędami krytycznymi z kodem 2**, a nie
ostrzeżeniami:

| sytuacja | dlaczego fatalna |
|---|---|
| urwane `$$`, literał, identyfikator lub komentarz blokowy | plik jest ucięty; tokenizer jest wyrozumiały i bez tego udałby, że przeczytał całą funkcję |
| niezbilansowane nawiasy | to samo — reszta pliku jest już zgadywaniem |
| bajt `0x00` w pliku `.sql` | to nie jest tekst, który ktoś napisał |
| plik `.sql` nie do odczytania (`EACCES`, `EISDIR`) | tej migracji **nie przeczytaliśmy**; pominięcie jej po cichu fałszuje wynik |
| katalog bez ani jednego pliku `.sql` | pusty obraz oczekiwany porównany z bazą daje wynik, któremu nie wolno ufać |
| `--as-of` odsiewający wszystkie migracje | nie ma z czego zbudować obrazu |
| niepoprawny `supadrift.json` | listy wyjątków są częścią definicji „czysto" |

Tokenizer zbiera uszkodzenia do osobnego kanału (`tokenize(sql, issues)`),
a `buildExpected()` zamienia je na wyjątek — raport nie powstaje w ogóle.

Każdy z tych scenariuszy ma w `test/odpornosc.test.js` **parę**: uruchomienie
uszkodzone i zdrowe na tym samym kształcie wejścia. Bez drugiej połowy pierwsza
nic by nie dowodziła — przechodziłaby także wtedy, gdyby narzędzie padało
zawsze i wszędzie.

Ślepą plamkę samego porównania — błąd, w którym pliki i baza mylą się tak samo —
zdejmują dwie kontrole zamiaru: dla funkcji (`EXECUTE` po `revoke` od `public`)
i dla tabel (RLS bez żadnej polityki). Obie patrzą na jeden obraz zamiast
porównywać dwa.

## Znana odpowiedź

Narzędzie powstało z konkretnego błędu i ten błąd jest jego testem odniesienia.
Nazwy poniżej są zneutralizowane; **fixtures w `test/` używają prawdziwych nazw
z prywatnego projektu autora i uruchamiają się tylko tam** — dlatego zostały
takie, jakie są. Kształt sprawdzenia jest identyczny.

Stan **sprzed** naprawy (`--as-of` udaje, że późniejszych migracji jeszcze nie
ma):

```
$ supadrift --via-cli --as-of 20240115130000 --only quota

JEST W OBU, ALE INACZEJ  (1)
  public.refund_quota(uuid, text)
      service_role     baza ma EXECUTE, w migracjach tego nadania NIE MA
      ostatnia zmiana uprawnien w migracjach:
        20240115120000_refund_quota.sql:58 (revoke public, anon, authenticated)
```

Wskazuje plik i wiersz. Zdrowa siostra `claim_quota`, która ma komplet
`revoke` + `grant`, milczy w tym samym przebiegu — to kontrola negatywna
wewnątrz kontroli pozytywnej.

W tym samym przebiegu odzywa się kontrola zamiaru i sama odtwarza linię, którą
człowiek dopisał ręcznie dopiero dwie migracje później:

```
NIE MA KTO WOLAC  (1)
  public.refund_quota(uuid, text)     martwa: w migracjach
      poza wlascicielem (postgres) EXECUTE nie ma nikt
      revoke bez pary: 20240115120000_refund_quota.sql:58 (od public, anon, authenticated)
      zadna inna funkcja SQL jej nie wola — wolajacy jest poza baza
      brakujaca polowa pary najpewniej brzmi:
        grant execute on function public.refund_quota(uuid, text) to service_role;
```

Na pełnym zestawie migracji `refund_quota` nie zgłasza się w ogóle.

**Dzień wdrożenia.** Najważniejszy przypadek to ten, w którym baza była z migracją
zgodna i obie były w błędzie. Rozjazd wynosi tam **zero**, a kontrola zamiaru
i tak mówi `martwa: w obu`. Ten scenariusz jest zapięty w
`test/intent.test.js` jako pierwszy test i chodzi bez bazy.

Wszystkie przebiegi: `npm test` — 180 testów, bez połączenia z czymkolwiek.

## Sześć wyzwalaczy, których nie było w atrapie

Przez długi odcinek powstawania to narzędzie nie miało dostępu do żywej bazy:
Management API zwracało 403, a hasła do połączenia bezpośredniego nie było. Było
więc weryfikowane offline — na obrazie bazy złożonym z samych migracji plus
wierszy odczytanych wcześniej ręcznie.

Ta weryfikacja nie była teatrem. Znalazła prawdziwe usterki: bajt NUL, który
rozjeżdżał klucz wyszukiwania, wyrażenie regularne odmawiające dopasowania
wywołań kwalifikowanych schematem, widmową tabelę produkowaną przez
`ON ALL TABLES IN SCHEMA`. Gdy model nadań na tabelach skonfrontowano później
z produkcją, zgodził się co do litery.

**A potem pierwszy przebieg na prawdziwej bazie zwrócił sześć zgłoszeń, których
żadna atrapa nigdy nie zawierała.**

```
WYZWALACZE — JEST W BAZIE, NIE MA W MIGRACJI  (6)
  event trigger pgrst_ddl_watch            ->  extensions.pgrst_ddl_watch()
  event trigger pgrst_drop_watch           ->  extensions.pgrst_drop_watch()
  event trigger issue_pg_cron_access       ->  extensions.grant_pg_cron_access()
  event trigger issue_pg_graphql_access    ->  extensions.grant_pg_graphql_access()
  event trigger issue_pg_net_access        ->  extensions.grant_pg_net_access()
  event trigger issue_graphql_placeholder  ->  extensions.set_graphql_placeholder()
```

To są własne wyzwalacze platformy Supabase. Stoją w **każdym** projekcie, należą
do `supabase_admin`, a ich funkcje mieszkają w schemacie `extensions`. Nigdy nie
pojawią się w niczyich migracjach, a zgłaszanie ich to czysty hałas — ten
rodzaj, po którym narzędzie zostaje wyłączone w pierwszym tygodniu.

Przyczyną była luka w zakresieniu. Wyzwalacz zdarzeniowy jest obiektem **całej
bazy**, nie schematu — i właśnie dlatego nie przyszło mi do głowy, że `--schema`
dotyczy też jego. Każda inna kontrola była zakresiona, ta jedna nie. Poprawka
zakresia wyzwalacze zdarzeniowe po schemacie funkcji, którą wołają: `extensions`
odpada, `public` zostaje. Rozróżnienie jest czyste i nie wymaga wpisywania na
sztywno nazwy roli Supabase.

**I teraz rzecz, którą warto zapamiętać.** Atrapa może zawierać wyłącznie to, co
jej autor już wie. To jest dokładnie ta klasa usterek, której nie jest w stanie
złapać — nie dlatego, że atrapa była niestaranna, tylko dlatego, że odtworzony
obraz powstaje z tych samych założeń co sprawdzany kod. Weryfikacja offline
dowodzi poprawności parsera i porównania. Nie dowodzi poprawności *zapytania*:
tego, co baza naprawdę zawiera i co jeszcze w niej stoi, czego nikt nie wpisał
do migracji.

Narzędzie, którego zadaniem jest porównywanie plików z bazą, musi być sprawdzone
NA bazie. Nie zamiast testów offline — te złapały usterki, których żywy przebieg
by nie pokazał — tylko dodatkowo, i zanim komukolwiek powie się, że wynik coś
znaczy.

To także powód, dla którego zestaw znanych odpowiedzi używa prawdziwych nazw
z prywatnego projektu i uruchamia się tylko tam. Test, który chodzi wszędzie,
sprawdza wyłącznie to, co jego autor sobie wyobraził.

## Bramka, która przechodziła, nie sprawdzając nic

Ta sama wada ma w tym repozytorium drugie wcielenie i to zabawniejsze, bo ofiarą
padł sam sprawdzający.

`tools/readme-gate.js` weryfikuje, czy README mówi prawdę: wyciąga bloki kodu,
uruchamia polecenia, porównuje każdą liczbę z rzeczywistym wynikiem i odtwarza
przykład zgłoszenia prawdziwym rendererem. W drzewie roboczym przechodziła.

Potem uruchomiono ją na **świeżym `git clone`** — i znalazła **zero bloków kodu**.
Git przy checkoucie na Windows zamienia LF na CRLF, a wzorzec ekstraktora
oczekiwał gołego `\n` po otwierającym ogrodzeniu. Każda kontrola oparta na tych
blokach porównywała od tej chwili zbiór pusty: żadnych opcji do sprawdzenia,
żadnego JSON-a do sparsowania, żadnych poleceń do uruchomienia.

Część z nich padła głośno i tak to wyszło. Ale to był przypadek, nie projekt —
przy odrobinę łagodniejszej asercji bramka wypisałaby czyste świadectwo, nie
sprawdziwszy **niczego**. Czyli dokładnie ten wynik, którego supadrift ma
odmawiać: „czysto" na wejściu, którego nikt nie przeczytał.

Poprawka ma dwie połowy i druga jest ważniejsza:

1. Normalizacja końców linii przy odczycie.
2. **Pusty zbiór jest błędem.** Każda kontrola operująca na zbiorze przechodzi
   przez jeden helper, który odmawia przy liczbie zero, a liczba stoi w wyniku —
   `opcje zgodne z --help (26)`, `odnosniki wzgledne (3)`. Zero widać gołym
   okiem, zamiast chować się za `OK`.

Z celowo usuniętą normalizacją bramka wypisuje teraz `sprawdzono ZERO elementow`
i kończy kodem 1. Błąd nie potrafi już udać sukcesu.

Kontrola, która potrafi po cichu nic nie znaleźć, musi paść, a nie przejść. To ta
sama zasada co „padnij głośno albo przejdź, nigdy nie zwracaj po cichu zera" —
i okazuje się równie łatwa do złamania w sprawdzającym, co w sprawdzanym.

## Jeszcze dwa razy to samo i reguła, która z tego wyszła

Ostatnia praca w tym repozytorium była kosmetyczna: zmiana polskich
identyfikatorów na angielskie przed publikacją. Komentarze i raport na ekran
zostawały po polsku, zmieniały się wyłącznie nazwy. Mechanicznie, niskiego
ryzyka, plik po pliku, z `npm test` po każdym. **156 na 156 przechodziło na
każdym kroku.**

I mimo to poszło źle dwa razy, a oba razy miały ten sam kształt co powyżej.

**Zmiana nazw weszła w napisy wypisywane na ekran.** `liczba` → `count`
zamieniło `'deklarowana liczba testow'` na `'deklarowana count testow'`. `padlo`
→ `failed` zamieniło `'przeszlo 156, padlo 0'` na `'przeszlo 156, failed 0'`.
Raport stał się półpolski, półangielski — dokładnie w miejscach, które człowiek
czyta najpierw.

Zestaw testów tego nie zauważył. Nie mógł: żaden test nie sprawdza akurat tych
zdań, a *zachowanie* programu nie zmieniło się ani o jotę. Złapała to bramka
README przy najbliższym uruchomieniu, bo bramka nie sprawdza zachowania — sprawdza
powierzchnię, zestawiając to, co program wypisuje, z tym, co obiecuje
dokumentacja.

**Sama zmiana nazw czasem nie robiła nic.** Puszczona przez powłokę, podmiana
gubiła granice słów we wzorcu. Jedno wywołanie zgłosiło `78 podmian`, drugie,
identyczne co do budowy, podmieniło zero. A `npm test` przechodził w obu
przypadkach — bo w tym nieudanym nic się nie zmieniło, a zestaw, który był
zielony przed pustą operacją, jest zielony i po niej.

I to jest pułapka warta nazwania. **Zielony zestaw testów mówi, że zachowanie się
nie zepsuło. Nie mówi, że praca została wykonana.** Po przebudowie, która po cichu
zawiodła, jedno od drugiego jest z zewnątrz nie do odróżnienia: te same testy, ten
sam wynik, ta sama pewność — i zero pracy.

Stąd reguła, wdrożona teraz w dwóch miejscach, a nie tylko opisana:

> Każda operacja, która potrafi po cichu nic nie zrobić, musi zgłaszać **ile**
> zrobiła, a zero traktować jako błąd.

- `recordSet()` w `tools/readme-gate.js` odmawia przy liczbie zero i wypisuje
  liczbę w wyniku.
- Narzędzie do zmiany nazw wypisuje liczbę podmian na plik i kończy kodem
  niezerowym, gdy suma wynosi zero.

Trzy wcielenia w jednym repozytorium — bramka, która nic nie zweryfikowała,
zmiana nazw, która nic nie zmieniła, i napisy, które popsuły się bez reakcji
choćby jednego testu. Kształt za każdym razem identyczny: operacja melduje
sukces, nie wykonawszy się. To ta sama wada, którą całe to narzędzie tropi
w bazie danych — i okazuje się, że w oprzyrządowaniu, które ją ściga, nie jest
o nią ani trochę trudniej.

## Opcje

```
--migrations <katalog>  katalog z migracjami (domyślnie ./supabase/migrations)
--via-cli               czytaj bazę przez `supabase db query --linked`
--workdir <katalog>     katalog projektu Supabase dla --via-cli
--schema <nazwa>        schemat do sprawdzenia, można powtórzyć (domyślnie public)
--as-of <prefiks>       pomiń migracje późniejsze niż podany prefiks nazwy
--only <fragment>       tylko funkcje, których nazwa zawiera fragment
--ignore-role <rola>    pomijaj tę rolę przy porównaniu, można powtórzyć
--no-intent             pomiń kontrolę zamiaru (funkcje bez wołającego)
--no-tables             pomiń sprawdzenie tabel (RLS i FORCE)
--no-policies           pomiń sprawdzenie polityk
--no-triggers           pomiń wyzwalacze tabelowe i zdarzeniowe
--no-secdef             pomiń kontrolę search_path w SECURITY DEFINER
--no-grants             pomiń nadania na tabelach i kolumnach
--no-policy-expr        porównuj polityki bez treści wyrażeń USING/WITH CHECK
--allow-owner-only <f>  ta funkcja MA być dostępna tylko dla właściciela,
                        można powtórzyć; przyjmuje nazwę albo pełny podpis
--allow-search-path <f> ta funkcja SECURITY DEFINER MA taki search_path, jaki ma
--allow-no-policy <t>   ta tabela MA mieć RLS bez polityk, można powtórzyć
--allow-manual <nazwa>  ten wyzwalacz jest zakładany ręcznie, poza migracjami
--hide-target           nie pokazuj hosta ani identyfikatora projektu
--sarif <plik>          zapisz wynik jako SARIF 2.1.0 (kod wyjścia wtedy 0)
--sarif-base <katalog>  korzeń repozytorium dla ścieżek w SARIF
--config <plik>         plik z listami wyjątków (domyślnie supadrift.json)
--fix <plik>            zapisz migrację naprawczą do pliku
--no-fix                nie wypisuj migracji naprawczej na ekran
--json                  wynik jako JSON
--env-file <plik>       skąd czytać .env (domyślnie ./.env)
-h, --help
```

`--as-of` przydaje się nie tylko do testów: odpowiada na pytanie „jak
wyglądałby rozjazd, gdyby ostatnie migracje jeszcze nie weszły".

## W CI

Raport w terminalu trzeba pamiętać uruchomić. Z SARIF-em wynik pojawia się
**przy linii kodu w pull requeście**, jako adnotacja, i w zakładce Security.
To różnica między narzędziem, które trzeba pamiętać, a takim, które samo się
odzywa.

Gotowy plik do skopiowania: [`.github/workflows/example.yml`](.github/workflows/example.yml).
Skrót:

```yaml
permissions:
  contents: read
  security-events: write        # wymagane przez upload-sarif

- name: Porownanie migracji z baza
  env:
    SUPADRIFT_DB_URL: ${{ secrets.SUPADRIFT_DB_URL }}   # NIGDY jako argument
  run: |
    node tools/supadrift/bin/supadrift.js \
      --migrations supabase/migrations \
      --sarif supadrift.sarif \
      --sarif-base . \
      --hide-target \
      --no-fix

- uses: github/codeql-action/upload-sarif@v3
  if: always() && hashFiles('supadrift.sarif') != ''
  with:
    sarif_file: supadrift.sarif
    category: supadrift
```

### Zgłoszenia nie wywracają budowania

Z `--sarif` kod wyjścia to **zawsze 0**, niezależnie od liczby zgłoszeń.
Wyniki idą do zakładki Security, a nie do wyniku budowania. Narzędzie, które
przy pierwszym zetknięciu blokuje merge, zostaje wyłączone w tym samym tygodniu
i wtedy nie zgłasza już nic.

**Wyjątek jest jeden i celowy: błąd krytyczny nadal daje kod 2** — nieodczytana
migracja, uszkodzony plik, brak połączenia. „Nie udało się sprawdzić" to co
innego niż „sprawdzone i czysto", i przebieg CI ma o tym powiedzieć głośno.

### Dlaczego wszystko jest `note`, nigdy `error`

`level` w SARIF nie steruje wynikiem budowania — steruje tym, jak alert wygląda
i czy przebija się do przeglądu. Ustawienie `error` nie dałoby więc nic poza
hałasem, a hałas kończy się wyłączeniem narzędzia.

Merytorycznie też jest to uczciwsze. Część zgłoszeń to twarde fakty z katalogu
(„migracja nadaje EXECUTE roli `service_role`, baza tego nadania nie ma"), ale
część wymaga decyzji człowieka i nie ma prawa udawać wyroku:

- treść wyrażeń w politykach i klauzula `WHEN` — Postgres przepisuje je po
  swojemu, więc różnica bywa czysto zapisowa;
- obie kontrole zamiaru — „funkcja bez wołającego" i „RLS bez polityk" są
  pytaniem o zamiar, a nie stwierdzeniem błędu;
- „jest w bazie, nie ma w migracji" bywa uzgodnionym krokiem ręcznym
  (patrz `allowManual`).

### Identyfikatory reguł

Każde zgłoszenie ma `ruleId` w rodzaju `supadrift/security-definer-search-path`.
**Ten sam identyfikator jest w raporcie tekstowym**, w sekcji „ZGŁOSZENIA WEDŁUG
REGUŁ" — oba wyjścia powstają z jednej funkcji (`zebrane()` w `src/sarif.js`),
więc nie mogą się rozjechać. Pełny katalog: `src/rules.js`.

### Ścieżki i kotwice

`--sarif-base` musi wskazywać korzeń repozytorium: GitHub dopasowuje alerty po
ścieżce **względnej**, pisanej ukośnikami w przód. Ścieżka bezwzględna albo
wychodząca poza korzeń da alert bez kotwicy — supadrift ostrzega o tym na stderr.

Zgłoszenia „jest w bazie, nie ma w migracji" z definicji nie mają pliku
źródłowego. Żeby alert w ogóle powstał, kotwiczymy je na **najnowszej migracji,
w pierwszym wierszu**, i piszemy to wprost w treści komunikatu — kotwica
wskazuje miejsce w zestawie migracji, a nie miejsce błędu.

### Zgodność ze schematem

Plik jest sprawdzany **oficjalnym schematem OASIS** (`ajv-draft-04`, schemat
w `test/fixtures/`), a nie oglądany okiem. Testy sprawdzają też wymagania GitHub
code scanning, których schemat nie wymusza: `startLine >= 1`, poprawny
`ruleIndex`, `partialFingerprints` (bez nich alerty gubią się przy przesunięciu
linii) i ścieżki względne. Jest też kontrola negatywna samego walidatora —
inaczej „przechodzi schemat" nic by nie znaczyło.

## Dlaczego tokenizer, a nie tree-sitter

`GRANT` i `REVOKE` to płaskie, regularne DDL. Pełne drzewo składniowe nic tu nie
dodaje, a kosztuje zależność i gramatykę, którą trzeba utrzymywać razem z każdą
wersją Postgresa.

Jedyna pułapka jest jedna i konkretna: **cytowanie dolarowe**. Ciało `plpgsql`
stoi między `$$` a `$$` i jest pełne średników; naiwne `sql.split(';')` rozcina
je na kawałki i wszystko dalej jest już zgadywaniem. Dlatego dzielenie na
instrukcje idzie po tokenach. `src/tokenizer.js` obsługuje `$$` i `$tag$`,
`--` i zagnieżdżalne `/* */`, `'...'` z podwojeniem, `E'...'` z odwrotnym
ukośnikiem, `"..."` z zachowaniem wielkości liter oraz `$1` jako parametr
pozycyjny, a nie początek cytowania. Każdy z tych przypadków ma test.

## Dalej

1. **Sekwencje i nadania na nich.** Ten sam model co tabele, inne litery ACL.
2. **`ALTER DEFAULT PRIVILEGES` w migracjach.** Dziś jest odnotowane jako
   nieobsłużone; modelowanie go pozwoliłoby porównać także samą linię bazową,
   a nie tylko brać ją z bazy jako daną.
3. **Kolumny i typy.** Najszerszy zakres i najwięcej hałasu — dlatego ostatni.

## Licencja

MIT. Patrz [LICENSE](LICENSE).
