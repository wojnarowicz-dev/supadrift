#!/usr/bin/env node
'use strict';

// ---------------------------------------------------------------------------
// Bramka: czy README mowi prawde
// ---------------------------------------------------------------------------
//
// ZASADA. Nie porownujemy tekstu z tekstem. Kazde polecenie z bloku kodu jest
// URUCHAMIANE, kazda liczba porownywana z wynikiem, kazdy odnosnik wzgledny
// sprawdzany na dysku, a przyklad zgloszenia odtwarzany przez prawdziwy kod
// i zestawiany z tym, co narzedzie faktycznie wypisuje.
//
// Dokumentacja starzeje sie po cichu. Liczba testow, lista opcji, ksztalt
// raportu — kazde z nich rozjezdza sie z kodem bez jednego bledu kompilacji
// i bez jednego czerwonego testu. Ta bramka jest dokladnie tym, czym supadrift
// jest dla migracji: porownaniem opisu z rzeczywistoscia.
//
// UZYCIE
//   node tools/bramka-readme.js [--root <katalog>]
//
// Sprawdzenia wymagajace bazy uruchamiaja sie tylko wtedy, gdy dostepny jest
// adres polaczenia. Pominiete sa WYPISYWANE, nie przemilczane — inaczej
// "bramka przeszla" znaczyloby mniej, niz sie wydaje.

const fs = require('fs');
const os = require('os');
const path = require('path');
const { spawnSync } = require('child_process');

const args = process.argv.slice(2);
const KORZEN = args.includes('--root')
  ? path.resolve(args[args.indexOf('--root') + 1])
  : path.resolve(__dirname, '..');

const EN = path.join(KORZEN, 'README.md');
const PL = path.join(KORZEN, 'README.pl.md');
const BIN = path.join(KORZEN, 'bin', 'supadrift.js');

const wyniki = [];
function zapisz(nazwa, ok, szczegol) {
  wyniki.push({ nazwa, ok, szczegol: szczegol || '' });
}

/**
 * Sprawdzenie, ktore policzylo ZERO elementow, nie jest sprawdzeniem — jest
 * cisza udajaca zgode. Tak wlasnie zachowala sie ta bramka na pierwszym
 * swiezym klonie: git zamienil LF na CRLF, ekstraktor blokow nie znalazl nic,
 * a czesc kontrol "przeszla", nie porownujac niczego z niczym.
 *
 * Dlatego kazda kontrola operujaca na zbiorze przechodzi przez ten helper:
 * pusty zbior jest bledem, a liczba sprawdzonych elementow stoi w wyniku,
 * zeby dalo sie ja zobaczyc golym okiem.
 */
function zapiszZbior(nazwa, liczba, ok, szczegol) {
  if (liczba === 0) {
    wyniki.push({
      nazwa: nazwa + ' (0)',
      ok: false,
      szczegol: 'sprawdzono ZERO elementow — kontrola nie mialaby czego oblac',
    });
    return;
  }
  wyniki.push({ nazwa: nazwa + ' (' + liczba + ')', ok, szczegol: szczegol || '' });
}
function pominiete(nazwa, powod) {
  wyniki.push({ nazwa, pominiete: true, szczegol: powod });
}

function czytaj(p) {
  // Klon z gita moze miec CRLF, drzewo robocze LF. Bez normalizacji ekstraktor
  // blokow nie znajduje niczego i bramka "przechodzi" nie sprawdzajac nic.
  const CR = String.fromCharCode(13);
  const LF = String.fromCharCode(10);
  return fs.readFileSync(p, 'utf8').split(CR + LF).join(LF);
}

/** Wyciaga bloki ``` z jezykiem. */
function bloki(tekst) {
  const out = [];
  const re = /```([a-z]*)\n([\s\S]*?)```/g;
  let m;
  while ((m = re.exec(tekst)) !== null) out.push({ jezyk: m[1], tresc: m[2] });
  return out;
}

function uruchom(argv, opts = {}) {
  return spawnSync(process.execPath, [BIN, ...argv], {
    encoding: 'utf8',
    timeout: opts.timeout || 120000,
    cwd: opts.cwd || os.tmpdir(),
    env: Object.assign({}, process.env, opts.env || {}),
  });
}

function katalogZMigracja(tresc) {
  const d = fs.mkdtempSync(path.join(os.tmpdir(), 'bramka-'));
  fs.writeFileSync(path.join(d, '001.sql'), tresc, 'utf8');
  return d;
}

// --- 1. odnosniki wzgledne ---------------------------------------------------

function sprawdzOdnosniki() {
  for (const [nazwa, plik] of [['README.md', EN], ['README.pl.md', PL]]) {
    const tekst = czytaj(plik);
    const cele = [...tekst.matchAll(/\]\(([^)]+)\)/g)]
      .map((m) => m[1])
      .filter((c) => !/^https?:|^#|^mailto:/.test(c));
    const brakujace = cele.filter((c) => !fs.existsSync(path.join(KORZEN, c.split('#')[0])));
    zapiszZbior(nazwa + ': odnosniki wzgledne', cele.length,
      brakujace.length === 0,
      brakujace.length ? 'brak plikow: ' + brakujace.join(', ') : cele.join(', '));
  }
}

// --- 2. liczba testow --------------------------------------------------------

function sprawdzLiczbeTestow() {
  const r = spawnSync('npm', ['test'], {
    cwd: KORZEN, encoding: 'utf8', timeout: 600000, shell: true,
  });
  const out = (r.stdout || '') + (r.stderr || '');
  const m = /^# pass (\d+)$/m.exec(out) || /pass (\d+)/.exec(out);
  const zdane = m ? Number(m[1]) : null;
  const nieudane = (/^# fail (\d+)$/m.exec(out) || /fail (\d+)/.exec(out) || [])[1];

  zapisz('npm test przechodzi', zdane !== null && Number(nieudane || 0) === 0,
    'przeszlo ' + zdane + ', padlo ' + (nieudane || '?'));

  for (const [nazwa, plik, wzor] of [
    ['README.md', EN, /(\d+)\s+tests/],
    ['README.pl.md', PL, /(\d+)\s+test[oó]w/],
  ]) {
    const t = czytaj(plik);
    const dek = wzor.exec(t);
    zapisz(nazwa + ': deklarowana liczba testow',
      !!dek && Number(dek[1]) === zdane,
      dek ? 'README mowi ' + dek[1] + ', naprawde ' + zdane : 'brak deklaracji w README');
  }
}

// --- 3. opcje: README kontra --help -----------------------------------------

function sprawdzOpcje() {
  const r = uruchom(['--help']);
  zapisz('--help konczy sie kodem 0', r.status === 0, 'kod ' + r.status);
  const zHelp = new Set([...(r.stdout || '').matchAll(/^\s{2}(--[a-z-]+)/gm)].map((m) => m[1]));

  for (const [nazwa, plik] of [['README.md', EN], ['README.pl.md', PL]]) {
    const t = czytaj(plik);
    const blok = bloki(t).find((b) => /^--migrations/m.test(b.tresc));
    const zReadme = new Set(blok
      ? [...blok.tresc.matchAll(/^(--[a-z-]+)/gm)].map((m) => m[1])
      : []);

    const wymysloneWReadme = [...zReadme].filter((o) => !zHelp.has(o));
    const nieudokumentowane = [...zHelp].filter((o) => !zReadme.has(o));
    zapiszZbior(nazwa + ': opcje zgodne z --help', zReadme.size,
      wymysloneWReadme.length === 0 && nieudokumentowane.length === 0,
      (wymysloneWReadme.length ? 'w README, nie ma w kodzie: ' + wymysloneWReadme.join(' ') : '')
      + (nieudokumentowane.length ? '  nieudokumentowane: ' + nieudokumentowane.join(' ') : ''));
  }
}

// --- 4. kody wyjscia ---------------------------------------------------------

function sprawdzKodyWyjscia() {
  const zly = katalogZMigracja('create function public.f() as $$ begin');
  const dobry = katalogZMigracja(
    'create function public.f() returns void language plpgsql as $$ begin end; $$;'
  );
  try {
    const r2 = uruchom(['--migrations', zly], { env: { SUPADRIFT_DB_URL: undefined } });
    zapisz('kod 2 przy uszkodzonym wejsciu', r2.status === 2, 'kod ' + r2.status);

    const rBrak = uruchom(['--migrations', dobry], { env: { SUPADRIFT_DB_URL: undefined } });
    zapisz('kod 2 przy braku adresu polaczenia', rBrak.status === 2, 'kod ' + rBrak.status);
  } finally {
    fs.rmSync(zly, { recursive: true, force: true });
    fs.rmSync(dobry, { recursive: true, force: true });
  }
}

// --- 5. blok JSON z supadrift.json ------------------------------------------

function sprawdzBlokJson() {
  const czytaneKlucze = ['allowOwnerOnly', 'allowNoPolicy', 'allowSearchPath', 'allowManual', 'ignoreRoles'];
  for (const [nazwa, plik] of [['README.md', EN], ['README.pl.md', PL]]) {
    const blok = bloki(czytaj(plik)).find((b) => b.jezyk === 'json' && /allow/.test(b.tresc));
    if (!blok) { zapisz(nazwa + ': blok supadrift.json', false, 'nie znaleziono bloku'); continue; }
    let cfg = null;
    try { cfg = JSON.parse(blok.tresc); } catch (e) {
      zapisz(nazwa + ': blok supadrift.json parsuje sie', false, e.message);
      continue;
    }
    const nieznane = Object.keys(cfg).filter((k) => !k.startsWith('$') && !czytaneKlucze.includes(k));
    zapisz(nazwa + ': blok supadrift.json parsuje sie i uzywa czytanych kluczy',
      nieznane.length === 0,
      nieznane.length ? 'klucze, ktorych kod nie czyta: ' + nieznane.join(', ') : Object.keys(cfg).join(', '));
  }
}

// --- 6. snippet YAML kontra prawdziwy plik akcji ----------------------------

function sprawdzYaml() {
  const plikAkcji = path.join(KORZEN, '.github', 'workflows', 'example.yml');
  if (!fs.existsSync(plikAkcji)) { zapisz('plik akcji istnieje', false, plikAkcji); return; }
  const akcja = czytaj(plikAkcji);
  const blok = bloki(czytaj(EN)).find((b) => b.jezyk === 'yaml');
  if (!blok) { zapisz('README.md: snippet YAML', false, 'nie znaleziono'); return; }

  const istotne = ['security-events: write', 'SUPADRIFT_DB_URL', '--sarif', '--sarif-base',
    'upload-sarif', 'sarif_file'];
  const brak = istotne.filter((s) => !akcja.includes(s));
  zapisz('README.md: snippet YAML odpowiada plikowi akcji',
    brak.length === 0,
    brak.length ? 'w pliku akcji brakuje: ' + brak.join(', ') : istotne.length + ' elementow zgodnych');
}

// --- 7. przyklad zgloszenia kontra prawdziwe wyjscie -------------------------
//
// Najwazniejsze sprawdzenie. README pokazuje ksztalt zgloszenia; odtwarzamy ten
// scenariusz PRAWDZIWYM kodem i porownujemy z tym, co narzedzie wypisuje.

function sprawdzPrzykladZgloszenia() {
  const { buildExpected } = require(path.join(KORZEN, 'src', 'expected'));
  const { introspect } = require(path.join(KORZEN, 'src', 'introspect'));
  const { compare } = require(path.join(KORZEN, 'src', 'compare'));
  const { checkOwnerOnly } = require(path.join(KORZEN, 'src', 'intent'));
  const { renderReport } = require(path.join(KORZEN, 'src', 'report'));

  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'bramka-przyklad-'));
  try {
    // Scenariusz z README: revoke bez pary, baza ma grant dla service_role.
    // Zdrowa siostra JEST czescia scenariusza z README — bez niej podpowiedz
    // roli nie ma sie od kogo uczyc i przyklad nie odtwarza sie wiernie.
    fs.writeFileSync(path.join(dir, '20240110120000_claim_quota.sql'), [
      'create function public.claim_quota(p_user uuid, p_action text)',
      'returns boolean language plpgsql security definer',
      'set search_path = public, pg_temp',
      'as $$ begin return true; end; $$;',
      'revoke all on function public.claim_quota(uuid, text)',
      '  from public, anon, authenticated;',
      'grant execute on function public.claim_quota(uuid, text) to service_role;',
    ].join('\n'), 'utf8');

    fs.writeFileSync(path.join(dir, '20240115120000_refund_quota.sql'), [
      'create function public.refund_quota(p_user uuid, p_action text)',
      'returns void language plpgsql security definer',
      'set search_path = public, pg_temp',
      'as $$ begin end; $$;',
      'revoke all on function public.refund_quota(uuid, text)',
      '  from public, anon, authenticated;',
    ].join('\n'), 'utf8');

    const e = buildExpected(dir, { schemas: ['public'] });
    return introspect({
      query: async () => [{
        schema: 'public', name: 'claim_quota', argtypes: ['uuid', 'text'],
        owner: 'postgres', kind: 'f', returns: 'boolean', body: '',
        security_definer: true, config: ['search_path=public, pg_temp'],
        acl: ['postgres=X/postgres', 'service_role=X/postgres'], acl_is_default: false,
      }, {
        schema: 'public', name: 'refund_quota', argtypes: ['uuid', 'text'],
        owner: 'postgres', kind: 'f', returns: 'void', body: '',
        security_definer: true, config: ['search_path=public, pg_temp'],
        acl: ['postgres=X/postgres', 'service_role=X/postgres'], acl_is_default: false,
      }],
      close: async () => {},
    }, { schemas: ['public'] }).then(async (a) => {
      // Wyzwalacze zdarzeniowe: jeden zglaszany, jeden uzgodniony jako reczny.
      // Dzieki temu raport zawiera takze sekcje, ktore README cytuje w rozdziale
      // o szesciu wyzwalaczach — bez nich kontrola naglowkow nie mialaby czego
      // porownac i zglaszalaby prawdziwe naglowki jako nieistniejace.
      const { introspectEventTriggers } = require(path.join(KORZEN, 'src', 'introspect'));
      const { compareEventTriggers } = require(path.join(KORZEN, 'src', 'compare'));
      const wyzw = (name) => ({
        name, event: 'ddl_command_end', enabled: 'O',
        function_schema: 'public', function_name: 'public.f', tags: [],
      });
      const aev = await introspectEventTriggers({
        query: async () => [wyzw('pgrst_ddl_watch'), wyzw('rls_guard')],
        close: async () => {},
      }, { schemas: ['public'] });

      const ctx = {
        result: compare(e.functions, a.functions),
        intent: checkOwnerOnly(e.functions, a.functions, {}),
        eventTriggerResult: compareEventTriggers(new Map(), aev, { allow: ['rls_guard'] }),
        expectedInfo: e,
        actualInfo: { functions: a.functions, tables: new Map(), policies: new Map() },
        target: '(bramka)',
        options: { migrationsDir: dir, schemas: ['public'], asOf: null },
      };
      const raport = renderReport(ctx);

      // Frazy, ktore README obiecuje w tym miejscu — sprawdzane wobec WYNIKU.
      const oczekiwane = [
        'JEST W OBU, ALE INACZEJ',
        'public.refund_quota(uuid, text)',
        'service_role',
        'baza ma EXECUTE, w migracjach tego nadania NIE MA',
        '20240115120000_refund_quota.sql',
        'NIE MA KTO WOLAC',
        'grant execute on function public.refund_quota(uuid, text) to service_role;',
      ];
      const brak = oczekiwane.filter((f) => !raport.includes(f));
      zapiszZbior('przyklad zgloszenia zgadza sie z prawdziwym wyjsciem', oczekiwane.length,
        brak.length === 0,
        brak.length ? 'w wyjsciu brakuje: ' + brak.join(' | ') : oczekiwane.length + ' fraz zgodnych');

      // Oba README cytuja naglowki sekcji raportu. Sprawdzamy, czy kod NAPRAWDE
      // je wypisuje — README, ktore tlumaczy wyjscie narzedzia, pokazuje cos,
      // czego nikt nigdy nie zobaczy na ekranie.
      for (const [nazwa, plik] of [['README.md', EN], ['README.pl.md', PL]]) {
        const cytowane = new Set();
        for (const b of bloki(czytaj(plik))) {
          for (const m of b.tresc.matchAll(/^([A-Z][A-Z ,—-]{6,})\s*\(\d+\)\s*$/gm)) {
            cytowane.add(m[1].trim());
          }
        }
        if (!cytowane.size) continue;
        const nieistniejace = [...cytowane].filter((h) => !raport.includes(h));
        zapiszZbior(nazwa + ': cytowane naglowki sekcji istnieja w wyjsciu', cytowane.size,
          nieistniejace.length === 0,
          nieistniejace.length
            ? 'kod NIE wypisuje: ' + nieistniejace.join(' | ')
            : [...cytowane].join(' | '));
      }
    });
  } finally {
    setTimeout(() => fs.rmSync(dir, { recursive: true, force: true }), 100);
  }
}

// --- 8. polecenia z blokow shell --------------------------------------------

function sprawdzPolecenia() {
  const wszystkie = [];
  for (const plik of [EN, PL]) {
    for (const b of bloki(czytaj(plik))) {
      if (!['bash', 'sh', 'powershell', ''].includes(b.jezyk)) continue;
      for (const l of b.tresc.split('\n')) {
        const s = l.trim().replace(/^\$\s*/, '');
        if (/^node bin\/supadrift\.js/.test(s) || /^supadrift\b/.test(s)) wszystkie.push(s);
      }
    }
  }
  const unikalne = [...new Set(wszystkie)];

  const maBaze = !!(process.env.SUPADRIFT_DB_URL || fs.existsSync(path.join(KORZEN, '.env')));
  let uruchomione = 0;
  const niepowodzenia = [];

  for (const cmd of unikalne) {
    const argv = cmd.replace(/^node bin\/supadrift\.js\s*/, '').replace(/^supadrift\s*/, '')
      .split(/\s+/).filter(Boolean);

    if (argv.includes('--via-cli')) { pominiete('polecenie: ' + cmd, 'wymaga Supabase CLI'); continue; }
    if (argv.includes('--migrations') && /\.\.\//.test(cmd)) {
      pominiete('polecenie: ' + cmd, 'sciezka przykladowa, nie istnieje');
      continue;
    }
    if (argv.length && !argv.includes('--help') && !maBaze) {
      pominiete('polecenie: ' + cmd, 'wymaga adresu bazy');
      continue;
    }

    // Polecenie bez --migrations jest w README pokazane jako uruchamiane
    // Z KATALOGU PROJEKTU SUPABASE. Zeby je naprawde uruchomic, a nie pominac,
    // budujemy katalog o tym ksztalcie — inaczej sprawdzalibysmy tylko to,
    // ze supadrift nie znajduje migracji tam, gdzie ich nie ma.
    let cwd = KORZEN;
    let tymczasowy = null;
    if (!argv.includes('--migrations') && !argv.includes('--help')) {
      tymczasowy = fs.mkdtempSync(path.join(os.tmpdir(), 'bramka-proj-'));
      fs.mkdirSync(path.join(tymczasowy, 'supabase', 'migrations'), { recursive: true });
      fs.writeFileSync(
        path.join(tymczasowy, 'supabase', 'migrations', '001.sql'),
        'create function public.f() returns void language plpgsql as $$ begin end; $$;',
        'utf8'
      );
      if (fs.existsSync(path.join(KORZEN, '.env'))) {
        fs.copyFileSync(path.join(KORZEN, '.env'), path.join(tymczasowy, '.env'));
      }
      cwd = tymczasowy;
    }

    const r = uruchom(argv, { cwd });
    if (tymczasowy) fs.rmSync(tymczasowy, { recursive: true, force: true });
    uruchomione++;
    // Kod 0/1 to poprawne wyniki; 2 znaczy blad uruchomienia.
    if (r.status === 2 && !argv.includes('--help')) {
      niepowodzenia.push(cmd + ' -> kod 2: '
        + ((r.stderr || '').split('\n').find((l) => l.includes('supadrift:')) || '').trim());
    }
  }
  zapiszZbior('polecenia z README uruchamiaja sie (z ' + unikalne.length + ' znalezionych)', uruchomione,
    niepowodzenia.length === 0, niepowodzenia.join(' ; '));
}

// --- 9. metadane paczki ------------------------------------------------------

function sprawdzMetadane() {
  const pkg = JSON.parse(czytaj(path.join(KORZEN, 'package.json')));
  const en = czytaj(EN);
  zapisz('licencja w README zgadza sie z package.json',
    /MIT/.test(en) && pkg.license === 'MIT', 'package.json: ' + pkg.license);
  zapisz('plik LICENSE istnieje i nie ma placeholdera',
    fs.existsSync(path.join(KORZEN, 'LICENSE'))
    && !/WPISZ|PLACEHOLDER|<.*>/.test(czytaj(path.join(KORZEN, 'LICENSE'))),
    'author: ' + (pkg.author || '(brak)'));
  const nodeWymog = /node-version: '(\d+)'/.exec(czytaj(path.join(KORZEN, '.github', 'workflows', 'example.yml')));
  zapisz('wersja Node w akcji spelnia engines z package.json',
    !!nodeWymog && Number(nodeWymog[1]) >= Number(String(pkg.engines.node).replace(/[^\d]/g, '')),
    'akcja: ' + (nodeWymog ? nodeWymog[1] : '?') + ', engines: ' + pkg.engines.node);
}

// --- przebieg ----------------------------------------------------------------

(async () => {
  sprawdzOdnosniki();
  sprawdzMetadane();
  sprawdzBlokJson();
  sprawdzYaml();
  sprawdzOpcje();
  sprawdzKodyWyjscia();
  await sprawdzPrzykladZgloszenia();
  sprawdzPolecenia();
  sprawdzLiczbeTestow();

  console.log('BRAMKA README — ' + KORZEN);
  console.log('='.repeat(78));
  let padlo = 0;
  for (const w of wyniki) {
    if (w.pominiete) {
      console.log('  POMIN  ' + w.nazwa + (w.szczegol ? '   (' + w.szczegol + ')' : ''));
      continue;
    }
    if (!w.ok) padlo++;
    console.log('  ' + (w.ok ? 'OK   ' : 'BLAD ') + '  ' + w.nazwa);
    if (w.szczegol) console.log('           ' + w.szczegol);
  }
  console.log('='.repeat(78));
  const pom = wyniki.filter((w) => w.pominiete).length;
  console.log('sprawdzen: ' + (wyniki.length - pom) + ', niezgodnosci: ' + padlo
    + ', pominietych: ' + pom);
  process.exitCode = padlo === 0 ? 0 : 1;
})();
