#!/usr/bin/env node
'use strict';

// ---------------------------------------------------------------------------
// Bramka: czy README mowi prawde
// ---------------------------------------------------------------------------
//
// ZASADA. Nie porownujemy tekstu z tekstem. Kazde polecenie z bloku kodu jest
// URUCHAMIANE, kazda count porownywana z wynikiem, kazdy odnosnik wzgledny
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
const ROOT = args.includes('--root')
  ? path.resolve(args[args.indexOf('--root') + 1])
  : path.resolve(__dirname, '..');

const EN = path.join(ROOT, 'README.md');
const PL = path.join(ROOT, 'README.pl.md');
const BIN = path.join(ROOT, 'bin', 'supadrift.js');

const results = [];
function record(label, ok, detail) {
  results.push({ label, ok, detail: detail || '' });
}

/**
 * Sprawdzenie, ktore policzylo ZERO elementow, nie jest sprawdzeniem — jest
 * cisza udajaca zgode. Tak wlasnie zachowala sie ta bramka na pierwszym
 * swiezym klonie: git zamienil LF na CRLF, ekstraktor blokow nie znalazl nic,
 * a czesc kontrol "przeszla", nie porownujac niczego z niczym.
 *
 * Dlatego kazda kontrola operujaca na zbiorze przechodzi przez ten helper:
 * pusty zbior jest bledem, a count sprawdzonych elementow stoi w wyniku,
 * zeby dalo sie ja zobaczyc golym okiem.
 */
function recordSet(label, count, ok, detail) {
  if (count === 0) {
    results.push({
      label: label + ' (0)',
      ok: false,
      detail: 'sprawdzono ZERO elementow — kontrola nie mialaby czego oblac',
    });
    return;
  }
  results.push({ label: label + ' (' + count + ')', ok, detail: detail || '' });
}
function skip(label, reason) {
  results.push({ label, skip: true, detail: reason });
}

function readFile(p) {
  // Klon z gita moze miec CRLF, drzewo robocze LF. Bez normalizacji ekstraktor
  // blokow nie znajduje niczego i bramka "przechodzi" nie sprawdzajac nic.
  const CR = String.fromCharCode(13);
  const LF = String.fromCharCode(10);
  return fs.readFileSync(p, 'utf8').split(CR + LF).join(LF);
}

/** Wyciaga codeBlocks ``` z jezykiem. */
function codeBlocks(text) {
  const out = [];
  const re = /```([a-z]*)\n([\s\S]*?)```/g;
  let m;
  while ((m = re.exec(text)) !== null) out.push({ lang: m[1], content: m[2] });
  return out;
}

function run(argv, opts = {}) {
  return spawnSync(process.execPath, [BIN, ...argv], {
    encoding: 'utf8',
    timeout: opts.timeout || 120000,
    cwd: opts.cwd || os.tmpdir(),
    env: Object.assign({}, process.env, opts.env || {}),
  });
}

function dirWithMigration(content) {
  const d = fs.mkdtempSync(path.join(os.tmpdir(), 'bramka-'));
  fs.writeFileSync(path.join(d, '001.sql'), content, 'utf8');
  return d;
}

// --- 1. odnosniki wzgledne ---------------------------------------------------

function checkLinks() {
  for (const [label, file] of [['README.md', EN], ['README.pl.md', PL]]) {
    const text = readFile(file);
    const targets = [...text.matchAll(/\]\(([^)]+)\)/g)]
      .map((m) => m[1])
      .filter((c) => !/^https?:|^#|^mailto:/.test(c));
    const missingFiles = targets.filter((c) => !fs.existsSync(path.join(ROOT, c.split('#')[0])));
    recordSet(label + ': odnosniki wzgledne', targets.length,
      missingFiles.length === 0,
      missingFiles.length ? 'missing plikow: ' + missingFiles.join(', ') : targets.join(', '));
  }
}

// --- 2. count testow --------------------------------------------------------

function checkTestCount() {
  const r = spawnSync('npm', ['test'], {
    cwd: ROOT, encoding: 'utf8', timeout: 600000, shell: true,
  });
  const out = (r.stdout || '') + (r.stderr || '');
  const m = /^# pass (\d+)$/m.exec(out) || /pass (\d+)/.exec(out);
  const passed = m ? Number(m[1]) : null;
  const failedCount = (/^# fail (\d+)$/m.exec(out) || /fail (\d+)/.exec(out) || [])[1];

  record('npm test przechodzi', passed !== null && Number(failedCount || 0) === 0,
    'przeszlo ' + passed + ', padlo ' + (failedCount || '?'));

  for (const [label, file, pattern] of [
    ['README.md', EN, /(\d+)\s+tests/],
    ['README.pl.md', PL, /(\d+)\s+test[oó]w/],
  ]) {
    const t = readFile(file);
    const declared = pattern.exec(t);
    record(label + ': deklarowana liczba testow',
      !!declared && Number(declared[1]) === passed,
      declared ? 'README mowi ' + declared[1] + ', naprawde ' + passed : 'missing deklaracji w README');
  }
}

// --- 3. opcje: README kontra --help -----------------------------------------

function checkOptions() {
  const r = run(['--help']);
  record('--help konczy sie kodem 0', r.status === 0, 'kod ' + r.status);
  const fromHelp = new Set([...(r.stdout || '').matchAll(/^\s{2}(--[a-z-]+)/gm)].map((m) => m[1]));

  for (const [label, file] of [['README.md', EN], ['README.pl.md', PL]]) {
    const t = readFile(file);
    const block = codeBlocks(t).find((b) => /^--migrations/m.test(b.content));
    const fromReadme = new Set(block
      ? [...block.content.matchAll(/^(--[a-z-]+)/gm)].map((m) => m[1])
      : []);

    const inventedInReadme = [...fromReadme].filter((o) => !fromHelp.has(o));
    const undocumented = [...fromHelp].filter((o) => !fromReadme.has(o));
    recordSet(label + ': opcje zgodne z --help', fromReadme.size,
      inventedInReadme.length === 0 && undocumented.length === 0,
      (inventedInReadme.length ? 'w README, nie ma w kodzie: ' + inventedInReadme.join(' ') : '')
      + (undocumented.length ? '  undocumented: ' + undocumented.join(' ') : ''));
  }
}

// --- 4. kody wyjscia ---------------------------------------------------------

function checkExitCodes() {
  const brokenDir = dirWithMigration('create function public.f() as $$ begin');
  const healthyDir = dirWithMigration(
    'create function public.f() returns void language plpgsql as $$ begin end; $$;'
  );
  try {
    const r2 = run(['--migrations', brokenDir], { env: { SUPADRIFT_DB_URL: undefined } });
    record('kod 2 przy uszkodzonym wejsciu', r2.status === 2, 'kod ' + r2.status);

    const rBrak = run(['--migrations', healthyDir], { env: { SUPADRIFT_DB_URL: undefined } });
    record('kod 2 przy braku adresu polaczenia', rBrak.status === 2, 'kod ' + rBrak.status);
  } finally {
    fs.rmSync(brokenDir, { recursive: true, force: true });
    fs.rmSync(healthyDir, { recursive: true, force: true });
  }
}

// --- 5. block JSON z supadrift.json ------------------------------------------

function checkJsonBlock() {
  const readKeys = ['allowOwnerOnly', 'allowNoPolicy', 'allowSearchPath', 'allowManual', 'ignoreRoles'];
  for (const [label, file] of [['README.md', EN], ['README.pl.md', PL]]) {
    const block = codeBlocks(readFile(file)).find((b) => b.lang === 'json' && /allow/.test(b.content));
    if (!block) { record(label + ': block supadrift.json', false, 'nie znaleziono bloku'); continue; }
    let cfg = null;
    try { cfg = JSON.parse(block.content); } catch (e) {
      record(label + ': block supadrift.json parsuje sie', false, e.message);
      continue;
    }
    const unknownKeys = Object.keys(cfg).filter((k) => !k.startsWith('$') && !readKeys.includes(k));
    record(label + ': block supadrift.json parsuje sie i uzywa czytanych kluczy',
      unknownKeys.length === 0,
      unknownKeys.length ? 'klucze, ktorych kod nie czyta: ' + unknownKeys.join(', ') : Object.keys(cfg).join(', '));
  }
}

// --- 6. snippet YAML kontra prawdziwy file akcji ----------------------------

function checkYaml() {
  const workflowFile = path.join(ROOT, '.github', 'workflows', 'example.yml');
  if (!fs.existsSync(workflowFile)) { record('file akcji istnieje', false, workflowFile); return; }
  const workflow = readFile(workflowFile);
  const block = codeBlocks(readFile(EN)).find((b) => b.lang === 'yaml');
  if (!block) { record('README.md: snippet YAML', false, 'nie znaleziono'); return; }

  const required = ['security-events: write', 'SUPADRIFT_DB_URL', '--sarif', '--sarif-base',
    'upload-sarif', 'sarif_file'];
  const missing = required.filter((s) => !workflow.includes(s));
  record('README.md: snippet YAML odpowiada plikowi akcji',
    missing.length === 0,
    missing.length ? 'w pliku akcji brakuje: ' + missing.join(', ') : required.length + ' elementow zgodnych');
}

// --- 7. przyklad zgloszenia kontra prawdziwe wyjscie -------------------------
//
// Najwazniejsze sprawdzenie. README pokazuje ksztalt zgloszenia; odtwarzamy ten
// scenariusz PRAWDZIWYM kodem i porownujemy z tym, co narzedzie wypisuje.

function checkFindingExample() {
  const { buildExpected } = require(path.join(ROOT, 'src', 'expected'));
  const { introspect } = require(path.join(ROOT, 'src', 'introspect'));
  const { compare } = require(path.join(ROOT, 'src', 'compare'));
  const { checkOwnerOnly } = require(path.join(ROOT, 'src', 'intent'));
  const { renderReport } = require(path.join(ROOT, 'src', 'report'));

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
      // Dzieki temu report zawiera takze sekcje, ktore README cytuje w rozdziale
      // o szesciu wyzwalaczach — bez nich kontrola naglowkow nie mialaby czego
      // porownac i zglaszalaby prawdziwe naglowki jako nonExistent.
      const { introspectEventTriggers } = require(path.join(ROOT, 'src', 'introspect'));
      const { compareEventTriggers } = require(path.join(ROOT, 'src', 'compare'));
      const evtRow = (name) => ({
        name, event: 'ddl_command_end', enabled: 'O',
        function_schema: 'public', function_name: 'public.f', tags: [],
      });
      const aev = await introspectEventTriggers({
        query: async () => [evtRow('pgrst_ddl_watch'), evtRow('rls_guard')],
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
      const report = renderReport(ctx);

      // Frazy, ktore README obiecuje w tym miejscu — sprawdzane wobec WYNIKU.
      const expected = [
        'JEST W OBU, ALE INACZEJ',
        'public.refund_quota(uuid, text)',
        'service_role',
        'baza ma EXECUTE, w migracjach tego nadania NIE MA',
        '20240115120000_refund_quota.sql',
        'NIE MA KTO WOLAC',
        'grant execute on function public.refund_quota(uuid, text) to service_role;',
      ];
      const missing = expected.filter((f) => !report.includes(f));
      recordSet('przyklad zgloszenia zgadza sie z prawdziwym wyjsciem', expected.length,
        missing.length === 0,
        missing.length ? 'w wyjsciu brakuje: ' + missing.join(' | ') : expected.length + ' fraz zgodnych');

      // Oba README cytuja naglowki sekcji raportu. Sprawdzamy, czy kod NAPRAWDE
      // je wypisuje — README, ktore tlumaczy wyjscie narzedzia, pokazuje cos,
      // czego nikt nigdy nie zobaczy na ekranie.
      for (const [label, file] of [['README.md', EN], ['README.pl.md', PL]]) {
        const quoted = new Set();
        for (const b of codeBlocks(readFile(file))) {
          for (const m of b.content.matchAll(/^([A-Z][A-Z ,—-]{6,})\s*\(\d+\)\s*$/gm)) {
            quoted.add(m[1].trim());
          }
        }
        if (!quoted.size) continue;
        const nonExistent = [...quoted].filter((h) => !report.includes(h));
        recordSet(label + ': quoted naglowki sekcji istnieja w wyjsciu', quoted.size,
          nonExistent.length === 0,
          nonExistent.length
            ? 'kod NIE wypisuje: ' + nonExistent.join(' | ')
            : [...quoted].join(' | '));
      }
    });
  } finally {
    setTimeout(() => fs.rmSync(dir, { recursive: true, force: true }), 100);
  }
}

// --- 8. polecenia z blokow shell --------------------------------------------

function checkCommands() {
  const wszystkie = [];
  for (const file of [EN, PL]) {
    for (const b of codeBlocks(readFile(file))) {
      if (!['bash', 'sh', 'powershell', ''].includes(b.lang)) continue;
      for (const l of b.content.split('\n')) {
        const s = l.trim().replace(/^\$\s*/, '');
        if (/^node bin\/supadrift\.js/.test(s) || /^supadrift\b/.test(s)) wszystkie.push(s);
      }
    }
  }
  const unique = [...new Set(wszystkie)];

  const hasDb = !!(process.env.SUPADRIFT_DB_URL || fs.existsSync(path.join(ROOT, '.env')));
  let executed = 0;
  const failures = [];

  for (const cmd of unique) {
    const argv = cmd.replace(/^node bin\/supadrift\.js\s*/, '').replace(/^supadrift\s*/, '')
      .split(/\s+/).filter(Boolean);

    if (argv.includes('--via-cli')) { skip('polecenie: ' + cmd, 'wymaga Supabase CLI'); continue; }
    if (argv.includes('--migrations') && /\.\.\//.test(cmd)) {
      skip('polecenie: ' + cmd, 'sciezka przykladowa, nie istnieje');
      continue;
    }
    // Takze polecenie BEZ argumentow wymaga bazy — jest w README pokazane jako
    // uruchamiane z katalogu projektu, wiec dochodzi az do warstwy polaczenia.
    if (!argv.includes('--help') && !hasDb) {
      skip('polecenie: ' + cmd, 'wymaga adresu bazy');
      continue;
    }

    // Polecenie bez --migrations jest w README pokazane jako uruchamiane
    // Z KATALOGU PROJEKTU SUPABASE. Zeby je naprawde uruchomic, a nie pominac,
    // budujemy katalog o tym ksztalcie — inaczej sprawdzalibysmy tylko to,
    // ze supadrift nie znajduje migracji tam, gdzie ich nie ma.
    let cwd = ROOT;
    let tempDir = null;
    if (!argv.includes('--migrations') && !argv.includes('--help')) {
      tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'bramka-proj-'));
      fs.mkdirSync(path.join(tempDir, 'supabase', 'migrations'), { recursive: true });
      fs.writeFileSync(
        path.join(tempDir, 'supabase', 'migrations', '001.sql'),
        'create function public.f() returns void language plpgsql as $$ begin end; $$;',
        'utf8'
      );
      if (fs.existsSync(path.join(ROOT, '.env'))) {
        fs.copyFileSync(path.join(ROOT, '.env'), path.join(tempDir, '.env'));
      }
      cwd = tempDir;
    }

    const r = run(argv, { cwd });
    if (tempDir) fs.rmSync(tempDir, { recursive: true, force: true });
    executed++;
    // Kod 0/1 to poprawne results; 2 znaczy blad uruchomienia.
    if (r.status === 2 && !argv.includes('--help')) {
      failures.push(cmd + ' -> kod 2: '
        + ((r.stderr || '').split('\n').find((l) => l.includes('supadrift:')) || '').trim());
    }
  }
  recordSet('polecenia z README uruchamiaja sie (z ' + unique.length + ' znalezionych)', executed,
    failures.length === 0, failures.join(' ; '));
}

// --- 9. metadane paczki ------------------------------------------------------

function checkPackageMetadata() {
  const pkg = JSON.parse(readFile(path.join(ROOT, 'package.json')));
  const en = readFile(EN);
  record('licencja w README zgadza sie z package.json',
    /MIT/.test(en) && pkg.license === 'MIT', 'package.json: ' + pkg.license);
  record('file LICENSE istnieje i nie ma placeholdera',
    fs.existsSync(path.join(ROOT, 'LICENSE'))
    && !/WPISZ|PLACEHOLDER|<.*>/.test(readFile(path.join(ROOT, 'LICENSE'))),
    'author: ' + (pkg.author || '(missing)'));
  const nodeVersion = /node-version: '(\d+)'/.exec(readFile(path.join(ROOT, '.github', 'workflows', 'example.yml')));
  record('wersja Node w akcji spelnia engines z package.json',
    !!nodeVersion && Number(nodeVersion[1]) >= Number(String(pkg.engines.node).replace(/[^\d]/g, '')),
    'workflow: ' + (nodeVersion ? nodeVersion[1] : '?') + ', engines: ' + pkg.engines.node);
}

// --- przebieg ----------------------------------------------------------------

(async () => {
  checkLinks();
  checkPackageMetadata();
  checkJsonBlock();
  checkYaml();
  checkOptions();
  checkExitCodes();
  await checkFindingExample();
  checkCommands();
  checkTestCount();

  console.log('BRAMKA README — ' + ROOT);
  console.log('='.repeat(78));
  let failed = 0;
  for (const w of results) {
    if (w.skip) {
      console.log('  POMIN  ' + w.label + (w.detail ? '   (' + w.detail + ')' : ''));
      continue;
    }
    if (!w.ok) failed++;
    console.log('  ' + (w.ok ? 'OK   ' : 'BLAD ') + '  ' + w.label);
    if (w.detail) console.log('           ' + w.detail);
  }
  console.log('='.repeat(78));
  const skipped = results.filter((w) => w.skip).length;
  console.log('sprawdzen: ' + (results.length - skipped) + ', niezgodnosci: ' + failed
    + ', pominietych: ' + skipped);
  process.exitCode = failed === 0 ? 0 : 1;
})();
