#!/usr/bin/env node
'use strict';

const fs = require('fs');
const path = require('path');

const secrets = require('../src/secrets');
const { buildExpected } = require('../src/expected');
const {
  introspect, introspectTables, introspectPolicies, introspectColumnAcls, introspectDefaultAcl,
  introspectTriggers, introspectEventTriggers,
} = require('../src/introspect');
const {
  compare, compareTables, comparePolicies, compareTriggers, compareEventTriggers, total,
} = require('../src/compare');
const { checkOwnerOnly, checkRlsWithoutPolicy } = require('../src/intent');
const { checkSecurityDefiner } = require('../src/secdef');
const { compareTableGrants } = require('../src/tablegrants');
const { renderReport, renderFix } = require('../src/report');
const { buildSarif } = require('../src/sarif');

const HELP = [
  'supadrift — porownuje migracje SQL na dysku z rzeczywistym stanem bazy Supabase',
  '',
  'UZYCIE',
  '  supadrift [opcje]',
  '',
  'POLACZENIE (szczegoly w README, sekcja "Polaczenie")',
  '  Adres bazy WYLACZNIE ze zmiennej srodowiskowej albo z .env:',
  '    SUPADRIFT_DB_URL   (albo SUPABASE_DB_URL, albo DATABASE_URL)',
  '  Argument z adresem albo kluczem jest ODRZUCANY — argumenty trafiaja',
  '  do historii powloki i do logow.',
  '',
  '  Albo bez zadnego hasla, jesli masz zalinkowany projekt w Supabase CLI:',
  '    supadrift --via-cli',
  '',
  'OPCJE',
  '  --migrations <katalog>  katalog z migracjami (domyslnie ./supabase/migrations)',
  '  --via-cli               czytaj baze przez `supabase db query --linked`',
  '  --workdir <katalog>     katalog projektu Supabase dla --via-cli',
  '  --schema <nazwa>        schemat do sprawdzenia, mozna powtorzyc (domyslnie public)',
  '  --as-of <prefiks>       pomin migracje pozniejsze niz podany prefiks nazwy',
  '  --only <fragment>       tylko funkcje, ktorych nazwa zawiera fragment',
  '  --ignore-role <rola>    pomijaj te role przy porownaniu, mozna powtorzyc',
  '  --no-intent             pomin kontrole zamiaru (funkcje bez wolajacego)',
  '  --no-tables             pomin sprawdzenie tabel (RLS i FORCE)',
  '  --no-policies           pomin sprawdzenie polityk',
  '  --no-secdef             pomin kontrole search_path w SECURITY DEFINER',
  '  --no-grants             pomin nadania na tabelach i kolumnach',
  '  --no-triggers           pomin wyzwalacze tabelowe i zdarzeniowe',
  '  --allow-manual <nazwa>  ten wyzwalacz jest zakladany recznie, poza migracjami;',
  '                          bedzie wypisywany osobno i nie wplynie na kod wyjscia',
  '  --no-policy-expr        porownuj polityki bez tresci wyrazen USING/WITH CHECK',
  '  --allow-owner-only <f>  ta funkcja MA byc dostepna tylko dla wlasciciela,',
  '                          mozna powtorzyc; przyjmuje nazwe albo pelny podpis',
  '  --allow-search-path <f> ta funkcja SECURITY DEFINER MA taki search_path,',
  '                          jaki ma; mozna powtorzyc',
  '  --allow-no-policy <t>   ta tabela MA miec RLS bez polityk (tylko service_role),',
  '                          mozna powtorzyc',
  '  --sarif <plik>          zapisz wynik jako SARIF 2.1.0 (podzbior dla GitHub',
  '                          code scanning). Z ta opcja kod wyjscia to 0 nawet',
  '                          przy zgloszeniach — wyniki ida do zakladki Security,',
  '                          a nie do wyniku budowania. Blad krytyczny nadal daje 2.',
  '  --sarif-base <katalog>  korzen repozytorium dla sciezek w SARIF',
  '                          (domyslnie katalog biezacy)',
  '  --hide-target           nie pokazuj hosta ani identyfikatora projektu',
  '                          (do logow, ktore zobaczy ktos postronny)',
  '  --config <plik>         plik z listami wyjatkow (domyslnie supadrift.json',
  '                          w biezacym katalogu albo w katalogu projektu Supabase)',
  '  --fix <plik>            zapisz migracje naprawcza do pliku',
  '  --no-fix                nie wypisuj migracji naprawczej na ekran',
  '  --json                  wynik jako JSON',
  '  --env-file <plik>       skad czytac .env (domyslnie ./.env)',
  '  -h, --help              ta pomoc',
  '',
  'KOD WYJSCIA',
  '  0  czysto        1  znaleziono rozjazd        2  blad',
  '',
  'supadrift czyta baze i nic wiecej. Nie tworzy, nie zmienia, nie nadaje,',
  'nie usuwa. Migracje naprawczej NIE STOSUJE — wypisuje ja do wklejenia.',
].join('\n');

function parseArgs(argv) {
  const o = {
    migrationsDir: null,
    viaCli: false,
    workdir: null,
    schemas: [],
    asOf: null,
    only: null,
    ignoreRoles: [],
    intent: true,
    tables: true,
    policies: true,
    secdef: true,
    grants: true,
    triggers: true,
    policyExpr: true,
    config: null,
    hideTarget: false,
    sarifFile: null,
    sarifBase: null,
    allowOwnerOnly: [],
    allowNoPolicy: [],
    allowSearchPath: [],
    allowManual: [],
    fixFile: null,
    showFix: true,
    json: false,
    envFile: null,
    help: false,
  };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    const need = () => {
      const v = argv[++i];
      if (v === undefined) throw exitError('opcja ' + a + ' wymaga wartosci', 2);
      return v;
    };
    switch (a) {
      case '-h': case '--help': o.help = true; break;
      case '--migrations': o.migrationsDir = need(); break;
      case '--via-cli': o.viaCli = true; break;
      case '--workdir': o.workdir = need(); break;
      case '--schema': o.schemas.push(need()); break;
      case '--as-of': o.asOf = need(); break;
      case '--only': o.only = need(); break;
      case '--ignore-role': o.ignoreRoles.push(need()); break;
      case '--no-intent': o.intent = false; break;
      case '--no-tables': o.tables = false; break;
      case '--no-policies': o.policies = false; break;
      case '--no-secdef': o.secdef = false; break;
      case '--no-grants': o.grants = false; break;
      case '--no-triggers': o.triggers = false; break;
      case '--allow-manual': o.allowManual.push(need()); break;
      case '--no-policy-expr': o.policyExpr = false; break;
      case '--config': o.config = need(); break;
      case '--hide-target': o.hideTarget = true; break;
      case '--sarif': o.sarifFile = need(); break;
      case '--sarif-base': o.sarifBase = need(); break;
      case '--allow-owner-only': o.allowOwnerOnly.push(need()); break;
      case '--allow-no-policy': o.allowNoPolicy.push(need()); break;
      case '--allow-search-path': o.allowSearchPath.push(need()); break;
      case '--fix': o.fixFile = need(); break;
      case '--no-fix': o.showFix = false; break;
      case '--json': o.json = true; break;
      case '--env-file': o.envFile = need(); break;
      default: {
        // NIE odbijamy tresci nierozpoznanego argumentu. Nierozpoznanym
        // argumentem bywa haslo wklejone omylkowo w zle miejsce, a komunikat
        // o bledzie idzie do logu CI, ktorego historia powloki nie obejmuje.
        // W tym miejscu nie ma jeszcze czego zarejestrowac w redact(), wiec
        // jedyna obrona jest nie wypisywac tego wcale.
        const label = a.startsWith('-')
          ? a.split('=')[0]
          : '(argument bez nazwy, text pominieta)';
        throw exitError('nieznana opcja: ' + label + '\n\n' + HELP, 2);
      }
    }
  }
  if (!o.schemas.length) o.schemas = ['public'];
  return o;
}

function exitError(msg, code) {
  const e = new Error(msg);
  e.supadriftExit = code || 2;
  return e;
}

/**
 * Listy wyjatkow z pliku. Sa faktem o projekcie, a nie o jednym uruchomieniu —
 * dlatego maja miejsce w repozytorium, obok migracji, a nie w historii powloki.
 * Plik NIE MOZE zawierac poswiadczen i supadrift ich stad nie czyta.
 */
function loadConfig(o) {
  const candidates = o.config
    ? [path.resolve(o.config)]
    : [
      path.join(process.cwd(), 'supadrift.json'),
      path.join(path.dirname(path.dirname(o.migrationsDir)), 'supadrift.json'),
    ];
  for (const file of candidates) {
    let text;
    try { text = fs.readFileSync(file, 'utf8'); } catch { continue; }
    let cfg;
    try {
      cfg = JSON.parse(text);
    } catch (e) {
      // Komunikat V8 potrafi zawierac FRAGMENT PLIKU. Zostawiamy samo
      // polozenie bledu — plik konfiguracyjny nie ma prawa zawierac
      // poswiadczen, ale nie budujemy bezpieczenstwa na cudzej dyscyplinie.
      const position = /position (d+)/.exec(String(e.message));
      throw exitError('nie udalo sie odczytac ' + file
        + (position ? ' (blad JSON na pozycji ' + position[1] + ')' : ' (niepoprawny JSON)'), 2);
    }
    for (const k of ['allowOwnerOnly', 'allowNoPolicy', 'allowSearchPath', 'allowManual', 'ignoreRoles']) {
      if (Array.isArray(cfg[k])) o[k] = o[k].concat(cfg[k].map(String));
    }
    return file;
  }
  if (o.config) throw exitError('nie znalazlem pliku konfiguracyjnego: ' + o.config, 2);
  return null;
}

function resolveMigrationsDir(given) {
  const candidates = given
    ? [given]
    : [path.join(process.cwd(), 'supabase', 'migrations'), path.join(process.cwd(), 'migrations')];
  for (const c of candidates) {
    if (fs.existsSync(c) && fs.statSync(c).isDirectory()) return path.resolve(c);
  }
  throw exitError(
    'Nie znalazlem katalogu z migracjami.\n'
    + 'Wskaz go: supadrift --migrations <katalog>\n'
    + 'Szukalem w: ' + candidates.join(', '),
    2
  );
}

async function openDriver(o) {
  if (o.viaCli) {
    const cli = require('../src/db/cli');
    const workdir = o.workdir || cli.guessWorkdir(o.migrationsDir) || process.cwd();
    const driver = await cli.open({ workdir });
    if (o.hideTarget) {
      driver.describe = 'Supabase CLI (--linked) -> (ukryty, odcisk '
        + secrets.fingerprint(workdir) + ')';
    }
    return driver;
  }
  const found = secrets.findConnectionString({
    cwd: process.cwd(),
    envFile: o.envFile ? path.resolve(o.envFile) : undefined,
  });
  if (!found) {
    throw exitError(
      'Brak adresu polaczenia.\n\n'
      + 'supadrift czyta go WYLACZNIE ze zmiennej srodowiskowej albo z .env —\n'
      + 'nigdy z argumentu, bo argument zostaje w historii powloki i w logach CI.\n\n'
      + 'Ustaw jedna z:  ' + secrets.ENV_KEYS.join(', ') + '\n\n'
      + '  PowerShell:  $env:SUPADRIFT_DB_URL = "postgresql://..."\n'
      + '  bash:        export SUPADRIFT_DB_URL="postgresql://..."\n'
      + '  albo wpisz ja do .env obok\n\n'
      + 'Najlepiej wskaz role tylko do odczytu — jak ja zalozyc, opisuje README\n'
      + 'w sekcji "Polaczenie". Klucz serwisowy nie jest do tego potrzebny.\n\n'
      + 'Alternatywa zupelnie bez hasla, jesli masz zalinkowany projekt w CLI:\n'
      + '  supadrift --via-cli',
      2
    );
  }
  secrets.registerSecret(found.url);
  if (o.hideTarget) secrets.registerTarget(found.url);
  const pg = require('../src/db/pg');
  const driver = await pg.open(found.url);
  driver.describe = o.hideTarget
    ? 'polaczenie bezposrednie -> (ukryty, odcisk ' + secrets.fingerprint(found.url) + ')'
    : driver.describe + '   [' + found.source + ']';
  return driver;
}

function filterOnly(map, fragment) {
  if (!fragment) return map;
  const f = fragment.toLowerCase();
  const out = new Map();
  for (const [k, v] of map) if (v.name.toLowerCase().includes(f)) out.set(k, v);
  return out;
}

async function main() {
  const argv = process.argv.slice(2);
  secrets.refuseCredentialsInArgv(argv);

  const o = parseArgs(argv);
  if (o.help) { process.stdout.write(HELP + '\n'); return 0; }

  o.migrationsDir = resolveMigrationsDir(o.migrationsDir);
  o.configFile = loadConfig(o);
  // Ustawienia z .env (np. SUPADRIFT_SSL_CA) musza dojsc do sterownika tak samo
  // jak adres polaczenia — inaczej wpis obok adresu nie robilby nic.
  secrets.applyDotenvSettings({
    cwd: process.cwd(),
    envFile: o.envFile ? path.resolve(o.envFile) : undefined,
  });

  const expectedInfo = buildExpected(o.migrationsDir, { asOf: o.asOf, schemas: o.schemas });

  const driver = await openDriver(o);
  let actualInfo;
  let actualTables = new Map();
  let actualPolicies = new Map();
  let actualColumns = new Map();
  let defaultAcl = { bySchemaOwner: new Map(), serverVersion: 0 };
  let actualTriggers = new Map();
  let actualEventTriggers = new Map();
  try {
    actualInfo = await introspect(driver, { schemas: o.schemas });
    if (o.tables || o.policies) actualTables = await introspectTables(driver, { schemas: o.schemas });
    if (o.policies) actualPolicies = await introspectPolicies(driver, { schemas: o.schemas });
    if (o.triggers) {
      actualTriggers = await introspectTriggers(driver, { schemas: o.schemas });
      actualEventTriggers = await introspectEventTriggers(driver, { schemas: o.schemas });
    }
    if (o.grants) {
      actualColumns = await introspectColumnAcls(driver, { schemas: o.schemas });
      defaultAcl = await introspectDefaultAcl(driver);
    }
  } finally {
    await driver.close();
  }

  const expectedFns = filterOnly(expectedInfo.functions, o.only);
  const actualFns = filterOnly(actualInfo.functions, o.only);

  const result = compare(expectedFns, actualFns, { ignoreRoles: o.ignoreRoles });
  const intent = o.intent
    ? checkOwnerOnly(expectedFns, actualFns, { allow: o.allowOwnerOnly })
    : null;

  const tableResult = o.tables ? compareTables(expectedInfo.tables, actualTables) : null;
  const policyResult = o.policies
    ? comparePolicies(expectedInfo.policies, actualPolicies, { compareExpr: o.policyExpr })
    : null;
  const tableGrants = o.grants
    ? compareTableGrants(expectedInfo.tables, actualTables, actualColumns, defaultAcl,
      { ignoreRoles: o.ignoreRoles })
    : null;
  const triggerResult = o.triggers
    ? compareTriggers(expectedInfo.triggers, actualTriggers,
      { allow: o.allowManual, compareExpr: o.policyExpr })
    : null;
  const eventTriggerResult = o.triggers
    ? compareEventTriggers(expectedInfo.eventTriggers, actualEventTriggers, { allow: o.allowManual })
    : null;
  const secdef = o.secdef
    ? checkSecurityDefiner(expectedFns, actualFns, { allow: o.allowSearchPath })
    : null;
  const rlsIntent = o.policies
    ? checkRlsWithoutPolicy(expectedInfo.tables, actualTables,
      expectedInfo.policies, actualPolicies, { allow: o.allowNoPolicy })
    : null;

  const ctx = {
    result,
    intent,
    tableResult,
    policyResult,
    secdef,
    tableGrants,
    triggerResult,
    eventTriggerResult,
    rlsIntent,
    expectedInfo: { ...expectedInfo, functions: expectedFns },
    actualInfo: {
      ...actualInfo, functions: actualFns, tables: actualTables, policies: actualPolicies,
    },
    target: driver.describe,
    options: o,
  };
  const findings = total(result) + (intent ? intent.length : 0)
    + (tableResult ? total(tableResult) : 0)
    + (policyResult ? total(policyResult) : 0)
    + (rlsIntent ? rlsIntent.length : 0)
    + (secdef ? secdef.length : 0)
    + (tableGrants ? tableGrants.length : 0)
    + (triggerResult ? total(triggerResult) : 0)
    + (eventTriggerResult ? total(eventTriggerResult) : 0);

  const fixSql = renderFix(ctx);

  if (o.json) {
    process.stdout.write(secrets.redact(JSON.stringify({
      migrations: { dir: o.migrationsDir, files: expectedInfo.files.length, asOf: o.asOf },
      scope: 'functions:execute',
      schemas: o.schemas,
      counts: {
        onlyInMigrations: result.onlyInMigrations.length,
        onlyInDb: result.onlyInDb.length,
        different: result.different.length,
        ownerOnly: intent ? intent.length : null,
        tables: tableResult ? total(tableResult) : null,
        policies: policyResult ? total(policyResult) : null,
        rlsWithoutPolicy: rlsIntent ? rlsIntent.length : null,
        searchPath: secdef ? secdef.length : null,
        tableGrants: tableGrants ? tableGrants.length : null,
        triggers: triggerResult ? total(triggerResult) : null,
        eventTriggers: eventTriggerResult ? total(eventTriggerResult) : null,
        total: findings,
      },
      result,
      ownerOnly: intent,
      tables: tableResult,
      policies: policyResult,
      rlsWithoutPolicy: rlsIntent,
      searchPath: secdef,
      tableGrants,
      triggers: triggerResult,
      eventTriggers: eventTriggerResult,
      unmodelled: expectedInfo.notes,
    }, null, 2)) + '\n');
  } else {
    process.stdout.write(secrets.redact(renderReport(ctx)) + '\n');
    if (o.showFix && findings > 0) {
      process.stdout.write('\nMIGRACJA NAPRAWCZA (do wklejenia — supadrift jej NIE stosuje)\n');
      process.stdout.write('-'.repeat(74) + '\n');
      process.stdout.write(secrets.redact(fixSql) + '\n');
    }
  }

  if (o.sarifFile) {
    const pkg = JSON.parse(fs.readFileSync(path.join(__dirname, "..", "package.json"), "utf8"));
    const { doc, warnings, findingCount } = buildSarif(ctx, {
      baseDir: path.resolve(o.sarifBase || process.cwd()),
      migrationsDir: o.migrationsDir,
      version: pkg.version,
    });
    fs.writeFileSync(path.resolve(o.sarifFile), secrets.redact(JSON.stringify(doc, null, 2)), "utf8");
    if (!o.json) {
      process.stdout.write('SARIF zapisany do: ' + path.resolve(o.sarifFile)
        + '  (' + findingCount + ' findingCount)\n');
    }
    for (const ostrz of warnings) process.stderr.write('supadrift: ' + ostrz + '\n');
  }

  if (o.fixFile) {
    fs.writeFileSync(path.resolve(o.fixFile), secrets.redact(fixSql), 'utf8');
    if (!o.json) process.stdout.write('Migracja naprawcza zapisana do: ' + path.resolve(o.fixFile) + '\n');
  }

  // Z --sarif wynik idzie do zakladki Security, a nie do wyniku budowania.
  // Zgloszenia NIE moga wywracac budowania — inaczej pierwsze zetkniecie
  // z narzedziem konczy sie jego wylaczeniem. Blad krytyczny to co innego:
  // ten nadal daje 2, bo "nie udalo sie sprawdzic" nie jest tym samym co
  // "sprawdzone i czysto" (patrz README, sekcja o odpornosci).
  if (o.sarifFile) return 0;
  return findings > 0 ? 1 : 0;
}

// Ostatnia siatka. Wszystko ponizej main() moze wybuchnac POZA lancuchem
// obietnic — zdarzenie z gniazda, timer, blad w bibliotece. Node wypisalby
// wtedy surowy obiekt bledu razem ze stosem i ominal redact(). Te dwa
// handlery istnieja po to, zeby taka droga nie istniala.
function onFatalError(kind, err) {
  const text = err && err.stack && process.env.SUPADRIFT_DEBUG === '1'
    ? err.stack
    : (err && err.message ? err.message : String(err));
  process.stderr.write('\nsupadrift: ' + kind + ': ' + secrets.redact(text) + '\n');
  process.exitCode = 2;
}
process.on('uncaughtException', (e) => onFatalError('blad nieobsluzony', e));
process.on('unhandledRejection', (e) => onFatalError('odrzucona obietnica', e));

main()
  .then((code) => { process.exitCode = code; })
  .catch((err) => {
    const code = err && err.supadriftExit ? err.supadriftExit : 2;
    process.stderr.write('\nsupadrift: ' + secrets.redact(err && err.message ? err.message : String(err)) + '\n');
    if (process.env.SUPADRIFT_DEBUG === '1' && err && err.stack) {
      process.stderr.write(secrets.redact(err.stack) + '\n');
    }
    process.exitCode = code;
  });
