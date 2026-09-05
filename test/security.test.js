'use strict';

// Testy regresyjne z audytu bezpieczenstwa.
//
// Kazdy z nich odpowiada konkretnej drodze, ktora poswiadczenie moglo wyjsc
// na zewnatrz. Trzy z nich opisuja bledy, ktore w kodzie BYLY i zostaly
// znalezione dopiero testem negatywnym — dlatego stoja tu na stale.

const test = require('node:test');
const assert = require('node:assert');
const { spawnSync } = require('child_process');
const path = require('path');
const os = require('os');
const fs = require('fs');

const secrets = require('../src/secrets');
const { czysteSrodowisko } = require('../src/db/cli');

const BIN = path.join(__dirname, '..', 'bin', 'supadrift.js');
const HASLO = 'PLAINTEXT_SEKRET_9f3a';

function uruchom(args, env) {
  return spawnSync(process.execPath, [BIN, ...args], {
    encoding: 'utf8',
    cwd: os.tmpdir(),   // nie czytaj .env ani supadrift.json dewelopera
    env: Object.assign({}, process.env, { SUPADRIFT_DB_URL: undefined }, env || {}),
    timeout: 30000,
  });
}

// --- BYL BLAD: nierozpoznany argument byl odbijany w calosci ------------------

test('nierozpoznany argument nie jest odbijany na wyjscie', () => {
  const r = uruchom([HASLO]);
  assert.equal(r.status, 2);
  const out = (r.stdout || '') + (r.stderr || '');
  assert.ok(!out.includes(HASLO),
    'tresc argumentu nie ma prawa trafic do komunikatu — log CI nie jest historia powloki');
  assert.match(out, /tresc pominieta/);
});

test('nazwa opcji jest odbijana, bo pomaga, i nie jest poswiadczeniem', () => {
  const r = uruchom(['--nie-ma-takiej']);
  assert.match((r.stderr || ''), /nieznana opcja: --nie-ma-takiej/);
});

test('opcja z wartoscia odbija sama nazwe, bez wartosci', () => {
  const r = uruchom(['--nie-ma-takiej=' + HASLO]);
  const out = (r.stdout || '') + (r.stderr || '');
  assert.ok(!out.includes(HASLO));
});

// --- poswiadczenie w argv ----------------------------------------------------

test('adres w argv jest odrzucany, a jego tresc nie jest powtarzana', () => {
  const r = uruchom(['--db-url', 'postgresql://u:' + HASLO + '@h:5432/postgres']);
  assert.equal(r.status, 2);
  const out = (r.stdout || '') + (r.stderr || '');
  assert.ok(!out.includes(HASLO));
  assert.match(out, /historii powloki/);
});

// --- BYL BLAD: podproces dziedziczyl haslo -----------------------------------

test('podproces supabase nie dostaje adresu bazy w srodowisku', () => {
  const przed = process.env.SUPADRIFT_DB_URL;
  process.env.SUPADRIFT_DB_URL = 'postgresql://u:' + HASLO + '@h/db';
  process.env.PGPASSWORD = HASLO;
  try {
    const env = czysteSrodowisko();
    for (const k of secrets.ENV_KEYS.concat(['PGPASSWORD', 'PGPASSFILE', 'PGSERVICE'])) {
      assert.equal(env[k], undefined, k + ' nie ma prawa dojsc do obcej binarki');
    }
    assert.ok(env.PATH || env.Path, 'reszta srodowiska musi zostac');
  } finally {
    if (przed === undefined) delete process.env.SUPADRIFT_DB_URL;
    else process.env.SUPADRIFT_DB_URL = przed;
    delete process.env.PGPASSWORD;
  }
});

// --- zaciemnianie ------------------------------------------------------------

test('redact usuwa haslo takze wtedy, gdy stoi w oderwaniu od adresu', () => {
  secrets.registerSecret('postgresql://rola:' + HASLO + '@db.przyklad.supabase.co:5432/postgres');
  const out = secrets.redact('blad uwierzytelnienia dla hasla ' + HASLO + ' (kod 28P01)');
  assert.ok(!out.includes(HASLO));
});

test('redact usuwa haslo z adresu, ktorego nikt nie zarejestrowal', () => {
  const out = secrets.redact('nie mozna polaczyc: postgresql://ktos:NieZarejestrowane1@h:5432/db');
  assert.ok(!out.includes('NieZarejestrowane1'), out);
});

test('redact usuwa tokeny o rozpoznawalnym ksztalcie', () => {
  assert.ok(!secrets.redact('klucz sb_secret_abcdef123456').includes('abcdef123456'));
  assert.ok(!secrets.redact('token sbp_0123456789abcdef').includes('0123456789abcdef'));
  const jwt = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.cGF5bG9hZA.c2lnbmF0dXJl';
  assert.ok(!secrets.redact('naglowek ' + jwt).includes(jwt));
});

// --- ukrywanie celu ----------------------------------------------------------

test('registerTarget usuwa host oraz identyfikator projektu', () => {
  const ref = 'abcdefghijklmnop';
  secrets.registerTarget('postgresql://ro:x@db.' + ref + '.supabase.co:5432/postgres');
  const out = secrets.redact('getaddrinfo ENOTFOUND db.' + ref + '.supabase.co, projekt ' + ref);
  assert.ok(!out.includes(ref), 'ref projektu tez identyfikuje cel: ' + out);
});

test('registerTarget wyciaga ref z nazwy uzytkownika puli', () => {
  const ref = 'qrstuvwxyz012345';
  secrets.registerTarget('postgresql://supadrift_ro.' + ref + ':x@aws-0-eu.pooler.supabase.com:5432/postgres');
  assert.ok(!secrets.redact('uzytkownik supadrift_ro.' + ref).includes(ref));
});

test('odcisk celu jest krotki, stabilny i nieodwracalny', () => {
  const a = secrets.fingerprint('postgresql://u:p@h/db');
  assert.equal(a, secrets.fingerprint('postgresql://u:p@h/db'));
  assert.notEqual(a, secrets.fingerprint('postgresql://u:p@inny/db'));
  assert.match(a, /^[0-9a-f]{8}$/);
});

test('describeTarget nigdy nie zwraca uzytkownika ani hasla', () => {
  const d = secrets.describeTarget('postgresql://rola:' + HASLO + '@h.example.com:5432/postgres');
  assert.ok(!d.includes(HASLO));
  assert.ok(!d.includes('rola'));
  assert.equal(d, 'h.example.com:5432/postgres');
  assert.equal(secrets.describeTarget('nie-url'), '(nierozpoznany adres)');
});

// --- BYL BRAK: siatka pod bledy poza lancuchem obietnic ----------------------

test('proces ma handlery na bledy spoza lancucha obietnic', () => {
  const src = fs.readFileSync(BIN, 'utf8');
  // Bez nich Node wypisuje surowy obiekt bledu ze stosem i omija redact().
  assert.match(src, /process\.on\('uncaughtException'/);
  assert.match(src, /process\.on\('unhandledRejection'/);
  assert.match(src, /secrets\.redact\(tresc\)/);
});

test('sterownik pg ma sluchacza na asynchroniczny blad polaczenia', () => {
  const src = fs.readFileSync(path.join(__dirname, '..', 'src', 'db', 'pg.js'), 'utf8');
  assert.match(src, /client\.on\('error'/);
});

// --- konfiguracja ------------------------------------------------------------

test('blad JSON w konfiguracji nie cytuje tresci pliku', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'supadrift-sec-'));
  try {
    fs.writeFileSync(path.join(dir, 'supadrift.json'), '{ "allowManual": "' + HASLO + '" bledny }');
    const r = spawnSync(process.execPath, [BIN, '--migrations', dir], {
      encoding: 'utf8', cwd: dir, timeout: 30000,
      env: Object.assign({}, process.env, { SUPADRIFT_DB_URL: undefined }),
    });
    const out = (r.stdout || '') + (r.stderr || '');
    assert.ok(!out.includes(HASLO), 'komunikat V8 potrafi cytowac fragment pliku: ' + out);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

// --- TLS: weryfikacja zostaje wlaczona ---------------------------------------
//
// Pula Supabase przedstawia certyfikat podpisany wlasnym CA, ktorego nie ma
// w magazynie Node'a. Wlasciwa odpowiedzia jest WSKAZANIE tego CA, a nie
// wylaczenie sprawdzania — te testy pilnuja, ze latwiejsza zla droga nie stala
// sie domyslna.

const { sslFor } = require('../src/db/pg');

const ADRES = 'postgresql://u:p@h:5432/postgres';

function zCA(tresc) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'supadrift-ca-'));
  const plik = path.join(dir, 'ca.crt');
  fs.writeFileSync(plik, tresc);
  return { dir, plik };
}

function bezZmiennych(fn) {
  const przed = {
    ca: process.env.SUPADRIFT_SSL_CA,
    nv: process.env.SUPADRIFT_SSL_NO_VERIFY,
  };
  delete process.env.SUPADRIFT_SSL_CA;
  delete process.env.SUPADRIFT_SSL_NO_VERIFY;
  try { return fn(); } finally {
    if (przed.ca === undefined) delete process.env.SUPADRIFT_SSL_CA;
    else process.env.SUPADRIFT_SSL_CA = przed.ca;
    if (przed.nv === undefined) delete process.env.SUPADRIFT_SSL_NO_VERIFY;
    else process.env.SUPADRIFT_SSL_NO_VERIFY = przed.nv;
  }
}

test('domyslnie certyfikat serwera JEST weryfikowany', () => {
  bezZmiennych(() => {
    assert.deepEqual(sslFor(ADRES), { rejectUnauthorized: true });
  });
});

test('SUPADRIFT_SSL_CA wczytuje CA i NIE oslabia weryfikacji', () => {
  const { dir, plik } = zCA('-----BEGIN CERTIFICATE-----\nQUJD\n-----END CERTIFICATE-----\n');
  try {
    bezZmiennych(() => {
      process.env.SUPADRIFT_SSL_CA = plik;
      const o = sslFor(ADRES);
      assert.equal(o.rejectUnauthorized, true, 'wskazanie CA nie ma prawa wylaczyc sprawdzania');
      assert.match(o.ca, /BEGIN CERTIFICATE/);
    });
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('brakujacy plik CA pada glosno, zamiast po cichu wrocic do domyslnych', () => {
  bezZmiennych(() => {
    process.env.SUPADRIFT_SSL_CA = path.join(os.tmpdir(), 'nie-ma-' + Date.now() + '.crt');
    assert.throws(() => sslFor(ADRES), (e) => e.supadriftExit === 2 && e.supadriftFatal === true);
  });
});

test('plik, ktory nie jest PEM, tez pada glosno', () => {
  const { dir, plik } = zCA('to nie jest certyfikat');
  try {
    bezZmiennych(() => {
      process.env.SUPADRIFT_SSL_CA = plik;
      assert.throws(() => sslFor(ADRES), /nie wyglada na certyfikat PEM/);
    });
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('wylaczenie weryfikacji wymaga jawnej zmiennej i nie ma go w argv', () => {
  bezZmiennych(() => {
    process.env.SUPADRIFT_SSL_NO_VERIFY = '1';
    assert.deepEqual(sslFor(ADRES), { rejectUnauthorized: false });
  });
  const src = fs.readFileSync(BIN, 'utf8');
  assert.ok(!/--ssl-no-verify|--insecure/.test(src),
    'wylaczenia TLS nie wolno wystawiac jako przelacznika wiersza polecen');
});

test('ustawienia z .env docieraja do sterownika, ale nie nadpisuja srodowiska', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'supadrift-set-'));
  try {
    fs.writeFileSync(path.join(dir, '.env'),
      'SUPADRIFT_DB_URL=postgresql://u:p@h/db\nSUPADRIFT_SSL_CA=/z/pliku.crt\n');
    bezZmiennych(() => {
      const a = secrets.applyDotenvSettings({ envFile: path.join(dir, '.env') });
      assert.ok(a.includes('SUPADRIFT_SSL_CA'), 'wpis z .env ma trafic do srodowiska');
      assert.equal(process.env.SUPADRIFT_SSL_CA, '/z/pliku.crt');

      process.env.SUPADRIFT_SSL_CA = '/ze/srodowiska.crt';
      secrets.applyDotenvSettings({ envFile: path.join(dir, '.env') });
      assert.equal(process.env.SUPADRIFT_SSL_CA, '/ze/srodowiska.crt',
        'jawnie podane ma pierwszenstwo nad plikiem');
    });
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});
