'use strict';

// ---------------------------------------------------------------------------
// Poswiadczenia: skad wolno je brac i jak nie dac im wyciec
// ---------------------------------------------------------------------------
//
// ZASADA. Adres polaczenia i klucz przychodza WYLACZNIE ze zmiennej
// srodowiskowej albo z pliku .env. Nigdy z argumentu wiersza polecen.
//
// Argument nie jest prywatny. Laduje w historii powloki (~/.bash_history,
// ConsoleHost_history.txt), w logu CI, w `ps` widocznym dla kazdego uzytkownika
// maszyny i w komunikacie o bledzie, ktory czlowiek wkleja potem do zgloszenia.
// Zmienna srodowiskowa nie jest doskonala, ale nie zostaje na dysku po sesji.
//
// Dlatego supadrift ODMAWIA startu, gdy zobaczy poswiadczenie w argv — nie
// ostrzega, tylko konczy. Ostrzezenie, ktore da sie przewinac, nie chroni
// niczego: klucz jest juz wtedy w historii.

const fs = require('fs');
const path = require('path');

const ENV_KEYS = ['SUPADRIFT_DB_URL', 'SUPABASE_DB_URL', 'DATABASE_URL'];

// Ksztalty, ktore nigdy nie maja prawa pojawic sie w argumencie.
const CREDENTIAL_SHAPES = [
  { re: /^postgres(ql)?:\/\//i, what: 'adres polaczenia do Postgresa' },
  { re: /^sb_secret_/, what: 'klucz serwisowy Supabase' },
  { re: /^sbp_/, what: 'token dostepowy Supabase' },
  { re: /^eyJ[A-Za-z0-9_-]{10,}\./, what: 'token JWT' },
];

/** Zatrzymuje program, jesli ktorykolwiek argument wyglada na poswiadczenie. */
function refuseCredentialsInArgv(argv) {
  for (const raw of argv) {
    const arg = raw.includes('=') ? raw.slice(raw.indexOf('=') + 1) : raw;
    for (const s of CREDENTIAL_SHAPES) {
      if (s.re.test(arg) || s.re.test(raw)) {
        const err = new Error(
          'W argumentach wiersza polecen jest ' + s.what + '.\n'
          + 'supadrift tego nie przyjmuje: argumenty trafiaja do historii powloki,\n'
          + 'do logu CI i do listy procesow widocznej dla innych uzytkownikow.\n\n'
          + 'Podaj to zmienna srodowiskowa albo w pliku .env:\n'
          + '  SUPADRIFT_DB_URL=postgresql://...\n\n'
          + 'Jesli ten klucz byl juz uzyty w argumencie, uznaj go za ujawniony\n'
          + 'i wymien go. Wyczysc tez historie powloki.'
        );
        err.supadriftExit = 2;
        throw err;
      }
    }
  }
}

/** Minimalny czytnik .env. Nie loguje wartosci. */
function loadDotenv(file) {
  const out = new Map();
  let text;
  try {
    text = fs.readFileSync(file, 'utf8');
  } catch {
    return out;
  }
  for (const line of text.split(/\r?\n/)) {
    const s = line.trim();
    if (!s || s.startsWith('#')) continue;
    const m = /^(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)$/.exec(s);
    if (!m) continue;
    let v = m[2].trim();
    if ((v.startsWith('"') && v.endsWith('"')) || (v.startsWith("'") && v.endsWith("'"))) {
      v = v.slice(1, -1);
    } else {
      const h = v.indexOf(' #');
      if (h !== -1) v = v.slice(0, h).trim();
    }
    out.set(m[1], v);
  }
  return out;
}

/**
 * Znajduje adres polaczenia. Kolejnosc: srodowisko procesu, potem .env.
 * @returns {{url:string, source:string}|null}
 */
function findConnectionString(opts = {}) {
  const cwd = opts.cwd || process.cwd();
  const envFile = opts.envFile || path.join(cwd, '.env');

  for (const k of ENV_KEYS) {
    if (process.env[k]) return { url: process.env[k], source: 'zmienna srodowiskowa ' + k };
  }
  const dot = loadDotenv(envFile);
  for (const k of ENV_KEYS) {
    if (dot.has(k)) return { url: dot.get(k), source: path.basename(envFile) + ' -> ' + k };
  }
  return null;
}

/**
 * Ustawienia (nie poswiadczenia), ktore wolno podac takze w .env.
 * Bez tego czlowiek wpisuje SUPADRIFT_SSL_CA obok adresu, w tym samym pliku,
 * i nic sie nie dzieje — bo sterownik czyta wylacznie process.env. Roznica
 * "adres z .env dziala, a ustawienie obok nie" jest dokladnie tym rodzajem
 * niespodzianki, ktora kosztuje godzine.
 */
const SETTING_KEYS = [
  'SUPADRIFT_SSL_CA',
  'SUPADRIFT_SSL_NO_VERIFY',
  'SUPADRIFT_SUPABASE_BIN',
  'SUPADRIFT_DEBUG',
];

/**
 * Przenosi ustawienia z .env do process.env, ale NIGDY nie nadpisuje tego,
 * co juz stoi w srodowisku — jawnie podane ma pierwszenstwo nad plikiem.
 * @returns {string[]} nazwy przeniesionych kluczy
 */
function applyDotenvSettings(opts = {}) {
  const cwd = opts.cwd || process.cwd();
  const envFile = opts.envFile || path.join(cwd, '.env');
  const dot = loadDotenv(envFile);
  const applied = [];
  for (const k of SETTING_KEYS) {
    if (process.env[k] === undefined && dot.has(k)) {
      process.env[k] = dot.get(k);
      applied.push(k);
    }
  }
  return applied;
}

// --- zaciemnianie -----------------------------------------------------------

const secrets = new Set();

/** Rejestruje wartosc, ktora nigdy nie ma sie pojawic na wyjsciu. */
function registerSecret(value) {
  if (typeof value !== 'string') return;
  const v = value.trim();
  if (v.length >= 6) secrets.add(v);
  // osobno samo haslo z adresu, bo biblioteki potrafia je wypisac w oderwaniu
  const m = /^[a-z+]+:\/\/([^:@/]+):([^@/]+)@/i.exec(v);
  if (m && m[2].length >= 4) secrets.add(decodeURIComponent(m[2]));
  if (m && m[2].length >= 4) secrets.add(m[2]);
}

/** Usuwa z tekstu wszystko, co moglo by byc poswiadczeniem. */
function redact(text) {
  let s = String(text === undefined || text === null ? '' : text);
  for (const sec of secrets) {
    if (!sec) continue;
    s = s.split(sec).join('[USUNIETE]');
  }
  // haslo w adresie, takze gdy nie bylo zarejestrowane
  s = s.replace(/([a-z+]+:\/\/)([^:@\s/]+):([^@\s/]+)@/gi, '$1$2:[USUNIETE]@');
  // tokeny o rozpoznawalnym ksztalcie
  s = s.replace(/\bsb_secret_[A-Za-z0-9_-]+/g, 'sb_secret_[USUNIETE]');
  s = s.replace(/\bsbp_[A-Za-z0-9]+/g, 'sbp_[USUNIETE]');
  s = s.replace(/\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+/g, '[USUNIETY-JWT]');
  return s;
}

/**
 * Rejestruje wszystko, co identyfikuje CEL, a nie tylko poswiadczenie:
 * nazwe hosta i — dla Supabase — sam identyfikator projektu, ktory siedzi
 * takze w nazwie uzytkownika puli (`rola.<ref>`). Uzywane przy --hide-target,
 * gdy raport ma trafic do logu, ktory zobaczy ktos postronny.
 */
function registerTarget(url) {
  try {
    const u = new URL(url);
    if (u.hostname) {
      secrets.add(u.hostname);
      const m = /^db\.([a-z0-9]{16,})\.supabase\.co$/i.exec(u.hostname);
      if (m) secrets.add(m[1]);
    }
    if (u.username) {
      const dot = u.username.indexOf('.');
      if (dot > 0) secrets.add(u.username.slice(dot + 1));
    }
  } catch { /* nierozpoznany adres — nie ma czego rejestrowac */ }
}

/** Krotki, nieodwracalny odcisk celu — pozwala odroznic dwa przebiegi. */
function fingerprint(value) {
  return require('crypto').createHash('sha256').update(String(value)).digest('hex').slice(0, 8);
}

/** Adres polaczenia w postaci nadajacej sie do wypisania. */
function describeTarget(url) {
  try {
    const u = new URL(url);
    return u.hostname + ':' + (u.port || '5432') + u.pathname;
  } catch {
    return '(nierozpoznany adres)';
  }
}

module.exports = {
  ENV_KEYS, SETTING_KEYS, refuseCredentialsInArgv, loadDotenv, findConnectionString,
  applyDotenvSettings,
  registerSecret, registerTarget, fingerprint, redact, describeTarget,
};
