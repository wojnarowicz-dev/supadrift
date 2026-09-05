'use strict';

// ---------------------------------------------------------------------------
// Sterownik: bezposrednie polaczenie do Postgresa
// ---------------------------------------------------------------------------
//
// Sciezka zalecana. Adres bierzemy wylacznie ze zmiennej srodowiskowej albo
// z .env (patrz src/secrets.js) i najlepiej wskazuje on role zalozona
// specjalnie dla supadrift, bez zadnych uprawnien poza CONNECT — instrukcja
// jest w README, w sekcji o polaczeniu.
//
// Tylko odczyt jest tu wymuszony na trzy sposoby naraz:
//   1. assertReadOnly() na kazdym zapytaniu, po naszej stronie,
//   2. sesja ustawiona na read only,
//   3. transakcja READ ONLY, zamykana przez ROLLBACK.
// Zaden z nich nie wystarcza sam. Razem oznaczaja, ze zapis nie przejdzie
// nawet przez pomylke w przyszlej zmianie w tym pliku.

const { assertReadOnly } = require('./readonly');
const { registerSecret, describeTarget, redact } = require('../secrets');

// TLS.
//
// Domyslnie weryfikujemy certyfikat. Pula Supabase przedstawia certyfikat
// podpisany wlasnym CA, ktorego nie ma w magazynie zaufania Node'a — polaczenie
// konczy sie wtedy bledem "self-signed certificate in certificate chain",
// ZANIM haslo w ogole pojdzie w eter.
//
// Wlasciwa odpowiedzia jest wskazanie tego CA, a nie wylaczenie sprawdzania.
// Certyfikat pobiera sie z panelu Supabase i podaje przez SUPADRIFT_SSL_CA.
// Weryfikacja zostaje wtedy WLACZONA, tylko z innym kotwiczeniem zaufania.
//
// SUPADRIFT_SSL_NO_VERIFY=1 zostaje jako furtka na awarie, ale jest ostatnia
// deska ratunku: wylacza uwierzytelnienie serwera, wiec polaczenie przestaje
// bronic przed podstawieniem sie pod baze.
function sslFor(url) {
  if (/[?&]sslmode=disable\b/i.test(url)) return false;

  const caPath = process.env.SUPADRIFT_SSL_CA;
  if (caPath) {
    let ca;
    try {
      ca = require('fs').readFileSync(caPath, 'utf8');
    } catch (e) {
      const err = new Error(
        'nie da sie odczytac certyfikatu CA wskazanego przez SUPADRIFT_SSL_CA:\n'
        + '  ' + caPath + '\n'
        + '  ' + (e.code || e.message) + '\n\n'
        + 'Sciezka musi wskazywac plik .crt albo .pem pobrany z panelu Supabase\n'
        + '(Settings -> Database -> SSL Configuration).'
      );
      err.supadriftExit = 2;
      err.supadriftFatal = true;
      throw err;
    }
    if (!/-----BEGIN CERTIFICATE-----/.test(ca)) {
      const err = new Error(
        'plik wskazany przez SUPADRIFT_SSL_CA nie wyglada na certyfikat PEM\n'
        + '  ' + caPath + '\n'
        + 'Oczekiwany naglowek: -----BEGIN CERTIFICATE-----'
      );
      err.supadriftExit = 2;
      err.supadriftFatal = true;
      throw err;
    }
    return { rejectUnauthorized: true, ca };
  }

  // Weryfikacje certyfikatu mozna wylaczyc tylko jawnie i tylko przez
  // srodowisko — nie ma na to przelacznika w wierszu polecen.
  if (process.env.SUPADRIFT_SSL_NO_VERIFY === '1') {
    return { rejectUnauthorized: false };
  }
  return { rejectUnauthorized: true };
}

async function open(url) {
  registerSecret(url);

  let Client;
  try {
    ({ Client } = require('pg'));
  } catch {
    const e = new Error(
      'Brakuje pakietu `pg`. Zainstaluj go w katalogu supadrift:\n'
      + '  npm install\n\n'
      + 'Albo uzyj sciezki bez hasla, jesli masz zalinkowany projekt w Supabase CLI:\n'
      + '  supadrift --via-cli'
    );
    e.supadriftExit = 2;
    throw e;
  }

  const client = new Client({
    connectionString: url,
    ssl: sslFor(url),
    application_name: 'supadrift (read-only)',
    statement_timeout: 30000,
    connectionTimeoutMillis: 15000,
  });

  // Client jest EventEmitterem i potrafi zglosic blad ASYNCHRONICZNIE, juz po
  // udanym polaczeniu — zerwana sesja, restart serwera, koniec limitu czasu.
  // Zdarzenie 'error' bez sluchacza wywraca proces WEWNETRZNYM mechanizmem
  // Node'a, ktory wypisuje surowy obiekt bledu i omija nasze redact().
  // Ten sluchacz istnieje wylacznie po to, zeby taka droga nie istniala.
  client.on('error', (e) => {
    process.stderr.write('\nsupadrift: polaczenie zglosilo blad: '
      + redact(e && e.message ? e.message : String(e)) + '\n');
    process.exitCode = 2;
  });

  await client.connect();
  await client.query('set session characteristics as transaction read only');

  return {
    describe: 'polaczenie bezposrednie -> ' + describeTarget(url),
    async query(sql) {
      assertReadOnly(sql);
      await client.query('begin read only');
      try {
        const res = await client.query(sql);
        return res.rows;
      } finally {
        await client.query('rollback');
      }
    },
    async close() {
      try { await client.end(); } catch { /* zamykanie nie ma prawa zaslonic wyniku */ }
    },
  };
}

module.exports = { open, sslFor };
