'use strict';

// ---------------------------------------------------------------------------
// Sterownik: przez Supabase CLI (`supabase db query --linked`)
// ---------------------------------------------------------------------------
//
// Sciezka wygodna, nie minimalna. Nie trzeba znac hasla do bazy — supadrift
// nie widzi tu zadnego poswiadczenia, bo uzywa tego, ktore CLI ma juz u siebie.
// Cena jest taka, ze to poswiadczenie jest silne (Management API), wiec do
// stalego uzycia, a zwlaszcza do CI, lepsza jest rola tylko do odczytu
// i sciezka bezposrednia. README mowi o tym w sekcji o polaczeniu.
//
// Nasza bramka assertReadOnly() obowiazuje tak samo jak tam.

const { spawnSync } = require('child_process');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { assertReadOnly } = require('./readonly');
const { redact, ENV_KEYS } = require('../secrets');

// Podproces NIE POTRZEBUJE adresu bazy — chodzi wlasnym tokenem CLI. Dziedziczone
// srodowisko oddaloby haslo obcej binarce, ktora nie ma z nim nic wspolnego,
// i pokazaloby je w `ps` kazdemu uzytkownikowi maszyny. Wycinamy je.
function cleanEnvironment() {
  const env = Object.assign({}, process.env);
  for (const k of ENV_KEYS.concat(['PGPASSWORD', 'PGPASSFILE', 'PGSERVICE'])) delete env[k];
  return env;
}

const CANDIDATES = process.env.SUPADRIFT_SUPABASE_BIN
  ? [process.env.SUPADRIFT_SUPABASE_BIN]
  : ['supabase', 'supabase.cmd', 'supabase.exe'];

function run(args, cwd) {
  let last = null;
  for (const bin of CANDIDATES) {
    // .cmd i .bat NIE SA plikami wykonywalnymi dla CreateProcess — spawnSync
    // bez powloki zwraca na nich ENOENT. Instalacja Supabase CLI przez npm
    // daje wlasnie `supabase.cmd`, wiec bez tego wyjatku ta sciezka nie
    // dzialala w ogole na Windows.
    const viaShell = /\.(cmd|bat)$/i.test(bin);
    const r = spawnSync(bin, args, {
      cwd,
      env: cleanEnvironment(),
      encoding: 'utf8',
      maxBuffer: 64 * 1024 * 1024,
      windowsHide: true,
      shell: viaShell,
    });
    if (r.error && r.error.code === 'ENOENT') { last = r; continue; }
    return r;
  }
  return last || { error: new Error('nie znaleziono programu supabase') };
}

async function open(opts = {}) {
  const workdir = opts.workdir || process.cwd();

  const probe = run(['--version'], workdir);
  if (probe.error) {
    const e = new Error(
      'Nie znaleziono programu `supabase` w PATH.\n'
      + 'Zainstaluj Supabase CLI albo wskaz sciezke: SUPADRIFT_SUPABASE_BIN=...\n'
      + 'Alternatywa bez CLI: ustaw SUPADRIFT_DB_URL i uruchom bez --via-cli.'
    );
    e.supadriftExit = 2;
    throw e;
  }

  return {
    describe: 'Supabase CLI (--linked), katalog projektu: ' + workdir,
    async query(sql) {
      assertReadOnly(sql);
      const tmp = path.join(
        fs.mkdtempSync(path.join(os.tmpdir(), 'supadrift-')),
        'query.sql'
      );
      fs.writeFileSync(tmp, sql, 'utf8');
      try {
        const r = run(['db', 'query', '--linked', '--output', 'json', '-f', tmp], workdir);
        if (r.error) throw new Error(redact(String(r.error.message)));
        if (r.status !== 0) {
          throw new Error(
            'supabase db query zakonczylo sie kodem ' + r.status + '\n'
            + redact(String(r.stderr || r.stdout || '').trim())
          );
        }
        return parseRows(String(r.stdout || ''));
      } finally {
        try { fs.rmSync(path.dirname(tmp), { recursive: true, force: true }); } catch { /* nic */ }
      }
    },
    async close() { /* nic do zamkniecia */ },
  };
}

function parseRows(stdout) {
  const start = stdout.indexOf('{');
  if (start === -1) throw new Error('supabase db query nie zwrocilo JSON-a');
  let payload;
  try {
    payload = JSON.parse(stdout.slice(start));
  } catch (e) {
    throw new Error('nie udalo sie odczytac odpowiedzi supabase db query: ' + e.message);
  }
  if (Array.isArray(payload)) return payload;
  if (Array.isArray(payload.rows)) return payload.rows;
  throw new Error('odpowiedz supabase db query nie zawiera wierszy');
}

/** Zgaduje katalog projektu Supabase na podstawie sciezki do migracji. */
function guessWorkdir(migrationsDir) {
  const norm = path.resolve(migrationsDir);
  const parent = path.dirname(norm);
  if (path.basename(norm).toLowerCase() === 'migrations'
    && path.basename(parent).toLowerCase() === 'supabase') {
    return path.dirname(parent);
  }
  return null;
}

module.exports = { open, guessWorkdir, parseRows, cleanEnvironment };
