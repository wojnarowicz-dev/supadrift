'use strict';

// Kontrola zamiaru. Najwazniejszy test w tym pliku to pierwszy: dzien wdrozenia
// migracji 20260901130000, kiedy baza byla z plikami zgodna CO DO ZNAKU i oba
// byly w bledzie. Rozjazd wynosi tam zero — i wlasnie dlatego ta kontrola musi
// istniec osobno.

const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const os = require('os');
const path = require('path');

const { buildExpected } = require('../src/expected');
const { introspect } = require('../src/introspect');
const { compare, total } = require('../src/compare');
const { checkOwnerOnly } = require('../src/intent');

const fakeDriver = (rows) => ({ query: async () => rows, close: async () => {} });

function dirWith(files) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'supadrift-intent-'));
  for (const [name, body] of Object.entries(files)) {
    fs.writeFileSync(path.join(dir, name), body, 'utf8');
  }
  return dir;
}

async function analyze(files, rows, opts = {}) {
  const dir = dirWith(files);
  try {
    const expected = buildExpected(dir, { schemas: ['public'] });
    const actual = await introspect(fakeDriver(rows), { schemas: ['public'] });
    return {
      expected,
      actual,
      drift: compare(expected.functions, actual.functions),
      intent: checkOwnerOnly(expected.functions, actual.functions, opts),
    };
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
}

const fn = (over) => Object.assign({
  schema: 'public', name: 'f', argtypes: [], owner: 'postgres', kind: 'f',
  returns: 'void', body: '', security_definer: true,
  acl: ['postgres=X/postgres'], acl_is_default: false,
}, over);

// --- dzien wdrozenia ---------------------------------------------------------

const TAKE = [
  'create function public.take_rate_slot(p_user uuid, p_action text)',
  'returns boolean language plpgsql security definer as $$ begin return true; end; $$;',
  'revoke all on function public.take_rate_slot(uuid, text) from public, anon, authenticated;',
  'grant execute on function public.take_rate_slot(uuid, text) to service_role;',
].join('\n');

const RELEASE_BUGGED = [
  'create function public.release_rate_slot(p_user uuid, p_action text)',
  'returns void language plpgsql security definer as $$ begin update t set a = 1; end; $$;',
  'revoke all on function public.release_rate_slot(uuid, text) from public, anon, authenticated;',
].join('\n');

test('dzien wdrozenia: rozjazd zero, a funkcja mimo to martwa', async () => {
  const { drift, intent } = await analyze(
    {
      '20260829130000_rate_limits.sql': TAKE,
      '20260901130000_rate_limit_release.sql': RELEASE_BUGGED,
    },
    [
      fn({ name: 'take_rate_slot', argtypes: ['uuid', 'text'], returns: 'boolean',
        acl: ['postgres=X/postgres', 'service_role=X/postgres'] }),
      // Baza dokladnie taka, jak kazala migracja: po revoke nie ma nikogo.
      fn({ name: 'release_rate_slot', argtypes: ['uuid', 'text'],
        acl: ['postgres=X/postgres'] }),
    ]
  );

  assert.equal(total(drift), 0, 'porownanie plikow z baza NIE ma tu nic do powiedzenia');

  assert.equal(intent.length, 1, 'a funkcja jest martwa i ktos musi to powiedziec');
  assert.equal(intent[0].text, 'public.release_rate_slot(uuid, text)');
  assert.equal(intent[0].where, 'w obu', 'martwa i w plikach, i w bazie');
  assert.equal(intent[0].inMigrations, true);
  assert.equal(intent[0].inDb, true);
  assert.equal(intent[0].excusedByDefinerCaller, false);
  assert.deepEqual(intent[0].callers, [], 'wolajacy jest poza baza, nie w SQL');
});

test('wskazuje revoke bez pary z dokladnoscia do pliku i wiersza', async () => {
  const { intent } = await analyze(
    { '20260901130000_rate_limit_release.sql': RELEASE_BUGGED },
    [fn({ name: 'release_rate_slot', argtypes: ['uuid', 'text'], acl: ['postgres=X/postgres'] })]
  );
  assert.equal(intent.length, 1);
  const rev = intent[0].touched.filter((t) => t.kind === 'revoke').pop();
  assert.equal(rev.file, '20260901130000_rate_limit_release.sql');
  assert.deepEqual(rev.roles, ['public', 'anon', 'authenticated']);
});

test('podpowiada brakujaca role z sasiadki w tym samym pliku migracji', async () => {
  const both = [
    'create function public.a() returns void as $$ begin end; $$;',
    'revoke all on function public.a() from public;',
    'grant execute on function public.a() to service_role;',
    'create function public.b() returns void as $$ begin end; $$;',
    'revoke all on function public.b() from public;',
  ].join('\n');
  const { intent } = await analyze(
    { '001_rodzina.sql': both },
    [fn({ name: 'a', acl: ['postgres=X/postgres', 'service_role=X/postgres'] }),
      fn({ name: 'b', acl: ['postgres=X/postgres'] })]
  );
  assert.equal(intent.length, 1);
  assert.equal(intent[0].text, 'public.b()');
  assert.equal(intent[0].suggestion.role, 'service_role');
  assert.match(intent[0].suggestion.why, /tego samego pliku/);
});

// --- czego NIE zglaszamy -----------------------------------------------------

test('funkcja wyzwalacza bez nadan to stan normalny, nie zgloszenie', async () => {
  const sql = [
    'create function public.set_updated_at() returns trigger language plpgsql as $$',
    'begin new.updated_at = now(); return new; end; $$;',
    'revoke all on function public.set_updated_at() from public, anon, authenticated;',
  ].join('\n');
  const { intent } = await analyze(
    { '001.sql': sql },
    [fn({ name: 'set_updated_at', returns: 'trigger', acl: ['postgres=X/postgres'] })]
  );
  assert.deepEqual(intent, [], 'EXECUTE do funkcji wyzwalacza Postgres sprawdza przy CREATE TRIGGER');
});

test('funkcja zdarzeniowa tez nie', async () => {
  const { intent } = await analyze(
    { '000_nic.sql': '-- katalog bez deklaracji, ale nie pusty' },
    [fn({ name: 'rls_auto_enable', returns: 'event_trigger', acl: ['postgres=X/postgres'] })]
  );
  assert.deepEqual(intent, []);
});

test('funkcja wolana z SECURITY DEFINER jest zglaszana slabiej i z powodem', async () => {
  const sql = [
    'create function public.helper() returns void language plpgsql as $$ begin end; $$;',
    'revoke all on function public.helper() from public, anon, authenticated;',
    'create function public.entry() returns void language plpgsql security definer as $$',
    'begin perform public.helper(); end; $$;',
    'revoke all on function public.entry() from public;',
    'grant execute on function public.entry() to authenticated;',
  ].join('\n');
  const { intent } = await analyze(
    { '001.sql': sql },
    [fn({ name: 'helper', acl: ['postgres=X/postgres'] }),
      fn({ name: 'entry', body: 'begin perform public.helper(); end;',
        acl: ['postgres=X/postgres', 'authenticated=X/postgres'] })]
  );
  assert.equal(intent.length, 1);
  assert.equal(intent[0].text, 'public.helper()');
  assert.equal(intent[0].excusedByDefinerCaller, true);
  assert.deepEqual(intent[0].callers, ['public.entry()']);
});

test('funkcja, ktorej public nadal moze wolac, nie jest martwa', async () => {
  const { intent } = await analyze(
    { '001.sql': 'create function public.otwarta() returns void as $$ begin end; $$;' },
    [fn({ name: 'otwarta', acl: [], acl_is_default: true })]
  );
  assert.deepEqual(intent, []);
});

test('lista wyjatkow wycisza swiadomie zamkniete funkcje', async () => {
  const sql = [
    'create function public.tylko_cron() returns void language plpgsql as $$ begin end; $$;',
    'revoke all on function public.tylko_cron() from public, anon, authenticated;',
  ].join('\n');
  const rows = [fn({ name: 'tylko_cron', acl: ['postgres=X/postgres'] })];

  const bez = await analyze({ '001.sql': sql }, rows);
  assert.equal(bez.intent.length, 1);

  for (const wpis of ['tylko_cron', 'public.tylko_cron', 'public.tylko_cron()']) {
    const z = await analyze({ '001.sql': sql }, rows, { allow: [wpis] });
    assert.deepEqual(z.intent, [], 'wyjatek podany jako ' + wpis);
  }
});

test('martwa tylko w migracjach albo tylko w bazie jest rozroznialna', async () => {
  const sql = [
    'create function public.f() returns void as $$ begin end; $$;',
    'revoke all on function public.f() from public;',
  ].join('\n');

  // baza ma nadanie, migracje nie
  const a = await analyze({ '001.sql': sql },
    [fn({ acl: ['postgres=X/postgres', 'service_role=X/postgres'] })]);
  assert.equal(a.intent[0].where, 'w migracjach');

  // migracje maja nadanie, baza nie
  const b = await analyze(
    { '001.sql': sql + '\ngrant execute on function public.f() to service_role;' },
    [fn({ acl: ['postgres=X/postgres'] })]
  );
  assert.equal(b.intent[0].where, 'w bazie');
});
