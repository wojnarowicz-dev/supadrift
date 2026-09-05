'use strict';

// ---------------------------------------------------------------------------
// Nadania na tabelach i kolumnach
// ---------------------------------------------------------------------------
//
// Trzy rzeczy odrozniaja to od nadan na funkcjach i kazda z nich, pominieta,
// daje zgloszenia, ktorych nie ma.
//
// 1. LINIA BAZOWA NIE JEST PUSTA. CREATE FUNCTION nadaje EXECUTE roli `public`;
//    CREATE TABLE nie nadaje nic — ale w Supabase dziala ALTER DEFAULT
//    PRIVILEGES, ustawione poza migracjami. Nowa tabela dostaje wiec nadania,
//    o ktorych w katalogu migracji nie ma ani slowa. Tej linii bazowej nie da
//    sie zgadnac z plikow: czytamy ja z pg_default_acl i od niej zaczynamy
//    odgrywanie.
//
//    (W sprawdzanym projekcie linia bazowa dla tabel tworzonych przez `postgres`
//    w schemacie public to anon=Dxtm, authenticated=Dxtm, service_role=Dxtm —
//    czyli TRUNCATE/REFERENCES/TRIGGER/MAINTAIN, bez SELECT i bez zapisu.
//    Ktos zawezil stockowe ustawienie Supabase i to widac dopiero tutaj.)
//
// 2. NADANIA KOLUMNOWE sa w pg_attribute.attacl, nie w pg_class.relacl.
//    `grant select (a, b) on table t to anon` zostawia relacl BEZ anon.
//
// 3. REVOKE NA POZIOMIE TABELI ZDEJMUJE TAKZE NADANIA KOLUMNOWE. Tak mowi
//    dokumentacja Postgresa i tak to odgrywamy — inaczej `revoke all ... from
//    anon` w jednej migracji i `grant select (kolumny) ... to anon` w nastepnej
//    daloby wynik zalezny od kolejnosci w zly sposob.

const { defaultAclKey } = require('./introspect');

const ALL_PRIVS_BASE = ['select', 'insert', 'update', 'delete', 'truncate', 'references', 'trigger'];

function allPrivsFor(serverVersion) {
  // MAINTAIN doszedl w Postgresie 17. Na starszym serwerze ALL go nie obejmuje
  // i doliczanie go tworzyloby rozjazd przy kazdym `grant all`.
  return serverVersion >= 170000
    ? ALL_PRIVS_BASE.concat(['maintain'])
    : ALL_PRIVS_BASE.slice();
}

function cloneAcl(acl) {
  const out = new Map();
  for (const [role, privs] of acl) out.set(role, new Set(privs));
  return out;
}

/**
 * Odgrywa operacje z migracji na linii bazowej z bazy.
 * @returns {{table: Map<string,Set<string>>, columns: Map<string, Map<string,Set<string>>>}}
 */
function replay(ops, baseline, serverVersion) {
  const table = cloneAcl(baseline || new Map());
  const columns = new Map(); // kolumna -> Map<rola, Set<priv>>
  const ALL = allPrivsFor(serverVersion);

  for (const op of ops || []) {
    const privs = op.all ? ALL : op.privs;

    for (const role of op.roles) {
      if (op.op === 'grant') {
        if (privs.length) {
          if (!table.has(role)) table.set(role, new Set());
          for (const p of privs) table.get(role).add(p);
        }
        for (const cp of op.columnPrivs || []) {
          for (const col of cp.columns) {
            if (!columns.has(col)) columns.set(col, new Map());
            if (!columns.get(col).has(role)) columns.get(col).set(role, new Set());
            columns.get(col).get(role).add(cp.name);
          }
        }
      } else {
        if (op.all) {
          table.delete(role);
          // REVOKE na tabeli zdejmuje takze nadania kolumnowe.
          for (const perCol of columns.values()) perCol.delete(role);
        } else {
          const cur = table.get(role);
          if (cur) {
            for (const p of privs) cur.delete(p);
            if (cur.size === 0) table.delete(role);
          }
          for (const p of privs) {
            for (const perCol of columns.values()) {
              const s = perCol.get(role);
              if (s) { s.delete(p); if (s.size === 0) perCol.delete(role); }
            }
          }
          for (const cp of op.columnPrivs || []) {
            for (const col of cp.columns) {
              const s = columns.get(col) && columns.get(col).get(role);
              if (s) { s.delete(cp.name); if (s.size === 0) columns.get(col).delete(role); }
            }
          }
        }
      }
    }
  }

  for (const [col, perCol] of [...columns]) if (perCol.size === 0) columns.delete(col);
  return { table, columns };
}

function setText(s) {
  return [...s].sort().join(', ') || '(nic)';
}

function sameSet(a, b) {
  if (a.size !== b.size) return false;
  for (const x of a) if (!b.has(x)) return false;
  return true;
}

/**
 * @param {Map} expectedTables obraz tabel z migracji (z lista operacji `ops`)
 * @param {Map} actualTables   tabele z bazy (z `acl` i `owner`)
 * @param {Map} actualColumns  nadania kolumnowe z bazy
 * @param {{bySchemaOwner:Map, serverVersion:number}} defaults
 */
function compareTableGrants(expectedTables, actualTables, actualColumns, defaults, opts = {}) {
  const ignoreRoles = new Set(opts.ignoreRoles || []);
  const findings = [];

  for (const key of [...expectedTables.keys()].sort()) {
    const e = expectedTables.get(key);
    const a = actualTables.get(key);
    if (!a) continue; // brak tabeli w bazie zglasza osobna kontrola

    const baseline = defaults.bySchemaOwner.get(defaultAclKey(e.schema, a.owner))
      || defaults.bySchemaOwner.get(defaultAclKey(String(), a.owner))
      || new Map();
    const want = replay(e.ops, baseline, defaults.serverVersion);

    const roleDiffs = [];
    const roles = new Set([...want.table.keys(), ...a.acl.keys()]);
    for (const role of [...roles].sort()) {
      if (role === '__owner__' || ignoreRoles.has(role)) continue;
      const w = want.table.get(role) || new Set();
      const g = a.acl.get(role) || new Set();
      if (!sameSet(w, g)) {
        roleDiffs.push({ role, inMigrations: setText(w), inDb: setText(g) });
      }
    }

    const colDiffs = [];
    const gotCols = actualColumns.get(key) || new Map();
    const cols = new Set([...want.columns.keys(), ...gotCols.keys()]);
    for (const col of [...cols].sort()) {
      const wRoles = want.columns.get(col) || new Map();
      const gRoles = gotCols.get(col) || new Map();
      const cr = new Set([...wRoles.keys(), ...gRoles.keys()]);
      for (const role of [...cr].sort()) {
        if (role === '__owner__' || ignoreRoles.has(role)) continue;
        const w = wRoles.get(role) || new Set();
        const g = gRoles.get(role) || new Set();
        if (!sameSet(w, g)) {
          colDiffs.push({ column: col, role, inMigrations: setText(w), inDb: setText(g) });
        }
      }
    }

    if (roleDiffs.length || colDiffs.length) {
      findings.push({
        key, text: key, owner: a.owner,
        declaredIn: e.createdIn,
        roles: roleDiffs,
        columns: colDiffs,
        baseline: [...baseline].filter(([r]) => r !== '__owner__')
          .map(([r, p]) => r + '=' + setText(p)).sort(),
      });
    }
  }

  return findings;
}

module.exports = { compareTableGrants, replay, allPrivsFor, setText };
