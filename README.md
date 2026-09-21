# supadrift

**English** · [Polski](README.pl.md)

supadrift compares the **permissions** your SQL migrations describe with the
permissions actually in force in a Supabase database: `grant` and `revoke` on
functions, RLS policies, `search_path` on `SECURITY DEFINER` functions, and
grants at table and column level.

That is a different layer from schema diffing. **Atlas**, **pg-schema-diff** and
**Liquibase** compare *structure* — tables, columns, indexes, constraints, views.
supadrift compares *who is allowed to do what*. Different question, different
answer — see [What supadrift does not do](#what-supadrift-does-not-do).

Nobody checks that permission layer against the files. Supabase's Security
Advisor looks **only at the database**. Tools like `pgrls` look **only at the
files**. The gap between the two is a real class of bug, and nothing reports it:

> Migration `20240115120000` had a `revoke` without a matching `grant execute`
> for `service_role`. The function `refund_quota` had not executed once since
> deployment. The database was "correct" (privileges exactly as instructed), the
> files were "correct" (the revoke sat where it was meant to), and the function
> was dead. It took a second migration, found by hand, to fix it.

## Run it without installing

```
npx supadrift --via-cli
```

Node 18 or newer, run from a Supabase project directory linked with the
Supabase CLI — that path needs no password at all. Without the CLI, put the
address in `SUPADRIFT_DB_URL` or in `.env`; it is never taken as an argument,
because arguments end up in the shell history. supadrift only reads.

---

## What supadrift does not do

It does not compare columns, types, indexes or constraints. It will not tell you
that a column changed type, that an index is missing, or that a check constraint
drifted. For that there are mature tools — **Atlas**, **pg-schema-diff**,
**Liquibase** — and this is not an attempt to replace any of them.

They are **complementary, not competing**. Running both is the sensible setup: a
schema differ to keep the structure honest, supadrift to keep the permission
layer honest. They catch different bugs and neither substitutes for the other.

The three real defects this tool found in its author's database make the split
concrete:

| finding | what it was | would a schema differ report it? |
|---|---|---|
| `revoke` with no matching `grant` | privilege drift: the database granted `EXECUTE` to `service_role`, the migrations did not | **no** — the object exists on both sides and is structurally identical |
| a function present in the database, absent from every migration | a missing schema object | **yes** — that is exactly what they are for |
| `SECURITY DEFINER` without `pg_temp` in `search_path` | not a drift at all: the files and the database agreed | **no** — a differ compares two sides, and here the two sides matched |

The third row is the one worth pausing on. **Nothing that works by comparing two
states can report it**, because there was nothing to compare: both sides said the
same thing and both were wrong. That is why the intent checks exist alongside the
drift checks — and it is the reason a permissions tool cannot be a feature bolted
onto a schema differ.

## Connecting

**Read this section first.** A tool you have to let into a production database
owes you an immediate account of what it does there.

### 1. Read-only, always

supadrift never issues `create`, `alter`, `grant`, `revoke` or `drop`. This is
not a promise in the documentation — it is a property of the program, enforced
in three places at once:

- `src/db/readonly.js` admits **only a single `SELECT`**. Every query passes
  through that gate before it reaches a driver; both connection paths use it and
  there is no way around it.
- The queries supadrift sends are **string constants** in this repository
  (`src/introspect.js`). There is no interpolation, so there is nothing to
  inject.
- The direct connection sets the session to `read only` and wraps each read in a
  `BEGIN READ ONLY` transaction closed by `ROLLBACK`.

supadrift **does not apply** the repair migration it generates. It prints it for
you to paste. A tool that fixes privileges itself would need permission to
change them — and at that point it stops being a read-only tool and becomes one
more thing that can break production at 3 a.m.

### 2. Credentials come from the environment or `.env` — never from an argument

supadrift **refuses to start** if it sees a connection string, service key or
token in `argv`. It does not warn; it exits with code 2.

The reason: an argument is not private. It lands in shell history
(`~/.bash_history`, `ConsoleHost_history.txt`), in CI logs, in `ps` visible to
every user on the machine, and in the error message someone later pastes into a
bug report. A warning you can scroll past protects nothing — by then the key is
already in the history.

```powershell
$env:SUPADRIFT_DB_URL = "postgresql://supadrift_ro:PASSWORD@..."
supadrift
```

```bash
export SUPADRIFT_DB_URL="postgresql://supadrift_ro:PASSWORD@..."
supadrift
```

Variables read, in order: `SUPADRIFT_DB_URL`, `SUPABASE_DB_URL`, `DATABASE_URL`.
If none is set, supadrift looks for them in `.env` in the current directory (or
in the file given by `--env-file`).

### 3. The key never reaches the output

Not the report, not the generated migration, not an error message. Every
output — including `--json` and the file written by `--fix` — passes through
`redact()` in `src/secrets.js`, which strips the registered connection string,
the password on its own, and anything shaped like `sb_secret_*`, `sbp_*` or a
JWT. The database address is shown as host and database name only, without user
or password.

Three more things stand behind `redact()`, each closing a different escape
route:

- **`process.on('uncaughtException')` and `('unhandledRejection')`** in
  `bin/supadrift.js`, plus `client.on('error')` in `src/db/pg.js`. An error
  thrown outside the promise chain — a socket event, a dropped session, a
  timer — would be printed by Node as a raw object with a stack trace,
  **bypassing `redact()`**. Those three listeners exist so that route does not.
- **An unrecognised argument is never echoed.** Only the option name is printed;
  a bare argument is reported as `(content omitted)`. An unrecognised argument is
  sometimes a password pasted into the wrong place, and the error message goes to
  a CI log that shell history does not cover.
- **The `supabase` subprocess never receives the database address.**
  `src/db/cli.js` strips `SUPADRIFT_DB_URL`, `SUPABASE_DB_URL`, `DATABASE_URL`,
  `PGPASSWORD`, `PGPASSFILE` and `PGSERVICE` from the environment handed to a
  binary that does not need them — it authenticates with its own token.
  Otherwise the password would be visible in `ps` to every user on the machine.

**What does come out, and is meant to: the host name.** The report states what it
connected to, and on Supabase the host contains the project reference
(`db.<ref>.supabase.co`); a DNS error shows it too. That is deliberate — a report
that does not say which database it checked is worthless. If the output is going
into a log a stranger will read, use **`--hide-target`**: the host and the `ref`
(including the one inside the pooler username `role.<ref>`) are registered as
secrets and disappear from the **entire** output, replaced by an eight-character,
non-reversible fingerprint that still lets you tell two runs apart.

One known limitation: `registerSecret()` registers passwords of four characters
and up. Shorter ones are not registered as standalone strings, because that would
turn incidental words in the report into `[REDACTED]`; the
`://user:password@` pattern catches them anyway.

### 4. A read-only role — you do not need the service key

Everything supadrift reads lives in system catalogues: `pg_proc`, `pg_class`,
`pg_namespace`, `pg_depend`, `pg_policy`, `pg_attribute`, `pg_default_acl`,
`pg_trigger` and `pg_event_trigger`. The first five were verified directly
against a live project: each has an `=r/…` entry in its ACL, meaning `SELECT` for
the `public` role, and `has_table_privilege('anon', …, 'SELECT')` returns true
for all of them. The rest are catalogues of the same class with the same default
grant. A role for supadrift therefore **needs no grant beyond `CONNECT`** — it
never has to see a single row of your data.

In the Supabase SQL editor:

```sql
-- Generate a long random password; do not type one from your head.
create role supadrift_ro with login password 'PASTE_A_LONG_RANDOM_PASSWORD';

grant connect on database postgres to supadrift_ro;

-- No ability to create anything, no role inheritance.
alter role supadrift_ro nosuperuser nocreatedb nocreaterole noinherit;

-- Extra layer: every transaction of this role defaults to read only.
alter role supadrift_ro set default_transaction_read_only = on;
```

This role holds no object privileges, so there is nothing in the database it
could write — or read, beyond the system catalogues.
`default_transaction_read_only` is an extra layer, not a boundary: a client can
override it. The boundary is the absence of grants.

Take the connection string from the Supabase dashboard (**Connect**) and replace
the user and password with the ones above. A custom role works over the direct
connection (`db.<ref>.supabase.co:5432`) and over the session pooler
(`aws-0-<region>.pooler.supabase.com:5432`, user `supadrift_ro.<ref>`). If your
network has no IPv6, use the pooler.

Use port **5432** (session mode), not 6543. In transaction mode `SET SESSION` is
not guaranteed to survive between statements, and supadrift relies on it.

Revoking the access when you no longer need it:

```sql
drop role supadrift_ro;
```

#### TLS: verification stays on

The Supabase pooler presents a certificate signed by its own CA, which is not in
Node's trust store. With verification enabled the connection fails with
`self-signed certificate in certificate chain` — **before the password is ever
sent**.

The right answer is to point at that CA, not to switch checking off. Download
the certificate from the dashboard (**Settings → Database → SSL Configuration**)
and give supadrift its path:

```
SUPADRIFT_SSL_CA=C:/Users/you/supadrift/supabase-ca.crt
```

Verification stays **on** — only the trust anchor changes. A missing file, or a
file that is not PEM, is a fatal error with exit code 2; supadrift will not
quietly fall back to the defaults.

`SUPADRIFT_SSL_NO_VERIFY=1` remains as a last resort. It disables server
authentication, so the connection stops defending against anything impersonating
your database. There is deliberately **no command-line switch** for it.

### 5. A path with no password at all

If you have a project linked in the Supabase CLI, supadrift can read the
database through it and then **sees no credential whatsoever**:

```bash
supadrift --via-cli
```

Convenient, but not minimal: the CLI uses its own Management API token, and that
token is powerful. For routine use, and for CI in particular, the read-only role
from point 4 is the better choice.

---

## Quick start

From a clone. Installed from the registry, `pg` comes with the package and the
command is `supadrift` — or `npx supadrift`, as at the top of this page.

```bash
cd supadrift
npm install                      # only to get `pg`; not needed with --via-cli
node bin/supadrift.js --help
```

From a Supabase project directory (supadrift finds `supabase/migrations` on its
own):

```bash
node bin/supadrift.js --via-cli
```

Or pointing at a directory and connecting directly:

```bash
export SUPADRIFT_DB_URL="postgresql://supadrift_ro:...@..."
node bin/supadrift.js --migrations ../my-project/supabase/migrations
```

Exit codes: **0** clean, **1** drift found, **2** error. Suitable for CI without
a wrapper.

---

## How it works, step by step

1. **Reads the migrations** from the directory, in filename order, and replays
   them onto a privilege model. It executes no SQL while doing so.
2. **Queries the database** — `pg_proc`, `pg_namespace`, `pg_depend` and the
   rest — for the actual state.
3. **Compares in three categories:**
   - in the migrations, not in the database — the migration was never deployed;
   - in the database, not in the migrations — somebody changed the database by
     hand, and a fresh environment will not get it;
   - **in both, but different** — this is where the real bugs live. The first two
     categories announce themselves the next time an environment is rebuilt. The
     third can survive for months: the code runs, the tests pass, and one role
     has exactly one privilege too few.
4. **Prints a report and a ready repair migration** for you to paste. It does not
   apply it.

On top of that come the **intent checks**, which compare nothing with nothing —
described below, because they exist for a different reason.

## Scope

| what | what it checks |
|---|---|
| functions and procedures | that they exist, who holds `EXECUTE`, `SECURITY DEFINER`, `search_path` |
| intent check | whether anything can call the function at all |
| `SECURITY DEFINER` | whether `search_path` contains `pg_temp`, and whether it is last |
| tables | `ROW LEVEL SECURITY` and `FORCE ROW LEVEL SECURITY` |
| table grants | privileges per role, **including column-level ones** |
| policies | command, kind, roles, `USING`, `WITH CHECK` |
| triggers | table triggers (`pg_trigger`) and event triggers (`pg_event_trigger`) |
| intent check for tables | RLS enabled with zero policies |

All within the `public` schema (or whichever you pass via `--schema`).

### Functions: EXECUTE

The privilege model mirrors what Postgres actually does, because that is where
the bug we are hunting lives:

- `CREATE FUNCTION` grants `EXECUTE` to **`public`** automatically. Every role
  then inherits the right to call it *through* `public` — `service_role`
  included, even though nobody granted it anything explicitly.
- `REVOKE ... FROM public` takes that away from **everyone** who held it only by
  that route. If no explicit grant follows the revoke, the function can be called
  by its owner and nobody else.
- `proacl = NULL` in the database does not mean "no privileges", it means
  "defaults": the owner **plus `EXECUTE` for `public`**. It looks like one thing
  and means the other.
- `CREATE OR REPLACE` does **not** reset grants — and neither does supadrift.

The owner's own ACL entry is not compared: Postgres adds it automatically and no
migration grants it explicitly. Comparing it would produce drift on every
function and drown the signal.

Functions belonging to extensions (`pg_depend.deptype = 'e'`, e.g. `pgcrypto`)
are filtered out — they will never be in a migrations directory and reporting
them would be pure noise.

### Intent check: a function nothing can call

Comparing files against the database has one blind spot, and it sits exactly
where it hurts most: **it cannot see a bug where the files and the database are
wrong in the same way.** On the day the buggy migration reached production, the
database matched it exactly. Drift was zero. The function was dead.

This check compares nothing with nothing. It looks at one image at a time — the
migrations, then the database — and asks: after these privileges, is there
anyone left who can call this function? If a `revoke` from `public` is followed
by no `grant execute`, only the owner remains, and no Supabase client is the
owner. The report says where the function is dead: `in migrations`, `in the
database`, or — worst — `in both`.

It also suggests the missing half of the pair, and does not guess it out of thin
air: it looks at the neighbours, first among functions created in the same
migration file, then across the whole set. That is exactly how you diagnose this
by hand.

**What it deliberately does not report**, because the absence of grants is normal
there:

- Trigger functions (`returns trigger`, `returns event_trigger`). Postgres checks
  `EXECUTE` on them at `CREATE TRIGGER` time, not on every firing.
- Functions called from the body of another `SECURITY DEFINER` function. During
  such a call the current user **is** the owner, so the check passes. That is a
  deliberate pattern, so it is reported separately, more weakly, and with the
  reason.
- Functions on the `--allow-owner-only` list — for the ones that genuinely should
  be reachable by the owner alone (`pg_cron` jobs and the like).

Disable with `--no-intent`.

### `SECURITY DEFINER` and `search_path`

A `SECURITY DEFINER` function resolves names with the owner's privileges, so its
`search_path` must be pinned in the definition. The half that is easiest to
forget:

```
set search_path = public              <- pg_temp is STILL first
set search_path = public, pg_temp     <- pg_temp last, which is the point
```

The temporary schema is searched **first** for relation names until it is listed
explicitly — and any user can create a table of any name in their own `pg_temp`.
So `set search_path = public` does not close that door; only putting `pg_temp` at
the end of the list moves it to the end of the search order.

The check distinguishes three states: `no-search-path` (worst, reported first),
`missing-pg_temp` and `pg_temp-not-last`.

The suggested fix is computed **per function**, not taken from the majority. A
function that already has `search_path = pg_catalog` must not be "fixed" to
`public, pg_temp` — that would substitute a different schema under its names. The
majority is used only where there is nothing to extend, and then the report says
how many other `SECURITY DEFINER` functions it is drawn from.

`SECURITY INVOKER` functions are not in scope: they run with the caller's
privileges, so substitution gains an attacker nothing they did not already have.
Disable with `--no-secdef`, silence with `--allow-search-path`.

### Tables: RLS and FORCE

Two things, both easy to miss:

- **`CREATE TABLE` does not enable RLS.** A migration that creates a table and
  does not say `alter table ... enable row level security` describes a table
  **with no protection** — even if production is protected, because somebody
  enabled it by hand or an event trigger did. A fresh environment gets the table
  open, and in Supabase `anon` and `authenticated` hold `SELECT` on the `public`
  schema.
- **RLS does not apply to the table owner by default.** Until
  `FORCE ROW LEVEL SECURITY` is set, policies do not constrain whoever created
  the table — usually the `postgres` role, which runs migrations and more than
  one maintenance job. That is why `FORCE` is tracked and compared separately
  from `RLS`.

The parser understands `enable`/`disable`, `force`/`no force` (in that order —
`no force` contains `force`), `rename to` and `drop table`. Extension-owned
tables are filtered out, as with functions.

Disable with `--no-tables`.

### Table and column grants

Three things separate this from function grants, and each one, if skipped,
produces findings that are not there. All three surfaced only on contact with a
real database.

**1. The baseline is not empty.** `CREATE FUNCTION` grants `EXECUTE` to `public`;
`CREATE TABLE` grants nothing — but Supabase ships `ALTER DEFAULT PRIVILEGES`,
configured outside migrations. A new table therefore receives grants that the
migrations directory says nothing about. That baseline cannot be guessed from the
files, so supadrift reads it from `pg_default_acl` and replays `grant`/`revoke`
on top of it. The report shows the baseline alongside every finding, so you can
see what it is counting from.

**2. Column grants live in `pg_attribute.attacl`, not `pg_class.relacl`.**
`grant select (a, b) on table t to anon` leaves `relacl` **without** `anon`. A
model that does not read that reports "the migration grants SELECT to anon and
the database does not" — lying precisely about the table whose privileges were
chosen most carefully.

**3. A table-level `REVOKE` also removes column grants.** That is what the
Postgres documentation says, and that is how it is replayed, in migration order.

`ALL` depends on the server version: `MAINTAIN` arrived in Postgres 17, so on an
older server `grant all` does not include it and counting it would create drift on
every table. supadrift reads `server_version_num` and computes `ALL` for that
server.

Disable with `--no-grants`.

### Triggers

**A trigger function is not the same thing as a trigger.** The function can be
present on both sides with identical privileges while the **attachment** exists
in one environment only — and then it fires for nobody else. None of the checks
above can see that.

Compared strictly: function, timing (`before`/`after`/`instead of`), events
(order does not matter), `UPDATE OF` with its column list, level
(`row`/`statement`), enabled state, and the presence of `WHEN`. The body of
`WHEN` is compared softly, for the same reason as policy expressions.

The `not tgisinternal` filter is a necessity, not a nicety: Postgres creates its
own hidden triggers for **every foreign key**. Without it the report would drown
in `RI_ConstraintTrigger_c_12345` entries that nobody will ever write in a
migration.

**Event triggers are a separate and worse case.** `CREATE EVENT TRIGGER` requires
superuser, and the `postgres` role that runs `supabase db push` **is not** one on
Supabase. Such a trigger therefore cannot be deployed by migration and is
necessarily created by hand — after which the repository knows nothing about it
and a fresh environment does not get it.

That is what `allowManual` is for. It **does not silence** the finding; it moves
it into a separate section, "OUTSIDE MIGRATIONS, DELIBERATELY": it does not count
towards the exit code, but it is printed in **every** report. A manually created
trigger must stay visible — otherwise in six months nobody will remember that a
new environment needs an extra step.

Disable with `--no-triggers`.

### Policies

Compared strictly: the command (`for select` / `insert` / …), the kind
(`permissive` / `restrictive`), the role list, and the **presence or absence** of
`USING` and `WITH CHECK`. Defaults matter more than usual here, because almost
nobody writes them and they determine the reach: no `AS` means `PERMISSIVE`
(policies combine with OR, they do not narrow), no `FOR` means `ALL`, and no `TO`
means **`public`, that is every role, including `anon`**.

Expression bodies are a separate matter, and it is worth knowing why. **Postgres
does not store the text you wrote** — it stores a tree and regenerates text on
demand:

```
in the migration   (select auth.uid()) = user_id
pg_get_expr()      (( SELECT auth.uid() AS uid) = user_id)
```

Enclosing parentheses and a column alias appeared. A string comparison would
report drift on **every** policy — and a tool that reports everything reports
nothing. So both sides are reduced to a token stream and stripped of exactly the
two things Postgres adds by itself (`src/expr.js`).

What that does not solve, and what the report says plainly: Postgres also rewrites
casts (`cast(x as text)` → `(x)::text`), expands operator names and qualifies
schemas. A difference in the expression body alone is therefore a **"look at this
with your own eyes"** signal, not proof of drift — and it is labelled as such.
Presence or absence of the clause stays strict. `--no-policy-expr` turns off body
comparison and leaves the rest.

Disable with `--no-policies`.

### Intent check for tables: RLS with no policy at all

The same shape of bug as with functions, one level up. RLS enabled with zero
policies means the table is reachable only by roles with `BYPASSRLS` (on
Supabase: `service_role`) and — unless `FORCE` is set — by the owner.

And now the important part: **two entirely different situations look identical in
the catalogue.** A table deliberately closed to everything but `service_role`, and
a table where somebody enabled RLS and forgot the policy, have the same
representation. No query can tell them apart, because the difference lives in
intent.

The only honest resolution is an exception list. Deliberately closed tables are
listed once and stop speaking up; every **new** table in that state reports
itself. Silence then means "checked and intended", not "overlooked".

## Exception lists — `supadrift.json`

An exception is a fact about the project, not about a single run, so it belongs
in the repository next to the migrations rather than in shell history. supadrift
looks for `supadrift.json` in the current directory, then in the Supabase project
directory (the one containing `supabase/`); `--config` overrides both.

```json
{
  "allowNoPolicy": [
    "public.quota_usage"
  ],
  "allowOwnerOnly": [
    "public.cron_only()"
  ],
  "allowSearchPath": [],
  "allowManual": ["rls_guard"],
  "ignoreRoles": []
}
```

Keys beginning with `$` are ignored — that is the place for the reason an
exception exists. An exception without a justification is, six months later,
indistinguishable from an oversight.

**Credentials must never be kept in this file.** supadrift does not read them
from here — the address and key come only from the environment or `.env`.

## What "clean" means

An absence of findings has to mean "I checked and it matches", not "I could not
check". Hence:

- Anything the parser **did not model** appears in its own section of the report,
  "WHAT SUPADRIFT DID NOT READ FROM THE MIGRATIONS" — `ALTER DEFAULT PRIVILEGES`,
  `GRANT ... ON ALL FUNCTIONS IN SCHEMA`, `GRANT`/`REVOKE` inside a `DO $$` block,
  `SECURITY LABEL`, `REASSIGN OWNED`. As long as anything is listed there, "clean"
  means "clean apart from that".
- A privilege granted to a function whose `CREATE` is not in the directory is
  recorded too, not passed over.
- Policy expression bodies are compared after normalisation and **marked as
  soft**. The report states plainly that the difference may be only a different
  spelling. We do not fake a certainty we do not have.

The blind spot of comparison itself — a bug where the files and the database are
wrong in the same way — is covered by the two intent checks: for functions
(`EXECUTE` after a `revoke` from `public`) and for tables (RLS with no policy).
Both look at a single image instead of comparing two.

### Fail loudly or pass — never quietly return zero

The worst possible result from this tool is **"clean" on input it never read**:
it tells you it checked when it checked nothing. The following are therefore
**fatal errors with exit code 2**, not warnings:

| situation | why fatal |
|---|---|
| unterminated `$$`, string literal, identifier or block comment | the file is truncated; the tokenizer is forgiving and would otherwise pretend it read the whole function |
| unbalanced parentheses | same — everything after that point is guesswork |
| a `0x00` byte in a `.sql` file | this is not text somebody wrote |
| a `.sql` file that cannot be read (`EACCES`, `EISDIR`) | that migration **was not read**; skipping it quietly falsifies the result |
| a directory with no `.sql` file at all | an empty expected image compared against a database yields a result you must not trust |
| `--as-of` filtering out every migration | there is nothing to build an image from |
| invalid `supadrift.json` | the exception lists are part of the definition of "clean" |

The tokenizer collects damage into a separate channel (`tokenize(sql, issues)`)
and `buildExpected()` turns it into an exception — the report is never produced.

Each of these scenarios has a **pair** in `test/odpornosc.test.js`: one run with
broken input and one with healthy input of the same shape. Without the second
half the first would prove nothing — it would also pass if the tool failed
always and everywhere.

## Known answer

The tool grew out of a specific bug, and that bug is its reference test. The
names below are neutralised; **the fixtures in `test/` use real names from the
author's private project and run only there** — which is why they were left
alone. The shape of the check is identical.

**A note on language.** The report itself is written in Polish. The blocks below
are the tool's real output, verbatim — not a translation — with an English gloss
underneath each one. `tools/readme-gate.js` reproduces this scenario with the
real code and fails if these blocks stop matching what the tool prints.

State **before** the fix (`--as-of` pretends the later migrations do not exist
yet):

```
$ supadrift --via-cli --as-of 20240115130000 --only quota

JEST W OBU, ALE INACZEJ  (1)
  public.refund_quota(uuid, text)
      service_role     baza ma EXECUTE, w migracjach tego nadania NIE MA
      ostatnia zmiana uprawnien w migracjach:
        20240115120000_refund_quota.sql:58 (revoke public, anon, authenticated)
```

> *In both, but different (1) — `public.refund_quota(uuid, text)`: the database
> has EXECUTE for `service_role`, the migrations have no such grant. Last
> privilege change in migrations: `20240115120000_refund_quota.sql:58` (revoke
> public, anon, authenticated).*

It points at the file and the line. The healthy sibling `claim_quota`, which has
the full `revoke` + `grant` pair, stays silent in the same run — a negative
control inside a positive one.

In the same run the intent check speaks up and reconstructs, on its own, the line
a human added by hand two migrations later:

```
NIE MA KTO WOLAC  (1)
  public.refund_quota(uuid, text)     martwa: w migracjach
      poza wlascicielem (postgres) EXECUTE nie ma nikt
      revoke bez pary: 20240115120000_refund_quota.sql:58
      zadna inna funkcja SQL jej nie wola — wolajacy jest poza baza
      brakujaca polowa pary najpewniej brzmi:
        grant execute on function public.refund_quota(uuid, text) to service_role;
```

> *Nothing can call it (1) — `public.refund_quota(uuid, text)`, dead: in
> migrations. Apart from the owner (`postgres`) nobody holds EXECUTE. Revoke
> without a pair: `20240115120000_refund_quota.sql:58`. No other SQL function
> calls it — the caller is outside the database. The missing half of the pair is
> most likely: `grant execute on function public.refund_quota(uuid, text) to
> service_role;`*

On the full set of migrations `refund_quota` does not report at all.

**Day of deployment.** The most important case is the one where the database
agreed with the migration and both were wrong. Drift there is **zero**, and the
intent check still says `dead: in both`. That scenario is the first test in
`test/intent.test.js` and runs without a database.

All of it: `npm test` — 160 tests, no connection to anything.

## The six triggers that were not in the mock

For a long stretch of its development this tool could not reach a live database:
the Management API returned 403 and there was no password for a direct
connection. So it was verified offline — against a database image reconstructed
from the migrations themselves, plus rows captured earlier by hand.

That verification was not theatre. It found real defects: a NUL byte that broke
a lookup key, a regex that refused to match schema-qualified calls, a phantom
table produced by `ON ALL TABLES IN SCHEMA`. When the table-grant model was later
checked against production, it matched to the letter.

**And then the first run against a real database returned six findings that no
mock had ever contained.**

```
WYZWALACZE — JEST W BAZIE, NIE MA W MIGRACJI  (6)
  event trigger pgrst_ddl_watch            ->  extensions.pgrst_ddl_watch()
  event trigger pgrst_drop_watch           ->  extensions.pgrst_drop_watch()
  event trigger issue_pg_cron_access       ->  extensions.grant_pg_cron_access()
  event trigger issue_pg_graphql_access    ->  extensions.grant_pg_graphql_access()
  event trigger issue_pg_net_access        ->  extensions.grant_pg_net_access()
  event trigger issue_graphql_placeholder  ->  extensions.set_graphql_placeholder()
```

These are Supabase's own platform triggers. They stand in **every** project, they
are owned by `supabase_admin`, and their functions live in the `extensions`
schema. They will never appear in anyone's migrations, and reporting them is pure
noise — the kind that gets a tool switched off in its first week.

The cause was a gap in scoping. An event trigger is an object of the **whole
database**, not of a schema — and that is exactly why it did not occur to me that
`--schema` applies to it as well. Every other check was scoped; this one was not.
The fix scopes event triggers by the schema of the function they call:
`extensions` drops out, `public` stays. The distinction is clean and needs no
hard-coded Supabase role name.

**Here is the part worth keeping.** A mock can only contain what its author
already knows. That is precisely the class of defect it cannot catch — not
because the mock was careless, but because a reconstructed image is built from
the same assumptions as the code under test. Offline verification proves the
parser and the comparison logic. It cannot prove the *query*: what the database
actually holds, and what else lives there that nobody put in a migration.

A tool whose job is to compare files against a database has to be verified
against a database. Not instead of the offline tests — those caught defects a
live run never would have surfaced — but in addition to them, and before anyone
is told the result means something.

This is also why the known-answer fixtures use real names from a private project
and run only there. A test that runs everywhere tests only what its author
imagined.

## A gate that passed while checking nothing

The same failure has a second instance in this repository, and this one is
funnier, because the victim was the checker itself.

`tools/readme-gate.js` verifies that the README tells the truth: it extracts
the fenced code blocks, runs the commands, compares every number against a real
result, and reproduces the example finding with the real renderer. In the working
tree it passed.

Then it was run against a **fresh `git clone`** — and found **zero code blocks**.
Git converts LF to CRLF on checkout on Windows, and the extractor's pattern
expected a bare `\n` after the opening fence. Every check built on those blocks
was now comparing an empty set: no options to verify, no JSON to parse, no
commands to run.

Some of those checks failed loudly, which is how it was caught. But that was
luck, not design — a slightly more forgiving assertion and the gate would have
printed a clean bill of health while verifying **nothing at all**. That is
precisely the outcome supadrift itself is built to refuse: "clean" on input that
was never read.

The fix has two halves, and the second matters more than the first:

1. Normalise line endings on read.
2. **An empty set is a failure.** Every check that operates on a collection goes
   through one helper that refuses a count of zero, and the count is printed in
   the result — `opcje zgodne z --help (26)`, `odnosniki wzgledne (3)`. A zero is
   visible to the eye instead of hiding behind an `OK`.

With the normalisation deliberately removed again, the gate now reports
`sprawdzono ZERO elementow` and exits 1. The bug can no longer pass as a pass.

A check that can silently find nothing must fail, not succeed. It is the same
rule as "fail loudly or pass, never quietly return zero" — and it turns out to be
just as easy to break in the checker as in the thing being checked.

## Twice more, and the rule that came out of it

The last piece of work on this repository was cosmetic: renaming Polish
identifiers to English before publication. Comments and the on-screen report
stayed Polish; only names changed. Mechanical, low-risk, done file by file with
`npm test` after each one. **156 of 156 passed at every single step.**

It still went wrong twice, and both failures had the same shape as the one above.

**The rename reached into the display strings.** `liczba` → `count` turned
`'deklarowana liczba testow'` into `'deklarowana count testow'`. `padlo` →
`failed` turned `'przeszlo 156, padlo 0'` into `'przeszlo 156, failed 0'`. The
report was now half-Polish, half-English, in exactly the places a user reads
first.

The test suite never noticed. It could not: no test asserts on those particular
sentences, and nothing about the program's *behaviour* had changed. The README
gate caught it on the next run, because the gate does not check behaviour — it
checks the surface, comparing what the program prints against what the
documentation claims.

**The rename itself sometimes did nothing at all.** Run through a shell, the
substitution lost the word boundaries in its pattern. One invocation reported
`78 podmian`; another, structurally identical, replaced zero. And `npm test`
passed in both cases — because in the failing case nothing had changed, and a
suite that was green before a no-op is green after it too.

That is the trap worth naming. **A green test suite tells you that behaviour did
not break. It cannot tell you that work was done.** After a refactor that
silently failed, the two are indistinguishable from the outside: same tests, same
result, same confidence — and no work.

So the rule, now implemented in two places rather than merely described:

> Any operation that can silently do nothing must report **how much** it did, and
> treat zero as a failure.

- `recordSet()` in `tools/readme-gate.js` refuses a count of zero and prints the
  count in the result.
- The rename tool prints substitutions per file and exits non-zero on a total of
  zero.

Three instances in one repository — the gate that verified nothing, the rename
that changed nothing, the strings that broke without a single test noticing. The
shape is identical each time: an operation reporting success without having
operated. It is the same failure this whole tool exists to catch in a database,
and it turns out to be no easier to avoid in the tooling that hunts it.

## Options

```
--migrations <dir>      migrations directory (default ./supabase/migrations)
--via-cli               read the database through `supabase db query --linked`
--workdir <dir>         Supabase project directory for --via-cli
--schema <name>         schema to check, repeatable (default public)
--as-of <prefix>        ignore migrations later than the given filename prefix
--only <fragment>       only functions whose name contains the fragment
--ignore-role <role>    skip this role when comparing, repeatable
--no-intent             skip the intent check (functions with no caller)
--no-tables             skip table checks (RLS and FORCE)
--no-grants             skip table and column grants
--no-policies           skip policy checks
--no-triggers           skip table and event triggers
--no-secdef             skip the SECURITY DEFINER search_path check
--no-policy-expr        compare policies without USING/WITH CHECK bodies
--allow-owner-only <f>  this function IS meant to be owner-only, repeatable
--allow-search-path <f> this SECURITY DEFINER function IS meant to have the
                        search_path it has, repeatable
--allow-no-policy <t>   this table IS meant to have RLS with no policies
--allow-manual <name>   this trigger is created by hand, outside migrations
--sarif <file>          write the result as SARIF 2.1.0 (exit code becomes 0)
--sarif-base <dir>      repository root for paths inside the SARIF file
--hide-target           do not show the host or the project reference
--config <file>         exception lists (default supadrift.json)
--fix <file>            write the repair migration to a file
--no-fix                do not print the repair migration
--json                  output as JSON
--env-file <file>       where to read .env from (default ./.env)
-h, --help
```

`--as-of` is useful beyond testing: it answers "what would the drift look like if
the last migrations had not landed yet".

## In CI

A report in a terminal is something you have to remember to run. With SARIF the
result appears **next to the line of code in a pull request**, as an annotation,
and in the Security tab. That is the difference between a tool you have to
remember and one that speaks up by itself.

A ready file to copy:
[`.github/workflows/example.yml`](.github/workflows/example.yml). In short:

```yaml
permissions:
  contents: read
  security-events: write        # required by upload-sarif

- name: Compare migrations against the database
  env:
    SUPADRIFT_DB_URL: ${{ secrets.SUPADRIFT_DB_URL }}   # NEVER as an argument
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

### Findings do not break the build

With `--sarif` the exit code is **always 0**, whatever the number of findings.
Results go to the Security tab, not into the build result. A tool that blocks a
merge the first time you meet it gets switched off the same week — and then it
reports nothing at all.

**There is one deliberate exception: a fatal error still exits 2** — an unread
migration, a damaged file, no connection. "I could not check" is not the same as
"checked and clean", and a CI run should say so loudly.

### Why everything is `note` and never `error`

`level` in SARIF does not drive the build result — it drives how an alert looks
and whether it surfaces in review. Setting `error` would add nothing but noise,
and noise ends with the tool being switched off.

It is also the more honest mapping. Some findings are hard catalogue facts ("the
migration grants `EXECUTE` to `service_role`, the database has no such grant"),
but others require a human decision and have no business posing as a verdict:

- policy expression bodies and `WHEN` clauses — Postgres rewrites them, so the
  difference is sometimes purely textual;
- both intent checks — "a function with no caller" and "RLS with no policies" are
  questions about intent, not statements of error;
- "in the database, not in the migrations" is sometimes an agreed manual step
  (see `allowManual`).

### Rule identifiers

Every finding carries a `ruleId` such as
`supadrift/security-definer-search-path`. **The same identifier appears in the
text report**, in the "FINDINGS BY RULE" section — both outputs are produced by a
single function (`zebrane()` in `src/sarif.js`), so they cannot drift apart. The
full catalogue is in `src/rules.js`.

### Paths and anchors

`--sarif-base` must point at the repository root: GitHub matches alerts by
**relative** path written with forward slashes. An absolute path, or one that
escapes the root, produces an alert with no anchor — supadrift warns about that
on stderr.

Findings of the "in the database, not in the migrations" kind have, by
definition, no source file. So that an alert exists at all, they are anchored to
the **newest migration, line 1**, and the message says so explicitly — the anchor
points into the migration set, not at the location of the bug.

### Schema conformance

The file is validated against the **official OASIS schema** (`ajv-draft-04`,
schema in `test/fixtures/`), not eyeballed. The tests also cover GitHub code
scanning requirements the schema does not enforce: `startLine >= 1`, a valid
`ruleIndex`, `partialFingerprints` (without them alerts are lost whenever lines
move), and relative paths. There is also a negative control on the validator
itself — otherwise "passes the schema" would mean nothing.

## Why a tokenizer and not tree-sitter

`GRANT` and `REVOKE` are flat, regular DDL. A full syntax tree adds nothing here
and costs a dependency plus a grammar that has to be maintained alongside every
Postgres release.

There is exactly one trap, and it is specific: **dollar quoting**. A `plpgsql`
body sits between `$$` and `$$` and is full of semicolons; a naive
`sql.split(';')` cuts it into pieces and everything after that is guesswork. So
statement splitting works on tokens. `src/tokenizer.js` handles `$$` and
`$tag$`, `--` and nestable `/* */`, `'...'` with doubling, `E'...'` with
backslashes, `"..."` preserving case, and `$1` as a positional parameter rather
than the start of a quote. Every one of those has a test.

## Next

1. **Sequences and grants on them.** The same model as tables, different ACL
   letters.
2. **`ALTER DEFAULT PRIVILEGES` in migrations.** Today it is recorded as
   unmodelled; modelling it would allow comparing the baseline itself rather than
   taking it from the database as given.
3. **Columns and types.** The widest scope and the most noise — hence last.

## Licence

MIT. See [LICENSE](LICENSE).
