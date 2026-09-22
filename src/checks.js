'use strict';

// supadrift — which checks this build runs, stated once.
//
// WHY THIS FILE EXISTS. The set of checks was written out by hand in three
// places a person reads before trusting anything: the "Scope" table on both
// pages, the `--no-*` switches in the help, and the anonymous array in
// bin/supadrift.js that counts how many checks were switched off. Nothing held
// them to each other. A check added without a row in the table is a check
// nobody knows runs; a row without a check is a promise nothing keeps; and the
// `notApplicable` count was a list of eight local variables that had to be
// remembered rather than derived.
//
// This is the same defect found in looks-clean, where a command's header
// promised a narrower set of languages than the line directly under it and two
// gates stood green over the contradiction. The repair there is the repair
// here: ONE FACT IN THE CODE, and every sentence measured against it —
// not two sentences measured against each other.
//
// `flag` IS SHARED ON PURPOSE. `--no-tables` switches off both the table check
// and nothing else, but `--no-policies` switches off the policy comparison AND
// the RLS-without-policy intent check, and `--no-triggers` covers table
// triggers and event triggers together. That is how the flags have always
// behaved; writing it down here is the first time it has been stated where a
// test can read it.
//
// NOTHING IS REQUIRED HERE. This module is a leaf: the CLI and the tests both
// reach for it, and a dependency of its own would make a cycle out of a list.

/**
 * One row per check. `key` is what the CLI calls the result; `flag` is the
 * switch that turns it off (null = always runs); `name` is what the Scope
 * table on the pages calls it, in each language.
 */
const CHECKS = [
  { key: 'result', flag: null, en: 'functions and procedures', pl: 'funkcje i procedury' },
  { key: 'intent', flag: '--no-intent', en: 'intent check', pl: 'kontrola zamiaru' },
  { key: 'secdef', flag: '--no-secdef', en: 'SECURITY DEFINER', pl: 'SECURITY DEFINER' },
  { key: 'tableResult', flag: '--no-tables', en: 'tables', pl: 'tabele' },
  { key: 'tableGrants', flag: '--no-grants', en: 'table grants', pl: 'nadania na tabelach' },
  { key: 'policyResult', flag: '--no-policies', en: 'policies', pl: 'polityki' },
  { key: 'triggerResult', flag: '--no-triggers', en: 'triggers', pl: 'wyzwalacze' },
  { key: 'eventTriggerResult', flag: '--no-triggers', en: 'triggers', pl: 'wyzwalacze' },
  { key: 'rlsIntent', flag: '--no-policies', en: 'intent check for tables', pl: 'kontrola zamiaru dla tabel' },
];

/** The switches the help must offer, once each. Built, so it cannot drift. */
const CHECK_FLAGS = [...new Set(CHECKS.map((c) => c.flag).filter(Boolean))].sort();

/**
 * How many checks a run did NOT form an opinion on.
 *
 * THIS COUNTS CHECKS, NOT ITEMS: `--no-tables` removes an opinion, not some
 * number of findings. It used to be an array of eight local variables written
 * out by hand next to the summary, which is the third hand-written copy of the
 * list above.
 */
function switchedOff(results) {
  return CHECKS.filter((c) => results[c.key] === null || results[c.key] === undefined).length;
}

module.exports = { CHECKS, CHECK_FLAGS, switchedOff };
