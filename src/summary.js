'use strict';

// supadrift — the four states a run can leave behind, in one shape.
//
// The same field, spelled the same way, in all four of these tools. A person
// reading the terminal can tell "three drifts" from "I could not reach the
// database". A build gets one number, and the two must not arrive identical.
//
//   actionable      somebody has to decide something
//   explained       looked at, and a reason was recorded for setting it aside
//   notApplicable   a check that was switched off, so it has no opinion
//   unreachable     the run could not look
//
// THIS TOOL READS A LIVE DATABASE, which makes `unreachable` more literal here
// than anywhere else: a refused connection, a password that no longer works, a
// network that is down. "I could not connect" must never be reported as "the
// permissions match" — and it never was: the exit path has returned 2 on a
// fatal error since before this field existed, with a comment saying exactly
// why. What was missing is the FIELD, so a build can see the state as well as
// the code.
//
// WHAT IS NOT COUNTED, AND SAID RATHER THAN GUESSED. `explained` here is the
// triggers moved aside by --allow-manual plus the notes for things the
// migrations do not model. The other three allow-flags — --allow-owner-only,
// --allow-no-policy, --allow-search-path — filter their items out without
// counting them, so what they removed is invisible to this field. That is a
// gap in those three code paths, not a number to invent, and it is recorded
// as its own piece of work.

/**
 * @param parts named by the caller, which is the only place that knows which
 *              of its numbers is which state.
 */
function summaryOf(parts) {
  const p = parts || {};
  const n = (v) => (typeof v === 'number' ? v : 0);

  const couldNotBeRead = n(p.couldNotBeRead);

  return {
    actionable: n(p.actionable),
    explained: n(p.explained),
    notApplicable: n(p.notApplicable),
    unreachable: couldNotBeRead,
    // Spelled out even though here it is the whole of it. In said-vs-done the
    // two halves differ — a question the tool cannot answer is not a failure
    // to look — and the same key has to mean the same thing in every one of
    // these tools, or a CI job written against one is wrong about the others.
    unreachableIs: { aQuestionForAPerson: 0, couldNotBeRead },
  };
}

/**
 * The exit code a finished run deserves.
 *
 * `1` IS STATE-BASED HERE, AND THAT IS NOT AN OVERSIGHT. The three sibling
 * tools report what is NEW, because each keeps a snapshot of the previous run
 * and can tell. This one keeps none: it compares migrations against a live
 * database, and there is no previous run to diff against. Making it
 * differential would mean inventing a baseline; making it silent by default
 * would remove the only thing it can currently tell a build. It has failed on
 * findings since 0.1.0 and it still does.
 *
 * `2` MEANS THE RUN COULD NOT LOOK — no connection, no migrations directory,
 * a fatal error. That behaviour predates this module; what is new is that the
 * same state is now also a number in the JSON.
 *
 * `--sarif` still returns 0 on findings, because there the result goes to a
 * Security tab rather than to the build, and a first encounter with a tool
 * that breaks the build is the last encounter.
 */
function exitCodeFor(summary, opts) {
  const o = opts || {};
  if (summary.unreachableIs.couldNotBeRead > 0 && summary.actionable === 0) return 2;
  if (o.sarif) return 0;
  return summary.actionable > 0 ? 1 : 0;
}

module.exports = { summaryOf, exitCodeFor };
