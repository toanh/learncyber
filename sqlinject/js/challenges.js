/*
 * challenges.js — the four missions of the NovaWave assessment.
 *
 * Each mission describes the scenario, which endpoint it targets, progressive
 * hints (the last of which offers a ready-to-run payload), and a win-detector
 * that inspects the query result to decide whether the objective was met.
 *
 * Win-detectors only fire in "vulnerable" mode — in patched mode the same
 * payloads are neutralised, which is exactly the lesson.
 */
(function (global) {
  "use strict";

  var DB = global.NovaDB;

  function cell(rows, value) {
    for (var i = 0; i < rows.length; i++) {
      for (var j = 0; j < rows[i].length; j++) {
        if (rows[i][j] === value) { return true; }
      }
    }
    return false;
  }

  var CHALLENGES = [
    {
      id: "login-bypass",
      order: 1,
      title: "Break the Staff Login",
      tag: "Authentication bypass",
      endpoint: "login",
      flag: "NOVA{auth_bypass_101}",
      brief:
        "You're a security intern hired to test the NovaWave staff console. " +
        "The login checks your username and password by dropping them straight " +
        "into a SQL query. Get in as the Administrator — without knowing the password.",
      objective: "Log in as an account with the role \"Administrator\".",
      hints: [
        "Look at the Query Inspector. Your username sits inside '...single quotes...'. What happens if YOUR input contains a single quote?",
        "In SQL, -- starts a comment: everything after it on the line is ignored. Could you comment out the password check entirely?",
        "The classic trick is to close the string, add a condition that's always true, then comment out the rest."
      ],
      // Prefills the form when the last hint is revealed.
      solution: { username: "admin' --", password: "anything" },
      check: function (result) {
        if (result.error) { return { won: false }; }
        // columns: id, username, role
        var roleIdx = result.columns.indexOf("role");
        for (var i = 0; i < result.rows.length; i++) {
          if (roleIdx !== -1 && result.rows[i][roleIdx] === "Administrator") {
            return { won: true, message: "Authenticated as Administrator. The password check never ran." };
          }
        }
        return { won: false };
      }
    },

    {
      id: "always-true",
      order: 2,
      title: "Dump the Whole Catalog",
      tag: "Boolean logic",
      endpoint: "search",
      flag: "NOVA{always_true}",
      brief:
        "The song search only shows titles that match what you type. But the " +
        "filter is glued into the query as text. Warm up your UNION skills by " +
        "forcing the search to return every song in the database at once.",
      objective: "Make a single search return all " + DB.SONG_COUNT + " songs.",
      hints: [
        "Your text lands inside LIKE '%...%'. Try closing that string early with a single quote.",
        "After closing the string, add OR followed by a condition that is always true.",
        "Then comment out the leftover %' at the end so it doesn't cause a syntax error."
      ],
      solution: { q: "%' OR '1'='1' -- " },
      check: function (result) {
        if (result.error) { return { won: false }; }
        if (result.rows.length >= DB.SONG_COUNT) {
          return { won: true, message: "Every song returned. Your 'always true' condition defeated the filter." };
        }
        return { won: false };
      }
    },

    {
      id: "union-creds",
      order: 3,
      title: "Steal the Staff Credentials",
      tag: "UNION injection",
      endpoint: "search",
      flag: "NOVA{union_select_pro}",
      brief:
        "Time for the real prize. The search returns three columns (title, " +
        "artist, album). With a UNION SELECT you can bolt on data from a " +
        "COMPLETELY different table — like the staff passwords.",
      objective: "Make the song search reveal a staff member's password.",
      hints: [
        "A UNION only works if both SELECTs return the same NUMBER of columns. The search returns 3.",
        "After closing the string, write: UNION SELECT col1, col2, col3 FROM staff -- (fill in real column names).",
        "The staff table has columns: username, password, role. Line them up with the three the search expects."
      ],
      solution: { q: "' UNION SELECT username, password, role FROM staff -- " },
      check: function (result) {
        if (result.error) { return { won: false }; }
        for (var i = 0; i < DB.STAFF_PASSWORDS.length; i++) {
          if (cell(result.rows, DB.STAFF_PASSWORDS[i])) {
            return { won: true, message: "Credentials exfiltrated. You pulled staff passwords through the song search." };
          }
        }
        return { won: false };
      }
    },

    {
      id: "vault",
      order: 4,
      title: "Crack the Vault",
      tag: "Schema discovery + exfiltration",
      endpoint: "search",
      flag: DB.VAULT_FLAG,
      brief:
        "Somewhere in this database is a hidden table full of secrets. You don't " +
        "know its name — yet. Every SQLite database describes itself in a special " +
        "table called sqlite_master. Find the hidden table, then loot it.",
      objective: "Exfiltrate the master flag hidden in the secret table.",
      hints: [
        "First, discover the schema: UNION SELECT name, type, sql FROM sqlite_master WHERE type='table' --",
        "One of the tables listed isn't 'songs' or 'staff'. That's your target — note its column names from the sql.",
        "The hidden table 'vault' has columns label and secret. Pull them: UNION SELECT label, secret, '' FROM vault --"
      ],
      solution: { q: "' UNION SELECT label, secret, '' FROM vault -- " },
      check: function (result) {
        if (result.error) { return { won: false }; }
        if (cell(result.rows, DB.VAULT_FLAG)) {
          return { won: true, message: "Vault breached. You captured the master flag from a table you discovered yourself." };
        }
        return { won: false };
      }
    }
  ];

  global.NovaChallenges = CHALLENGES;
})(window);
