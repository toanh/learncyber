/*
 * db.js — the client-side SQLite database for the NovaWave SQLi lab.
 *
 * Everything lives in the browser. sql.js compiles a real SQLite engine to
 * WebAssembly, so the queries students run are executed by genuine SQLite.
 * There is no server and no real data — the "secrets" below are fictional.
 *
 * The two endpoints deliberately build SQL by string concatenation (the
 * classic vulnerable pattern) so students can watch their input break out of
 * the string. Each endpoint also ships a parameterised ("patched") version so
 * they can see the exact same attack fail once the bug is fixed.
 */
(function (global) {
  "use strict";

  // ---- Seed data (fictional). Kept identical to the verified test fixture. ----
  var SEED_SQL = [
    "PRAGMA foreign_keys = OFF;",

    "DROP TABLE IF EXISTS staff;",
    "CREATE TABLE staff (id INTEGER PRIMARY KEY, username TEXT NOT NULL, password TEXT NOT NULL, role TEXT NOT NULL, email TEXT NOT NULL);",
    "INSERT INTO staff (id, username, password, role, email) VALUES",
    " (1,'admin','Wntr!2024$Nova','Administrator','admin@novawave.fm'),",
    " (2,'dj_mika','sunset-drive-88','Curator','mika@novawave.fm'),",
    " (3,'leo.b','g0ldenHour','Support','leo@novawave.fm'),",
    " (4,'intern','changeme123','Intern','intern@novawave.fm');",

    "DROP TABLE IF EXISTS songs;",
    "CREATE TABLE songs (id INTEGER PRIMARY KEY, title TEXT NOT NULL, artist TEXT NOT NULL, album TEXT NOT NULL, plays INTEGER NOT NULL);",
    "INSERT INTO songs (id, title, artist, album, plays) VALUES",
    " (1,'Neon Tokyo','Aria Vale','Midnight Signal',1820344),",
    " (2,'Gravity','The Paper Kites','Low Orbit',944210),",
    " (3,'Sunset Drive','Kite & Co.','Coastline',2310985),",
    " (4,'Static Hearts','Aria Vale','Midnight Signal',678120),",
    " (5,'Golden Hour','Lumen','Daybreak',3120044),",
    " (6,'Paper Planes','Kite & Co.','Coastline',512300),",
    " (7,'Afterglow','Nova Rey','Supernova',1450990),",
    " (8,'Midnight Signal','Aria Vale','Midnight Signal',889201),",
    " (9,'Low Orbit','The Paper Kites','Low Orbit',402118),",
    " (10,'Daybreak','Lumen','Daybreak',1990233),",
    " (11,'Cassette Summer','Nova Rey','Supernova',734512),",
    " (12,'Echo Park','Kite & Co.','Coastline',321044);",

    "DROP TABLE IF EXISTS vault;",
    "CREATE TABLE vault (id INTEGER PRIMARY KEY, label TEXT NOT NULL, secret TEXT NOT NULL);",
    "INSERT INTO vault (id, label, secret) VALUES",
    " (1,'stripe_api_key','sk_live_9f2Ka0xNovaWave7Qm'),",
    " (2,'master_flag','NOVA{y0u_0wn3d_th3_vault}'),",
    " (3,'root_recovery_code','4417-8823-1190-2274');"
  ].join("\n");

  // Values the app uses to detect a successful attack (win conditions).
  var STAFF_PASSWORDS = ["Wntr!2024$Nova", "sunset-drive-88", "g0ldenHour", "changeme123"];
  var VAULT_FLAG = "NOVA{y0u_0wn3d_th3_vault}";
  var SONG_COUNT = 12;

  var SQL = null; // the sql.js module
  var db = null;  // the live Database instance

  function loadSeed() {
    db.run(SEED_SQL);
  }

  function initDb() {
    return global.initSqlJs({
      // Pin the wasm to our vendored copy; never fetch from a CDN.
      locateFile: function (file) { return "vendor/" + file; }
    }).then(function (sqlModule) {
      SQL = sqlModule;
      db = new SQL.Database();
      loadSeed();
      return true;
    });
  }

  function resetDb() {
    if (!SQL) { throw new Error("Database not initialised yet."); }
    if (db) { db.close(); }
    db = new SQL.Database();
    loadSeed();
  }

  // Turn a sql.js exec() result into a simple {columns, rows} shape.
  function normalizeExec(res) {
    if (!res || res.length === 0) { return { columns: [], rows: [] }; }
    var first = res[0];
    return { columns: first.columns.slice(), rows: first.values.map(function (r) { return r.slice(); }) };
  }

  // ---- Endpoint definitions -------------------------------------------------
  // Each endpoint returns query "segments" so the UI can highlight exactly
  // which part of the SQL came from user input.

  var endpoints = {
    login: {
      // VULNERABLE: raw string concatenation.
      buildVulnerable: function (inputs) {
        var u = inputs.username || "";
        var p = inputs.password || "";
        return {
          segments: [
            { kind: "sql", text: "SELECT id, username, role FROM staff\nWHERE username = '" },
            { kind: "input", text: u },
            { kind: "sql", text: "' AND password = '" },
            { kind: "input", text: p },
            { kind: "sql", text: "'" }
          ],
          sql: "SELECT id, username, role FROM staff WHERE username = '" + u + "' AND password = '" + p + "'"
        };
      },
      // PATCHED: parameterised. User input is bound, never parsed as SQL.
      buildSafe: function (inputs) {
        return {
          segments: [
            { kind: "sql", text: "SELECT id, username, role FROM staff\nWHERE username = " },
            { kind: "param", text: "?" },
            { kind: "sql", text: " AND password = " },
            { kind: "param", text: "?" }
          ],
          sql: "SELECT id, username, role FROM staff WHERE username = ? AND password = ?",
          params: [inputs.username || "", inputs.password || ""]
        };
      }
    },

    search: {
      buildVulnerable: function (inputs) {
        var q = inputs.q || "";
        return {
          segments: [
            { kind: "sql", text: "SELECT title, artist, album FROM songs\nWHERE title LIKE '%" },
            { kind: "input", text: q },
            { kind: "sql", text: "%'\nORDER BY plays DESC" }
          ],
          sql: "SELECT title, artist, album FROM songs WHERE title LIKE '%" + q + "%' ORDER BY plays DESC"
        };
      },
      buildSafe: function (inputs) {
        return {
          segments: [
            { kind: "sql", text: "SELECT title, artist, album FROM songs\nWHERE title LIKE '%' || " },
            { kind: "param", text: "?" },
            { kind: "sql", text: " || '%'\nORDER BY plays DESC" }
          ],
          sql: "SELECT title, artist, album FROM songs WHERE title LIKE '%' || ? || '%' ORDER BY plays DESC",
          params: [inputs.q || ""]
        };
      }
    }
  };

  // Run an endpoint in the given mode. Returns { sql, columns, rows, error, segments }.
  function runEndpoint(name, mode, inputs) {
    var ep = endpoints[name];
    if (!ep) { throw new Error("Unknown endpoint: " + name); }

    if (mode === "safe") {
      var built = ep.buildSafe(inputs);
      var out = { sql: built.sql, segments: built.segments, params: built.params, columns: [], rows: [], error: null };
      var stmt = null;
      try {
        stmt = db.prepare(built.sql);
        stmt.bind(built.params);
        out.columns = stmt.getColumnNames();
        while (stmt.step()) { out.rows.push(stmt.get()); }
      } catch (e) {
        out.error = String(e && e.message ? e.message : e);
      } finally {
        if (stmt) { stmt.free(); }
      }
      return out;
    }

    // vulnerable
    var v = ep.buildVulnerable(inputs);
    var result = { sql: v.sql, segments: v.segments, params: null, columns: [], rows: [], error: null };
    try {
      var res = db.exec(v.sql);
      var n = normalizeExec(res);
      result.columns = n.columns;
      result.rows = n.rows;
    } catch (e) {
      result.error = String(e && e.message ? e.message : e);
    }
    return result;
  }

  global.NovaDB = {
    init: initDb,
    reset: resetDb,
    run: runEndpoint,
    // constants used by challenge win-detectors
    STAFF_PASSWORDS: STAFF_PASSWORDS,
    VAULT_FLAG: VAULT_FLAG,
    SONG_COUNT: SONG_COUNT
  };
})(window);
