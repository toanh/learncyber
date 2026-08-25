# NovaWave — SQL Injection Lab

A self-contained, **client-side only** lab that lets students practise and
simulate SQL injection safely. There is **no server and no real data**: a full
SQLite engine (`sql.js`, SQLite compiled to WebAssembly) runs in the browser,
and every table and record lives in an in-memory database created on page load.

## For students

You're a security intern doing an **authorised** assessment of the fictional
"NovaWave" staff console. Work through four missions:

1. **Break the Staff Login** — authentication bypass (`admin' --`)
2. **Dump the Whole Catalog** — always-true conditions (`' OR '1'='1`)
3. **Steal the Staff Credentials** — `UNION SELECT` across tables
4. **Crack the Vault** — discover a hidden table via `sqlite_master`, then loot it

Each mission shows the **exact SQL** your input builds (your text is
highlighted), gives progressive hints, and awards a flag when you succeed.

Flip **Patched mode** to see the same attack fail once the query is rewritten to
use bound parameters — that's the real-world fix.

## Running it

It must be served over `http://` (or `https://`), **not** opened as a `file://`
path, because browsers block WebAssembly loading from `file://`.

```
# from the repo root
python -m http.server 8000
# then open http://localhost:8000/sqlinject/
```

It also works as-is on GitHub Pages.

## How it stays safe

- **No network, no backend.** All queries run against an in-memory SQLite DB.
- **Strict Content-Security-Policy** (`default-src 'none'`, scripts from `'self'`
  only, no `unsafe-inline`). The one relaxation is `'wasm-unsafe-eval'`, required
  to compile the SQLite WebAssembly module — it is *not* JavaScript `eval`.
- **No DOM XSS.** All user input and query output is rendered with
  `textContent` / `createElement`, never `innerHTML`. The vulnerable SQL is
  deliberate and confined to the sandboxed database; the app around it is not.
- **No CDNs.** `sql.js` is vendored locally under `vendor/` (MIT licensed; see
  `vendor/LICENSE-sql.js`) and pinned to version 1.13.0.

## Files

```
sqlinject/
  index.html            markup + CSP
  css/styles.css        theme
  js/db.js              schema, seed data, vulnerable + parameterised endpoints
  js/challenges.js      the four missions and win-detectors
  js/app.js             UI wiring (XSS-safe rendering)
  vendor/sql-wasm.js    sql.js loader (v1.13.0)
  vendor/sql-wasm.wasm  SQLite compiled to WebAssembly
  vendor/LICENSE-sql.js sql.js license
```

## A note for instructors

The credentials and "secrets" in the database are fictional. The techniques
taught here are for defensive education and authorised testing only. Make sure
students understand that running these attacks against systems they don't own or
have permission to test is illegal.
