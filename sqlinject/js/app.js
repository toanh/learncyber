/*
 * app.js — UI wiring for the NovaWave SQL Injection lab.
 *
 * Security note for the reader: this app INTENTIONALLY builds vulnerable SQL so
 * students can exploit it. That is safe because it targets a throwaway in-memory
 * SQLite database with fictional data and no server.
 *
 * What is NOT allowed to be sloppy is the DOM: user input and query results are
 * rendered with textContent / createElement ONLY — never innerHTML — so the lab
 * itself can never be turned into a real (DOM XSS) attack.
 */
(function () {
  "use strict";

  var DB = window.NovaDB;
  var CHALLENGES = window.NovaChallenges;
  var STORAGE_KEY = "novawave_sqli_progress_v1";

  var state = {
    current: 0,
    patched: false,
    hintsShown: 0,
    solved: {},            // { challengeId: true }
    lastInputs: {}         // { challengeId: {..inputs} }
  };

  // ---- tiny DOM helpers -----------------------------------------------------
  function $(id) { return document.getElementById(id); }
  function clear(node) { while (node.firstChild) { node.removeChild(node.firstChild); } }
  function el(tag, className, text) {
    var n = document.createElement(tag);
    if (className) { n.className = className; }
    if (text != null) { n.textContent = text; }
    return n;
  }

  // ---- persistence (best-effort; storage may be unavailable) ----------------
  function loadProgress() {
    try {
      var raw = window.localStorage.getItem(STORAGE_KEY);
      if (!raw) { return; }
      var data = JSON.parse(raw);
      if (data && typeof data === "object") {
        if (data.solved && typeof data.solved === "object") { state.solved = data.solved; }
        if (typeof data.patched === "boolean") { state.patched = data.patched; }
      }
    } catch (e) { /* ignore: private mode, blocked storage, corrupt value */ }
  }
  function saveProgress() {
    try {
      window.localStorage.setItem(STORAGE_KEY, JSON.stringify({
        solved: state.solved, patched: state.patched
      }));
    } catch (e) { /* ignore */ }
  }

  // ---- boot -----------------------------------------------------------------
  function boot() {
    if (!window.initSqlJs || !DB) {
      showBootError("Could not load the SQLite engine files.");
      return;
    }
    DB.init().then(onReady).catch(function (err) {
      showBootError(err && err.message ? err.message : String(err));
    });
  }

  function showBootError(msg) {
    var box = $("bootError");
    if (box) {
      box.textContent = "Failed to start: " + msg +
        "  —  Tip: open this page over http:// (a local web server), not as a file://, so the WebAssembly can load.";
    }
  }

  function onReady() {
    $("bootScreen").hidden = true;
    $("appRoot").hidden = false;

    $("scoreTotal").textContent = String(CHALLENGES.length);
    $("patchToggle").checked = state.patched;

    buildMissionList();
    wireEvents();
    selectMission(0);
    updateScore();
    updateModePill();
  }

  // ---- mission list ---------------------------------------------------------
  function buildMissionList() {
    var list = $("missionList");
    clear(list);
    CHALLENGES.forEach(function (c, i) {
      var btn = el("button", "mission-item");
      btn.type = "button";
      btn.setAttribute("data-index", String(i));

      var num = el("span", "mi-num", String(c.order));
      var body = el("span", "mi-body");
      body.appendChild(el("span", "mi-title", c.title));
      body.appendChild(el("span", "mi-tag", c.tag));

      var status = el("span", "mi-status");
      status.setAttribute("aria-hidden", "true");

      btn.appendChild(num);
      btn.appendChild(body);
      btn.appendChild(status);

      btn.addEventListener("click", function () { selectMission(i); });
      list.appendChild(btn);
    });
    refreshMissionList();
  }

  function refreshMissionList() {
    var items = $("missionList").children;
    for (var i = 0; i < items.length; i++) {
      var c = CHALLENGES[i];
      var solved = !!state.solved[c.id];
      items[i].classList.toggle("is-active", i === state.current);
      items[i].classList.toggle("is-solved", solved);
      var status = items[i].querySelector(".mi-status");
      status.textContent = solved ? "✓" : "";
    }
  }

  // ---- mission selection ----------------------------------------------------
  function selectMission(index) {
    state.current = index;
    state.hintsShown = 0;
    var c = CHALLENGES[index];

    $("missionTag").textContent = c.tag;
    $("missionTitle").textContent = c.title;
    $("missionBrief").textContent = c.brief;
    $("missionObjective").textContent = c.objective;

    // Swap the correct attack surface into view.
    var isLogin = c.endpoint === "login";
    $("loginSurface").hidden = !isLogin;
    $("searchSurface").hidden = isLogin;

    // Restore any inputs the student left here before.
    var saved = state.lastInputs[c.id] || {};
    if (isLogin) {
      $("inUser").value = saved.username || "";
      $("inPass").value = saved.password || "";
    } else {
      $("inQuery").value = saved.q || "";
    }

    // Reset transient views.
    resetQueryView();
    clearResult();
    hideBanner();
    renderHints();

    refreshMissionList();
    $("mission").focus();
  }

  function currentChallenge() { return CHALLENGES[state.current]; }

  function collectInputs(c) {
    if (c.endpoint === "login") {
      return { username: $("inUser").value, password: $("inPass").value };
    }
    return { q: $("inQuery").value };
  }

  // ---- running a query ------------------------------------------------------
  function runCurrent() {
    var c = currentChallenge();
    var inputs = collectInputs(c);
    state.lastInputs[c.id] = inputs;

    var mode = state.patched ? "safe" : "vulnerable";
    var result = DB.run(c.endpoint, mode, inputs);

    renderQuery(result);
    renderResult(result);
    evaluateOutcome(c, result, mode);
  }

  function evaluateOutcome(c, result, mode) {
    if (result.error) {
      showBanner("error", "SQL error", result.error +
        "  — that is real feedback from SQLite. Adjust your payload and try again.");
      return;
    }

    var win = mode === "vulnerable" ? c.check(result) : { won: false };

    if (win.won) {
      var firstTime = !state.solved[c.id];
      state.solved[c.id] = true;
      saveProgress();
      refreshMissionList();
      updateScore();
      showFlagBanner(c, win.message, firstTime);
      return;
    }

    // Not a win — give context-appropriate feedback.
    if (mode === "safe") {
      showBanner("info", "Patched mode",
        "Your input was sent as a bound parameter, so SQLite treated it purely as data. " +
        "The injection did nothing" + (result.rows.length === 0 ? " and no rows matched." : "."));
      return;
    }

    if (c.endpoint === "login") {
      if (result.rows.length >= 1) {
        var uIdx = result.columns.indexOf("username");
        var rIdx = result.columns.indexOf("role");
        var who = uIdx !== -1 ? result.rows[0][uIdx] : "(unknown)";
        var role = rIdx !== -1 ? result.rows[0][rIdx] : "";
        showBanner("info", "Signed in", "You are logged in as “" + who + "” (" + role +
          "). Objective needs the Administrator account — keep going.");
      } else {
        showBanner("info", "Login failed", "No row matched, so the console rejects you. Study the Query Inspector.");
      }
    } else {
      showBanner("info", "Search complete",
        result.rows.length + " row" + (result.rows.length === 1 ? "" : "s") + " returned.");
    }
  }

  // ---- query inspector rendering (XSS-safe) ---------------------------------
  function resetQueryView() {
    var code = $("queryView").querySelector("code") || document.createElement("code");
    clear(code);
    code.appendChild(document.createTextNode("Run the form above to see the query."));
    var pre = $("queryView");
    clear(pre);
    pre.appendChild(code);
    $("paramsView").hidden = true;
    clear($("paramsView"));
  }

  function renderQuery(result) {
    var pre = $("queryView");
    clear(pre);
    var code = el("code");

    result.segments.forEach(function (seg) {
      if (seg.kind === "input") {
        // Highlight the attacker-controlled portion. textContent = safe.
        var span = el("span", "seg-input");
        span.textContent = seg.text.length ? seg.text : "​"; // zero-width so empty still shows highlight
        code.appendChild(span);
      } else if (seg.kind === "param") {
        code.appendChild(el("span", "seg-param", seg.text));
      } else {
        code.appendChild(document.createTextNode(seg.text));
      }
    });
    pre.appendChild(code);

    // Show bound parameters (patched mode only).
    var pv = $("paramsView");
    clear(pv);
    if (result.params && result.params.length) {
      pv.hidden = false;
      pv.appendChild(el("span", "params-label", "Bound parameters:"));
      result.params.forEach(function (p, i) {
        var chip = el("span", "param-chip");
        chip.appendChild(el("span", "param-i", "$" + (i + 1)));
        chip.appendChild(document.createTextNode(" " + (p === "" ? "(empty)" : p)));
        pv.appendChild(chip);
      });
    } else {
      pv.hidden = true;
    }
  }

  // ---- result table rendering (XSS-safe) ------------------------------------
  function clearResult() {
    var area = $("resultArea");
    clear(area);
    area.appendChild(el("p", "muted", "No query run yet."));
  }

  function renderResult(result) {
    var area = $("resultArea");
    clear(area);

    if (result.error) {
      var errBox = el("div", "result-error");
      errBox.appendChild(el("strong", null, "SQLite error: "));
      errBox.appendChild(document.createTextNode(result.error));
      area.appendChild(errBox);
      return;
    }

    if (!result.rows.length) {
      area.appendChild(el("p", "muted", "0 rows returned."));
      return;
    }

    var wrap = el("div", "table-wrap");
    var table = el("table", "result-table");

    var thead = el("thead");
    var htr = el("tr");
    result.columns.forEach(function (col) { htr.appendChild(el("th", null, String(col))); });
    thead.appendChild(htr);
    table.appendChild(thead);

    var tbody = el("tbody");
    result.rows.forEach(function (row) {
      var tr = el("tr");
      row.forEach(function (val) {
        var td = el("td");
        if (val === null || typeof val === "undefined") {
          td.appendChild(el("span", "null-val", "NULL"));
        } else {
          td.textContent = String(val);
        }
        tr.appendChild(td);
      });
      tbody.appendChild(tr);
    });
    table.appendChild(tbody);

    wrap.appendChild(table);
    area.appendChild(wrap);
    area.appendChild(el("p", "row-count", result.rows.length + " row(s)"));
  }

  // ---- banners --------------------------------------------------------------
  function hideBanner() {
    var b = $("banner");
    b.hidden = true;
    clear(b);
    b.className = "banner";
  }
  function showBanner(kind, title, text) {
    var b = $("banner");
    clear(b);
    b.className = "banner banner-" + kind;
    b.hidden = false;
    b.appendChild(el("strong", "banner-title", title));
    b.appendChild(el("span", "banner-text", text));
  }
  function showFlagBanner(c, message, firstTime) {
    var b = $("banner");
    clear(b);
    b.className = "banner banner-flag";
    b.hidden = false;

    var head = el("div", "flag-head");
    head.appendChild(el("span", "flag-badge", "OBJECTIVE COMPLETE"));
    head.appendChild(el("strong", "flag-msg", message));
    b.appendChild(head);

    var flagRow = el("div", "flag-row");
    flagRow.appendChild(el("span", "flag-label", "Flag"));
    flagRow.appendChild(el("code", "flag-value", c.flag));
    b.appendChild(flagRow);

    if (!firstTime) {
      b.appendChild(el("span", "flag-note", "(already captured earlier — nice repeat!)"));
    }
  }

  // ---- score ----------------------------------------------------------------
  function updateScore() {
    var n = 0;
    CHALLENGES.forEach(function (c) { if (state.solved[c.id]) { n++; } });
    $("scoreCount").textContent = String(n);
  }

  // ---- hints ----------------------------------------------------------------
  function renderHints() {
    var list = $("hintList");
    clear(list);
    var c = currentChallenge();

    for (var i = 0; i < state.hintsShown && i < c.hints.length; i++) {
      list.appendChild(el("li", "hint", c.hints[i]));
    }

    var allShown = state.hintsShown >= c.hints.length;
    var btn = $("hintBtn");
    if (allShown) {
      // Offer a ready-to-run payload as the final assist.
      if (!list.querySelector(".hint-solution")) {
        var li = el("li", "hint hint-solution");
        li.appendChild(el("span", null, "Still stuck? Load a working payload into the form:"));
        var use = el("button", "btn btn-sm btn-solution", "Fill in a solution");
        use.type = "button";
        use.addEventListener("click", fillSolution);
        li.appendChild(use);
        list.appendChild(li);
      }
      btn.disabled = true;
      btn.textContent = "No more hints";
    } else {
      btn.disabled = false;
      btn.textContent = state.hintsShown === 0 ? "Show a hint" : "Show another hint";
    }
  }

  function fillSolution() {
    var c = currentChallenge();
    var sol = c.solution || {};
    if (c.endpoint === "login") {
      $("inUser").value = sol.username || "";
      $("inPass").value = sol.password || "";
      $("inUser").focus();
    } else {
      $("inQuery").value = sol.q || "";
      $("inQuery").focus();
    }
  }

  // ---- events ---------------------------------------------------------------
  function wireEvents() {
    $("loginSurface").addEventListener("submit", function (e) { e.preventDefault(); runCurrent(); });
    $("searchSurface").addEventListener("submit", function (e) { e.preventDefault(); runCurrent(); });

    $("hintBtn").addEventListener("click", function () {
      var c = currentChallenge();
      if (state.hintsShown < c.hints.length) { state.hintsShown++; }
      renderHints();
    });

    $("patchToggle").addEventListener("change", function (e) {
      state.patched = e.target.checked;
      saveProgress();
      updateModePill();
      // Re-run the last inputs so the difference is immediately visible.
      var c = currentChallenge();
      if (state.lastInputs[c.id]) { runCurrent(); }
    });

    $("resetDbBtn").addEventListener("click", function () {
      try {
        DB.reset();
        clearResult();
        resetQueryView();
        showBanner("info", "Database reset", "A fresh copy of the database was loaded. Your captured flags are kept.");
      } catch (err) {
        showBanner("error", "Reset failed", String(err && err.message ? err.message : err));
      }
    });
  }

  function updateModePill() {
    var pill = $("modePill");
    if (state.patched) {
      pill.textContent = "Patched";
      pill.className = "mode-pill mode-safe";
    } else {
      pill.textContent = "Vulnerable";
      pill.className = "mode-pill mode-vuln";
    }
  }

  // ---- go -------------------------------------------------------------------
  loadProgress();
  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", boot);
  } else {
    boot();
  }
})();
