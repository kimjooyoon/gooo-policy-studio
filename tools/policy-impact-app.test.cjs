"use strict";
const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");

const root = path.resolve(__dirname, "..");
const html = fs.readFileSync(path.join(root, "web/index.html"), "utf8");
const script = fs.readFileSync(path.join(root, "web/app.js"), "utf8");
const copy = (value) => JSON.parse(JSON.stringify(value));
const response = (body, ok = true) => ({ ok, json: async () => body });
const tick = () => new Promise((resolve) => setImmediate(resolve));
function deferred() {
  let resolve;
  const promise = new Promise((r) => { resolve = r; });
  return { promise, resolve };
}
function jsonFile(text, name = "fixture.json") {
  const bytes = new TextEncoder().encode(text);
  return { name, size: bytes.length, arrayBuffer: async () => bytes.buffer };
}

// Only the DOM behavior used by this app is modeled. Tests drive its actual
// event handlers and deferred fetches, rather than reimplementing UI behavior.
function boot(fetchHandler = async () => response({})) {
  const elements = new Map();
  const all = [];
  const downloads = [];
  const blobs = [];
  const writes = [];
  const calls = [];
  class Element {
    constructor(tag, attrs = {}) {
      this.tag = tag;
      this.id = attrs.id || "";
      this.dataset = {};
      for (const [name, value] of Object.entries(attrs)) {
        if (name.startsWith("data-")) {
          this.dataset[name.slice(5).replace(/-([a-z])/g, (_, c) => c.toUpperCase())] = value;
        }
      }
      this.attributes = { ...attrs };
      this.value = attrs.value || (tag === "select" ? "all" : "");
      this.checked = "checked" in attrs;
      this.disabled = "disabled" in attrs;
      this.hidden = "hidden" in attrs;
      this.files = [];
      this.listeners = new Map();
      this.textContent = "";
      this._html = "";
      this.children = [];
      this.classes = new Set((attrs.class || "").split(/\s+/).filter(Boolean));
      this.classList = {
        toggle: (name, force) => {
          const enabled = force === undefined ? !this.classes.has(name) : force;
          if (enabled) this.classes.add(name); else this.classes.delete(name);
          return enabled;
        },
      };
      all.push(this);
      if (this.id) elements.set(this.id, this);
    }
    set innerHTML(value) { this._html = value; this.children = parse(value); }
    get innerHTML() { return this._html; }
    set className(value) { this.classes = new Set(value.split(/\s+/)); }
    get className() { return [...this.classes].join(" "); }
    addEventListener(type, handler) {
      if (!this.listeners.has(type)) this.listeners.set(type, []);
      this.listeners.get(type).push(handler);
    }
    setAttribute(name, value) { this.attributes[name] = value; }
    querySelectorAll(selector) { return select(this.children, selector); }
    reportValidity() { return true; }
    requestSubmit() { return emit(this.id, "submit"); }
    focus() { document.focused = this; }
    scrollIntoView() {}
    click() {
      if (this.tag === "a") downloads.push({ name: this.download, href: this.href });
      return fire(this, "click");
    }
  }
  function parse(source) {
    return [...source.matchAll(/<([a-z][a-z0-9-]*)\b([^>]*)>/gi)].map((match) => {
      const attrs = {};
      for (const a of match[2].matchAll(/([a-z][\w-]*)(?:="([^"]*)")?/gi)) attrs[a[1]] = a[2] || "";
      return new Element(match[1], attrs);
    });
  }
  function select(nodes, selector) {
    if (selector.startsWith(".")) return nodes.filter((n) => n.classes.has(selector.slice(1)));
    const attr = selector.match(/^\[([^\]]+)\]$/)?.[1];
    return attr ? nodes.filter((n) => attr in n.attributes) : [];
  }
  const document = {
    getElementById: (id) => {
      assert.ok(elements.has(id), `missing DOM element ${id}`);
      return elements.get(id);
    },
    querySelectorAll: (selector) => select(all, selector),
    createElement: (tag) => new Element(tag),
    focused: null,
  };
  parse(html);
  function fire(element, type) {
    const event = { target: element, preventDefault() {} };
    return Promise.all((element.listeners.get(type) || []).map((handler) => handler(event)));
  }
  function emit(id, type) { return fire(elements.get(id), type); }
  const context = vm.createContext({
    document, TextDecoder, TextEncoder, Uint8Array, Blob, Intl,
    setTimeout: () => 1, clearTimeout() {},
    window: { scrollTo() {} },
    localStorage: {
      getItem: () => null,
      setItem: (key, value) => writes.push({ key, value }),
      removeItem: (key) => writes.push({ key, removed: true }),
    },
    URL: {
      createObjectURL: (blob) => { blobs.push(blob); return `blob:test-${blobs.length}`; },
      revokeObjectURL() {},
    },
    fetch: (url, options) => {
      calls.push({ url, options });
      return fetchHandler(url, options, calls.length);
    },
  });
  vm.runInContext(script, context, { filename: "app.js" });
  return {
    context, elements, calls, downloads, blobs, writes, emit,
    el: (id) => document.getElementById(id),
    state: vm.runInContext("operations", context),
    upload: (id, file) => { document.getElementById(id).files = [file]; return emit(id, "change"); },
    report: (r) => context.acceptImpactReport(copy(r), true),
  };
}

function receipt(key = "API-1") {
  const before = { approved: false, reason: "OVER_LIMIT", amount_ok: false, team_ok: true, reviewer_ok: true, self_ok: true, submitted_ok: true };
  const after = { ...before, approved: true, reason: "APPROVED", amount_ok: true };
  return {
    schema: "policy-studio/execution/v1", id: `receipt-${key}`, created_at: "2026-10-13T00:00:00Z",
    source_sha256: "source", generated_sha256: "generated", compiler_source_sha: "compiler", scope: "one case",
    input: {
      request: { key, requester: "export-service", team: "데이터팀", amount: 750000, submitted: true },
      reviewer: { key: "budget-guard", team: "데이터팀", active: true },
      before: { limit: 500000, same_team: true, active_reviewer: true, prevent_self: true },
      after: { limit: 1000000, same_team: true, active_reviewer: true, prevent_self: true },
    },
    result: { before, after, change: { changed: true, direction: "NEWLY_APPROVED", reason_changed: true } },
  };
}
function report(label = "API 자동 검증") {
  const a = receipt("API-1");
  const b = receipt("API-2");
  b.result.after = { ...b.result.after, approved: false, reason: "TEAM_MISMATCH", team_ok: false };
  b.result.change = { changed: false, direction: "UNCHANGED", reason_changed: true };
  const cases = [a, b].map((r, i) => ({ id: `case-${i + 1}`, request: r.input.request, reviewer: r.input.reviewer, expected_after: i ? a.result.after : r.result.after }));
  return {
    schema: "policy-studio/impact-report/v1", id: `report-${label}`, created_at: a.created_at,
    corpus_sha256: "corpus", input: { schema: "policy-studio/impact-input/v1", label, before: a.input.before, after: a.input.after, cases },
    provenance: { source_sha256: "source", generated_sha256: "generated", compiler_source_sha: "compiler", adapter_sha256: "adapter", generation_sha256: "generation" },
    rows: [{ id: "case-1", receipt: a, expectation_matched: true }, { id: "case-2", receipt: b, expectation_matched: false }],
    summary: { cases: 2, before_approved: 0, after_approved: 1, newly_approved: 1, newly_denied: 0, reason_only_changed: 1, before_approved_amount: 0, after_approved_amount: 750000, rule_changes: { amount_ok: 2, team_ok: 1, reviewer_ok: 0, self_ok: 0, submitted_ok: 0 } },
    checks: { passed: false, matched: 1, mismatched: 1 }, scope: "Finite input cases, not an external-effect safety proof.",
  };
}

test("operation revisions reject an edit followed by restoring the old value", () => {
  const app = boot();
  const token = app.state.begin();
  app.state.changed();
  app.state.changed();
  assert.equal(app.state.current(token), false);
});
test("the newest operation owns completion even without a form edit", () => {
  const app = boot();
  const first = app.state.begin();
  const second = app.state.begin();
  assert.equal(app.state.current(first), false);
  assert.equal(app.state.current(second), true);
});
test("UTF-8 decoding preserves duplicate keys, whitespace and BOM", async () => {
  const app = boot();
  const text = '\ufeff{\n "cases":[], "cases":[{}]\n}';
  assert.equal(await app.context.readJSONFile(jsonFile(text), 256 * 1024), text);
});
test("all file imports reject malformed UTF-8 before contacting the server", async () => {
  for (const id of ["impact-corpus-file", "impact-report-file", "import-receipt"]) {
    const app = boot();
    const bytes = Uint8Array.from([0x7b, 0xc3, 0x28, 0x7d]);
    await app.upload(id, { name: "bad.json", size: bytes.length, arrayBuffer: async () => bytes.buffer });
    assert.equal(app.calls.length, 0, id);
    assert.match(app.el("toast").textContent, /UTF-8/);
  }
});
test("byte caps apply both before reading and to the returned buffer", async () => {
  const app = boot();
  let read = false;
  await assert.rejects(app.context.readJSONFile({ size: 11, arrayBuffer: async () => { read = true; } }, 10), /KiB/);
  assert.equal(read, false);
  await assert.rejects(app.context.readJSONFile({ size: 1, arrayBuffer: async () => new Uint8Array(11).buffer }, 10), /KiB/);
});
test("receipt import sends original duplicate-key JSON to strict replay", async () => {
  const app = boot(async () => response({ error: "duplicate key" }, false));
  const text = '{ "id":"first", "id":"second" }\n';
  await app.upload("import-receipt", jsonFile(text));
  assert.equal(app.calls[0].url, "/api/replay");
  assert.equal(app.calls[0].options.body, text);
  assert.equal(app.writes.length, 0);
});
test("corpus import sends original JSON and preserves server validation failure", async () => {
  const app = boot(async () => response({ error: "cases[0].expected_after missing" }, false));
  const text = '{"cases":[],"cases":[{}]}';
  await app.upload("impact-corpus-file", jsonFile(text));
  assert.equal(app.calls[0].url, "/api/impact/corpus");
  assert.equal(app.calls[0].options.body, text);
  assert.equal(app.el("impact-run").disabled, true);
  assert.match(app.el("impact-corpus-status").textContent, /expected_after/);
});
test("report import sends original JSON to whole-report replay", async () => {
  const app = boot(async () => response({ error: "duplicate key" }, false));
  const text = '{"rows":[],"rows":[{}]}\n';
  await app.upload("impact-report-file", jsonFile(text));
  assert.equal(app.calls[0].url, "/api/impact/replay");
  assert.equal(app.calls[0].options.body, text);
  assert.equal(app.el("impact-download").disabled, true);
});
test("validated corpus is previewed, then all canonical cases and expectations are posted", async () => {
  const fixture = report();
  const app = boot(async (url) => response(url === "/api/impact/corpus" ? { cases: fixture.input.cases } : fixture));
  await app.upload("impact-corpus-file", jsonFile(JSON.stringify({ cases: fixture.input.cases })));
  assert.equal(app.el("impact-run").disabled, false);
  await app.emit("impact-form", "submit");
  const posted = JSON.parse(app.calls[1].options.body);
  assert.equal(posted.schema, "policy-studio/impact-input/v1");
  assert.deepEqual(posted.cases, fixture.input.cases);
  assert.match(app.el("impact-summary").innerHTML, /FAIL/);
  assert.equal(app.el("impact-download").disabled, false);
  assert.equal(app.writes.length, 0, "batch cases must not reach browser storage");
});
test("stale simulation is saved as individual history without replacing edit-back inputs", async () => {
  const pending = deferred();
  const app = boot(() => pending.promise);
  const run = app.emit("policy-form", "submit");
  await tick();
  app.el("amount").value = "760000";
  await app.emit("request-form", "input");
  app.el("amount").value = "750000";
  await app.emit("request-form", "input");
  pending.resolve(response(receipt()));
  await run;
  assert.equal(app.el("download").disabled, true);
  assert.match(app.el("result").innerHTML, /입력이 변경/);
  assert.equal(app.writes.length, 1);
});
test("suite completion cannot restore a table after policy edit-back", async () => {
  const pending = deferred();
  const app = boot((url, options, n) => n === 1 ? pending.promise : Promise.resolve(response(receipt())));
  const run = app.emit("run-suite", "click");
  await tick();
  app.el("before-limit").value = "550000";
  await app.emit("policy-form", "input");
  app.el("before-limit").value = "500000";
  await app.emit("policy-form", "input");
  pending.resolve(response(receipt()));
  await run;
  assert.match(app.el("suite").innerHTML, /정책이 변경/);
  assert.equal(app.el("suite").querySelectorAll("[data-case]").length, 0);
});
test("concurrent individual replays preserve the newest intent", async () => {
  const first = deferred(), second = deferred();
  const app = boot((url, options, n) => n === 1 ? first.promise : second.promise);
  const old = app.context.replay(receipt("OLD"));
  const newer = app.context.replay(receipt("NEW"));
  second.resolve(response({ matched: true, receipt: receipt("NEW") }));
  await newer;
  first.resolve(response({ matched: true, receipt: receipt("OLD") }));
  await old;
  assert.equal(app.el("request-key").value, "NEW");
  assert.match(app.el("result").innerHTML, /NEW/);
  assert.equal(app.writes.length, 2);
});
test("an individual replay cannot overwrite edits made while it waits", async () => {
  const pending = deferred();
  const app = boot(() => pending.promise);
  const run = app.context.replay(receipt("OLD"));
  app.el("request-key").value = "EDITED";
  await app.emit("request-form", "input");
  pending.resolve(response({ matched: true, receipt: receipt("OLD") }));
  await run;
  assert.equal(app.el("request-key").value, "EDITED");
  assert.equal(app.el("download").disabled, true);
});
test("a file read superseded by a newer action never sends stale replay", async () => {
  const bytes = deferred();
  const app = boot();
  const file = { name: "old.json", size: 2, arrayBuffer: () => bytes.promise };
  const run = app.upload("import-receipt", file);
  app.state.begin();
  bytes.resolve(new TextEncoder().encode("{}").buffer);
  await run;
  assert.equal(app.calls.length, 0);
});
test("batch edit-back invalidates pending output without saving workload", async () => {
  const pending = deferred();
  const fixture = report();
  const app = boot((url) => url === "/api/impact/corpus" ? Promise.resolve(response({ cases: fixture.input.cases })) : pending.promise);
  await app.upload("impact-corpus-file", jsonFile(JSON.stringify({ cases: fixture.input.cases })));
  const run = app.emit("impact-form", "submit");
  app.el("impact-label").value = "temporary";
  await app.emit("impact-label", "input");
  app.el("impact-label").value = "API·자동화 실행 예산 변경 검증";
  await app.emit("impact-label", "input");
  pending.resolve(response(fixture));
  await run;
  assert.equal(app.el("impact-download").disabled, true);
  assert.equal(app.el("impact-summary").innerHTML, "");
  assert.equal(app.writes.length, 0);
});
test("report replay cannot restore policies after a newer edit", async () => {
  const pending = deferred();
  const app = boot(() => pending.promise);
  const run = app.upload("impact-report-file", jsonFile(JSON.stringify(report("OLD"))));
  await tick();
  app.el("before-limit").value = "600000";
  await app.emit("policy-form", "input");
  pending.resolve(response({ matched: true, report: report("OLD") }));
  await run;
  assert.equal(app.el("before-limit").value, "600000");
  assert.equal(app.el("impact-download").disabled, true);
  assert.equal(app.writes.length, 0);
});
test("newer report replay wins when two replies arrive in reverse order", async () => {
  const first = deferred(), second = deferred();
  const app = boot((url, options, n) => n === 1 ? first.promise : second.promise);
  const old = app.upload("impact-report-file", jsonFile(JSON.stringify(report("OLD"))));
  await tick();
  const newer = app.upload("impact-report-file", jsonFile(JSON.stringify(report("NEW"))));
  await tick();
  second.resolve(response({ matched: true, report: report("NEW") }));
  await newer;
  first.resolve(response({ matched: true, report: report("OLD") }));
  await old;
  assert.equal(app.el("impact-label").value, "NEW");
  assert.match(app.el("impact-summary").innerHTML, /NEW/);
  assert.equal(app.writes.length, 0);
});
test("failed-case filtering preserves all rows in download and invalidation blocks stale download", async () => {
  const app = boot();
  const fixture = report();
  app.report(fixture);
  app.el("impact-filter").value = "failed";
  await app.emit("impact-filter", "change");
  assert.match(app.el("impact-rows").innerHTML, /case-2/);
  assert.doesNotMatch(app.el("impact-rows").innerHTML, /case-1/);
  await app.emit("impact-download", "click");
  assert.deepEqual(JSON.parse(await app.blobs[0].text()), fixture);
  assert.equal(app.downloads[0].name, "gooo-policy-impact-report.json");
  await app.emit("impact-label", "input");
  await app.emit("impact-download", "click");
  assert.equal(app.blobs.length, 1);
  assert.equal(app.el("impact-filter").disabled, true);
});
test("detail preserves actual mismatched results and does not store or replace request inputs", async () => {
  const app = boot();
  app.report(report());
  const original = app.el("request-key").value;
  const buttons = app.el("impact-rows").querySelectorAll("[data-impact-row]");
  await buttons[1].click();
  assert.match(app.el("impact-detail-title").textContent, /FAIL/);
  assert.match(app.el("impact-detail-content").innerHTML, /TEAM_MISMATCH/);
  assert.match(app.el("impact-detail-content").innerHTML, /APPROVED/);
  assert.equal(app.el("request-key").value, original);
  assert.equal(app.writes.length, 0);
  await app.emit("impact-label", "input");
  await buttons[1].click();
  assert.equal(app.el("impact-detail").hidden, true);
});
test("user-controlled report labels and row IDs are escaped in markup", () => {
  const app = boot();
  const fixture = report('<img src=x onerror="bad">');
  fixture.rows[0].id = "<script>bad</script>";
  fixture.input.cases[0].id = fixture.rows[0].id;
  app.report(fixture);
  assert.match(app.el("impact-summary").innerHTML, /&lt;img/);
  assert.doesNotMatch(app.el("impact-summary").innerHTML, /<img/);
  assert.match(app.el("impact-rows").innerHTML, /&lt;script&gt;/);
  assert.doesNotMatch(app.el("impact-rows").innerHTML, /<script>/);
});
test("sample has explicit finite expectations and names service execution cases", () => {
  const app = boot();
  const sample = copy(app.context.sampleCorpus());
  assert.equal(sample.cases.length, 4);
  assert.equal(sample.cases[0].id, "api-export-001");
  assert.equal(sample.cases[1].id, "automation-sync-002");
  for (const c of sample.cases) {
    assert.deepEqual(Object.keys(c.expected_after).sort(), ["approved", "reason", "amount_ok", "team_ok", "reviewer_ok", "self_ok", "submitted_ok"].sort());
  }
  assert.equal(sample.cases[0].expected_after.reason, "APPROVED");
  assert.equal(sample.cases[1].expected_after.reason, "OVER_LIMIT");
  assert.equal(sample.cases[2].expected_after.reviewer_ok, false);
  assert.equal(sample.cases[3].expected_after.self_ok, false);
});
