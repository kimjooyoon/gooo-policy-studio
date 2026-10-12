"use strict";
const $ = (id) => document.getElementById(id);
const esc = (value) =>
  String(value).replace(
    /[&<>"']/g,
    (c) =>
      ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[
        c
      ],
  );
const money = (value) => new Intl.NumberFormat("ko-KR").format(value);
const reasons = {
  APPROVED: "모든 승인 조건을 충족했습니다.",
  NOT_SUBMITTED: "아직 제출되지 않은 요청입니다.",
  REVIEWER_INACTIVE: "검토자가 비활성 상태입니다.",
  SELF_APPROVAL: "요청자 본인의 승인은 허용되지 않습니다.",
  TEAM_MISMATCH: "요청자와 검토자의 팀이 다릅니다.",
  OVER_LIMIT: "요청 금액이 승인 한도를 초과했습니다.",
};
const impactReasons = {
  ...reasons,
  REVIEWER_INACTIVE: "검증 주체가 비활성 상태입니다.",
  SELF_APPROVAL: "요청 주체와 검증 주체가 같아 분리 조건을 충족하지 않습니다.",
  TEAM_MISMATCH: "요청 팀과 담당 서비스 팀이 다릅니다.",
  OVER_LIMIT: "요청 실행 예산이 한도를 초과했습니다.",
};
const rules = [
  ["same_team", "같은 팀만 승인", "요청 팀과 검토 팀 일치"],
  ["active_reviewer", "활성 검토자 필수", "비활성 검토자의 승인 제한"],
  ["prevent_self", "본인 승인 방지", "요청자와 검토자 분리"],
];
const observedRules = [
  ["submitted_ok", "요청 제출"],
  ["reviewer_ok", "검증 주체 활성"],
  ["self_ok", "요청·검증 주체 분리"],
  ["team_ok", "팀 일치 조건"],
  ["amount_ok", "실행 예산 한도"],
];
// A revision records edits, including A → B → A. The sequence records the
// newest requested action, so an older replay cannot replace a newer intent.
function createOperationState() {
  let revision = 0, sequence = 0;
  return {
    changed() { revision++; },
    begin() { return { revision, sequence: ++sequence }; },
    current(token) {
      return token.revision === revision && token.sequence === sequence;
    },
  };
}
const operations = createOperationState();
let receipt = null,
  source = null,
  codeTab = "gooo",
  busy = false,
  suiteBusy = false,
  history = [],
  toastTimer;
let corpus = null,
  corpusName = "",
  impactReport = null,
  impactRevision = 0,
  reportRevision = -1,
  impactBusy = false;
async function readJSONFile(file, maxBytes) {
  if (file.size > maxBytes)
    throw Error(`파일은 ${maxBytes / 1024}KiB 이하로 가져오세요.`);
  const bytes = new Uint8Array(await file.arrayBuffer());
  if (bytes.byteLength > maxBytes)
    throw Error(`파일은 ${maxBytes / 1024}KiB 이하로 가져오세요.`);
  try {
    // Preserve a BOM too: JSON validation belongs to the server, and must see
    // the original text rather than a normalized browser JSON object.
    return new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(bytes);
  } catch {
    throw Error("올바른 UTF-8 JSON 파일을 가져오세요.");
  }
}
try {
  const stored = JSON.parse(
    localStorage.getItem("gooo-policy-history-v1") || "[]",
  );
  if (Array.isArray(stored))
    history = stored
      .filter(
        (r) =>
          r?.schema === "policy-studio/execution/v1" &&
          r.input?.request &&
          r.result?.before &&
          r.result?.after,
      )
      .slice(0, 30);
} catch {}
for (const side of ["before", "after"])
  $("" + side + "-rules").innerHTML = rules
    .map(
      ([key, title, desc]) =>
        `<label class="rule" for="${side}-${key}"><span><strong>${title}</strong><small>${desc}</small></span><input class="switch" id="${side}-${key}" type="checkbox" checked aria-label="${side === "before" ? "현재" : "변경"} 정책: ${title}"></label>`,
    )
    .join("");
function toast(message, error = false) {
  clearTimeout(toastTimer);
  $("toast").textContent = message;
  $("toast").classList.toggle("error", error);
  $("toast").hidden = false;
  toastTimer = setTimeout(() => ($("toast").hidden = true), 5000);
}
function showView(view) {
  for (const name of ["studio", "impact", "history", "source"])
    $(name + "-view").hidden = name !== view;
  document
    .querySelectorAll(".nav-item")
    .forEach((b) => b.classList.toggle("active", b.dataset.view === view));
  $("breadcrumb").textContent = {
    studio: "정책 시뮬레이터",
    impact: "API·자동화 자동 정책 검증",
    history: "실행 기록",
    source: "소스 & 실행 근거",
  }[view];
  if (view === "history") renderHistory();
  if (view === "impact") renderImpactPolicies();
  if (view === "source") loadSource();
  window.scrollTo({ top: 0 });
}
document
  .querySelectorAll("[data-view]")
  .forEach((b) => b.addEventListener("click", () => showView(b.dataset.view)));
function policy(side) {
  return {
    limit: Number($(side + "-limit").value),
    same_team: $(side + "-same_team").checked,
    active_reviewer: $(side + "-active_reviewer").checked,
    prevent_self: $(side + "-prevent_self").checked,
  };
}
function input() {
  return {
    request: {
      key: $("request-key").value.trim(),
      requester: $("requester").value.trim(),
      team: $("request-team").value.trim(),
      amount: Number($("amount").value),
      submitted: $("submitted").checked,
    },
    reviewer: {
      key: $("reviewer-key").value.trim(),
      team: $("reviewer-team").value.trim(),
      active: $("reviewer-active").checked,
    },
    before: policy("before"),
    after: policy("after"),
  };
}
function valid() {
  return (
    $("policy-form").reportValidity() && $("request-form").reportValidity()
  );
}
async function api(path, data) {
  return apiText(path, JSON.stringify(data));
}
async function apiText(path, text) {
  const r = await fetch(path, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: text,
  });
  const body = await r.json();
  if (!r.ok) throw Error(body.error || "실행에 실패했습니다.");
  return body;
}
function invalidate() {
  receipt = null;
  $("download").disabled = true;
  $("result").className = "empty-state";
  $("result").innerHTML =
    '<span class="empty-icon">⇄</span><h3>입력이 변경됐습니다.</h3><p>정책 비교를 실행해 현재 값의 결과를 확인하세요.</p>';
}
function invalidateSuite() {
  $("suite").innerHTML =
    '<div class="quiet-empty">정책이 변경됐습니다. 사례 비교를 다시 실행하세요.</div>';
}
$("policy-form").addEventListener("input", () => {
  operations.changed();
  invalidate();
  invalidateSuite();
  invalidateImpact();
  renderImpactPolicies();
});
$("request-form").addEventListener("input", () => {
  operations.changed();
  invalidate();
});
function save(r) {
  history = [r, ...history.filter((h) => h.id !== r.id)].slice(0, 30);
  try {
    localStorage.setItem("gooo-policy-history-v1", JSON.stringify(history));
  } catch {
    toast("실행은 완료됐지만 브라우저 기록 저장에 실패했습니다.", true);
  }
  $("history-count").textContent = history.length;
}
function receiptMarkup(r, executionBudget = false) {
  const { before, after, change } = r.result;
  const item = r.input.request;
  const reasonText = executionBudget ? impactReasons : reasons;
  const label =
    change.direction === "NEWLY_APPROVED"
      ? "거절 → 승인"
      : change.direction === "NEWLY_DENIED"
        ? "승인 → 거절"
        : change.reason_changed
          ? "승인 상태 동일 · 이유 변경"
          : "판단 유지";
  return `<div class="result-summary"><div><h3>${esc(item.key)} <span class="crumb">·</span> ₩${money(item.amount)}</h3><p>${executionBudget ? "요청 실행 예산 · " : ""}${esc(item.requester)} · ${esc(item.team)} / ${executionBudget ? "검증 주체" : "검토자"} ${esc(r.input.reviewer.key)}</p></div><span class="impact">${label}</span></div><div class="outcomes">${[
      ["현재 정책", before],
      ["변경할 정책", after],
    ]
      .map(
        ([name, d]) =>
          `<article class="outcome"><small>${name}</small><div class="decision ${d.approved ? "approved" : "denied"}">${d.approved ? "승인 가능 ↗" : "승인 거절"}</div><p>${esc(reasonText[d.reason] || d.reason)}</p></article>`,
      )
      .join(
        "",
      )}</div><table class="trace-table"><thead><tr><th scope="col">Gooo 규칙 관측</th><th scope="col">현재 정책</th><th scope="col">변경할 정책</th></tr></thead><tbody>${[
      ["submitted_ok", "요청 제출"],
      ["reviewer_ok", executionBudget ? "검증 주체 활성" : "검토자 활성 조건"],
      ["self_ok", executionBudget ? "요청·검증 주체 분리" : "자기 승인 제한"],
      ["team_ok", "팀 일치 조건"],
      ["amount_ok", executionBudget ? "실행 예산 한도" : "금액 한도"],
    ]
      .map(
        ([key, title]) =>
          `<tr><td>${title}</td>${[before, after].map((d) => `<td class="${d[key] ? "ok" : "fail"}">${d[key] ? "✓ 통과" : "× 미충족"}</td>`).join("")}</tr>`,
      )
      .join(
        "",
      )}</tbody></table><div class="receipt-foot">규칙을 비활성화하면 해당 조건은 통과합니다. 거절 이유는 제출 → 활성 → 자기 승인 → 팀 → 금액 순으로 선택합니다.<br>실행 ${esc(new Date(r.created_at).toLocaleString("ko-KR"))} · 근거 ${esc(r.id)}<br>소스 ${esc(r.source_sha256)}<br>실행한 두 정책과 이 요청에 대한 관측입니다. 전체 입력에 대한 증명은 아닙니다.</div>`;
}
function render(r) {
  $("result").className = "result-content";
  $("result").innerHTML = receiptMarkup(r);
  receipt = r;
  $("download").disabled = false;
}
$("policy-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  if (busy || !valid()) return;
  const snapshot = input();
  const token = operations.begin();
  busy = true;
  $("run").disabled = true;
  $("run").textContent = "Gooo 실행 중…";
  try {
    const r = await api("/api/simulate", snapshot);
    save(r);
    if (operations.current(token)) {
      render(r);
      toast("두 정책을 실행했습니다.");
    } else
      toast("새 작업 또는 입력 변경이 있습니다. 이전 실행은 기록에 보관했습니다.");
  } catch (err) {
    toast(err.message, true);
  } finally {
    busy = false;
    $("run").disabled = false;
    $("run").innerHTML = "정책 비교 실행 <span>→</span>";
  }
});
$("request-form").addEventListener("submit", (e) => {
  e.preventDefault();
  $("policy-form").requestSubmit();
});
function resetRequest() {
  for (const [id, value] of Object.entries({
    "request-key": "REQ-2026-042",
    requester: "김민수",
    "request-team": "제품팀",
    amount: 750000,
    "reviewer-key": "이지원",
    "reviewer-team": "제품팀",
  }))
    $(id).value = value;
  $("submitted").checked = true;
  $("reviewer-active").checked = true;
}
$("reset").addEventListener("click", () => {
  operations.changed();
  $("before-limit").value = 500000;
  $("after-limit").value = 1000000;
  for (const side of ["before", "after"])
    for (const [key] of rules) $(side + "-" + key).checked = true;
  resetRequest();
  invalidate();
  invalidateSuite();
  invalidateImpact();
  renderImpactPolicies();
});
document.querySelectorAll("[data-preset]").forEach((b) =>
  b.addEventListener("click", () => {
    operations.changed();
    resetRequest();
    switch (b.dataset.preset) {
      case "team":
        $("reviewer-team").value = "운영팀";
        break;
      case "self":
        $("reviewer-key").value = "김민수";
        break;
      case "inactive":
        $("reviewer-active").checked = false;
        break;
      case "draft":
        $("submitted").checked = false;
        break;
    }
    invalidate();
  }),
);
function download(data, name, type = "application/json") {
  const blob = new Blob(
    [typeof data === "string" ? data : JSON.stringify(data, null, 2)],
    { type },
  );
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = name;
  a.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}
$("download").addEventListener("click", () => {
  if (receipt) download(receipt, "gooo-policy-receipt.json");
});
function scenarios(before, after) {
  const base = {
    request: {
      key: "CASE",
      requester: "김민수",
      team: "제품팀",
      amount: 100000,
      submitted: true,
    },
    reviewer: { key: "이지원", team: "제품팀", active: true },
    before,
    after,
  };
  const definitions = [
    ["기본 승인", {}],
    ["현재 한도 바로 아래", { amount: Math.max(0, before.limit - 1) }],
    ["현재 한도 일치", { amount: before.limit }],
    [
      "현재 한도 바로 위",
      { amount: Math.min(9000000000000, before.limit + 1) },
    ],
    ["변경 한도 일치", { amount: after.limit }],
    ["변경 한도 바로 위", { amount: Math.min(9000000000000, after.limit + 1) }],
    ["0원 요청", { amount: 0 }],
    ["다른 팀 검토", {}, { team: "운영팀" }],
    ["비활성 검토자", {}, { active: false }],
    ["본인 승인", {}, { key: "김민수" }],
    ["미제출 요청", { submitted: false }],
    [
      "여러 조건 미충족",
      { submitted: false, amount: 9000000000000 },
      { key: "김민수", team: "운영팀", active: false },
    ],
  ];
  return definitions.map(([name, req = {}, rev = {}], i) => ({
    name,
    input: {
      ...base,
      request: {
        ...base.request,
        ...req,
        key: `CASE-${String(i + 1).padStart(2, "0")}`,
      },
      reviewer: { ...base.reviewer, ...rev },
    },
  }));
}
$("run-suite").addEventListener("click", async () => {
  if (suiteBusy || !$("policy-form").reportValidity()) return;
  suiteBusy = true;
  $("run-suite").disabled = true;
  $("run-suite").textContent = "12개 사례 실행 중…";
  const before = policy("before"),
    after = policy("after");
  const token = operations.begin();
  try {
    const rows = [];
    for (const s of scenarios(before, after))
      rows.push({ ...s, receipt: await api("/api/simulate", s.input) });
    if (!operations.current(token)) {
      toast("새 작업 또는 입력 변경이 있습니다. 사례 비교를 다시 실행하세요.");
      return;
    }
    const changed = rows.filter((r) => r.receipt.result.change.changed).length;
    const approved = rows.filter((r) => r.receipt.result.after.approved).length;
    $("suite").innerHTML =
      `<div class="suite-summary"><span><strong>12</strong> 실행 사례</span><span><strong>${changed}</strong> 승인 상태 변경</span><span><strong>${approved}</strong> 변경 정책 승인</span></div><div class="table-scroll"><table class="suite-table"><thead><tr><th>사례</th><th>금액</th><th>현재</th><th>변경</th><th>결과</th><th></th></tr></thead><tbody>${rows.map((s, i) => `<tr><td>${esc(s.name)}</td><td>₩${money(s.input.request.amount)}</td><td>${s.receipt.result.before.approved ? "승인" : "거절"}</td><td>${s.receipt.result.after.approved ? "승인" : "거절"}</td><td class="${s.receipt.result.change.changed ? "ok" : ""}">${s.receipt.result.change.changed ? "변경" : "유지"}</td><td><button data-case="${i}">상세 ↗</button></td></tr>`).join("")}</tbody></table></div>`;
    $("suite")
      .querySelectorAll("[data-case]")
      .forEach((b) =>
        b.addEventListener("click", () => {
          const r = rows[Number(b.dataset.case)].receipt;
          applyInput(r.input);
          save(r);
          render(r);
          $("result").scrollIntoView({ block: "center", behavior: "smooth" });
        }),
      );
    toast("12개 사례의 실제 실행 결과를 비교했습니다.");
  } catch (err) {
    toast(err.message, true);
  } finally {
    suiteBusy = false;
    $("run-suite").disabled = false;
    $("run-suite").textContent = "12개 사례 비교 ↗";
  }
});
function applyInput(inData) {
  operations.changed();
  for (const side of ["before", "after"]) {
    $(side + "-limit").value = inData[side].limit;
    for (const [key] of rules) $(side + "-" + key).checked = inData[side][key];
  }
  for (const [id, v] of Object.entries({
    "request-key": inData.request.key,
    requester: inData.request.requester,
    "request-team": inData.request.team,
    amount: inData.request.amount,
    "reviewer-key": inData.reviewer.key,
    "reviewer-team": inData.reviewer.team,
  }))
    $(id).value = v;
  $("submitted").checked = inData.request.submitted;
  $("reviewer-active").checked = inData.reviewer.active;
  invalidateSuite();
  invalidateImpact();
  renderImpactPolicies();
}
function renderHistory() {
  $("history-count").textContent = history.length;
  $("history-list").innerHTML = history.length
    ? history
        .map(
          (r, i) =>
            `<article class="card history-item"><div><h3>${esc(r.input.request.key)} · ₩${money(r.input.request.amount)}</h3><p>${esc(new Date(r.created_at).toLocaleString("ko-KR"))} · ${r.result.before.approved ? "승인" : "거절"} → ${r.result.after.approved ? "승인" : "거절"}<br>${esc(r.id?.slice(0, 31))}…</p></div><div class="history-actions"><button class="button small" data-replay="${i}">재실행 ↺</button><button class="button small" data-export="${i}">JSON ↓</button></div></article>`,
        )
        .join("")
    : '<div class="card empty-state"><h3>아직 실행 기록이 없습니다.</h3><p>정책 비교를 실행하거나 JSON 기록을 가져오세요.</p></div>';
  $("history-list")
    .querySelectorAll("[data-export]")
    .forEach((b) =>
      b.addEventListener("click", () =>
        download(history[Number(b.dataset.export)], "gooo-policy-receipt.json"),
      ),
    );
  $("history-list")
    .querySelectorAll("[data-replay]")
    .forEach((b) =>
      b.addEventListener("click", async () => {
        b.disabled = true;
        try {
          await replay(history[Number(b.dataset.replay)]);
        } finally {
          b.disabled = false;
        }
      }),
    );
}
async function replay(r, token = operations.begin(), raw = false) {
  try {
    const out = await (raw ? apiText("/api/replay", r) : api("/api/replay", r));
    save(out.receipt);
    if (!operations.current(token)) {
      toast("새 작업 또는 입력 변경이 있습니다. 재실행은 기록에 보관했습니다.");
      return;
    }
    applyInput(out.receipt.input);
    render(out.receipt);
    showView("studio");
    toast("소스·생성 코드와 실행 결과가 일치합니다.");
  } catch (err) {
    toast(err.message, true);
  }
}
$("import-receipt").addEventListener("change", async (e) => {
  const file = e.target.files[0];
  if (!file) return;
  const token = operations.begin();
  try {
    const text = await readJSONFile(file, 128 * 1024);
    if (!operations.current(token)) return;
    await replay(text, token, true);
  } catch (err) {
    toast(err.message, true);
  } finally {
    e.target.value = "";
  }
});
$("clear-history").addEventListener("click", () => {
  history = [];
  try {
    localStorage.removeItem("gooo-policy-history-v1");
  } catch {}
  renderHistory();
  toast("이 브라우저의 실행 기록을 지웠습니다.");
});
function currentImpactReport() {
  return impactReport && reportRevision === impactRevision ? impactReport : null;
}
function invalidateImpact(message = "설정 또는 사례가 변경됐습니다. 전체 비교를 다시 실행하세요.") {
  impactRevision++;
  impactReport = null;
  reportRevision = -1;
  $("impact-download").disabled = true;
  $("impact-filter").disabled = true;
  $("impact-summary").innerHTML = "";
  $("impact-rows").innerHTML = "";
  $("impact-evidence").textContent = "";
  $("impact-detail").hidden = true;
  setImpactStatus(message);
}
function setImpactStatus(message, error = false) {
  $("impact-status").textContent = message;
  $("impact-status").classList.toggle("error", error);
}
function renderImpactPolicies() {
  const labels = [
    ["same_team", "팀 일치"],
    ["active_reviewer", "검증 주체 활성"],
    ["prevent_self", "요청·검증 주체 분리"],
  ];
  $("impact-policy-preview").innerHTML = ["before", "after"].map((side) => {
    const p = policy(side);
    return `<article><h3>${side === "before" ? "현재 설정" : "변경 설정"}</h3><p>요청 실행 예산 한도: ₩${money(p.limit)}<br>${labels.map(([key, title]) => `${title}: ${p[key] ? "필수" : "해제"}`).join(" · ")}<br>요청 제출: 항상 필수</p></article>`;
  }).join("");
}
function renderCorpus() {
  const cases = corpus?.cases || [];
  $("impact-run").disabled = !cases.length || impactBusy;
  $("impact-corpus-preview").hidden = !cases.length;
  $("impact-corpus-status").textContent = cases.length
    ? `${corpusName} · ${cases.length}개 사례 · 모든 행을 서버에서 검증했습니다. 아래는 처음 ${Math.min(5, cases.length)}개입니다.`
    : "아직 가져온 사례가 없습니다.";
  $("impact-corpus-preview").innerHTML = cases.length
    ? `<table class="suite-table impact-table"><caption class="section-description">가져온 사례 미리보기 · 전체 사례를 비교합니다</caption><thead><tr><th scope="col">사례 ID</th><th scope="col">요청 주체 · 팀</th><th scope="col">요청 실행 예산 (원)</th><th scope="col">검증 주체 · 담당 서비스 팀</th><th scope="col">변경 설정 기대 결과</th></tr></thead><tbody>${cases.slice(0, 5).map((c) => `<tr><td>${esc(c.id)}<small>${esc(c.request.key)}</small></td><td>${esc(c.request.requester)}<small>${esc(c.request.team)}</small></td><td>₩${money(c.request.amount)}</td><td>${esc(c.reviewer.key)}<small>${esc(c.reviewer.team)}</small></td><td>${c.expected_after.approved ? "승인 가능" : "거절"}<small>${esc(c.expected_after.reason)}</small></td></tr>`).join("")}</tbody></table>`
    : "";
}
function sampleCorpus() {
  // Independently authored expectations for the default changed parameters:
  // limit 1,000,000; same-team, active and separate-principal predicates on.
  const cases = [
    {
      id: "api-export-001",
      request: { key: "API-EXPORT-001", requester: "export-service", team: "데이터팀", amount: 750000, submitted: true },
      reviewer: { key: "budget-guard", team: "데이터팀", active: true },
      expected_after: { approved: true, reason: "APPROVED", amount_ok: true, team_ok: true, reviewer_ok: true, self_ok: true, submitted_ok: true },
    },
    {
      id: "automation-sync-002",
      request: { key: "SYNC-002", requester: "sync-service", team: "운영팀", amount: 1250000, submitted: true },
      reviewer: { key: "execution-guard", team: "운영팀", active: true },
      expected_after: { approved: false, reason: "OVER_LIMIT", amount_ok: false, team_ok: true, reviewer_ok: true, self_ok: true, submitted_ok: true },
    },
    {
      id: "automation-queue-003",
      request: { key: "QUEUE-003", requester: "queue-service", team: "운영팀", amount: 250000, submitted: true },
      reviewer: { key: "paused-guard", team: "운영팀", active: false },
      expected_after: { approved: false, reason: "REVIEWER_INACTIVE", amount_ok: true, team_ok: true, reviewer_ok: false, self_ok: true, submitted_ok: true },
    },
    {
      id: "api-webhook-004",
      request: { key: "WEBHOOK-004", requester: "webhook-service", team: "연동팀", amount: 50000, submitted: true },
      reviewer: { key: "webhook-service", team: "연동팀", active: true },
      expected_after: { approved: false, reason: "SELF_APPROVAL", amount_ok: true, team_ok: true, reviewer_ok: true, self_ok: false, submitted_ok: true },
    },
  ];
  return { cases };
}
$("impact-sample").addEventListener("click", () => {
  download(sampleCorpus(), "gooo-api-automation-synthetic-cases.json");
  toast("합성 사례 양식입니다. 기대 결과는 변경 한도 100만원·모든 조건 필수 기준입니다.");
});
$("impact-label").addEventListener("input", () => {
  operations.changed();
  invalidateImpact();
});
$("impact-corpus-file").addEventListener("change", async (e) => {
  const file = e.target.files[0];
  if (!file) return;
  operations.changed();
  corpus = null;
  corpusName = "";
  invalidateImpact("사례를 검증하는 중입니다.");
  renderCorpus();
  const token = operations.begin();
  try {
    const text = await readJSONFile(file, 256 * 1024);
    if (!operations.current(token)) return;
    const validated = await apiText("/api/impact/corpus", text);
    if (!operations.current(token)) return;
    operations.changed();
    corpus = validated;
    corpusName = file.name;
    renderCorpus();
    setImpactStatus("사례 검증 완료. 전체 비교를 실행하면 변경 설정의 기대 결과도 자동 대조합니다.");
  } catch (err) {
    if (operations.current(token)) {
      $("impact-corpus-status").textContent = err.message;
      setImpactStatus("사례를 가져오지 못했습니다. 파일을 확인하고 다시 선택하세요.", true);
      toast(err.message, true);
    }
  } finally {
    e.target.value = "";
  }
});
function impactRowMatches(row, filter) {
  const { before, after, change } = row.receipt.result;
  if (filter === "failed") return !row.expectation_matched;
  if (filter === "newly_approved") return change.direction === "NEWLY_APPROVED";
  if (filter === "newly_denied") return change.direction === "NEWLY_DENIED";
  if (filter === "reason_only") return !change.changed && change.reason_changed;
  if (filter === "rule_changed") return observedRules.some(([key]) => before[key] !== after[key]);
  if (filter === "unchanged") return !change.changed && !change.reason_changed;
  return true;
}
function impactChangeLabel(change) {
  if (change.direction === "NEWLY_APPROVED") return "새로 승인 가능";
  if (change.direction === "NEWLY_DENIED") return "새로 거절";
  if (change.reason_changed) return "이유 변경";
  return "판단 유지";
}
function renderImpactRows() {
  const report = currentImpactReport();
  if (!report) return;
  const rows = report.rows.filter((row) => impactRowMatches(row, $("impact-filter").value));
  setImpactStatus(`${report.checks.passed ? "PASS" : "FAIL"} · 기대 결과 일치 ${report.checks.matched}개 / 불일치 ${report.checks.mismatched}개 · 전체 ${report.rows.length}개 중 ${rows.length}개 표시`, !report.checks.passed);
  $("impact-rows").innerHTML = rows.length
    ? `<table class="suite-table impact-table"><caption class="section-description">Gooo 실제 실행 결과 · 필터는 표시만 바꿉니다</caption><thead><tr><th scope="col">사례 · 요청 팀</th><th scope="col">요청 실행 예산 (원)</th><th scope="col">현재 설정</th><th scope="col">변경 설정</th><th scope="col">변경 영향</th><th scope="col">자동 대조</th><th scope="col">상세</th></tr></thead><tbody>${rows.map((row) => {
      const { input: inData, result } = row.receipt;
      const changedRules = observedRules.filter(([key]) => result.before[key] !== result.after[key]).map(([, label]) => label);
      return `<tr><td>${esc(row.id)}<small>${esc(inData.request.team)} · ${esc(inData.request.key)}</small></td><td>₩${money(inData.request.amount)}</td><td>${result.before.approved ? "승인 가능" : "거절"}<small>${esc(impactReasons[result.before.reason] || result.before.reason)}</small></td><td>${result.after.approved ? "승인 가능" : "거절"}<small>${esc(impactReasons[result.after.reason] || result.after.reason)}</small></td><td>${impactChangeLabel(result.change)}<small>${changedRules.length ? `관측 변경: ${esc(changedRules.join(" · "))}` : "규칙별 관측 유지"}</small></td><td class="${row.expectation_matched ? "ok" : "fail"}">${row.expectation_matched ? "PASS" : "FAIL"}</td><td><button data-impact-row="${report.rows.indexOf(row)}" aria-label="${esc(row.id)} 사례 상세">상세 ↗</button></td></tr>`;
    }).join("")}</tbody></table>`
    : '<div class="quiet-empty">선택한 필터에 해당하는 사례가 없습니다.</div>';
  $("impact-rows").querySelectorAll("[data-impact-row]").forEach((button) => {
    button.addEventListener("click", () => {
      const current = currentImpactReport();
      if (current !== report) return;
      const row = current.rows[Number(button.dataset.impactRow)];
      renderImpactDetail(row);
    });
  });
}
function renderImpactDetail(row) {
  const report = currentImpactReport();
  if (!report) return;
  const expected = report.input.cases.find((c) => c.id === row.id).expected_after;
  const actual = row.receipt.result.after;
  $("impact-detail-title").textContent = `${row.id} · ${row.expectation_matched ? "PASS" : "FAIL"}`;
  $("impact-detail-content").innerHTML = receiptMarkup(row.receipt, true) +
    `<h3 class="impact-expectation-title">독립 기대 결과와 변경 설정의 실제 결과</h3><table class="trace-table"><thead><tr><th scope="col">항목</th><th scope="col">입력한 기대값</th><th scope="col">Gooo 실제 결과</th></tr></thead><tbody>${[["approved", "승인 여부"], ["reason", "이유 코드"], ...observedRules].map(([key, label]) => `<tr><th scope="row">${label}</th><td>${esc(String(expected[key]))}</td><td class="${expected[key] === actual[key] ? "ok" : "fail"}">${esc(String(actual[key]))}</td></tr>`).join("")}</tbody></table>`;
  $("impact-detail").hidden = false;
  $("impact-detail").focus();
}
function renderImpactReport() {
  const report = currentImpactReport();
  if (!report) return;
  const s = report.summary;
  $("impact-summary").innerHTML =
    `<div class="impact-check-banner ${report.checks.passed ? "check-pass" : "check-fail"}"><h3>${report.checks.passed ? "PASS · 모든 사례의 기대 결과 일치" : "FAIL · 기대 결과 불일치"}</h3><p>${esc(report.input.label)} · ${report.checks.matched}개 일치 / ${report.checks.mismatched}개 불일치</p><p>입력한 유한 사례의 변경 설정 결과를 대조했습니다. 실제 결과는 기대값으로 바꾸지 않습니다. ${report.checks.passed ? "" : "실패한 검증도 보고서로 내려받아 원인을 확인할 수 있습니다."}</p></div>` +
    `<div class="impact-summary-grid">${[
      ["실행 사례", `${s.cases}개`, "가져온 모든 사례를 실제로 실행"],
      ["새로 승인 가능", `${s.newly_approved}개`, "현재 거절 → 변경 승인 가능"],
      ["새로 거절", `${s.newly_denied}개`, "현재 승인 가능 → 변경 거절"],
      ["승인 상태 동일 · 이유 변경", `${s.reason_only_changed}개`, "첫 거절 이유가 달라진 사례"],
      ["현재 설정 · 승인 가능 실행 예산", `₩${money(s.before_approved_amount)}`, `${s.before_approved}개 사례의 요청 예산 합계`],
      ["변경 설정 · 승인 가능 실행 예산", `₩${money(s.after_approved_amount)}`, `${s.after_approved}개 사례의 요청 예산 합계`],
    ].map(([title, value, detail]) => `<article><small>${title}</small><strong>${value}</strong><span>${detail}</span></article>`).join("")}</div>` +
    `<div class="impact-rule-summary"><strong>규칙별 관측이 변경된 사례 수</strong><ul>${observedRules.map(([key, label]) => `<li>${label}: ${s.rule_changes[key]}개</li>`).join("")}</ul><span>예산 합계는 가져온 사례의 관측입니다. 실제 지출·절감액이나 서비스 사용량을 뜻하지 않습니다.</span></div>`;
  $("impact-evidence").textContent = `생성 ${new Date(report.created_at).toLocaleString("ko-KR")} · 보고서 ${report.id}\n사례 묶음 ${report.corpus_sha256}\n소스 ${report.provenance.source_sha256} · 생성 코드 ${report.provenance.generated_sha256}\n컴파일러 ${report.provenance.compiler_source_sha}\n생성 근거 ${report.provenance.generation_sha256} · 전달 어댑터 ${report.provenance.adapter_sha256}\n전체 입력·기대 결과·두 정책·행 결과·요약이 보고서에 포함됩니다. 내용 해시는 발급자를 인증하지 않습니다. ${report.scope}`;
  $("impact-download").disabled = false;
  $("impact-filter").disabled = false;
  $("impact-detail").hidden = true;
  renderImpactRows();
}
function acceptImpactReport(report, restoreInputs = false) {
  if (restoreInputs) {
    operations.changed();
    for (const side of ["before", "after"]) {
      $(side + "-limit").value = report.input[side].limit;
      for (const [key] of rules) $(side + "-" + key).checked = report.input[side][key];
    }
    $("impact-label").value = report.input.label;
    corpus = { cases: report.input.cases };
    corpusName = "검증 보고서에 포함된 사례";
    invalidate();
    invalidateSuite();
    invalidateImpact();
    renderCorpus();
    renderImpactPolicies();
  }
  impactReport = report;
  reportRevision = impactRevision;
  $("impact-filter").value = "all";
  renderImpactReport();
}
$("impact-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  if (impactBusy || !corpus || !$("impact-form").reportValidity() || !$("policy-form").reportValidity()) return;
  const snapshot = { schema: "policy-studio/impact-input/v1", label: $("impact-label").value.trim(), before: policy("before"), after: policy("after"), cases: corpus.cases };
  const token = operations.begin();
  impactBusy = true;
  $("impact-run").disabled = true;
  $("impact-run").textContent = "Gooo 전체 사례 실행 중…";
  invalidateImpact("모든 사례를 실제로 실행하고 기대 결과를 자동 대조하는 중입니다.");
  try {
    const report = await api("/api/impact", snapshot);
    if (!operations.current(token)) {
      toast("새 작업 또는 입력 변경이 있습니다. 이전 묶음 결과를 표시하지 않았습니다.");
      return;
    }
    acceptImpactReport(report);
    toast(report.checks.passed ? "자동 정책 검증 PASS. 모든 기대 결과가 일치합니다." : "자동 정책 검증 FAIL. 불일치 사례의 상세 결과를 확인하세요.", !report.checks.passed);
  } catch (err) {
    if (operations.current(token)) {
      setImpactStatus(err.message, true);
      toast(err.message, true);
    }
  } finally {
    impactBusy = false;
    $("impact-run").disabled = !corpus;
    $("impact-run").textContent = "전체 사례 비교 →";
  }
});
$("impact-filter").addEventListener("change", () => {
  $("impact-detail").hidden = true;
  renderImpactRows();
});
$("impact-close-detail").addEventListener("click", () => {
  $("impact-detail").hidden = true;
  $("impact-filter").focus();
});
$("impact-download").addEventListener("click", () => {
  const report = currentImpactReport();
  if (report) download(report, "gooo-policy-impact-report.json");
});
$("impact-report-file").addEventListener("change", async (e) => {
  const file = e.target.files[0];
  if (!file) return;
  const token = operations.begin();
  invalidateImpact("보고서의 전체 입력·기대 결과·행 결과·요약을 재실행하는 중입니다.");
  try {
    const text = await readJSONFile(file, 4 * 1024 * 1024);
    if (!operations.current(token)) return;
    const out = await apiText("/api/impact/replay", text);
    if (!operations.current(token)) {
      toast("새 작업 또는 입력 변경이 있습니다. 재실행 결과가 현재 설정을 덮어쓰지 않았습니다.");
      return;
    }
    if (!out.matched) throw Error("보고서의 전체 결과가 재현되지 않았습니다.");
    acceptImpactReport(out.report, true);
    showView("impact");
    toast(out.report.checks.passed ? "보고서 전체가 재현됐습니다. 자동 검증 PASS." : "보고서 전체가 재현됐습니다. 원래의 자동 검증 FAIL도 유지됩니다.", !out.report.checks.passed);
  } catch (err) {
    if (operations.current(token)) {
      setImpactStatus(err.message, true);
      toast(err.message, true);
    }
  } finally {
    e.target.value = "";
  }
});
async function loadSource() {
  if (!source) {
    try {
      const r = await fetch("/api/source");
      if (!r.ok) throw Error("소스를 불러오지 못했습니다.");
      source = await r.json();
    } catch (err) {
      $("source-code").textContent = err.message;
      return;
    }
  }
  renderSource();
}
function renderSource() {
  $("source-code").textContent =
    codeTab === "generation"
      ? JSON.stringify(source.generation, null, 2)
      : source[codeTab];
  document
    .querySelectorAll("[data-code]")
    .forEach((b) =>
      b.setAttribute("aria-selected", String(b.dataset.code === codeTab)),
    );
}
document.querySelectorAll("[data-code]").forEach((b) =>
  b.addEventListener("click", () => {
    codeTab = b.dataset.code;
    if (source) renderSource();
  }),
);
$("download-source").addEventListener("click", () => {
  if (source)
    download(
      codeTab === "generation" ? source.generation : source[codeTab],
      {
        gooo: "approval.gooo",
        go: "rules_generated.go",
        generation: "generation.json",
      }[codeTab],
      codeTab === "generation"
        ? "application/json"
        : "text/plain;charset=utf-8",
    );
});
$("history-count").textContent = history.length;
renderImpactPolicies();
