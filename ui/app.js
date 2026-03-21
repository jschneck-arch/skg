async function fetchJson(path) {
  const res = await fetch(path);
  if (!res.ok) throw new Error(`${path}: ${res.status}`);
  return res.json();
}

function el(tag, cls, html) {
  const node = document.createElement(tag);
  if (cls) node.className = cls;
  if (html !== undefined) node.innerHTML = html;
  return node;
}

function esc(value) {
  return String(value ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;");
}

const state = {
  data: null,
  selected: null,
  filter: "",
  activeMode: "operate",
  activeView: "surface",
  gravityStatus: null,
  artifactsByIdentity: {},
  artifactsLoading: null,
  artifactPreviewByPath: {},
  artifactPreviewLoading: null,
  selectedArtifactPath: null,
  timelineByIdentity: {},
  timelineLoading: null,
  actionStatus: null,
  actionHistory: null,
  actionHistoryLoading: false,
  assistantBySelection: {},
  assistantLoading: null,
  assistantTaskBySelection: {},
};

function setActiveView(view) {
  state.activeView = view || "surface";
}

function setActiveMode(mode) {
  state.activeMode = mode || "operate";
}

function renderPills(values, cls = "badge") {
  if (!values || !values.length) return '<span class="meta">none</span>';
  return `<div class="pill-list">${values.map((v) => `<span class="${cls}">${esc(v)}</span>`).join("")}</div>`;
}

function renderServiceSummary(services, limit = 4) {
  if (!services || !services.length) return '<span class="meta">no services recorded</span>';
  return `<div class="pill-list">${services.slice(0, limit).map((svc) => {
    const label = `${svc.port}/${svc.service}${svc.banner ? ` ${svc.banner}` : ""}`;
    return `<span class="badge warn">${esc(label)}</span>`;
  }).join("")}</div>`;
}

function renderProfile(profile) {
  if (!profile || !profile.evidence_count) return '<span class="meta">no host-side machine profile recorded yet</span>';
  const facts = [];
  if ((profile.users || []).length) facts.push(`users: ${(profile.users || []).join(", ")}`);
  if ((profile.groups || []).length) facts.push(`groups: ${(profile.groups || []).slice(0, 8).join(", ")}`);
  if (profile.kernel_version) facts.push(`kernel: ${profile.kernel_version}`);
  if (profile.package_manager || profile.package_count) facts.push(`packages: ${profile.package_manager || "pkg"} ${profile.package_count || ""}`.trim());
  if (profile.docker_access !== null && profile.docker_access !== undefined) facts.push(`docker access: ${profile.docker_access ? "yes" : "no"}`);
  if ((profile.interesting_suid || []).length) facts.push(`suid: ${(profile.interesting_suid || []).slice(0, 4).join(", ")}`);
  if ((profile.credential_indicators || []).length) facts.push(`cred indicators: ${(profile.credential_indicators || []).join(", ")}`);
  if ((profile.ssh_keys || []).length) facts.push(`ssh keys: ${(profile.ssh_keys || []).slice(0, 3).join(", ")}`);
  if (profile.sudo_state) facts.push(`sudo: ${profile.sudo_state}`);
  if (profile.av_edr) facts.push(`av/edr: ${profile.av_edr}`);
  if (profile.domain_membership) facts.push(`domain: ${profile.domain_membership}`);
  if (profile.container && Object.keys(profile.container).length) {
    facts.push(`container: ${Object.entries(profile.container).map(([k, v]) => `${k}=${Array.isArray(v) ? v.join(",") : v}`).join(" | ")}`);
  }
  if ((profile.notes || []).length) facts.push(`notes: ${(profile.notes || []).slice(0, 3).join(" | ")}`);
  return renderActionItems(facts);
}

function targetMap(targets) {
  const byIp = new Map();
  (targets.targets || []).forEach((target) => {
    if (target.ip) byIp.set(target.ip, target);
  });
  return byIp;
}

function groupSurfaceByIdentity(surface) {
  const groups = new Map();
  (surface.workloads || []).forEach((row) => {
    const key = row.identity_key || row.workload_id || "unknown";
    if (!groups.has(key)) {
      groups.set(key, { identity_key: key, manifestations: new Set(), paths: [] });
    }
    const group = groups.get(key);
    group.paths.push(row);
    if (row.manifestation_key) group.manifestations.add(row.manifestation_key);
  });
  return Array.from(groups.values()).map((group) => ({
    ...group,
    manifestations: Array.from(group.manifestations.values()),
    paths: group.paths.sort((a, b) => (b.score || 0) - (a.score || 0)),
  }));
}

function normalizedFilter() {
  return (state.filter || "").trim().toLowerCase();
}

function matchesFilter(...values) {
  const query = normalizedFilter();
  if (!query) return true;
  return values
    .flat()
    .filter(Boolean)
    .some((value) => String(value).toLowerCase().includes(query));
}

function itemSelectable(node, kind, id, payload) {
  node.classList.add("selectable");
  node.dataset.kind = kind;
  node.dataset.id = id;
  node.addEventListener("click", () => {
    state.selected = { kind, id, payload };
    render();
  });
}

function selectionMatches(kind, id) {
  return state.selected && state.selected.kind === kind && state.selected.id === id;
}

function selectPrimaryTarget() {
  const group = currentGroupedTargets(state.data)[0];
  if (!group) {
    state.actionStatus = "No target is available in the current field.";
    renderActionStatus();
    return;
  }
  state.selected = {
    kind: "target",
    id: group.identity_key,
    payload: { group, target: targetMap(state.data.targets).get(group.identity_key) || {} },
  };
  setActiveView("surface");
  render();
}

function selectTopFold() {
  const fold = currentFilteredFolds(state.data)[0];
  if (!fold) {
    state.actionStatus = "No fold is available in the current field.";
    renderActionStatus();
    return;
  }
  const foldId = fold.fold_id || `${fold.target_ip || fold.location || "fold"}:0`;
  state.selected = { kind: "fold", id: foldId, payload: fold };
  setActiveView("surface");
  render();
}

function selectPendingProposal() {
  const proposal = currentPendingProposals(state.data)[0];
  if (!proposal) {
    state.actionStatus = "No pending approval is available right now.";
    renderActionStatus();
    return;
  }
  state.selected = { kind: "proposal", id: proposal.id, payload: proposal };
  setActiveView("surface");
  render();
}

function selectionIdentity(selection) {
  if (!selection) return "";
  if (selection.kind === "target") return selection.payload?.group?.identity_key || "";
  if (selection.kind === "proposal") return (selection.payload?.hosts || [])[0] || "";
  if (selection.kind === "memory") return selection.payload?.identity_key || "";
  return selection.payload?.target_ip || selection.payload?.location || "";
}

function selectionCacheKey(selection) {
  if (!selection) return "";
  return `${selection.kind}:${selection.id}:${selectionIdentity(selection)}`;
}

function selectionTask(selection) {
  if (!selection) return "overview";
  const key = selectionCacheKey(selection);
  if (key && state.assistantTaskBySelection[key]) return state.assistantTaskBySelection[key];
  return {
    target: "target_summary",
    fold: "fold_explanation",
    proposal: "proposal_explanation",
    memory: "memory_summary",
  }[selection.kind] || "target_summary";
}

function buildEngagementNote(payload) {
  const refs = payload.references || {};
  const findings = (payload.findings || []).map((item) => `- ${item}`).join("\n");
  const actions = (payload.next_actions || []).map((item) => `- ${item}`).join("\n");
  const cautions = (payload.cautions || []).map((item) => `- ${item}`).join("\n");
  return [
    `Selection: ${payload.selection?.kind || "unknown"} ${payload.selection?.identity_key || payload.selection?.id || ""}`.trim(),
    `Task: ${payload.task || "engagement_note"}`,
    `Mode: ${payload.mode || "fallback"}${payload.model ? ` (${payload.model})` : ""}`,
    "",
    `Summary: ${payload.summary || ""}`,
    "",
    "Findings:",
    findings || "- none",
    "",
    "Next Actions:",
    actions || "- none",
    "",
    "Cautions:",
    cautions || "- none",
    "",
    `References: folds=${refs.fold_count || 0}, proposals=${refs.proposal_count || 0}, artifacts=${refs.artifact_count || 0}, transitions=${(refs.timeline || {}).transition_count || 0}`,
  ].join("\n");
}

function renderFieldSummary(data) {
  const { status, targets, proposals, folds } = data;
  document.getElementById("mode").textContent = status.mode || "-";
  document.getElementById("target-count").textContent = String((targets.targets || []).length);

  const growthPending = (proposals.proposals || []).filter(
    (p) => p.proposal_kind === "catalog_growth" && p.status === "pending"
  ).length;
  document.getElementById("growth-count").textContent = String(growthPending);

  const summary = document.getElementById("field-summary");
  summary.innerHTML = "";
  const fieldState = status.field_state || {};
  summary.appendChild(
    el(
      "div",
      "item",
      `<strong>Active paths</strong>
       <div class="meta">Workloads in current field state: ${(fieldState.workloads || []).length || 0}</div>`
    )
  );
  summary.appendChild(
    el(
      "div",
      "item",
      `<strong>Fold pressure</strong>
       <div class="meta">Active folds: ${(folds.summary || {}).total || 0} | top types: ${Object.entries((folds.summary || {}).by_type || {}).map(([k, v]) => `${k}=${v}`).join(", ") || "n/a"}</div>`
    )
  );
  summary.appendChild(
    el(
      "div",
      "item",
      `<strong>Growth pressure</strong>
       <div class="meta">Pending proposals: ${(proposals.proposals || []).filter((p) => p.status === "pending").length} | pending growth clusters: ${growthPending}</div>`
    )
  );
}

function latestArtifactsForSelection() {
  const identity = selectionIdentity(state.selected);
  return identity ? (state.artifactsByIdentity[identity]?.artifacts || []) : [];
}

function reportHtml() {
  const selection = state.selected;
  if (!selection) {
    return "Select a target, fold, proposal, or memory neighborhood to build a report view.";
  }
  const identity = selectionIdentity(selection);
  const engagement = state.assistantBySelection[`${selectionCacheKey(selection)}:engagement_note`];
  const timeline = state.timelineByIdentity[identity] || {};
  const artifacts = latestArtifactsForSelection().slice(0, 5);
  const related = relatedObjects(selection, state.data);
  const summary = engagement?.summary || "No engagement note is loaded yet for this selection.";
  const findings = (engagement?.findings || []).slice(0, 5);
  const actions = (engagement?.next_actions || []).slice(0, 5);
  return `
    <div class="assistant-block">
      <p><strong>${esc(identity || selection.id)}</strong></p>
      <p>${esc(summary)}</p>
      <strong>Findings</strong>
      <ul>${(findings.length ? findings : ["No report findings loaded yet."]).map((item) => `<li>${esc(item)}</li>`).join("")}</ul>
      <strong>Next Steps</strong>
      <ul>${(actions.length ? actions : ["Switch the assistant task to Engagement Note or Next Observation for a tighter report cut."]).map((item) => `<li>${esc(item)}</li>`).join("")}</ul>
      <div class="meta">timeline: ${timeline.transition_count || 0} transitions | folds: ${related.folds.length} | proposals: ${related.proposals.length} | artifacts: ${artifacts.length}</div>
      ${artifacts.length ? `<div class="meta">recent artifacts: ${artifacts.map((row) => esc(row.file)).join(", ")}</div>` : ""}
    </div>`;
}

function currentGroupedTargets(data) {
  return groupSurfaceByIdentity(data.surface)
    .filter((group) => matchesFilter(
      group.identity_key,
      group.manifestations,
      group.paths.map((p) => [p.attack_path_id, p.classification, p.domain])
    ))
    .sort((a, b) => ((b.paths[0] || {}).score || 0) - ((a.paths[0] || {}).score || 0));
}

function assistantOverview(data) {
  document.getElementById("assistant-mode-badge").textContent = "deterministic";
  document.getElementById("assistant-task-badge").textContent = "overview";
  const { targets, folds, proposals } = data;
  const topFold = (folds.folds || [])[0];
  const topProposal = (proposals.proposals || []).find((p) => p.status === "pending");
  return (
    `SKG currently sees <strong>${(targets.targets || []).length}</strong> targets, ` +
    `<strong>${(folds.summary || {}).total || 0}</strong> active folds, and ` +
    `<strong>${(proposals.proposals || []).filter((p) => p.proposal_kind === "catalog_growth" && p.status === "pending").length}</strong> pending growth clusters. ` +
    (topFold
      ? `Highest current structural pressure: <strong>${esc(topFold.fold_type)}</strong> on <strong>${esc(topFold.target_ip || topFold.location || "unknown")}</strong>. `
      : "") +
    (topProposal
      ? `Nearest growth action: <strong>${esc(topProposal.description || topProposal.id)}</strong>. `
      : "") +
    `This view is read-only and speaks from the current substrate.`
  );
}

function renderTargets(data) {
  const box = document.getElementById("targets");
  box.innerHTML = "";
  const targetsByIp = targetMap(data.targets);
  currentGroupedTargets(data)
    .slice(0, 16)
    .forEach((group) => {
    const target = targetsByIp.get(group.identity_key) || {};
    const services = (target.services || []);
    const domains = Array.from(new Set(group.paths.map((p) => p.domain))).slice(0, 6);
    const topPath = group.paths[0] || {};
    const label = target.hostname || target.host || group.identity_key;
    const sublabel = [target.ip, target.os || target.kind, services.length ? `${services.length} services` : ""]
      .filter(Boolean)
      .join(" | ");
    const node = el(
      "div",
      "item",
      `<strong>${esc(label)}</strong>
       <div class="meta">${esc(sublabel || group.identity_key)}</div>
       <div class="meta">paths: ${group.paths.length} | top path: ${esc(topPath.attack_path_id || "n/a")} (${esc(topPath.classification || "unknown")})</div>
       ${renderServiceSummary(services, 3)}
       <div class="badge-row">${domains.map((d) => `<span class="badge">${esc(d)}</span>`).join("")}</div>`
    );
    itemSelectable(node, "target", group.identity_key, { group, target });
    if (selectionMatches("target", group.identity_key)) node.classList.add("selected");
    box.appendChild(node);
    });
}

function currentFilteredFolds(data) {
  return (data.folds.folds || [])
    .filter((fold) => matchesFilter(
      fold.fold_type,
      fold.target_ip,
      fold.location,
      fold.detail,
      fold.why?.mismatch,
      fold.why?.service,
      fold.why?.attack_path_id
    ))
    .slice(0, 12);
}

function renderFolds(data) {
  const box = document.getElementById("folds");
  box.innerHTML = "";
  currentFilteredFolds(data)
    .forEach((fold, index) => {
    const foldId = fold.fold_id || `${fold.target_ip || fold.location || "fold"}:${index}`;
    const why = (fold.why || {}).mismatch || "fold";
    const node = el(
      "div",
      "item",
      `<strong>${esc(fold.fold_type)}</strong> <span class="badge warn">Φ=${Number(fold.gravity_weight || 0).toFixed(2)}</span>
       <div class="meta">${esc(fold.target_ip || fold.location || "unknown")} | ${esc(why)}</div>
       <div class="meta">${esc((fold.detail || "").slice(0, 180))}</div>`
    );
    itemSelectable(node, "fold", foldId, fold);
    if (selectionMatches("fold", foldId)) node.classList.add("selected");
    box.appendChild(node);
    });
}

function currentPendingProposals(data) {
  return (data.proposals.proposals || [])
    .filter((proposal) => proposal.status === "pending")
    .filter((proposal) => matchesFilter(
      proposal.id,
      proposal.description,
      proposal.proposal_kind,
      proposal.domain,
      proposal.hosts,
      proposal.attack_surface
    ))
    .sort((a, b) => {
      const ag = (((a.recall || {}).growth_memory || {}).delta || 0);
      const bg = (((b.recall || {}).growth_memory || {}).delta || 0);
      if (bg !== ag) return bg - ag;
      return (b.confidence || 0) - (a.confidence || 0);
    });
}

function renderProposals(data) {
  const box = document.getElementById("proposals");
  box.innerHTML = "";
  currentPendingProposals(data)
    .slice(0, 12)
    .forEach((proposal) => {
    const growth = (proposal.recall || {}).growth_memory || {};
    const reasons = (growth.proposal_reasons || []).slice(0, 3).join(", ");
    const node = el(
      "div",
      "item",
      `<strong>${esc(proposal.description || proposal.id)}</strong>
       <div class="meta">${esc(proposal.proposal_kind)} | ${esc(proposal.status)} | ${esc(proposal.domain || "-")}</div>
       <div class="meta">hosts: ${esc((proposal.hosts || []).join(", ") || "n/a")}</div>
       <div class="meta">growth-memory: ${Number(growth.delta || 0).toFixed(3)}${reasons ? ` via ${esc(reasons)}` : ""}</div>
       ${proposal.action?.command_hint ? `<div class="meta"><code class="inline">${esc(proposal.action.command_hint)}</code></div>` : ""}`
    );
    itemSelectable(node, "proposal", proposal.id, proposal);
    if (selectionMatches("proposal", proposal.id)) node.classList.add("selected");
    box.appendChild(node);
    });
}

function renderMemory(data) {
  const box = document.getElementById("memory");
  box.innerHTML = "";
  (data.memory.neighborhoods || [])
    .filter((n) => matchesFilter(
      n.identity_key,
      n.domain,
      n.manifestation_keys,
      n.reinforced_wickets,
      n.reinforced_reasons
    ))
    .slice(0, 12)
    .forEach((n, index) => {
    const id = `${n.identity_key}:${n.domain || "unknown"}:${index}`;
    const node = el(
      "div",
      "item",
      `<strong>${esc(n.identity_key)}</strong>
       <div class="meta">${esc(n.domain || "unknown")} | pearls=${esc(n.pearl_count)} | reinforced wickets=${esc((n.reinforced_wickets || []).join(", ") || "none")}</div>
       <div class="meta">growth reasons: ${esc((n.reinforced_reasons || []).join(", ") || "none")}</div>`
    );
    itemSelectable(node, "memory", id, n);
    if (selectionMatches("memory", id)) node.classList.add("selected");
    box.appendChild(node);
    });
}

function detailRows(rows) {
  return rows
    .map(
      ([label, value]) => `
        <div class="detail-row">
          <strong>${esc(label)}</strong>
          <div>${value}</div>
        </div>`
    )
    .join("");
}

function renderLinkChips(items) {
  if (!items || !items.length) return '<span class="meta">none</span>';
  return `<div class="link-list">${items
    .map(
      (item) =>
        `<button class="link-chip" data-select-kind="${esc(item.kind)}" data-select-id="${esc(item.id)}">${esc(item.label)}</button>`
    )
    .join("")}</div>`;
}

function renderActionItems(items) {
  if (!items || !items.length) return '<span class="meta">none</span>';
  return `<div class="action-list">${items.map((item) => `<div class="action-item">${item}</div>`).join("")}</div>`;
}

function renderCommandItems(items) {
  if (!items || !items.length) return '<span class="meta">none</span>';
  return `<div class="command-list">${items
    .map((item) => `<div class="command-item"><code class="inline">${esc(item)}</code></div>`)
    .join("")}</div>`;
}

function formatBytes(size) {
  const value = Number(size || 0);
  if (value < 1024) return `${value} B`;
  if (value < 1024 * 1024) return `${(value / 1024).toFixed(1)} KB`;
  return `${(value / (1024 * 1024)).toFixed(1)} MB`;
}

function renderProjectionCards(paths) {
  if (!paths || !paths.length) return '<span class="meta">none</span>';
  return `<div class="projection-list">${paths
    .map(
      (path) => `
        <div class="projection-card">
          <strong>${esc(path.manifestation_key || path.workload_id || "unknown")} | ${esc(path.attack_path_id || "n/a")}</strong>
          <div class="meta">${esc(path.domain)} | ${esc(path.classification)} | score ${Number(path.score || 0).toFixed(2)}</div>
          <div class="meta">R: ${esc((path.realized || []).join(", ") || "none")}</div>
          <div class="meta">B: ${esc((path.blocked || []).join(", ") || "none")}</div>
          <div class="meta">U: ${esc((path.unknown || []).join(", ") || "none")}</div>
          ${
            path.unresolved_detail && Object.keys(path.unresolved_detail).length
              ? `<div class="meta">U detail: ${esc(
                  Object.entries(path.unresolved_detail)
                    .map(([wid, info]) => `${wid}=${info.reason}${info.is_latent ? "/latent" : ""}`)
                    .join("; ")
                )}</div>`
              : ""
          }
        </div>`
    )
    .join("")}</div>`;
}

async function ensureArtifacts(identity) {
  if (!identity || state.artifactsByIdentity[identity] || state.artifactsLoading === identity) {
    return;
  }
  state.artifactsLoading = identity;
  renderArtifactsPanel();
  try {
    state.artifactsByIdentity[identity] = await fetchJson(`/artifacts/${encodeURIComponent(identity)}?limit=12`);
  } catch (err) {
    state.artifactsByIdentity[identity] = { identity_key: identity, error: err.message, artifacts: [] };
  } finally {
    state.artifactsLoading = null;
    renderArtifactsPanel();
  }
}

async function ensureArtifactPreview(path) {
  if (!path || state.artifactPreviewByPath[path] || state.artifactPreviewLoading === path) {
    return;
  }
  state.artifactPreviewLoading = path;
  renderArtifactPreview();
  try {
    state.artifactPreviewByPath[path] = await fetchJson(`/artifact/preview?path=${encodeURIComponent(path)}&lines=12`);
  } catch (err) {
    state.artifactPreviewByPath[path] = { path, error: err.message, rows: [] };
  } finally {
    state.artifactPreviewLoading = null;
    renderArtifactPreview();
  }
}

async function ensureTimeline(identity) {
  if (!identity || state.timelineByIdentity[identity] || state.timelineLoading === identity) {
    return;
  }
  state.timelineLoading = identity;
  renderTimelinePanel();
  try {
    state.timelineByIdentity[identity] = await fetchJson(`/timeline/${encodeURIComponent(identity)}?limit=24`);
  } catch (err) {
    state.timelineByIdentity[identity] = { identity_key: identity, error: err.message, snapshots: [], transitions: [] };
  } finally {
    state.timelineLoading = null;
    renderTimelinePanel();
  }
}

async function postJson(path, body) {
  const res = await fetch(path, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body || {}),
  });
  const text = await res.text();
  let payload = {};
  try {
    payload = text ? JSON.parse(text) : {};
  } catch {
    payload = { raw: text };
  }
  if (!res.ok) {
    throw new Error(payload.detail || payload.error || text || `${res.status}`);
  }
  return payload;
}

async function reloadAll() {
  const [status, targets, surface, folds, proposals, memory] = await Promise.all([
    fetchJson("/status"),
    fetchJson("/targets"),
    fetchJson("/surface"),
    fetchJson("/folds"),
    fetchJson("/proposals?status=all"),
    fetchJson("/memory/pearls/manifold"),
  ]);
  state.data = { status, targets, surface, folds, proposals, memory };
  state.gravityStatus = status.gravity_state || null;
}

async function refreshGravityStatus() {
  try {
    state.gravityStatus = await fetchJson("/gravity/status");
  } catch (err) {
    state.gravityStatus = { error: err.message, running: false, recent_output: [] };
  }
  renderRunMonitor();
}

async function ensureActionHistory() {
  if (state.actionHistory || state.actionHistoryLoading) return;
  state.actionHistoryLoading = true;
  renderActionHistory();
  try {
    state.actionHistory = await fetchJson("/history/actions?limit=40");
  } catch (err) {
    state.actionHistory = { error: err.message, actions: [] };
  } finally {
    state.actionHistoryLoading = false;
    renderActionHistory();
  }
}

async function handleAction(kind, payload) {
  try {
    if (kind === "proposal-accept") {
      await postJson(`/proposals/${encodeURIComponent(payload.id)}/accept`, {});
      state.actionStatus = `Accepted proposal ${payload.id}.`;
    } else if (kind === "proposal-defer") {
      const result = await postJson(`/proposals/${encodeURIComponent(payload.id)}/defer`, { days: 7 });
      state.actionStatus = `Deferred proposal ${payload.id} until ${result.until || "later"}.`;
    } else if (kind === "proposal-reject") {
      const result = await postJson(`/proposals/${encodeURIComponent(payload.id)}/reject`, {
        reason: "ui_operator_review",
        cooldown_days: 30,
      });
      state.actionStatus = `Rejected proposal ${payload.id} until ${result.cooldown_until || "cooldown"}.`;
    } else if (kind === "fold-resolve") {
      const result = await postJson(
        `/folds/resolve/${encodeURIComponent(payload.foldId)}?target_ip=${encodeURIComponent(payload.targetIp)}`,
        {}
      );
      state.actionStatus = result.ok
        ? `Resolved fold ${payload.foldId}.`
        : `Fold ${payload.foldId} was not resolved: ${result.error || "unknown error"}`;
    } else {
      return;
    }
    state.actionHistory = null;
    await reloadAll();
    ensureActionHistory();
    render();
  } catch (err) {
    if (String(err.message || "").includes("Proposal not found")) {
      state.selected = null;
      await reloadAll();
      ensureActionHistory();
      render();
      state.actionStatus = "Proposal rotated out of the queue. The surface was refreshed.";
    } else {
      state.actionStatus = `Action failed: ${err.message}`;
    }
    renderActionStatus();
  }
}

async function startGravity() {
  try {
    await postJson("/gravity/start", {});
    state.actionStatus = "Gravity loop started.";
    await refreshGravityStatus();
  } catch (err) {
    state.actionStatus = `Could not start gravity: ${err.message}`;
  }
  renderActionStatus();
}

async function stopGravity() {
  try {
    await postJson("/gravity/stop", {});
    state.actionStatus = "Gravity loop stopped.";
    await refreshGravityStatus();
  } catch (err) {
    state.actionStatus = `Could not stop gravity: ${err.message}`;
  }
  renderActionStatus();
}

async function runFocusedTarget() {
  const selection = state.selected;
  const identity = selectionIdentity(selection);
  if (!selection || !identity) {
    state.actionStatus = "Select a target or target-linked object first.";
    renderActionStatus();
    return;
  }
  try {
    await postJson(`/gravity/run?target_ip=${encodeURIComponent(identity)}`, {});
    state.actionStatus = `Started focused gravity cycle for ${identity}.`;
    await refreshGravityStatus();
  } catch (err) {
    state.actionStatus = `Could not start focused cycle: ${err.message}`;
  }
  renderActionStatus();
}

function handleUiClick(event) {
  const button = event.target.closest("button, [data-select-kind], [data-action-kind]");
  if (!button) return;

  const modeTab = button.closest(".mode-tab");
  if (modeTab) {
    setActiveMode(modeTab.dataset.mode);
    state.actionStatus = `Switched mode to ${modeTab.dataset.mode}.`;
    render();
    return;
  }

  const viewTab = button.closest(".view-tab");
  if (viewTab) {
    setActiveView(viewTab.dataset.view);
    state.actionStatus = `Switched workspace view to ${viewTab.dataset.view}.`;
    renderWorkspaceTabs();
    renderActionStatus();
    return;
  }

  if (button.id === "jump-primary-target") {
    selectPrimaryTarget();
    return;
  }
  if (button.id === "jump-top-fold") {
    selectTopFold();
    return;
  }
  if (button.id === "jump-pending-proposal") {
    selectPendingProposal();
    return;
  }
  if (button.id === "gravity-start") {
    startGravity();
    return;
  }
  if (button.id === "gravity-stop") {
    stopGravity();
    return;
  }
  if (button.id === "gravity-run-target") {
    runFocusedTarget();
    return;
  }

  if (button.dataset.selectKind && button.dataset.selectId) {
    const next = findSelection(button.dataset.selectKind, button.dataset.selectId, state.data);
    if (!next) {
      state.actionStatus = "That object is no longer available in the current field.";
      renderActionStatus();
      return;
    }
    state.selected = next;
    render();
    return;
  }

  if (button.dataset.actionKind) {
    handleAction(button.dataset.actionKind, { ...button.dataset });
  }
}

function relatedObjects(selection, data) {
  const identity = selectionIdentity(selection);
  if (!identity) return { targets: [], folds: [], proposals: [], memory: [] };

  const targets = groupSurfaceByIdentity(data.surface)
    .filter((group) => group.identity_key === identity)
    .map((group) => ({ kind: "target", id: group.identity_key, label: `${group.identity_key} target` }));

  const folds = (data.folds.folds || [])
    .filter((fold, index) => (fold.target_ip || fold.location) === identity)
    .slice(0, 6)
    .map((fold, index) => ({
      kind: "fold",
      id: fold.fold_id || `${fold.target_ip || fold.location || "fold"}:${index}`,
      label: `${fold.fold_type} Φ=${Number(fold.gravity_weight || 0).toFixed(2)}`,
    }));

  const proposals = (data.proposals.proposals || [])
    .filter((proposal) => (proposal.hosts || []).includes(identity))
    .slice(0, 6)
    .map((proposal) => ({
      kind: "proposal",
      id: proposal.id,
      label: proposal.description || proposal.id,
    }));

  const memory = (data.memory.neighborhoods || [])
    .filter((neighborhood, index) => neighborhood.identity_key === identity)
    .slice(0, 6)
    .map((neighborhood, index) => ({
      kind: "memory",
      id: `${neighborhood.identity_key}:${neighborhood.domain || "unknown"}:${index}`,
      label: `${neighborhood.domain || "unknown"} pearls=${neighborhood.pearl_count}`,
    }));

  return { targets, folds, proposals, memory };
}

function renderTargetDetail(selection, data) {
  const { group, target } = selection.payload;
  const paths = group.paths.map((path) => `${path.attack_path_id} (${path.classification}, ${Number(path.score || 0).toFixed(2)})`);
  const domains = Array.from(new Set(group.paths.map((path) => path.domain)));
  const related = relatedObjects(selection, data);
  const pending = (data.proposals.proposals || []).filter(
    (proposal) => proposal.status === "pending" && (proposal.hosts || []).includes(group.identity_key)
  );
  const content = `
    <div class="detail-block">
      <h3>${esc(target.hostname || target.host || group.identity_key)}</h3>
      <div class="detail-meta">
        <div class="meta">${esc(target.ip || group.identity_key)} | ${esc(target.os || target.kind || "target")} | manifestations: ${esc(group.manifestations.join(", ") || "none")}</div>
        ${
          target.hostname && target.hostname !== (target.ip || group.identity_key)
            ? `<div class="meta">hostname: ${esc(target.hostname)}</div>`
            : ""
        }
      </div>
      ${detailRows([
        ["Domains", renderPills(domains)],
        ["Services", renderPills((target.services || []).map((s) => `${s.port}/${s.service}`), "badge warn")],
        ["Service banners", renderServiceSummary(target.services || [], 8)],
        ["Machine profile", renderProfile(target.profile || {})],
        ["Attack Paths", renderPills(paths, "badge")],
        ["Projection rows", renderProjectionCards(group.paths)],
        ["Neighbors", renderPills(group.paths.flatMap((p) => p.neighbors || []), "badge")],
        ["Related folds", renderLinkChips(related.folds)],
        ["Related proposals", renderLinkChips(related.proposals)],
        ["Review commands", renderCommandItems([
          `curl http://127.0.0.1:5055/surface`,
          ...(group.paths || [])
            .slice(0, 4)
            .map((path) => `curl 'http://127.0.0.1:5055/projections/${path.workload_id}/field?domain=${path.domain}'`),
        ])],
        ["Operator next moves", renderActionItems(
          pending.slice(0, 3).map((proposal) => esc(proposal.description || proposal.id)).concat(
            pending.length ? [] : ["No pending proposals on this identity. Use folds and attack-path state to decide the next observation."]
          )
        )],
      ])}
    </div>`;
  const assistant = [
    `SKG sees <strong>${esc(group.identity_key)}</strong> as a stable identity with <strong>${group.paths.length}</strong> current attack-path manifestations.`,
    `The strongest current path is <strong>${esc((group.paths[0] || {}).attack_path_id || "n/a")}</strong>, classified as <strong>${esc((group.paths[0] || {}).classification || "unknown")}</strong>.`,
    `This target should be read as one identity with multiple observed facets, not as separate workload strings.`,
  ].join(" ");
  return { content, assistant };
}

function renderFoldDetail(selection, data) {
  const fold = selection.payload;
  const why = fold.why || {};
  const related = relatedObjects(selection, data);
  const wouldDo = [];
  if (why.attack_path_id) {
    wouldDo.push(`Inspect the existing ${esc(why.attack_path_id)} projection rows for missing support or missing wickets.`);
  }
  if (why.service) {
    wouldDo.push(`Review ${esc(why.service)} against current catalog coverage before creating anything new.`);
  }
  if (!wouldDo.length) {
    wouldDo.push("Re-observe the surrounding surface before deciding whether this fold is structural, contextual, or temporal pressure.");
  }
  const reviewCommands = [];
  if (fold.fold_id && (fold.target_ip || fold.location)) {
    reviewCommands.push(`curl -X POST 'http://127.0.0.1:5055/folds/resolve/${fold.fold_id}?target_ip=${fold.target_ip || fold.location}'`);
  }
  if (why.service) {
    reviewCommands.push(`skg catalog compile --domain ${why.service.toLowerCase().replace(/[^a-z0-9]+/g, "_")} --description 'review ${why.service} fold coverage' --dry-run`);
  }
  const content = `
    <div class="detail-block">
      <h3>${esc(fold.fold_type)}</h3>
      <div class="detail-meta">
        <div class="meta">${esc(fold.target_ip || fold.location || "unknown")} | gravity ${Number(fold.gravity_weight || 0).toFixed(3)}</div>
        ${
          fold.fold_id && (fold.target_ip || fold.location)
            ? `<div class="button-row">
                 <button class="action-button" data-action-kind="fold-resolve" data-fold-id="${esc(fold.fold_id)}" data-target-ip="${esc(fold.target_ip || fold.location)}">Resolve Fold</button>
               </div>`
            : ""
        }
      </div>
      ${detailRows([
        ["Mismatch", esc(why.mismatch || "n/a")],
        ["Service", esc(why.service || "n/a")],
        ["Attack Path", esc(why.attack_path_id || "n/a")],
        ["Detail", esc(fold.detail || "n/a")],
        ["Related target", renderLinkChips(related.targets)],
        ["Related proposals", renderLinkChips(related.proposals)],
        ["Review commands", renderCommandItems(reviewCommands)],
        ["Would do", renderActionItems(wouldDo)],
        ["Operator next moves", renderActionItems([
          "Keep the fold as unresolved structure until the new observation or growth pressure is actually measured.",
          "Do not collapse this fold into certainty just because the service or CVE vocabulary looks familiar.",
        ])],
      ])}
    </div>`;
  const assistant = [
    `This fold marks a region where SKG cannot fully close the model around <strong>${esc(fold.target_ip || fold.location || "unknown")}</strong>.`,
    `It is a <strong>${esc(fold.fold_type)}</strong> fold with mismatch <strong>${esc(why.mismatch || "unspecified")}</strong>.`,
    `The correct response is not to narrate certainty, but to decide whether this needs re-observation, catalog growth, or toolchain growth.`,
  ].join(" ");
  return { content, assistant };
}

function renderProposalDetail(selection) {
  const proposal = selection.payload;
  const growth = (proposal.recall || {}).growth_memory || {};
  const related = relatedObjects(selection, state.data);
  const preview = [];
  if (proposal.action?.command_hint) {
    preview.push(`Run review command: <code class="inline">${esc(proposal.action.command_hint)}</code>`);
  }
  if (proposal.proposal_kind === "catalog_growth") {
    preview.push("This would extend catalog structure after operator review; it does not alter observed state.");
  } else if (proposal.proposal_kind === "field_action") {
    preview.push("This would drive a follow-on instrument or exploit action against the selected surface.");
  }
  const reviewCommands = [
    `skg proposals show ${proposal.id}`,
    `skg proposals accept ${proposal.id}`,
    `skg proposals defer ${proposal.id}`,
    `skg proposals reject ${proposal.id}`,
  ];
  const content = `
    <div class="detail-block">
      <h3>${esc(proposal.description || proposal.id)}</h3>
      <div class="detail-meta">
        <div class="meta">${esc(proposal.proposal_kind)} | ${esc(proposal.status)} | confidence ${Number(proposal.confidence || 0).toFixed(3)}</div>
        ${
          proposal.status === "pending"
            ? `<div class="button-row">
                 <button class="action-button" data-action-kind="proposal-accept" data-id="${esc(proposal.id)}">Accept</button>
                 <button class="action-button" data-action-kind="proposal-defer" data-id="${esc(proposal.id)}">Defer 7d</button>
                 <button class="action-button" data-action-kind="proposal-reject" data-id="${esc(proposal.id)}">Reject 30d</button>
               </div>`
            : ""
        }
      </div>
      ${detailRows([
        ["Hosts", renderPills(proposal.hosts || [], "badge warn")],
        ["Fold IDs", renderPills(proposal.fold_ids || [], "badge")],
        ["Growth Memory", `${Number(growth.delta || 0).toFixed(3)} ${growth.proposal_reasons?.length ? `via ${esc(growth.proposal_reasons.join(", "))}` : ""}`],
        ["Command", proposal.action?.command_hint ? `<code class="inline">${esc(proposal.action.command_hint)}</code>` : "n/a"],
        ["Related target", renderLinkChips(related.targets)],
        ["Related memory", renderLinkChips(related.memory)],
        ["Review commands", renderCommandItems(reviewCommands)],
        ["Would do", renderActionItems(preview)],
        ["Operator next moves", renderActionItems([
          proposal.action?.command_hint ? `Review and run: <code class="inline">${esc(proposal.action.command_hint)}</code>` : "Review the proposal evidence before acting.",
          proposal.fold_ids?.length ? `This proposal clusters ${proposal.fold_ids.length} source folds.` : "This proposal is not fold-backed.",
        ])],
      ])}
    </div>`;
  const assistant = [
    `This proposal is a structural-growth response, not a direct exploit action.`,
    `SKG is clustering pressure across <strong>${esc((proposal.hosts || []).join(", ") || "n/a")}</strong> in the <strong>${esc(proposal.domain || "unknown")}</strong> domain.`,
    `Growth memory of <strong>${Number(growth.delta || 0).toFixed(3)}</strong> means this pressure has already recurred in remembered proposal lifecycle history.`,
  ].join(" ");
  return { content, assistant };
}

function renderMemoryDetail(selection) {
  const n = selection.payload;
  const related = relatedObjects(selection, state.data);
  const content = `
    <div class="detail-block">
      <h3>${esc(n.identity_key)}</h3>
      <div class="detail-meta">
        <div class="meta">${esc(n.domain || "unknown")} | pearls ${esc(n.pearl_count)} | mean energy ${Number(n.mean_energy || 0).toFixed(3)}</div>
      </div>
      ${detailRows([
        ["Manifestations", renderPills(n.manifestation_keys || [], "badge warn")],
        ["Reinforced Wickets", renderPills(n.reinforced_wickets || [], "badge")],
        ["Growth Reasons", renderPills(n.reinforced_reasons || [], "badge")],
        ["Related target", renderLinkChips(related.targets)],
        ["Related proposals", renderLinkChips(related.proposals)],
        ["Operator next moves", renderActionItems([
          n.reinforced_wickets?.length
            ? `Bias future observation toward ${esc(n.reinforced_wickets.join(", "))} without assigning new state.`
            : "This neighborhood is still thin; wait for more pearls before biasing action.",
        ])],
      ])}
    </div>`;
  const assistant = [
    `This pearl neighborhood is structural memory over one identity, not a single row in the ledger.`,
    `Repeated confirmations or lifecycle decisions have reinforced <strong>${esc((n.reinforced_wickets || []).join(", ") || "no wickets yet")}</strong>.`,
    `When this neighborhood strengthens, gravity can bias future observation toward the same wavelength without fabricating new state.`,
  ].join(" ");
  return { content, assistant };
}

function buildAssistantContext(selection) {
  const identity = selectionIdentity(selection);
  const related = relatedObjects(selection, state.data);
  const artifacts = (state.artifactsByIdentity[identity]?.artifacts || []).slice(0, 6).map((row) => ({
    file: row.file,
    category: row.category,
    mtime: row.mtime,
    workload_id: row.workload_id,
  }));
  const timeline = state.timelineByIdentity[identity] || {};
  return {
    kind: selection.kind,
    id: selection.id,
    identity_key: identity,
    subject: selection.payload,
    fold_count: related.folds.length,
    proposal_count: related.proposals.length,
    related_folds: related.folds.slice(0, 6).map((row) => row.payload),
    related_proposals: related.proposals.slice(0, 6).map((row) => row.payload),
    related_memory: related.memory.slice(0, 4).map((row) => row.payload),
    timeline: {
      workload_count: timeline.workload_count || 0,
      snapshot_count: timeline.snapshot_count || 0,
      transition_count: timeline.transition_count || 0,
      recent_transitions: (timeline.transitions || []).slice(0, 6),
    },
    artifacts,
  };
}

async function ensureAssistantExplanation(selection) {
  if (!selection) return;
  const baseKey = selectionCacheKey(selection);
  const task = selectionTask(selection);
  const key = `${baseKey}:${task}`;
  if (!baseKey || state.assistantBySelection[key] || state.assistantLoading === key) return;
  state.assistantLoading = key;
  renderSelection(state.data);
  try {
    state.assistantBySelection[key] = await postJson("/assistant/explain", {
      kind: selection.kind,
      id: selection.id,
      identity_key: selectionIdentity(selection),
      limit: 6,
      task: selectionTask(selection),
      context: buildAssistantContext(selection),
    });
  } catch (err) {
    state.assistantBySelection[key] = { error: err.message };
  } finally {
    state.assistantLoading = null;
    renderSelection(state.data);
  }
}

function renderAssistantResponse(selection, fallbackHtml) {
  const modeBadge = document.getElementById("assistant-detail-mode-badge");
  const taskBadge = document.getElementById("assistant-detail-task-badge");
  const key = `${selectionCacheKey(selection)}:${selectionTask(selection)}`;
  if (modeBadge) modeBadge.textContent = "deterministic";
  if (taskBadge) taskBadge.textContent = selectionTask(selection);
  if (!key) return fallbackHtml;
  if (state.assistantLoading === key) {
    return "Loading bounded assistant explanation from live SKG substrate.";
  }
  const payload = state.assistantBySelection[key];
  if (!payload) return fallbackHtml;
  if (payload.error) {
    return `${fallbackHtml}<div class="meta">Assistant endpoint failed: ${esc(payload.error)}</div>`;
  }
  const findings = (payload.findings || []).map((item) => `<li>${esc(item)}</li>`).join("");
  const actions = (payload.next_actions || []).map((item) => `<li>${esc(item)}</li>`).join("");
  const cautions = (payload.cautions || []).map((item) => `<li>${esc(item)}</li>`).join("");
  const refs = payload.references || {};
  if (modeBadge) modeBadge.textContent = payload.mode || "fallback";
  if (taskBadge) taskBadge.textContent = payload.task || selectionTask(selection);
  return `
    <div class="assistant-block">
      <div class="meta">assistant mode: ${esc(payload.mode || "fallback")}${payload.model ? ` | model: ${esc(payload.model)}` : ""}</div>
      <p>${esc(payload.summary || "")}</p>
      ${findings ? `<strong>Findings</strong><ul>${findings}</ul>` : ""}
      ${actions ? `<strong>Next Actions</strong><ul>${actions}</ul>` : ""}
      ${cautions ? `<strong>Cautions</strong><ul>${cautions}</ul>` : ""}
      <div class="meta">refs: folds=${esc(refs.fold_count || 0)} | proposals=${esc(refs.proposal_count || 0)} | artifacts=${esc(refs.artifact_count || 0)} | transitions=${esc((refs.timeline || {}).transition_count || 0)}</div>
    </div>`;
}

function renderEngagementNote(selection) {
  const panel = document.getElementById("engagement-note-panel");
  const text = document.getElementById("engagement-note-text");
  const copy = document.getElementById("engagement-note-copy");
  if (!panel || !text || !copy) return;
  const key = `${selectionCacheKey(selection)}:${selectionTask(selection)}`;
  const payload = state.assistantBySelection[key];
  if (selectionTask(selection) !== "engagement_note" || !payload || payload.error) {
    panel.hidden = true;
    text.textContent = "";
    copy.onclick = null;
    return;
  }
  const note = buildEngagementNote(payload);
  panel.hidden = false;
  text.textContent = note;
  copy.onclick = async () => {
    try {
      await navigator.clipboard.writeText(note);
      state.actionStatus = "Copied engagement note.";
    } catch {
      state.actionStatus = "Could not copy engagement note.";
    }
    renderActionStatus();
  };
}

function renderSelection(data) {
  const kindNode = document.getElementById("selection-kind");
  const detailNode = document.getElementById("detail");
  const assistantNode = document.getElementById("assistant-detail");
  const selection = state.selected;

  if (!selection) {
    kindNode.textContent = "none";
    detailNode.className = "detail-empty";
    detailNode.innerHTML = "Select a target, fold, proposal, or pearl neighborhood to inspect its shape.";
    assistantNode.innerHTML = "The assistant will explain the selected object from live substrate state.";
    const panel = document.getElementById("engagement-note-panel");
    const text = document.getElementById("engagement-note-text");
    if (panel) panel.hidden = true;
    if (text) text.textContent = "";
    renderActionStatus();
    renderCommandDesk();
    return;
  }

  let rendered;
  if (selection.kind === "target") rendered = renderTargetDetail(selection, data);
  else if (selection.kind === "fold") rendered = renderFoldDetail(selection, data);
  else if (selection.kind === "proposal") rendered = renderProposalDetail(selection, data);
  else rendered = renderMemoryDetail(selection, data);

  kindNode.textContent = selection.kind;
  detailNode.className = "";
  detailNode.innerHTML = rendered.content;
  assistantNode.innerHTML = renderAssistantResponse(selection, rendered.assistant);
  document.querySelectorAll("#assistant-detail-actions [data-assistant-task]").forEach((node) => {
    const task = node.dataset.assistantTask;
    if (task === selectionTask(selection)) node.classList.add("selected");
    else node.classList.remove("selected");
    node.onclick = () => {
      const baseKey = selectionCacheKey(selection);
      state.assistantTaskBySelection[baseKey] = task === "selection"
        ? ({
            target: "target_summary",
            fold: "fold_explanation",
            proposal: "proposal_explanation",
            memory: "memory_summary",
          }[selection.kind] || "target_summary")
        : task;
      renderSelection(data);
      ensureAssistantExplanation(selection);
    };
  });

  const identity = selectionIdentity(selection);
  if (identity) {
    ensureArtifacts(identity);
    ensureTimeline(identity);
  }
  ensureAssistantExplanation(selection);
  renderEngagementNote(selection);
  renderActionStatus();
  renderCommandDesk();
}

function findSelection(kind, id, data) {
  if (kind === "target") {
    const grouped = groupSurfaceByIdentity(data.surface);
    const group = grouped.find((row) => row.identity_key === id);
    if (!group) return null;
    return { kind, id, payload: { group, target: targetMap(data.targets).get(group.identity_key) || {} } };
  }
  if (kind === "proposal") {
    const proposal = (data.proposals.proposals || []).find((row) => row.id === id);
    return proposal ? { kind, id, payload: proposal } : null;
  }
  if (kind === "memory") {
    const neighborhood = (data.memory.neighborhoods || []).find((row, index) => `${row.identity_key}:${row.domain || "unknown"}:${index}` === id);
    return neighborhood ? { kind, id, payload: neighborhood } : null;
  }
  const fold = (data.folds.folds || []).find((row, index) => (row.fold_id || `${row.target_ip || row.location || "fold"}:${index}`) === id);
  return fold ? { kind: "fold", id, payload: fold } : null;
}

function render() {
  const data = state.data;
  if (!data) return;
  renderFieldSummary(data);
  document.getElementById("assistant").innerHTML = assistantOverview(data);
  renderTargets(data);
  renderFolds(data);
  renderProposals(data);
  renderMemory(data);
  renderSelection(data);
  renderMode();
  renderRunMonitor();
  renderArtifactsPanel();
  renderArtifactPreview();
  renderTimelinePanel();
  renderActionHistory();
  renderCommandDesk();
}

function renderWorkspaceTabs() {
  document.querySelectorAll(".view-tab").forEach((node) => {
    const active = node.dataset.view === state.activeView;
    node.classList.toggle("selected", active);
  });
  document.querySelectorAll(".view-panel").forEach((node) => {
    const active = node.id === `view-${state.activeView}`;
    node.classList.toggle("active", active);
  });
  const stateNode = document.getElementById("workspace-state");
  if (stateNode) {
    stateNode.innerHTML = `UI mode: <strong>${esc(state.activeMode)}</strong> · workspace view: <strong>${esc(state.activeView)}</strong>`;
  }
}

function renderMode() {
  document.querySelectorAll(".mode-tab").forEach((node) => {
    node.classList.toggle("selected", node.dataset.mode === state.activeMode);
  });

  const left = document.getElementById("workspace-left");
  const proposals = document.getElementById("panel-proposals");
  const desk = document.getElementById("panel-command-desk");
  const assistant = document.getElementById("panel-assistant");
  const report = document.getElementById("panel-report");
  const reportPane = document.getElementById("report-pane");

  if (left) left.classList.remove("collapsed");
  if (proposals) proposals.hidden = false;
  if (desk) desk.hidden = false;
  if (assistant) assistant.hidden = false;
  if (report) report.hidden = true;

  if (state.activeMode === "operate") {
    setActiveView("surface");
  } else if (state.activeMode === "inspect") {
    if (!["surface", "artifacts", "timeline", "memory"].includes(state.activeView)) setActiveView("artifacts");
  } else if (state.activeMode === "history") {
    if (!["timeline", "actions", "memory"].includes(state.activeView)) setActiveView("timeline");
  } else if (state.activeMode === "report") {
    setActiveView("surface");
    if (left) left.classList.add("collapsed");
    if (proposals) proposals.hidden = true;
    if (desk) desk.hidden = true;
    if (report) report.hidden = false;
    if (reportPane) reportPane.innerHTML = reportHtml();
  }

  renderWorkspaceTabs();
}

function commandDeskItems() {
  const selection = state.selected;
  if (!selection) {
    return [
      "Stop the continuous gravity loop before launching a focused target cycle from the UI.",
      "curl http://127.0.0.1:5055/surface",
      "curl http://127.0.0.1:5055/folds",
      "curl 'http://127.0.0.1:5055/proposals?status=pending'",
    ];
  }
  if (selection.kind === "target") {
    const group = selection.payload.group;
    const identity = group.identity_key;
    return [
      `curl -X POST 'http://127.0.0.1:5055/gravity/run?target_ip=${identity}'`,
      `curl 'http://127.0.0.1:5055/artifacts/${identity}?limit=12'`,
      `curl 'http://127.0.0.1:5055/timeline/${identity}?limit=24'`,
      ...group.paths.slice(0, 4).map((path) => `curl 'http://127.0.0.1:5055/projections/${path.workload_id}/field?domain=${path.domain}'`),
    ];
  }
  if (selection.kind === "proposal") {
    const p = selection.payload;
    return [
      `skg proposals show ${p.id}`,
      `skg proposals accept ${p.id}`,
      `skg proposals defer ${p.id}`,
      p.action?.command_hint || "",
    ].filter(Boolean);
  }
  if (selection.kind === "fold") {
    const f = selection.payload;
    return [
      f.fold_id && (f.target_ip || f.location)
        ? `curl -X POST 'http://127.0.0.1:5055/folds/resolve/${f.fold_id}?target_ip=${f.target_ip || f.location}'`
        : "",
      f.why?.service
        ? `skg catalog compile --domain ${f.why.service.toLowerCase().replace(/[^a-z0-9]+/g, "_")} --description 'review ${f.why.service} fold coverage' --dry-run`
        : "",
    ].filter(Boolean);
  }
  return [
    `curl 'http://127.0.0.1:5055/memory/pearls/manifold'`,
    `curl 'http://127.0.0.1:5055/history/actions?limit=20'`,
  ];
}

function renderCommandDesk() {
  const node = document.getElementById("command-desk");
  if (!node) return;
  const selection = state.selected;
  const title = selection
    ? `${selection.kind}: ${selectionIdentity(selection) || selection.id}`
    : "No selection";
  node.innerHTML = `
    <div class="assistant-block">
      <p><strong>${esc(title)}</strong></p>
      <p class="meta">These are the next useful commands for the current object. The desk is intentionally narrow so you can initiate something without digging through panels.</p>
      ${renderCommandItems(commandDeskItems())}
    </div>`;
}

function renderRunMonitor() {
  const node = document.getElementById("run-monitor");
  if (!node) return;
  const g = state.gravityStatus || state.data?.status?.gravity_state || {};
  const lines = (g.recent_output || []).slice(-10);
  const selection = state.selected;
  const identity = selectionIdentity(selection);
  const runFocused = document.getElementById("gravity-run-target");
  const startBtn = document.getElementById("gravity-start");
  const stopBtn = document.getElementById("gravity-stop");
  if (runFocused) {
    runFocused.disabled = !selection || !identity || !!g.running;
    runFocused.textContent = identity ? `Run ${identity}` : "Run Focused Target";
  }
  if (startBtn) startBtn.disabled = !!g.running;
  if (stopBtn) stopBtn.disabled = !g.running;
  node.innerHTML = `
    <div class="assistant-block">
      <p><strong>${g.running ? "running" : "idle"}</strong> · cycle ${esc(g.cycle ?? "-")}</p>
      <p class="meta">activity: ${esc(g.current_activity || g.error || "no active cycle")}</p>
      <p class="meta">selection: ${esc(identity || "none")} | focused run available: ${!g.running && !!identity ? "yes" : "no"}</p>
      <p class="meta">started: ${esc(g.cycle_started_at || "-")} | last complete: ${esc(g.last_cycle_at || "-")}</p>
      <p class="meta">field energy: ${esc(g.total_entropy ?? "-")} | unresolved: ${esc(g.total_unknowns ?? "-")} | rc: ${esc(g.last_returncode ?? "-")}</p>
      ${g.current_surface ? `<div class="meta">surface: ${esc(String(g.current_surface).split("/").pop())}</div>` : ""}
      ${lines.length ? `<pre class="run-log">${esc(lines.join("\n"))}</pre>` : `<div class="meta">No live run output yet.</div>`}
    </div>`;
}

function renderActionStatus() {
  const node = document.getElementById("action-status");
  if (!node) return;
  if (!state.actionStatus) {
    node.hidden = true;
    node.textContent = "";
    return;
  }
  node.hidden = false;
  node.textContent = state.actionStatus;
}

function renderArtifactsPanel() {
  const box = document.getElementById("artifacts");
  const note = document.getElementById("artifacts-assistant");
  const identity = selectionIdentity(state.selected);

  if (!identity) {
    box.innerHTML = "Select an object to load recent events, discovery, and interp artifacts for its identity.";
    if (note) note.innerHTML = "Artifact summaries will appear here once an identity is selected.";
    return;
  }

  if (state.artifactsLoading === identity) {
    box.innerHTML = `<div class="artifact-card"><strong>${esc(identity)}</strong><div class="meta">Loading recent artifacts...</div></div>`;
    if (note) note.innerHTML = `Loading measured support for <strong>${esc(identity)}</strong>.`;
    return;
  }

  const result = state.artifactsByIdentity[identity];
  if (!result) {
    box.innerHTML = `<div class="artifact-card"><strong>${esc(identity)}</strong><div class="meta">Artifact lookup not started.</div></div>`;
    if (note) note.innerHTML = `No artifact summary is available yet for <strong>${esc(identity)}</strong>.`;
    return;
  }

  if (result.error) {
    box.innerHTML = `<div class="artifact-card"><strong>${esc(identity)}</strong><div class="meta">Artifact lookup failed: ${esc(result.error)}</div></div>`;
    if (note) note.innerHTML = `SKG could not load recent artifacts for <strong>${esc(identity)}</strong>.`;
    return;
  }

  box.innerHTML = "";
  (result.artifacts || []).forEach((artifact) => {
    const node = el(
      "div",
      "artifact-card",
      `<strong>${esc(artifact.file)}</strong>
       <div class="meta">${esc(artifact.category)} | ${esc(formatBytes(artifact.size))} | ${esc(artifact.mtime)}</div>
       <div class="meta">${esc(artifact.workload_id || artifact.path)}</div>`
    );
    node.classList.add("selectable");
    if (state.selectedArtifactPath === artifact.path) node.classList.add("selected");
    node.addEventListener("click", () => {
      state.selectedArtifactPath = artifact.path;
      renderArtifactsPanel();
      renderArtifactPreview();
      ensureArtifactPreview(artifact.path);
    });
    box.appendChild(node);
  });

  const counts = (result.artifacts || []).reduce((acc, artifact) => {
    acc[artifact.category] = (acc[artifact.category] || 0) + 1;
    return acc;
  }, {});
  if (note) {
    note.innerHTML =
      `Recent measured support for <strong>${esc(identity)}</strong> includes ` +
      `${Object.entries(counts).map(([k, v]) => `<strong>${v}</strong> ${esc(k)}`).join(", ") || "no artifacts"}. ` +
      `These are the files backing the current field state, not a narrative summary.`;
  }

  const currentSet = new Set((result.artifacts || []).map((artifact) => artifact.path));
  if (state.selectedArtifactPath && !currentSet.has(state.selectedArtifactPath)) {
    state.selectedArtifactPath = null;
  }
  if (!state.selectedArtifactPath && result.artifacts && result.artifacts.length) {
    state.selectedArtifactPath = result.artifacts[0].path;
    ensureArtifactPreview(state.selectedArtifactPath);
  }
}

function renderArtifactPreview() {
  const box = document.getElementById("artifact-preview");
  const note = document.getElementById("artifact-preview-assistant");
  const path = state.selectedArtifactPath;

  if (!path) {
    box.className = "detail-empty";
    box.innerHTML = "Select one measured-support artifact to inspect its first rows or keys.";
    if (note) note.innerHTML = "Preview notes will appear here once an artifact is selected.";
    return;
  }

  if (state.artifactPreviewLoading === path) {
    box.className = "";
    box.innerHTML = `<div class="preview-row"><strong>${esc(path.split("/").pop() || path)}</strong><div class="meta">Loading preview...</div></div>`;
    if (note) note.innerHTML = `Loading preview for <strong>${esc(path.split("/").pop() || path)}</strong>.`;
    return;
  }

  const preview = state.artifactPreviewByPath[path];
  if (!preview) {
    box.className = "detail-empty";
    box.innerHTML = "Preview not loaded yet.";
    if (note) note.innerHTML = "Preview metadata is not available yet.";
    return;
  }

  if (preview.error) {
    box.className = "";
    box.innerHTML = `<div class="preview-row"><strong>${esc(path.split("/").pop() || path)}</strong><div class="meta">Preview failed: ${esc(preview.error)}</div></div>`;
    if (note) note.innerHTML = `SKG could not preview <strong>${esc(path.split("/").pop() || path)}</strong>.`;
    return;
  }

  box.className = "";
  box.innerHTML = `<div class="preview-box">${(preview.rows || [])
    .slice(0, 12)
    .map((row, index) => {
      const label = row.line ? `line ${row.line}` : row.keys ? "json keys" : `row ${index + 1}`;
      return `<div class="preview-row">
        <strong>${esc(label)}</strong>
        <pre>${esc(JSON.stringify(row.data || row, null, 2))}</pre>
      </div>`;
    })
    .join("")}</div>`;

  const kind = preview.preview_kind || "artifact";
  if (note) {
    note.innerHTML =
      `<strong>${esc(preview.file || path.split("/").pop() || path)}</strong> is being previewed as <strong>${esc(kind)}</strong>. ` +
      `This is a bounded sample of the measured file, not a re-interpretation of it.`;
  }
}

function renderTimelinePanel() {
  const box = document.getElementById("timeline");
  const note = document.getElementById("timeline-assistant");
  const identity = selectionIdentity(state.selected);

  if (!identity) {
    box.innerHTML = "Select an object to load its identity timeline.";
    if (note) note.innerHTML = "Timeline notes will appear here once an identity is selected.";
    return;
  }

  if (state.timelineLoading === identity) {
    box.innerHTML = `<div class="timeline-card"><strong>${esc(identity)}</strong><div class="meta">Loading timeline...</div></div>`;
    if (note) note.innerHTML = `Loading temporal history for <strong>${esc(identity)}</strong>.`;
    return;
  }

  const timeline = state.timelineByIdentity[identity];
  if (!timeline) {
    box.innerHTML = `<div class="timeline-card"><strong>${esc(identity)}</strong><div class="meta">Timeline not loaded yet.</div></div>`;
    if (note) note.innerHTML = `No timeline is loaded yet for <strong>${esc(identity)}</strong>.`;
    return;
  }

  if (timeline.error) {
    box.innerHTML = `<div class="timeline-card"><strong>${esc(identity)}</strong><div class="meta">Timeline lookup failed: ${esc(timeline.error)}</div></div>`;
    if (note) note.innerHTML = `SKG could not load temporal history for <strong>${esc(identity)}</strong>.`;
    return;
  }

  const rows = []
    .concat((timeline.transitions || []).slice(0, 8).map((row) => ({
      kind: "transition",
      at: row.ts || row.computed_at || "",
      title: `${row.node_id || "node"} ${row.from_state || "?"}→${row.to_state || "?"}`,
      meta: `${row._workload_id || row.workload_id || "unknown"} | ${row.attack_path_id || "path n/a"}`,
    })))
    .concat((timeline.snapshots || []).slice(0, 8).map((row) => ({
      kind: "snapshot",
      at: row.computed_at || row.ts || "",
      title: `${row.attack_path_id || "snapshot"} ${row.classification || ""}`.trim(),
      meta: `${row._workload_id || row.workload_id || "unknown"} | realized=${(row.realized || []).length || 0} blocked=${(row.blocked || []).length || 0} unknown=${(row.unknown || []).length || 0}`,
    })))
    .sort((a, b) => String(b.at).localeCompare(String(a.at)))
    .slice(0, 12);

  box.innerHTML = rows.length
    ? rows
        .map(
          (row) => `<div class="timeline-card">
            <strong>${esc(row.title)}</strong>
            <div class="meta">${esc(row.kind)} | ${esc(row.at || "unknown time")}</div>
            <div class="meta">${esc(row.meta)}</div>
          </div>`
        )
        .join("")
    : `<div class="timeline-card"><strong>${esc(identity)}</strong><div class="meta">No temporal rows available.</div></div>`;

  note.innerHTML =
    `<strong>${esc(identity)}</strong> currently has <strong>${esc(timeline.workload_count || 0)}</strong> workload manifestations, ` +
    `<strong>${esc(timeline.snapshot_count || 0)}</strong> snapshots, and ` +
    `<strong>${esc(timeline.transition_count || 0)}</strong> recorded transitions in this aggregated timeline.`;
}

function renderActionHistory() {
  const box = document.getElementById("actions");
  const note = document.getElementById("actions-assistant");
  const identity = selectionIdentity(state.selected);

  if (state.actionHistoryLoading) {
    box.innerHTML = `<div class="history-card"><strong>Loading action history...</strong></div>`;
    note.innerHTML = "Loading recent operator-visible lifecycle actions.";
    return;
  }

  if (!state.actionHistory) {
    box.innerHTML = "Recent operator-visible actions will appear here.";
    note.innerHTML = "Action history notes will appear here.";
    return;
  }

  if (state.actionHistory.error) {
    box.innerHTML = `<div class="history-card"><strong>Action history failed</strong><div class="meta">${esc(state.actionHistory.error)}</div></div>`;
    note.innerHTML = "SKG could not load action history.";
    return;
  }

  const historyRows = state.actionHistory.actions || state.actionHistory.items || [];
  const rows = historyRows.filter((row) => !identity || row.identity_key === identity).slice(0, 12);
  box.innerHTML = rows.length
    ? rows
        .map(
          (row) => `<div class="history-card">
            <strong>${esc(row.reason || row.action || row.kind || "action")}</strong>
            <div class="meta">${esc(row.timestamp || "")}</div>
            <div class="meta">${esc(row.identity_key || row.target_ip || "global")} | ${esc(row.domain || "unknown")}</div>
            <div class="meta">${esc(row.proposal_id || row.fold_id || row.status || "")}</div>
          </div>`
        )
        .join("")
    : `<div class="history-card"><strong>No recent actions</strong><div class="meta">${identity ? `No recent actions for ${identity}.` : "No action history yet."}</div></div>`;

  note.innerHTML = identity
    ? `Recent operator-visible lifecycle actions scoped to <strong>${esc(identity)}</strong> are shown here from pearl-backed memory.`
    : `Recent operator-visible lifecycle actions across the current system are shown here from pearl-backed memory.`;
}

async function main() {
  try {
    await reloadAll();
    ensureActionHistory();
    document.addEventListener("click", handleUiClick);
    const filter = document.getElementById("focus-filter");
    filter.addEventListener("input", (event) => {
      state.filter = event.target.value || "";
      render();
    });
    render();
    refreshGravityStatus();
    setInterval(refreshGravityStatus, 3000);
  } catch (err) {
    document.getElementById("assistant").textContent = `UI load failed: ${err.message}`;
  }
}

main();
