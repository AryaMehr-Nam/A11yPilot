(function () {
  "use strict";

  const state = {
    windows: [],
    selectedWindowId: null,
    snapshot: null,
    nodesByRef: new Map(),
    keyToNode: new Map(),
    parentKeyByKey: new Map(),
    treeRowByRef: new Map(),
    collapsedKeys: new Set(),
    selectedRef: null,
    filterRole: "all",
    searchQuery: "",
    mode: "safe",
    emergencyStopped: false,
    overlayEnabled: false,
    recording: false,
    approvals: [],
    feedEvents: [],
    mcpConfigText: "",
    compactText: "",
    sampleLoaded: false,
    yamlEdited: false,
    eventSource: null,
    canvas: null,
  };

  const dom = {};

  function byId(id) {
    return document.getElementById(id);
  }

  function clearNode(node) {
    while (node.firstChild) {
      node.removeChild(node.firstChild);
    }
  }

  function makeEl(tag, className, text) {
    const node = document.createElement(tag);
    if (className) node.className = className;
    if (text !== undefined && text !== null) node.textContent = String(text);
    return node;
  }

  function makeChevronSvg(expanded) {
    const ns = "http://www.w3.org/2000/svg";
    const svg = document.createElementNS(ns, "svg");
    svg.setAttribute("viewBox", "0 0 16 16");
    svg.setAttribute("width", "12");
    svg.setAttribute("height", "12");
    svg.setAttribute("fill", "none");
    svg.setAttribute("stroke", "currentColor");
    svg.setAttribute("stroke-width", "1.75");
    svg.setAttribute("aria-hidden", "true");
    const path = document.createElementNS(ns, "path");
    path.setAttribute("d", expanded ? "M4 6l4 4 4-4" : "M6 4l4 4-4 4");
    svg.appendChild(path);
    return svg;
  }

  function showError(msg) {
    if (!dom.errorBanner || !dom.errorBannerText) return;
    dom.errorBannerText.textContent = msg;
    dom.errorBanner.hidden = false;
  }

  function clearError() {
    if (dom.errorBanner) dom.errorBanner.hidden = true;
  }

  async function apiFetch(url, options) {
    const opts = Object.assign({ headers: {} }, options || {});
    if (opts.body && typeof opts.body !== "string") {
      opts.headers["Content-Type"] = "application/json";
      opts.body = JSON.stringify(opts.body);
    }
    const resp = await fetch(url, opts);
    const text = await resp.text();
    let data = {};
    if (text) {
      try {
        data = JSON.parse(text);
      } catch (_err) {
        data = { raw: text };
      }
    }
    if (!resp.ok) {
      const detail = data.detail || data.error || data.message || ("Request failed with status " + resp.status);
      throw new Error(typeof detail === "string" ? detail : JSON.stringify(detail));
    }
    return data;
  }

  function roleGroupFor(node) {
    const risk = String(node.risk_level || "").toUpperCase();
    if (risk === "HIGH" || risk === "CRITICAL") return "danger";
    if (node.is_password || node.role === "password") return "password";
    if (node.role === "text_input" || node.role === "combobox") return "input";
    if (node.role === "checkbox" || node.role === "radio" || node.role === "tab") return "toggle";
    if (node.role === "button" || node.role === "menu_item" || node.role === "link") return "button";
    return "muted";
  }

  function formatCompactNode(node, depth, lines) {
    if (!node) return;
    const indent = "  ".repeat(depth);
    const parts = [];
    if (node.ref) parts.push(node.ref);
    parts.push("[" + (node.role || "unknown") + "]");
    if (node.name) parts.push('"' + node.name + '"');
    if (node.is_password || node.role === "password") {
      parts.push("value=[REDACTED:PASSWORD]");
    } else if (node.value !== null && node.value !== undefined && node.value !== "") {
      parts.push('value="' + node.value + '"');
    }
    if (node.checked === true) parts.push("(checked)");
    if (node.selected === true) parts.push("(selected)");
    if (node.enabled === false) parts.push("(disabled)");
    if (node.risk_level && String(node.risk_level).toUpperCase() !== "LOW") {
      parts.push("risk=" + String(node.risk_level).toLowerCase());
    }
    if (node.ref || node.name || depth === 0) {
      lines.push(indent + parts.join(" "));
    }
    const children = Array.isArray(node.children) ? node.children : [];
    for (let i = 0; i < children.length; i++) {
      formatCompactNode(children[i], depth + 1, lines);
    }
  }

  function buildCompactSnapshotText(snapshot) {
    if (!snapshot) return "No snapshot captured.";
    if (typeof snapshot.compact_text === "string" && snapshot.compact_text.trim()) {
      return snapshot.compact_text;
    }
    const win = snapshot.window || {};
    const header =
      "[window] " +
      (win.title || "Untitled") +
      " (" +
      (win.process_name || "unknown") +
      " pid=" +
      (win.pid || 0) +
      ")";
    const lines = [header];
    if (snapshot.root) {
      formatCompactNode(snapshot.root, 0, lines);
    }
    return lines.join("\n");
  }

  function indexTreeNodes(node, parentKey, pathKey) {
    if (!node) return;
    const nodeKey = node.ref || pathKey;
    node._uiKey = nodeKey;
    state.keyToNode.set(nodeKey, node);
    if (parentKey) {
      state.parentKeyByKey.set(nodeKey, parentKey);
    }
    if (node.ref) {
      state.nodesByRef.set(node.ref, node);
    }
    const children = Array.isArray(node.children) ? node.children : [];
    for (let i = 0; i < children.length; i++) {
      indexTreeNodes(children[i], nodeKey, pathKey + "." + i);
    }
  }

  function nodeMatchesSearch(node, query) {
    if (!query) return true;
    const q = query.toLowerCase();
    const hay = [
      node.ref || "",
      node.name || "",
      node.role || "",
      node.automation_id || "",
      node.risk_level || "",
    ]
      .join(" ")
      .toLowerCase();
    return hay.includes(q);
  }

  function nodeMatchesRoleFilter(node) {
    if (state.filterRole === "all") return true;
    const risk = String(node.risk_level || "").toUpperCase();
    if (state.filterRole === "risk") {
      return risk === "HIGH" || risk === "CRITICAL";
    }
    return roleGroupFor(node) === state.filterRole;
  }

  function collectMatchingSubtree(node, query, matchRefs, visibleKeys) {
    if (!node) return false;
    const selfDirectMatch = nodeMatchesSearch(node, query) && nodeMatchesRoleFilter(node);
    const children = Array.isArray(node.children) ? node.children : [];
    let childMatched = false;
    for (let i = 0; i < children.length; i++) {
      if (collectMatchingSubtree(children[i], query, matchRefs, visibleKeys)) {
        childMatched = true;
      }
    }
    if (selfDirectMatch && node.ref) {
      matchRefs.add(node.ref);
    }
    if (selfDirectMatch || childMatched) {
      visibleKeys.add(node._uiKey);
      return true;
    }
    return false;
  }

  function renderTree() {
    clearNode(dom.treeContainer);
    state.treeRowByRef.clear();

    if (!state.snapshot || !state.snapshot.root) {
      dom.treeContainer.appendChild(makeEl("div", "state-empty", "Capture a window snapshot to inspect its accessibility tree."));
      dom.treeCountLabel.textContent = "0 elements";
      if (state.canvas) state.canvas.setFilters(state.filterRole, null);
      return;
    }

    const filteringActive = state.filterRole !== "all" || Boolean(state.searchQuery.trim());
    const matchRefs = new Set();
    const visibleKeys = new Set();
    collectMatchingSubtree(state.snapshot.root, state.searchQuery.trim(), matchRefs, visibleKeys);

    if (state.canvas) {
      state.canvas.setFilters(state.filterRole, state.searchQuery.trim() ? matchRefs : null);
    }

    let renderedCount = 0;

    function appendNode(node, depth) {
      if (filteringActive && !visibleKeys.has(node._uiKey)) return;

      const children = Array.isArray(node.children) ? node.children : [];
      const visibleChildren = filteringActive
        ? children.filter((c) => visibleKeys.has(c._uiKey))
        : children;
      const hasChildren = visibleChildren.length > 0;
      const isCollapsed = !filteringActive && state.collapsedKeys.has(node._uiKey);
      const isMatch = !filteringActive || (node.ref ? matchRefs.has(node.ref) : nodeMatchesRoleFilter(node));

      const row = makeEl("div", "tree-node-row");
      row.setAttribute("role", "treeitem");
      row.setAttribute("tabindex", node.ref && node.ref === state.selectedRef ? "0" : "-1");
      row.style.paddingLeft = (8 + depth * 14) + "px";
      if (hasChildren) {
        row.setAttribute("aria-expanded", String(!isCollapsed));
      }
      if (node.ref && node.ref === state.selectedRef) {
        row.classList.add("is-selected");
        row.setAttribute("aria-selected", "true");
      } else {
        row.setAttribute("aria-selected", "false");
      }
      if (filteringActive && !isMatch) {
        row.classList.add("is-dimmed");
      }

      if (hasChildren) {
        const chevBtn = makeEl("button", "tree-chevron");
        chevBtn.type = "button";
        chevBtn.setAttribute("aria-label", isCollapsed ? "Expand node" : "Collapse node");
        chevBtn.appendChild(makeChevronSvg(!isCollapsed));
        chevBtn.addEventListener("click", (e) => {
          e.stopPropagation();
          if (state.collapsedKeys.has(node._uiKey)) {
            state.collapsedKeys.delete(node._uiKey);
          } else {
            state.collapsedKeys.add(node._uiKey);
          }
          renderTree();
        });
        row.appendChild(chevBtn);
      } else {
        row.appendChild(makeEl("span", "tree-chevron--spacer"));
      }

      const rg = roleGroupFor(node);
      const bar = makeEl("span", "tree-role-bar tree-role-bar--" + (rg === "button" ? "trigger" : rg));
      row.appendChild(bar);

      if (node.ref) {
        row.appendChild(makeEl("span", "ref-code", node.ref));
        state.treeRowByRef.set(node.ref, row);
      }

      const displayLabel =
        node.is_password || node.role === "password"
          ? (node.name || "Secret input") + " [REDACTED]"
          : node.name || node.automation_id || node.role || "node";
      const nameSpan = makeEl("span", "tree-node-name", displayLabel);
      nameSpan.title = displayLabel;
      row.appendChild(nameSpan);

      row.appendChild(makeEl("span", "tree-node-role", node.role || "unknown"));

      row.addEventListener("click", () => {
        if (node.ref) {
          selectElementRef(node.ref, { flyCanvas: true, scrollTree: false });
        } else if (state.canvas && node.bounds) {
          state.canvas.flyTo(node.bounds);
        }
      });

      row.addEventListener("keydown", (e) => {
        if (e.key === "Enter" || e.key === " ") {
          e.preventDefault();
          if (node.ref) selectElementRef(node.ref, { flyCanvas: true, scrollTree: false });
        } else if (e.key === "ArrowRight" && hasChildren && isCollapsed) {
          e.preventDefault();
          state.collapsedKeys.delete(node._uiKey);
          renderTree();
        } else if (e.key === "ArrowLeft" && hasChildren && !isCollapsed) {
          e.preventDefault();
          state.collapsedKeys.add(node._uiKey);
          renderTree();
        } else if (e.key === "ArrowDown" || e.key === "ArrowUp") {
          e.preventDefault();
          const rows = Array.from(dom.treeContainer.querySelectorAll(".tree-node-row"));
          const idx = rows.indexOf(row);
          const next = rows[idx + (e.key === "ArrowDown" ? 1 : -1)];
          if (next) next.focus();
        }
      });

      dom.treeContainer.appendChild(row);
      renderedCount++;

      if (hasChildren && !isCollapsed) {
        for (let i = 0; i < visibleChildren.length; i++) {
          appendNode(visibleChildren[i], depth + 1);
        }
      }
    }

    appendNode(state.snapshot.root, 0);

    if (renderedCount === 0) {
      dom.treeContainer.appendChild(makeEl("div", "state-empty", "No elements match the active filter."));
    }

    const interactiveTotal = state.nodesByRef.size;
    dom.treeCountLabel.textContent = filteringActive
      ? matchRefs.size + " matched of " + interactiveTotal + " refs"
      : interactiveTotal + " interactive refs";
  }

  function selectElementRef(ref, options) {
    const opts = options || {};
    state.selectedRef = ref || null;
    if (opts.scrollTree && ref && state.nodesByRef.has(ref)) {
      let curKey = state.nodesByRef.get(ref)._uiKey;
      while (curKey && state.parentKeyByKey.has(curKey)) {
        const parentKey = state.parentKeyByKey.get(curKey);
        state.collapsedKeys.delete(parentKey);
        curKey = parentKey;
      }
    }
    updateSandboxSelection();
    renderTree();

    if (state.canvas && ref) {
      state.canvas.selectRef(ref, { fly: Boolean(opts.flyCanvas) });
    }
    if (opts.scrollTree && ref && state.treeRowByRef.has(ref)) {
      const row = state.treeRowByRef.get(ref);
      const reduced = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
      row.scrollIntoView({ block: "nearest", behavior: reduced ? "auto" : "smooth" });
    }
  }

  function updateSandboxSelection() {
    const node = state.selectedRef ? state.nodesByRef.get(state.selectedRef) : null;
    if (!node) {
      dom.selectedRefBadge.textContent = "No selection";
      dom.selectedRoleBadge.textContent = "none";
      dom.selectedRiskBadge.hidden = true;
      dom.selectedNameVal.textContent = "Select an element from the tree or canvas";
      dom.selectedAutoVal.textContent = "none";
      dom.selectedBoundsVal.textContent = "none";
      dom.selectedActionsVal.textContent = "none";
      dom.actClickBtn.disabled = true;
      dom.actFocusBtn.disabled = true;
      dom.actToggleBtn.disabled = true;
      dom.actTypeInput.disabled = true;
      dom.actTypeBtn.disabled = true;
      dom.actSelectInput.disabled = true;
      dom.actSelectBtn.disabled = true;
      return;
    }

    dom.selectedRefBadge.textContent = node.ref || "node";
    dom.selectedRoleBadge.textContent = node.role || "unknown";

    const risk = String(node.risk_level || "LOW").toLowerCase();
    dom.selectedRiskBadge.hidden = false;
    dom.selectedRiskBadge.textContent = "risk: " + risk;
    dom.selectedRiskBadge.className = "risk-tag risk-tag--" + risk;

    dom.selectedNameVal.textContent = node.name || "Unnamed element";
    dom.selectedAutoVal.textContent = node.automation_id || "none";
    const b = node.bounds || { x: 0, y: 0, width: 0, height: 0 };
    dom.selectedBoundsVal.textContent = b.x + ", " + b.y + " (" + b.width + "x" + b.height + ")";
    const supported = Array.isArray(node.supported_actions) ? node.supported_actions : [];
    dom.selectedActionsVal.textContent = supported.length ? supported.join(", ") : "click, focus";

    const disabledByStop = state.emergencyStopped;
    dom.actClickBtn.disabled = disabledByStop;
    dom.actFocusBtn.disabled = disabledByStop;
    dom.actToggleBtn.disabled = disabledByStop;
    dom.actTypeInput.disabled = disabledByStop;
    dom.actTypeBtn.disabled = disabledByStop;
    dom.actSelectInput.disabled = disabledByStop;
    dom.actSelectBtn.disabled = disabledByStop;
  }

  function applySnapshot(rawSnapshot, options) {
    const snapshot = rawSnapshot && rawSnapshot.snapshot ? rawSnapshot.snapshot : rawSnapshot;
    if (!snapshot || !snapshot.root) return;
    state.snapshot = snapshot;
    if (snapshot.window && snapshot.window.window_id) {
      state.selectedWindowId = snapshot.window.window_id;
    }
    state.nodesByRef.clear();
    state.keyToNode.clear();
    state.parentKeyByKey.clear();
    indexTreeNodes(snapshot.root, null, "root");

    if (state.selectedRef && !state.nodesByRef.has(state.selectedRef)) {
      state.selectedRef = null;
    }

    const win = snapshot.window || {};
    const bounds = win.bounds || { width: 0, height: 0 };
    const msText = typeof snapshot.capture_ms === "number" ? " (" + snapshot.capture_ms.toFixed(1) + " ms)" : "";
    dom.stageWindowInfo.textContent =
      (win.title || "Window") + " " + bounds.width + "x" + bounds.height + msText;

    updateTelemetryUI(snapshot);
    renderTree();
    updateSandboxSelection();

    if (state.canvas) {
      state.canvas.setSnapshot(snapshot, options);
      if (state.selectedRef) {
        state.canvas.selectRef(state.selectedRef, { fly: false });
      }
    }
  }

  function updateTelemetryUI(snapshot) {
    const tel = snapshot && snapshot.telemetry ? snapshot.telemetry : null;
    if (!tel) {
      dom.savingsPill.textContent = "No telemetry";
      return;
    }
    const a11yTokens = Number(tel.a11y_tokens || 0);
    const baseline = Math.max(1, Number(tel.vision_tokens_baseline || 3200));
    const saved = Number(tel.tokens_saved || Math.max(0, baseline - a11yTokens));
    const pct = Number(tel.savings_percent || 0);

    dom.savingsPill.textContent = "~" + Math.round(pct) + "% fewer tokens";
    dom.a11yTokensVal.textContent = a11yTokens + " tokens";
    dom.visionTokensVal.textContent = baseline + " tokens";

    const a11yRatio = Math.max(0, Math.min(1, a11yTokens / baseline));
    dom.a11yTokensBar.style.transform = "scaleX(" + a11yRatio.toFixed(4) + ")";
    dom.visionTokensBar.style.transform = "scaleX(1)";

    dom.statTokensSaved.textContent = String(saved);
    dom.statSavingsPct.textContent = pct.toFixed(1) + "%";
    dom.statPrunedNodes.textContent = (tel.total_raw_nodes || 0) + " / " + (tel.pruned_nodes || 0);
    dom.statInteractiveCount.textContent = String(tel.interactive_count || state.nodesByRef.size);

    if (typeof snapshot.capture_ms === "number") {
      dom.economyCaptureMs.textContent = snapshot.capture_ms.toFixed(1) + " ms";
    }

    state.compactText = buildCompactSnapshotText(snapshot);
    dom.compactSnapshotPre.textContent = state.compactText;
  }

  function updateStatusUI(statusData) {
    if (!statusData) return;
    const backendName = statusData.backend || statusData.backend_name || statusData.active_backend || "ready";
    dom.backendBadge.textContent = "Backend: " + backendName;

    const mode = statusData.mode || statusData.execution_mode || state.mode;
    setActiveModeUI(mode);

    const stopped = Boolean(
      statusData.emergency_stopped || statusData.emergency_stop || statusData.stopped
    );
    setEmergencyStopUI(stopped);

    const overlayOn = Boolean(
      statusData.overlay_enabled || statusData.overlay_active || statusData.overlay
    );
    setOverlayUI(overlayOn);

    if (typeof statusData.recording === "boolean") {
      setRecordingUI(statusData.recording);
    } else if (typeof statusData.is_recording === "boolean") {
      setRecordingUI(statusData.is_recording);
    }
  }

  function setActiveModeUI(mode) {
    state.mode = mode || "safe";
    const btns = dom.modeButtons;
    for (let i = 0; i < btns.length; i++) {
      const btn = btns[i];
      const active = btn.getAttribute("data-mode") === state.mode;
      btn.setAttribute("aria-pressed", String(active));
    }
  }

  function setEmergencyStopUI(stopped) {
    state.emergencyStopped = Boolean(stopped);
    dom.emergencyToggleBtn.setAttribute("aria-pressed", String(state.emergencyStopped));
    if (state.emergencyStopped) {
      dom.emergencyToggleBtn.classList.add("is-stopped");
      dom.emergencyBtnLabel.textContent = "Resume";
      dom.emergencyBanner.hidden = false;
    } else {
      dom.emergencyToggleBtn.classList.remove("is-stopped");
      dom.emergencyBtnLabel.textContent = "Emergency Stop";
      dom.emergencyBanner.hidden = true;
    }
    updateSandboxSelection();
  }

  function setOverlayUI(enabled) {
    state.overlayEnabled = Boolean(enabled);
    dom.overlayToggleBtn.setAttribute("aria-pressed", String(state.overlayEnabled));
    dom.overlayToggleBtn.textContent = state.overlayEnabled ? "Overlay: On" : "Overlay: Off";
  }

  function setRecordingUI(recording) {
    state.recording = Boolean(recording);
    dom.macroRecordBtn.setAttribute("aria-pressed", String(state.recording));
    dom.macroRecordBtn.textContent = state.recording ? "Stop Recording" : "Start Recording";
    dom.recordingBadge.textContent = state.recording ? "Recording" : "Idle";
    dom.recordingBadge.className = state.recording ? "status-pill status-pill--danger" : "status-pill";
  }

  function renderWindowsSelect() {
    clearNode(dom.windowSelect);
    if (!state.windows.length) {
      const opt = makeEl("option", null, "No desktop windows detected");
      opt.value = "";
      dom.windowSelect.appendChild(opt);
      return;
    }
    for (let i = 0; i < state.windows.length; i++) {
      const w = state.windows[i];
      const opt = makeEl("option", null, w.title + " (" + w.process_name + ")");
      opt.value = w.window_id;
      if (w.window_id === state.selectedWindowId) {
        opt.selected = true;
      }
      dom.windowSelect.appendChild(opt);
    }
  }

  function parseTimestampMs(val) {
    if (val === null || val === undefined || val === "") return null;
    if (typeof val === "number") return val < 1e12 ? val * 1000 : val;
    const n = Number(val);
    if (!Number.isNaN(n) && /^\d+(?:\.\d+)?$/.test(String(val).trim())) {
      return n < 1e12 ? n * 1000 : n;
    }
    const parsed = Date.parse(String(val));
    return Number.isNaN(parsed) ? null : parsed;
  }

  function renderApprovals() {
    clearNode(dom.approvalsList);
    const pending = state.approvals.filter(
      (a) => !a.status || String(a.status).toLowerCase() === "pending"
    );

    if (pending.length > 0) {
      dom.approvalsCountPill.hidden = false;
      dom.approvalsCountPill.textContent = pending.length + " pending";
      dom.approvalsCountPill.className = "status-pill status-pill--danger";
    } else {
      dom.approvalsCountPill.hidden = true;
    }

    if (pending.length === 0) {
      dom.approvalsList.appendChild(makeEl("div", "state-empty", "No pending human approvals."));
      return;
    }

    for (let i = 0; i < pending.length; i++) {
      const ap = pending[i];
      const apId = ap.approval_id || ap.id;
      const card = makeEl("article", "approval-card");
      card.setAttribute("data-approval-id", apId);

      const head = makeEl("div", "approval-card-head");
      const title =
        (ap.action || "action") +
        " on " +
        (ap.ref || ap.target_name || ap.element_name || "element");
      head.appendChild(makeEl("span", "approval-card-title", title));
      const risk = String(ap.risk_level || "CRITICAL").toLowerCase();
      head.appendChild(makeEl("span", "risk-tag risk-tag--" + risk, risk));
      card.appendChild(head);

      const targetRole = ap.target_role ? "[" + ap.target_role + "] " : "";
      const targetInfo =
        targetRole +
        (ap.target_name || ap.element_name || "Target element") +
        (ap.window_title ? " in " + ap.window_title : "");
      card.appendChild(makeEl("div", "muted-note", targetInfo));

      const reasonList = Array.isArray(ap.reasons)
        ? ap.reasons
        : Array.isArray(ap.risk_reasons)
          ? ap.risk_reasons
          : null;
      const reason = reasonList && reasonList.length
        ? reasonList.join("; ")
        : ap.reason || ap.decision_reason || "Safety gate requires explicit approval.";
      card.appendChild(makeEl("p", "approval-card-reason", reason));

      const timerRow = makeEl("div", "approval-timer-row");
      const track = makeEl("div", "approval-timer-track");
      const fill = makeEl("div", "approval-timer-fill");
      track.appendChild(fill);
      const timerLabel = makeEl("span", "mono-value muted-note", "--s");
      timerRow.appendChild(track);
      timerRow.appendChild(timerLabel);
      card.appendChild(timerRow);

      const createdMs = parseTimestampMs(ap.created_at) || Date.now();
      const ttlSec = Number(ap.ttl_seconds || ap.timeout_seconds || 30);
      const expiresMs = parseTimestampMs(ap.expires_at) || createdMs + ttlSec * 1000;
      const totalMs = Math.max(1000, expiresMs - createdMs);
      card._timerFill = fill;
      card._timerLabel = timerLabel;
      card._expiresMs = expiresMs;
      card._totalMs = totalMs;

      const actions = makeEl("div", "approval-actions");
      const approveBtn = makeEl("button", "btn-approve", "Approve");
      approveBtn.type = "button";
      approveBtn.addEventListener("click", () => decideApproval(apId, "approve", approveBtn, denyBtn));

      const denyBtn = makeEl("button", "btn-danger-outline", "Deny");
      denyBtn.type = "button";
      denyBtn.addEventListener("click", () => decideApproval(apId, "deny", approveBtn, denyBtn));

      actions.appendChild(approveBtn);
      actions.appendChild(denyBtn);
      card.appendChild(actions);

      dom.approvalsList.appendChild(card);
    }

    updateApprovalTimers();
  }

  function updateApprovalTimers() {
    const cards = dom.approvalsList.querySelectorAll(".approval-card");
    const now = Date.now();
    for (let i = 0; i < cards.length; i++) {
      const card = cards[i];
      if (!card._expiresMs || !card._timerFill) continue;
      const remMs = Math.max(0, card._expiresMs - now);
      const ratio = Math.max(0, Math.min(1, remMs / card._totalMs));
      card._timerFill.style.transform = "scaleX(" + ratio.toFixed(4) + ")";
      card._timerLabel.textContent = Math.ceil(remMs / 1000) + "s";
    }
  }

  function appendFeedEvent(evt) {
    if (!evt || typeof evt !== "object") return;
    state.feedEvents.unshift(evt);
    if (state.feedEvents.length > 150) {
      state.feedEvents.length = 150;
    }
    renderFeed();
  }

  function renderFeed() {
    clearNode(dom.eventFeed);
    if (state.feedEvents.length === 0) {
      dom.eventFeed.appendChild(makeEl("div", "state-empty", "Listening for backend events…"));
      return;
    }

    for (let i = 0; i < state.feedEvents.length; i++) {
      const evt = state.feedEvents[i];
      const evtType = String(evt.type || "event");
      const risk = String(evt.risk_level || "").toUpperCase();
      const isDanger =
        evtType.includes("blocked") ||
        evtType.includes("denied") ||
        evtType.includes("stop") ||
        evtType.includes("approval_requested") ||
        risk === "HIGH" ||
        risk === "CRITICAL";
      const isCyan = evtType.includes("executed") || evtType.includes("approved");

      const entry = makeEl(
        "div",
        "feed-entry" + (isDanger ? " feed-entry--danger" : isCyan ? " feed-entry--button" : "")
      );

      const head = makeEl("div", "feed-entry-head");
      head.appendChild(makeEl("span", "mono-value", evtType));
      const ts = evt.timestamp ? formatTime(evt.timestamp) : "";
      if (ts) head.appendChild(makeEl("span", "mono-value muted-note", ts));
      entry.appendChild(head);

      const summary = makeEl("div", "feed-entry-summary", evt.summary || evt.message || evtType);
      entry.appendChild(summary);

      if (evt.ref) {
        const refBtn = makeEl("button", "btn-quiet ref-code", evt.ref);
        refBtn.type = "button";
        refBtn.addEventListener("click", () => {
          selectElementRef(evt.ref, { flyCanvas: true, scrollTree: true });
        });
        entry.appendChild(refBtn);
      }

      dom.eventFeed.appendChild(entry);
    }
  }

  function formatTime(iso) {
    const d = new Date(iso);
    if (Number.isNaN(d.getTime())) return String(iso);
    return d.toLocaleTimeString([], { hour12: false, hour: "2-digit", minute: "2-digit", second: "2-digit" });
  }

  async function refreshWindowsAndSnapshot() {
    clearError();
    try {
      const winResp = await apiFetch("/api/windows");
      const list = Array.isArray(winResp) ? winResp : winResp.windows || [];
      state.windows = list;
      if (!state.selectedWindowId && list.length > 0) {
        const active = list.find((w) => w.is_active) || list[0];
        state.selectedWindowId = active.window_id;
      }
      renderWindowsSelect();

      if (state.selectedWindowId) {
        await captureSnapshot(state.selectedWindowId, true);
      }
    } catch (err) {
      showError("Failed to refresh windows: " + err.message);
    }
  }

  async function captureSnapshot(windowId, fitCamera) {
    if (!windowId) return;
    clearError();
    try {
      const snap = await apiFetch("/api/snapshot", {
        method: "POST",
        body: { window_id: windowId },
      });
      applySnapshot(snap, { fit: Boolean(fitCamera) });
    } catch (_postErr) {
      try {
        const snap = await apiFetch("/api/snapshot?window_id=" + encodeURIComponent(windowId));
        applySnapshot(snap, { fit: Boolean(fitCamera) });
      } catch (getErr) {
        showError("Snapshot failed: " + getErr.message);
      }
    }
  }

  async function triggerAction(actionName) {
    if (!state.selectedRef || !state.snapshot) return;
    clearError();
    dom.actResultStatus.className = "action-feedback";
    dom.actResultStatus.textContent = "Executing " + actionName + " on " + state.selectedRef + "…";

    const payload = {
      window_id: state.selectedWindowId || (state.snapshot.window && state.snapshot.window.window_id),
      snapshot_id: state.snapshot.snapshot_id,
      ref: state.selectedRef,
      action: actionName,
      text: actionName === "type" ? dom.actTypeInput.value : null,
      option: actionName === "select" ? dom.actSelectInput.value : null,
      clear_first: Boolean(dom.actClearCheckbox.checked),
    };

    try {
      const res = await apiFetch("/api/act", { method: "POST", body: payload });
      const status = String(res.status || "executed").toLowerCase();
      const msg = res.message || res.reason || res.detail || (actionName + " -> " + status);

      if (status === "blocked" || status === "denied" || status === "failed") {
        dom.actResultStatus.className = "action-feedback action-feedback--danger";
        if (state.canvas) state.canvas.triggerRipple(state.selectedRef, "danger");
        if (res.approval || res.approval_id) {
          await fetchApprovals();
          activateTab("tab-feed");
        }
      } else if (status === "dry_run") {
        dom.actResultStatus.className = "action-feedback action-feedback--warn";
        if (state.canvas) state.canvas.triggerRipple(state.selectedRef, "warning");
      } else {
        dom.actResultStatus.className = "action-feedback action-feedback--ok";
        if (state.canvas) state.canvas.triggerRipple(state.selectedRef, "executed");
      }

      dom.actResultStatus.textContent = msg;

      if (res.snapshot) {
        applySnapshot(res.snapshot, { fit: false });
      } else if (status === "executed") {
        await captureSnapshot(payload.window_id, false);
      }
    } catch (err) {
      dom.actResultStatus.className = "action-feedback action-feedback--danger";
      dom.actResultStatus.textContent = "Error: " + err.message;
      if (state.canvas) state.canvas.triggerRipple(state.selectedRef, "danger");
    }
  }

  async function fetchApprovals() {
    try {
      const resp = await apiFetch("/api/approvals");
      state.approvals = Array.isArray(resp) ? resp : resp.approvals || resp.pending || [];
      renderApprovals();
    } catch (err) {
      showError("Failed to fetch approvals: " + err.message);
    }
  }

  async function decideApproval(approvalId, decision, approveBtn, denyBtn) {
    if (!approvalId) return;
    approveBtn.disabled = true;
    denyBtn.disabled = true;
    clearError();
    try {
      await apiFetch("/api/approvals/" + encodeURIComponent(approvalId) + "/decide", {
        method: "POST",
        body: { decision: decision },
      });
      await fetchApprovals();
      if (state.selectedWindowId) {
        await captureSnapshot(state.selectedWindowId, false);
      }
    } catch (err) {
      approveBtn.disabled = false;
      denyBtn.disabled = false;
      showError("Approval decision failed: " + err.message);
    }
  }

  async function setExecutionMode(mode) {
    clearError();
    try {
      const res = await apiFetch("/api/mode", { method: "POST", body: { mode: mode } });
      setActiveModeUI(res.mode || mode);
    } catch (err) {
      showError("Mode switch failed: " + err.message);
    }
  }

  async function toggleEmergencyStop() {
    clearError();
    const targetUrl = state.emergencyStopped ? "/api/emergency-resume" : "/api/emergency-stop";
    try {
      const res = await apiFetch(targetUrl, { method: "POST", body: {} });
      const stopped =
        typeof res.emergency_stopped === "boolean"
          ? res.emergency_stopped
          : !state.emergencyStopped;
      setEmergencyStopUI(stopped);
    } catch (err) {
      showError("Emergency control failed: " + err.message);
    }
  }

  async function toggleOverlay() {
    clearError();
    try {
      const res = await apiFetch("/api/overlay/toggle", {
        method: "POST",
        body: { enabled: !state.overlayEnabled },
      });
      const next =
        typeof res.enabled === "boolean"
          ? res.enabled
          : typeof res.overlay_enabled === "boolean"
            ? res.overlay_enabled
            : !state.overlayEnabled;
      setOverlayUI(next);
    } catch (err) {
      showError("Overlay toggle failed: " + err.message);
    }
  }

  async function toggleRecording() {
    clearError();
    try {
      if (!state.recording) {
        await apiFetch("/api/macros/record/start", { method: "POST", body: {} });
        setRecordingUI(true);
      } else {
        const res = await apiFetch("/api/macros/record/stop", { method: "POST", body: {} });
        setRecordingUI(false);
        const yamlText = res.yaml || res.macro_yaml || "";
        if (yamlText) {
          dom.macroYamlEditor.value = yamlText;
          state.sampleLoaded = false;
          state.yamlEdited = true;
        }
      }
    } catch (err) {
      showError("Macro recording failed: " + err.message);
    }
  }

  async function loadSampleMacro() {
    clearError();
    try {
      const res = await apiFetch("/api/macros");
      const sampleYaml = res.sample_yaml || res.yaml || res.sample || "";
      if (sampleYaml) {
        dom.macroYamlEditor.value = sampleYaml;
        state.sampleLoaded = true;
        state.yamlEdited = false;
        dom.macroRunStatus.textContent = "Loaded sample_macro.yaml";
      } else {
        dom.macroRunStatus.textContent = "No bundled sample macro returned.";
      }
    } catch (err) {
      showError("Failed to load sample macro: " + err.message);
    }
  }

  async function replayMacro() {
    clearError();
    const yamlText = dom.macroYamlEditor.value.trim();
    const winQuery = dom.macroWindowQuery.value.trim() || null;
    const useSample = !yamlText || (state.sampleLoaded && !state.yamlEdited);

    dom.macroRunStatus.textContent = "Running macro…";
    dom.macroReplayBtn.disabled = true;
    clearNode(dom.macroResultsList);
    dom.macroResultsList.hidden = true;

    try {
      const res = await apiFetch("/api/macros/run", {
        method: "POST",
        body: {
          yaml: yamlText || null,
          use_sample: useSample,
          window_query: winQuery,
        },
      });
      const results = Array.isArray(res.results) ? res.results : Array.isArray(res.steps) ? res.steps : [];
      dom.macroRunStatus.textContent = res.summary || ("Completed " + results.length + " step(s)");
      if (results.length > 0) {
        dom.macroResultsList.hidden = false;
        for (let i = 0; i < results.length; i++) {
          const r = results[i];
          const row = makeEl("div", "feed-entry");
          const stepTitle = (r.action || "step") + " " + (r.ref || r.target_name || "");
          row.appendChild(makeEl("div", "mono-value", stepTitle + " -> " + (r.status || "ok")));
          if (r.message || r.reason) {
            row.appendChild(makeEl("div", "muted-note", r.message || r.reason));
          }
          dom.macroResultsList.appendChild(row);
        }
      }
      await fetchApprovals();
      if (state.selectedWindowId) {
        await captureSnapshot(state.selectedWindowId, false);
      }
    } catch (err) {
      dom.macroRunStatus.textContent = "Macro error: " + err.message;
    } finally {
      dom.macroReplayBtn.disabled = false;
    }
  }

  function downloadMacroYaml() {
    const content = dom.macroYamlEditor.value || "";
    const blob = new Blob([content], { type: "text/yaml;charset=utf-8" });
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.download = "a11ypilot-macro.yaml";
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    URL.revokeObjectURL(url);
  }

  async function fetchMcpConfig() {
    try {
      const res = await apiFetch("/api/mcp-config");
      const text =
        typeof res.json === "string"
          ? res.json
          : JSON.stringify(res.config || res, null, 2);
      state.mcpConfigText = text;
      dom.mcpConfigPre.textContent = text;
    } catch (err) {
      dom.mcpConfigPre.textContent = "Could not load MCP config: " + err.message;
    }
  }

  async function copyToClipboard(text, btn, defaultLabel) {
    if (!text) return;
    try {
      await navigator.clipboard.writeText(text);
      btn.textContent = "Copied";
      setTimeout(() => {
        btn.textContent = defaultLabel;
      }, 1400);
    } catch (_err) {
      showError("Clipboard write unavailable in this browser context.");
    }
  }

  function activateTab(tabId) {
    const tabs = dom.tabButtons;
    const panels = dom.tabPanels;
    for (let i = 0; i < tabs.length; i++) {
      const t = tabs[i];
      const active = t.id === tabId;
      t.classList.toggle("is-selected", active);
      t.setAttribute("aria-selected", String(active));
      t.setAttribute("tabindex", active ? "0" : "-1");
      const panelId = t.getAttribute("aria-controls");
      const panel = panels.find((p) => p.id === panelId);
      if (panel) panel.hidden = !active;
    }
  }

  function handleSsePayload(raw, fallbackType) {
    if (!raw) return;
    let payload;
    try {
      payload = JSON.parse(raw);
    } catch (_err) {
      payload = { type: fallbackType || "message", summary: String(raw) };
    }
    if (!payload.type && fallbackType) payload.type = fallbackType;

    appendFeedEvent(payload);

    if (payload.snapshot) {
      applySnapshot(payload.snapshot, { fit: false });
    }
    if (payload.approval) {
      const ap = payload.approval;
      const apId = ap.approval_id || ap.id;
      const idx = state.approvals.findIndex((x) => (x.approval_id || x.id) === apId);
      if (idx >= 0) {
        state.approvals[idx] = ap;
      } else {
        state.approvals.unshift(ap);
      }
      renderApprovals();
      if (String(payload.type || "").includes("requested")) {
        activateTab("tab-feed");
      }
    } else if (String(payload.type || "").includes("approval")) {
      fetchApprovals();
    }

    if (typeof payload.emergency_stopped === "boolean") {
      setEmergencyStopUI(payload.emergency_stopped);
    } else if (payload.type === "emergency_stop" || payload.type === "emergency_stopped") {
      setEmergencyStopUI(true);
    } else if (payload.type === "emergency_resume" || payload.type === "emergency_resumed") {
      setEmergencyStopUI(false);
    }

    if (payload.mode) {
      setActiveModeUI(payload.mode);
    }
    if (typeof payload.overlay_enabled === "boolean") {
      setOverlayUI(payload.overlay_enabled);
    }

    if (state.canvas && (payload.ref || payload.bounds)) {
      const target = payload.ref || payload.bounds;
      const evtType = String(payload.type || "").toLowerCase();
      const risk = String(payload.risk_level || "").toUpperCase();
      if (
        evtType.includes("blocked") ||
        evtType.includes("denied") ||
        evtType.includes("approval_requested") ||
        risk === "HIGH" ||
        risk === "CRITICAL"
      ) {
        state.canvas.triggerRipple(target, "danger");
      } else if (evtType.includes("executed") || evtType.includes("dry_run") || evtType.includes("preview")) {
        state.canvas.triggerRipple(
          target,
          evtType.includes("dry_run") || evtType.includes("preview") ? "warning" : "executed"
        );
      }
    }
  }

  function connectSse() {
    if (state.eventSource) {
      state.eventSource.close();
    }
    const es = new EventSource("/api/events");
    state.eventSource = es;

    es.onopen = () => {
      dom.streamBadge.textContent = "Stream: live";
      dom.streamBadge.className = "status-pill status-pill--emerald";
    };

    es.onerror = () => {
      dom.streamBadge.textContent = "Stream: reconnecting";
      dom.streamBadge.className = "status-pill status-pill--danger";
    };

    es.onmessage = (e) => {
      handleSsePayload(e.data, null);
    };

    const namedEvents = [
      "snapshot_captured",
      "snapshot",
      "action_executed",
      "action_blocked",
      "action_denied",
      "action_preview",
      "approval_requested",
      "approval_decided",
      "mode_changed",
      "emergency_stop",
      "emergency_stopped",
      "emergency_resume",
      "emergency_resumed",
      "overlay_toggled",
      "macro_started",
      "macro_step",
      "macro_finished",
      "macro_completed",
    ];
    for (let i = 0; i < namedEvents.length; i++) {
      const evtName = namedEvents[i];
      es.addEventListener(evtName, (e) => handleSsePayload(e.data, evtName));
    }
  }

  function cacheDom() {
    dom.backendBadge = byId("backend-badge");
    dom.streamBadge = byId("stream-badge");
    dom.savingsPill = byId("savings-pill");
    dom.modeButtons = Array.from(document.querySelectorAll(".mode-btn"));
    dom.emergencyToggleBtn = byId("emergency-toggle-btn");
    dom.emergencyBtnLabel = byId("emergency-btn-label");
    dom.emergencyBanner = byId("emergency-banner");
    dom.emergencyBannerResume = byId("emergency-banner-resume");
    dom.errorBanner = byId("error-banner");
    dom.errorBannerText = byId("error-banner-text");
    dom.errorBannerDismiss = byId("error-banner-dismiss");

    dom.overlayToggleBtn = byId("overlay-toggle-btn");
    dom.windowSelect = byId("window-select");
    dom.refreshSnapshotBtn = byId("refresh-snapshot-btn");
    dom.treeSearch = byId("tree-search");
    dom.clearSearchBtn = byId("clear-search-btn");
    dom.roleFilterButtons = Array.from(document.querySelectorAll(".filter-chip"));
    dom.treeCountLabel = byId("tree-count-label");
    dom.treeExpandAll = byId("tree-expand-all");
    dom.treeCollapseAll = byId("tree-collapse-all");
    dom.treeContainer = byId("tree-container");

    dom.stageWindowInfo = byId("stage-window-info");
    dom.zoomOutBtn = byId("zoom-out-btn");
    dom.zoomFitBtn = byId("zoom-fit-btn");
    dom.zoomInBtn = byId("zoom-in-btn");
    dom.xrayCanvas = byId("xray-canvas");
    dom.canvasTooltip = byId("canvas-tooltip");

    dom.selectedRefBadge = byId("selected-ref-badge");
    dom.selectedRoleBadge = byId("selected-role-badge");
    dom.selectedRiskBadge = byId("selected-risk-badge");
    dom.selectedNameVal = byId("selected-name-val");
    dom.selectedAutoVal = byId("selected-auto-val");
    dom.selectedBoundsVal = byId("selected-bounds-val");
    dom.selectedActionsVal = byId("selected-actions-val");

    dom.actClickBtn = byId("act-click-btn");
    dom.actFocusBtn = byId("act-focus-btn");
    dom.actToggleBtn = byId("act-toggle-btn");
    dom.actTypeInput = byId("act-type-input");
    dom.actClearCheckbox = byId("act-clear-checkbox");
    dom.actTypeBtn = byId("act-type-btn");
    dom.actSelectInput = byId("act-select-input");
    dom.actSelectBtn = byId("act-select-btn");
    dom.actResultStatus = byId("act-result-status");

    dom.approvalsCountPill = byId("approvals-count-pill");
    dom.tabButtons = Array.from(document.querySelectorAll('[role="tab"]'));
    dom.tabPanels = Array.from(document.querySelectorAll('[role="tabpanel"]'));

    dom.refreshApprovalsBtn = byId("refresh-approvals-btn");
    dom.approvalsList = byId("approvals-list");
    dom.clearFeedBtn = byId("clear-feed-btn");
    dom.eventFeed = byId("event-feed");

    dom.recordingBadge = byId("recording-badge");
    dom.macroRecordBtn = byId("macro-record-btn");
    dom.macroLoadSampleBtn = byId("macro-load-sample-btn");
    dom.macroDownloadBtn = byId("macro-download-btn");
    dom.macroWindowQuery = byId("macro-window-query");
    dom.macroYamlEditor = byId("macro-yaml-editor");
    dom.macroReplayBtn = byId("macro-replay-btn");
    dom.macroRunStatus = byId("macro-run-status");
    dom.macroResultsList = byId("macro-results-list");

    dom.economyCaptureMs = byId("economy-capture-ms");
    dom.a11yTokensVal = byId("a11y-tokens-val");
    dom.a11yTokensBar = byId("a11y-tokens-bar");
    dom.visionTokensVal = byId("vision-tokens-val");
    dom.visionTokensBar = byId("vision-tokens-bar");
    dom.statTokensSaved = byId("stat-tokens-saved");
    dom.statSavingsPct = byId("stat-savings-pct");
    dom.statPrunedNodes = byId("stat-pruned-nodes");
    dom.statInteractiveCount = byId("stat-interactive-count");
    dom.compactSnapshotPre = byId("compact-snapshot-pre");
    dom.copyCompactBtn = byId("copy-compact-btn");
    dom.refreshMcpBtn = byId("refresh-mcp-btn");
    dom.copyMcpBtn = byId("copy-mcp-btn");
    dom.mcpConfigPre = byId("mcp-config-pre");
  }

  function bindUiEvents() {
    dom.errorBannerDismiss.addEventListener("click", clearError);

    for (let i = 0; i < dom.modeButtons.length; i++) {
      const btn = dom.modeButtons[i];
      btn.addEventListener("click", () => setExecutionMode(btn.getAttribute("data-mode")));
    }

    dom.emergencyToggleBtn.addEventListener("click", toggleEmergencyStop);
    dom.emergencyBannerResume.addEventListener("click", toggleEmergencyStop);
    dom.overlayToggleBtn.addEventListener("click", toggleOverlay);

    dom.windowSelect.addEventListener("change", () => {
      state.selectedWindowId = dom.windowSelect.value;
      if (state.selectedWindowId) {
        captureSnapshot(state.selectedWindowId, true);
      }
    });

    dom.refreshSnapshotBtn.addEventListener("click", refreshWindowsAndSnapshot);

    dom.treeSearch.addEventListener("input", () => {
      state.searchQuery = dom.treeSearch.value;
      dom.clearSearchBtn.hidden = !state.searchQuery;
      renderTree();
    });

    dom.clearSearchBtn.addEventListener("click", () => {
      state.searchQuery = "";
      dom.treeSearch.value = "";
      dom.clearSearchBtn.hidden = true;
      renderTree();
    });

    for (let i = 0; i < dom.roleFilterButtons.length; i++) {
      const chip = dom.roleFilterButtons[i];
      chip.addEventListener("click", () => {
        state.filterRole = chip.getAttribute("data-role") || "all";
        for (let j = 0; j < dom.roleFilterButtons.length; j++) {
          const c = dom.roleFilterButtons[j];
          const active = c === chip;
          c.classList.toggle("is-active", active);
          c.setAttribute("aria-pressed", String(active));
        }
        renderTree();
      });
    }

    dom.treeExpandAll.addEventListener("click", () => {
      state.collapsedKeys.clear();
      renderTree();
    });

    dom.treeCollapseAll.addEventListener("click", () => {
      state.collapsedKeys.clear();
      if (state.snapshot && state.snapshot.root) {
        const markCollapsed = (n, depth) => {
          if (depth >= 1 && Array.isArray(n.children) && n.children.length > 0 && n._uiKey) {
            state.collapsedKeys.add(n._uiKey);
          }
          if (Array.isArray(n.children)) {
            for (let i = 0; i < n.children.length; i++) {
              markCollapsed(n.children[i], depth + 1);
            }
          }
        };
        markCollapsed(state.snapshot.root, 0);
      }
      renderTree();
    });

    dom.zoomInBtn.addEventListener("click", () => state.canvas && state.canvas.zoomBy(1.2));
    dom.zoomOutBtn.addEventListener("click", () => state.canvas && state.canvas.zoomBy(1 / 1.2));
    dom.zoomFitBtn.addEventListener("click", () => state.canvas && state.canvas.fitToWindow(true));

    dom.actClickBtn.addEventListener("click", () => triggerAction("click"));
    dom.actFocusBtn.addEventListener("click", () => triggerAction("focus"));
    dom.actToggleBtn.addEventListener("click", () => triggerAction("toggle"));
    dom.actTypeBtn.addEventListener("click", () => triggerAction("type"));
    dom.actSelectBtn.addEventListener("click", () => triggerAction("select"));
    dom.actTypeInput.addEventListener("keydown", (e) => {
      if (e.key === "Enter") {
        e.preventDefault();
        triggerAction("type");
      }
    });
    dom.actSelectInput.addEventListener("keydown", (e) => {
      if (e.key === "Enter") {
        e.preventDefault();
        triggerAction("select");
      }
    });

    for (let i = 0; i < dom.tabButtons.length; i++) {
      const tab = dom.tabButtons[i];
      tab.addEventListener("click", () => activateTab(tab.id));
      tab.addEventListener("keydown", (e) => {
        if (e.key !== "ArrowLeft" && e.key !== "ArrowRight") return;
        e.preventDefault();
        const dir = e.key === "ArrowRight" ? 1 : -1;
        const nextIdx = (i + dir + dom.tabButtons.length) % dom.tabButtons.length;
        const nextTab = dom.tabButtons[nextIdx];
        activateTab(nextTab.id);
        nextTab.focus();
      });
    }

    dom.refreshApprovalsBtn.addEventListener("click", fetchApprovals);
    dom.clearFeedBtn.addEventListener("click", () => {
      state.feedEvents = [];
      renderFeed();
    });

    dom.macroRecordBtn.addEventListener("click", toggleRecording);
    dom.macroLoadSampleBtn.addEventListener("click", loadSampleMacro);
    dom.macroDownloadBtn.addEventListener("click", downloadMacroYaml);
    dom.macroReplayBtn.addEventListener("click", replayMacro);
    dom.macroYamlEditor.addEventListener("input", () => {
      state.yamlEdited = true;
    });

    dom.copyCompactBtn.addEventListener("click", () =>
      copyToClipboard(state.compactText, dom.copyCompactBtn, "Copy text")
    );
    dom.copyMcpBtn.addEventListener("click", () =>
      copyToClipboard(state.mcpConfigText, dom.copyMcpBtn, "Copy JSON")
    );
    dom.refreshMcpBtn.addEventListener("click", fetchMcpConfig);

    document.addEventListener("keydown", (e) => {
      const activeTag = document.activeElement ? document.activeElement.tagName.toLowerCase() : "";
      const typing = activeTag === "input" || activeTag === "textarea" || activeTag === "select";
      if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === "k") {
        e.preventDefault();
        dom.treeSearch.focus();
        dom.treeSearch.select();
      } else if (!typing && e.key === "/") {
        e.preventDefault();
        dom.treeSearch.focus();
      } else if (e.key === "Escape" && document.activeElement === dom.treeSearch && dom.treeSearch.value) {
        state.searchQuery = "";
        dom.treeSearch.value = "";
        dom.clearSearchBtn.hidden = true;
        renderTree();
      }
    });
  }

  async function bootstrap() {
    cacheDom();
    if (window.A11yWireframeCanvas && dom.xrayCanvas) {
      state.canvas = new window.A11yWireframeCanvas(dom.xrayCanvas, dom.canvasTooltip, {
        onSelectRef: (ref) => selectElementRef(ref, { flyCanvas: false, scrollTree: true }),
      });
    }
    bindUiEvents();
    connectSse();
    setInterval(updateApprovalTimers, 250);

    try {
      const status = await apiFetch("/api/status");
      updateStatusUI(status);
    } catch (err) {
      dom.backendBadge.textContent = "Backend: offline";
      dom.backendBadge.className = "status-pill status-pill--danger";
      showError("Unable to reach /api/status: " + err.message);
    }

    await Promise.allSettled([
      refreshWindowsAndSnapshot(),
      fetchApprovals(),
      fetchMcpConfig(),
    ]);
  }

  document.addEventListener("DOMContentLoaded", bootstrap);
})();
