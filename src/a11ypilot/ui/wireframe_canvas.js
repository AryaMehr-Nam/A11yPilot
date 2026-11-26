(function () {
  "use strict";

  function readCssTokens() {
    const style = getComputedStyle(document.documentElement);
    const get = (name, fallback) => {
      const val = style.getPropertyValue(name);
      return val ? val.trim() : fallback;
    };
    return {
      canvas: get("--color-canvas", "#070b14"),
      surface1: get("--color-paper-1", "#0b101d"),
      surface2: get("--color-paper-2", "#111829"),
      surfaceGlassStrong: get("--color-surface-glass-strong", "rgba(14, 20, 34, 0.94)"),
      ink: get("--color-ink", "#eef2f7"),
      inkMuted: get("--color-ink-muted", "#9aa8bd"),
      hairline: get("--color-hairline", "rgba(148, 163, 184, 0.16)"),
      hairlineStrong: get("--color-hairline-strong", "rgba(148, 163, 184, 0.30)"),
      wireMuted: get("--color-wire-muted", "rgba(148, 163, 184, 0.34)"),
      gridMinor: get("--color-grid-minor", "rgba(148, 163, 184, 0.06)"),
      gridMajor: get("--color-grid-major", "rgba(148, 163, 184, 0.12)"),
      accent: get("--color-accent", "#22d3ee"),
      button: get("--color-role-button", "#22d3ee"),
      input: get("--color-role-input", "#a855f7"),
      toggle: get("--color-role-toggle", "#34d399"),
      password: get("--color-role-password", "#fbbf24"),
      danger: get("--color-role-danger", "#fb7185"),
      fontSans: get("--font-sans", "sans-serif"),
      fontMono: get("--font-mono", "monospace"),
    };
  }

  function isHighRisk(node) {
    const risk = String(node.risk_level || "").toUpperCase();
    return risk === "HIGH" || risk === "CRITICAL";
  }

  function roleGroup(node) {
    if (isHighRisk(node)) return "danger";
    if (node.is_password || node.role === "password") return "password";
    if (node.role === "text_input" || node.role === "combobox") return "input";
    if (node.role === "checkbox" || node.role === "radio" || node.role === "tab") return "toggle";
    if (node.role === "button" || node.role === "menu_item" || node.role === "link") return "button";
    return "muted";
  }

  function roleColor(node, tokens) {
    const group = roleGroup(node);
    if (group === "danger") return tokens.danger;
    if (group === "password") return tokens.password;
    if (group === "input") return tokens.input;
    if (group === "toggle") return tokens.toggle;
    if (group === "button") return tokens.button;
    return tokens.wireMuted;
  }

  function collectRenderList(node, depth, out) {
    if (!node) return;
    const b = node.bounds || { x: 0, y: 0, width: 0, height: 0 };
    if (b.width > 0 && b.height > 0) {
      out.push({ node, depth, bounds: b });
    }
    const children = Array.isArray(node.children) ? node.children : [];
    for (let i = 0; i < children.length; i++) {
      collectRenderList(children[i], depth + 1, out);
    }
  }

  class WireframeCanvas {
    constructor(canvas, tooltipEl, callbacks) {
      this.canvas = canvas;
      this.ctx = canvas.getContext("2d");
      this.tooltipEl = tooltipEl;
      this.callbacks = callbacks || {};
      this.tokens = readCssTokens();
      this.snapshot = null;
      this.items = [];
      this.refToItem = new Map();
      this.selectedRef = null;
      this.hoveredRef = null;
      this.hoveredItem = null;
      this.filterRole = "all";
      this.searchMatches = null;
      this.ripples = [];

      this.view = { x: 0, y: 0, scale: 1 };
      this.targetView = null;
      this.velocity = { x: 0, y: 0 };
      this.dragging = false;
      this.dragMoved = false;
      this.pointerDownPos = { x: 0, y: 0 };
      this.lastPointerPos = { x: 0, y: 0 };
      this.width = 640;
      this.height = 420;
      this.dpr = window.devicePixelRatio || 1;
      this.lastFrameTime = performance.now();
      this.rafId = null;
      this.motionQuery = window.matchMedia("(prefers-reduced-motion: reduce)");

      this.buildTooltipElements();
      this.bindEvents();
      this.observeResize();
      this.startLoop();
    }

    buildTooltipElements() {
      if (!this.tooltipEl) return;
      while (this.tooltipEl.firstChild) {
        this.tooltipEl.removeChild(this.tooltipEl.firstChild);
      }
      this.ttHead = document.createElement("div");
      this.ttHead.className = "mono-value";
      this.ttName = document.createElement("div");
      this.ttMeta = document.createElement("div");
      this.ttMeta.className = "muted-note mono-value";
      this.tooltipEl.appendChild(this.ttHead);
      this.tooltipEl.appendChild(this.ttName);
      this.tooltipEl.appendChild(this.ttMeta);
    }

    prefersReducedMotion() {
      return Boolean(this.motionQuery && this.motionQuery.matches);
    }

    observeResize() {
      const parent = this.canvas.parentElement || this.canvas;
      this.resizeObserver = new ResizeObserver((entries) => {
        for (const entry of entries) {
          const rect = entry.contentRect;
          this.resize(rect.width, rect.height);
        }
      });
      this.resizeObserver.observe(parent);
      const rect = parent.getBoundingClientRect();
      this.resize(rect.width || 640, rect.height || 420);
    }

    resize(width, height) {
      if (width <= 0 || height <= 0) return;
      const hadSize = this.width > 0 && this.height > 0;
      const prevW = this.width;
      const prevH = this.height;
      this.width = width;
      this.height = height;
      this.dpr = window.devicePixelRatio || 1;
      this.canvas.width = Math.round(width * this.dpr);
      this.canvas.height = Math.round(height * this.dpr);
      this.tokens = readCssTokens();
      if (hadSize && this.snapshot) {
        this.view.x += (width - prevW) * 0.5;
        this.view.y += (height - prevH) * 0.5;
      }
    }

    bindEvents() {
      this._onWheel = (e) => {
        e.preventDefault();
        const rect = this.canvas.getBoundingClientRect();
        const px = e.clientX - rect.left;
        const py = e.clientY - rect.top;
        const factor = e.deltaY < 0 ? 1.12 : 1 / 1.12;
        this.zoomAt(px, py, factor);
      };

      this._onPointerDown = (e) => {
        if (e.button !== 0) return;
        this.dragging = true;
        this.dragMoved = false;
        this.targetView = null;
        this.velocity.x = 0;
        this.velocity.y = 0;
        this.pointerDownPos = { x: e.clientX, y: e.clientY };
        this.lastPointerPos = { x: e.clientX, y: e.clientY };
        if (this.canvas.setPointerCapture) {
          try {
            this.canvas.setPointerCapture(e.pointerId);
          } catch (_err) {
            // ignore pointer capture failure
          }
        }
      };

      this._onPointerMove = (e) => {
        const rect = this.canvas.getBoundingClientRect();
        const localX = e.clientX - rect.left;
        const localY = e.clientY - rect.top;

        if (this.dragging) {
          const dx = e.clientX - this.lastPointerPos.x;
          const dy = e.clientY - this.lastPointerPos.y;
          const totalDist = Math.hypot(
            e.clientX - this.pointerDownPos.x,
            e.clientY - this.pointerDownPos.y
          );
          if (totalDist > 4) {
            this.dragMoved = true;
          }
          this.view.x += dx;
          this.view.y += dy;
          this.velocity.x = dx * 0.85;
          this.velocity.y = dy * 0.85;
          this.lastPointerPos = { x: e.clientX, y: e.clientY };
          this.hideTooltip();
          return;
        }

        const hit = this.hitTest(localX, localY);
        this.hoveredItem = hit;
        this.hoveredRef = hit && hit.node.ref ? hit.node.ref : null;
        this.canvas.style.cursor = hit ? "pointer" : "grab";
        if (hit) {
          this.showTooltip(hit.node, e.clientX, e.clientY);
        } else {
          this.hideTooltip();
        }
      };

      this._onPointerUp = (e) => {
        if (!this.dragging) return;
        this.dragging = false;
        if (this.canvas.releasePointerCapture) {
          try {
            this.canvas.releasePointerCapture(e.pointerId);
          } catch (_err) {
            // ignore
          }
        }
        if (!this.dragMoved) {
          const rect = this.canvas.getBoundingClientRect();
          const hit = this.hitTest(e.clientX - rect.left, e.clientY - rect.top);
          if (hit && hit.node.ref) {
            this.selectRef(hit.node.ref, { fly: false });
            if (typeof this.callbacks.onSelectRef === "function") {
              this.callbacks.onSelectRef(hit.node.ref, hit.node);
            }
          }
        }
      };

      this._onDoubleClick = (e) => {
        const rect = this.canvas.getBoundingClientRect();
        const hit = this.hitTest(e.clientX - rect.left, e.clientY - rect.top);
        if (hit) {
          this.flyTo(hit.bounds);
        } else {
          this.fitToWindow(true);
        }
      };

      this._onPointerLeave = () => {
        this.hoveredItem = null;
        this.hoveredRef = null;
        this.hideTooltip();
      };

      this._onKeyDown = (e) => {
        if (e.key === "+" || e.key === "=") {
          e.preventDefault();
          this.zoomBy(1.2);
        } else if (e.key === "-") {
          e.preventDefault();
          this.zoomBy(1 / 1.2);
        } else if (e.key === "0" || e.key === "f" || e.key === "F") {
          e.preventDefault();
          this.fitToWindow(true);
        } else if (e.key === "ArrowLeft") {
          e.preventDefault();
          this.view.x += 40;
        } else if (e.key === "ArrowRight") {
          e.preventDefault();
          this.view.x -= 40;
        } else if (e.key === "ArrowUp") {
          e.preventDefault();
          this.view.y += 40;
        } else if (e.key === "ArrowDown") {
          e.preventDefault();
          this.view.y -= 40;
        }
      };

      this.canvas.addEventListener("wheel", this._onWheel, { passive: false });
      this.canvas.addEventListener("pointerdown", this._onPointerDown);
      this.canvas.addEventListener("pointermove", this._onPointerMove);
      window.addEventListener("pointerup", this._onPointerUp);
      this.canvas.addEventListener("dblclick", this._onDoubleClick);
      this.canvas.addEventListener("pointerleave", this._onPointerLeave);
      this.canvas.addEventListener("keydown", this._onKeyDown);
    }

    showTooltip(node, clientX, clientY) {
      if (!this.tooltipEl) return;
      const refText = node.ref ? node.ref : "container";
      const risk = node.risk_level ? " [" + String(node.risk_level).toLowerCase() + "]" : "";
      this.ttHead.textContent = refText + " (" + (node.role || "unknown") + ")" + risk;
      this.ttName.textContent = node.name || node.automation_id || "Unnamed node";
      const b = node.bounds || { x: 0, y: 0, width: 0, height: 0 };
      this.ttMeta.textContent = b.x + "," + b.y + " " + b.width + "x" + b.height;
      this.tooltipEl.hidden = false;
      const offsetX = Math.min(clientX + 14, window.innerWidth - 290);
      const offsetY = Math.min(clientY + 14, window.innerHeight - 90);
      this.tooltipEl.style.transform =
        "translate3d(" + Math.round(offsetX) + "px, " + Math.round(offsetY) + "px, 0)";
    }

    hideTooltip() {
      if (this.tooltipEl) {
        this.tooltipEl.hidden = true;
      }
    }

    getWorldFrame() {
      if (this.snapshot && this.snapshot.window && this.snapshot.window.bounds) {
        const wb = this.snapshot.window.bounds;
        if (wb.width > 0 && wb.height > 0) return wb;
      }
      if (this.items.length > 0) {
        let minX = Infinity;
        let minY = Infinity;
        let maxX = -Infinity;
        let maxY = -Infinity;
        for (const it of this.items) {
          minX = Math.min(minX, it.bounds.x);
          minY = Math.min(minY, it.bounds.y);
          maxX = Math.max(maxX, it.bounds.x + it.bounds.width);
          maxY = Math.max(maxY, it.bounds.y + it.bounds.height);
        }
        if (Number.isFinite(minX) && maxX > minX && maxY > minY) {
          return { x: minX, y: minY, width: maxX - minX, height: maxY - minY };
        }
      }
      return { x: 0, y: 0, width: 800, height: 600 };
    }

    setSnapshot(snapshot, options) {
      const opts = options || {};
      const prevWindowId = this.snapshot && this.snapshot.window ? this.snapshot.window.window_id : null;
      const nextWindowId = snapshot && snapshot.window ? snapshot.window.window_id : null;
      this.snapshot = snapshot || null;
      this.items = [];
      this.refToItem.clear();

      if (this.snapshot && this.snapshot.root) {
        collectRenderList(this.snapshot.root, 0, this.items);
        for (const it of this.items) {
          if (it.node.ref) {
            this.refToItem.set(it.node.ref, it);
          }
        }
      }

      if (opts.fit || prevWindowId !== nextWindowId) {
        this.fitToWindow(false);
      }
    }

    setFilters(filterRole, searchMatches) {
      this.filterRole = filterRole || "all";
      this.searchMatches = searchMatches || null;
    }

    selectRef(ref, options) {
      this.selectedRef = ref || null;
      const opts = options || {};
      if (opts.fly && ref && this.refToItem.has(ref)) {
        this.flyTo(this.refToItem.get(ref).bounds);
      }
    }

    zoomAt(screenX, screenY, factor) {
      this.targetView = null;
      const nextScale = Math.max(0.15, Math.min(8, this.view.scale * factor));
      const ratio = nextScale / this.view.scale;
      this.view.x = screenX - (screenX - this.view.x) * ratio;
      this.view.y = screenY - (screenY - this.view.y) * ratio;
      this.view.scale = nextScale;
    }

    zoomBy(factor) {
      this.zoomAt(this.width * 0.5, this.height * 0.5, factor);
    }

    fitToWindow(animate) {
      const frame = this.getWorldFrame();
      const pad = 44;
      const availW = Math.max(80, this.width - pad * 2);
      const availH = Math.max(80, this.height - pad * 2);
      const targetScale = Math.max(
        0.15,
        Math.min(2.5, Math.min(availW / Math.max(1, frame.width), availH / Math.max(1, frame.height)))
      );
      const centerX = frame.x + frame.width * 0.5;
      const centerY = frame.y + frame.height * 0.5;
      const targetX = this.width * 0.5 - centerX * targetScale;
      const targetY = this.height * 0.5 - centerY * targetScale;

      this.velocity.x = 0;
      this.velocity.y = 0;
      if (!animate || this.prefersReducedMotion()) {
        this.view = { x: targetX, y: targetY, scale: targetScale };
        this.targetView = null;
      } else {
        this.targetView = { x: targetX, y: targetY, scale: targetScale };
      }
    }

    flyTo(bounds) {
      if (!bounds || bounds.width <= 0 || bounds.height <= 0) return;
      const frame = this.getWorldFrame();
      const maxFocusScale = Math.min(
        3.2,
        Math.max(
          0.6,
          Math.min((this.width * 0.55) / bounds.width, (this.height * 0.55) / bounds.height)
        )
      );
      const minComfortScale = Math.max(
        0.4,
        Math.min(this.width / Math.max(1, frame.width), this.height / Math.max(1, frame.height)) * 1.15
      );
      const targetScale = Math.max(minComfortScale, Math.min(2.6, maxFocusScale));
      const cx = bounds.x + bounds.width * 0.5;
      const cy = bounds.y + bounds.height * 0.5;
      const targetX = this.width * 0.5 - cx * targetScale;
      const targetY = this.height * 0.5 - cy * targetScale;

      this.velocity.x = 0;
      this.velocity.y = 0;
      if (this.prefersReducedMotion()) {
        this.view = { x: targetX, y: targetY, scale: targetScale };
        this.targetView = null;
      } else {
        this.targetView = { x: targetX, y: targetY, scale: targetScale };
      }
    }

    triggerRipple(refOrBounds, kind) {
      let bounds = null;
      if (typeof refOrBounds === "string") {
        const item = this.refToItem.get(refOrBounds);
        if (item) bounds = item.bounds;
      } else if (refOrBounds && typeof refOrBounds === "object") {
        bounds = refOrBounds;
      }
      if (!bounds) return;
      const cx = bounds.x + bounds.width * 0.5;
      const cy = bounds.y + bounds.height * 0.5;
      const baseRadius = Math.max(24, Math.hypot(bounds.width, bounds.height) * 0.45);
      const color =
        kind === "danger" || kind === "blocked" || kind === "denied"
          ? this.tokens.danger
          : kind === "warning"
            ? this.tokens.password
            : this.tokens.button;

      const now = performance.now();
      this.ripples.push({ cx, cy, maxRadius: baseRadius + 90, color, start: now, duration: 900 });
      if (!this.prefersReducedMotion()) {
        this.ripples.push({
          cx,
          cy,
          maxRadius: baseRadius + 135,
          color,
          start: now + 140,
          duration: 950,
        });
      }
    }

    hitTest(screenX, screenY) {
      const worldX = (screenX - this.view.x) / this.view.scale;
      const worldY = (screenY - this.view.y) / this.view.scale;
      let fallback = null;
      for (let i = this.items.length - 1; i >= 0; i--) {
        const it = this.items[i];
        const b = it.bounds;
        if (worldX >= b.x && worldX <= b.x + b.width && worldY >= b.y && worldY <= b.y + b.height) {
          if (it.node.ref) return it;
          if (!fallback) fallback = it;
        }
      }
      return fallback;
    }

    nodeMatchesFilter(node) {
      if (this.searchMatches && node.ref && !this.searchMatches.has(node.ref)) {
        return false;
      }
      if (this.searchMatches && !node.ref) {
        return false;
      }
      if (this.filterRole === "all") return true;
      const group = roleGroup(node);
      if (this.filterRole === "risk") return isHighRisk(node);
      return group === this.filterRole;
    }

    startLoop() {
      const tick = (now) => {
        const dt = Math.min(0.05, (now - this.lastFrameTime) / 1000);
        this.lastFrameTime = now;
        this.updatePhysics(dt);
        this.draw(now);
        this.rafId = requestAnimationFrame(tick);
      };
      this.rafId = requestAnimationFrame(tick);
    }

    updatePhysics(dt) {
      if (this.targetView) {
        const k = 1 - Math.exp(-11 * dt);
        this.view.x += (this.targetView.x - this.view.x) * k;
        this.view.y += (this.targetView.y - this.view.y) * k;
        this.view.scale += (this.targetView.scale - this.view.scale) * k;
        const done =
          Math.abs(this.targetView.x - this.view.x) < 0.35 &&
          Math.abs(this.targetView.y - this.view.y) < 0.35 &&
          Math.abs(this.targetView.scale - this.view.scale) < 0.002;
        if (done) {
          this.view = { ...this.targetView };
          this.targetView = null;
        }
      } else if (!this.dragging && (Math.abs(this.velocity.x) > 0.1 || Math.abs(this.velocity.y) > 0.1)) {
        this.view.x += this.velocity.x;
        this.view.y += this.velocity.y;
        const damp = Math.exp(-9 * dt);
        this.velocity.x *= damp;
        this.velocity.y *= damp;
      }
    }

    draw(now) {
      const ctx = this.ctx;
      if (!ctx) return;
      const t = this.tokens;

      ctx.setTransform(this.dpr, 0, 0, this.dpr, 0, 0);
      ctx.clearRect(0, 0, this.width, this.height);
      ctx.fillStyle = t.canvas;
      ctx.fillRect(0, 0, this.width, this.height);

      this.drawBlueprintGrid(ctx, t);

      if (!this.snapshot || this.items.length === 0) {
        ctx.fillStyle = t.inkMuted;
        ctx.font = "13px " + t.fontSans;
        ctx.textAlign = "center";
        ctx.textBaseline = "middle";
        ctx.fillText("Select a window or click Refresh to inspect accessibility bounds", this.width * 0.5, this.height * 0.5);
        return;
      }

      ctx.save();
      ctx.translate(this.view.x, this.view.y);
      ctx.scale(this.view.scale, this.view.scale);

      const frame = this.getWorldFrame();
      this.drawWindowBackdrop(ctx, frame, t);

      const badgeItems = [];
      for (let i = 0; i < this.items.length; i++) {
        const it = this.items[i];
        this.drawNode(ctx, it, t);
        if (it.node.ref) {
          badgeItems.push(it);
        }
      }

      this.drawCornerBadges(ctx, badgeItems, t);
      this.drawRipples(ctx, now);
      ctx.restore();
    }

    drawBlueprintGrid(ctx, t) {
      const minorStep = 24 * this.view.scale;
      const showMinor = minorStep >= 10;
      const majorStep = 120 * this.view.scale;

      if (showMinor) {
        ctx.beginPath();
        ctx.strokeStyle = t.gridMinor;
        ctx.lineWidth = 1;
        const startX = ((this.view.x % minorStep) + minorStep) % minorStep;
        const startY = ((this.view.y % minorStep) + minorStep) % minorStep;
        for (let x = startX; x < this.width; x += minorStep) {
          ctx.moveTo(x + 0.5, 0);
          ctx.lineTo(x + 0.5, this.height);
        }
        for (let y = startY; y < this.height; y += minorStep) {
          ctx.moveTo(0, y + 0.5);
          ctx.lineTo(this.width, y + 0.5);
        }
        ctx.stroke();
      }

      if (majorStep >= 18) {
        ctx.beginPath();
        ctx.strokeStyle = t.gridMajor;
        ctx.lineWidth = 1;
        const startX = ((this.view.x % majorStep) + majorStep) % majorStep;
        const startY = ((this.view.y % majorStep) + majorStep) % majorStep;
        for (let x = startX; x < this.width; x += majorStep) {
          ctx.moveTo(x + 0.5, 0);
          ctx.lineTo(x + 0.5, this.height);
        }
        for (let y = startY; y < this.height; y += majorStep) {
          ctx.moveTo(0, y + 0.5);
          ctx.lineTo(this.width, y + 0.5);
        }
        ctx.stroke();
      }
    }

    drawWindowBackdrop(ctx, frame, t) {
      ctx.save();
      ctx.fillStyle = t.surface1;
      ctx.strokeStyle = t.hairlineStrong;
      ctx.lineWidth = 1.5 / this.view.scale;
      ctx.fillRect(frame.x, frame.y, frame.width, frame.height);
      ctx.strokeRect(frame.x, frame.y, frame.width, frame.height);

      const labelH = Math.min(26 / this.view.scale, Math.max(18, frame.height * 0.08));
      ctx.fillStyle = t.surface2;
      ctx.fillRect(frame.x, frame.y - labelH, frame.width, labelH);
      ctx.strokeRect(frame.x, frame.y - labelH, frame.width, labelH);

      ctx.fillStyle = t.inkMuted;
      ctx.font = (11 / this.view.scale) + "px " + t.fontMono;
      ctx.textAlign = "left";
      ctx.textBaseline = "middle";
      const winTitle = this.snapshot.window ? this.snapshot.window.title : "Window";
      const dims = frame.width + "x" + frame.height;
      ctx.fillText(winTitle + "  [" + dims + "]", frame.x + 8 / this.view.scale, frame.y - labelH * 0.5);
      ctx.restore();
    }

    drawNode(ctx, item, t) {
      const node = item.node;
      const b = item.bounds;
      const color = roleColor(node, t);
      const isSelected = Boolean(this.selectedRef && node.ref === this.selectedRef);
      const isHovered = Boolean(this.hoveredRef && node.ref === this.hoveredRef);
      const matchesFilter = this.nodeMatchesFilter(node);
      const activeFiltering = this.filterRole !== "all" || Boolean(this.searchMatches);

      ctx.save();
      let alpha = 1;
      if (node.enabled === false || node.offscreen === true) {
        alpha *= 0.45;
      }
      if (activeFiltering && node.ref && !matchesFilter && !isSelected) {
        alpha *= 0.22;
      }
      ctx.globalAlpha = alpha;

      if (node.ref || isSelected || isHovered) {
        ctx.fillStyle = color;
        ctx.globalAlpha = alpha * (isSelected ? 0.18 : isHovered ? 0.13 : 0.06);
        ctx.fillRect(b.x, b.y, b.width, b.height);
        ctx.globalAlpha = alpha;
      }

      if (node.enabled === false) {
        ctx.setLineDash([4 / this.view.scale, 3 / this.view.scale]);
      }

      ctx.strokeStyle = isSelected ? t.ink : color;
      ctx.lineWidth = (isSelected ? 2.2 : isHovered ? 1.8 : node.ref ? 1.2 : 0.75) / this.view.scale;
      ctx.strokeRect(b.x, b.y, b.width, b.height);

      if (isSelected) {
        this.drawSelectionReticle(ctx, b, color);
      }

      const screenW = b.width * this.view.scale;
      const screenH = b.height * this.view.scale;
      if (screenW >= 54 && screenH >= 18 && (node.name || node.value)) {
        const label = node.is_password || node.role === "password"
          ? "[REDACTED:PASSWORD]"
          : (node.name || node.value || "");
        if (label) {
          ctx.save();
          ctx.beginPath();
          ctx.rect(b.x + 3 / this.view.scale, b.y + 2 / this.view.scale, Math.max(0, b.width - 6 / this.view.scale), Math.max(0, b.height - 4 / this.view.scale));
          ctx.clip();
          ctx.fillStyle = isSelected ? t.ink : t.inkMuted;
          ctx.font = (11 / this.view.scale) + "px " + t.fontSans;
          ctx.textAlign = "left";
          ctx.textBaseline = "middle";
          ctx.fillText(label, b.x + 6 / this.view.scale, b.y + b.height * 0.5);
          ctx.restore();
        }
      }

      ctx.restore();
    }

    drawSelectionReticle(ctx, b, color) {
      const arm = Math.min(10 / this.view.scale, b.width * 0.28, b.height * 0.28);
      const pad = 3 / this.view.scale;
      const x1 = b.x - pad;
      const y1 = b.y - pad;
      const x2 = b.x + b.width + pad;
      const y2 = b.y + b.height + pad;
      ctx.save();
      ctx.setLineDash([]);
      ctx.strokeStyle = color;
      ctx.lineWidth = 2.2 / this.view.scale;
      ctx.beginPath();
      ctx.moveTo(x1, y1 + arm); ctx.lineTo(x1, y1); ctx.lineTo(x1 + arm, y1);
      ctx.moveTo(x2 - arm, y1); ctx.lineTo(x2, y1); ctx.lineTo(x2, y1 + arm);
      ctx.moveTo(x1, y2 - arm); ctx.lineTo(x1, y2); ctx.lineTo(x1 + arm, y2);
      ctx.moveTo(x2 - arm, y2); ctx.lineTo(x2, y2); ctx.lineTo(x2, y2 - arm);
      ctx.stroke();
      ctx.restore();
    }

    drawCornerBadges(ctx, badgeItems, t) {
      const activeFiltering = this.filterRole !== "all" || Boolean(this.searchMatches);
      ctx.save();
      const fontSize = 10 / this.view.scale;
      ctx.font = "600 " + fontSize + "px " + t.fontMono;
      ctx.textAlign = "left";
      ctx.textBaseline = "middle";

      for (let i = 0; i < badgeItems.length; i++) {
        const it = badgeItems[i];
        const node = it.node;
        const b = it.bounds;
        const isSelected = node.ref === this.selectedRef;
        const isHovered = node.ref === this.hoveredRef;
        if (!isSelected && !isHovered && b.width * this.view.scale < 22) continue;

        const matchesFilter = this.nodeMatchesFilter(node);
        ctx.globalAlpha = activeFiltering && !matchesFilter && !isSelected ? 0.25 : 1;

        const color = roleColor(node, t);
        const text = node.ref;
        const padX = 4 / this.view.scale;
        const badgeH = 14 / this.view.scale;
        const badgeW = ctx.measureText(text).width + padX * 2;
        const bx = b.x;
        const by = b.y - badgeH * 0.55;

        ctx.fillStyle = isSelected ? color : t.surfaceGlassStrong;
        ctx.strokeStyle = color;
        ctx.lineWidth = 1 / this.view.scale;
        ctx.fillRect(bx, by, badgeW, badgeH);
        ctx.strokeRect(bx, by, badgeW, badgeH);

        ctx.fillStyle = isSelected ? t.canvas : color;
        ctx.fillText(text, bx + padX, by + badgeH * 0.52);
      }
      ctx.restore();
    }

    drawRipples(ctx, now) {
      if (this.ripples.length === 0) return;
      const alive = [];
      for (let i = 0; i < this.ripples.length; i++) {
        const rp = this.ripples[i];
        const elapsed = now - rp.start;
        if (elapsed < 0) {
          alive.push(rp);
          continue;
        }
        if (elapsed >= rp.duration) continue;
        alive.push(rp);
        const p = elapsed / rp.duration;
        const eased = 1 - Math.pow(1 - p, 3);
        const radius = 8 / this.view.scale + rp.maxRadius * eased;
        ctx.save();
        ctx.strokeStyle = rp.color;
        ctx.globalAlpha = Math.max(0, 0.85 * (1 - p));
        ctx.lineWidth = (2.5 * (1 - p * 0.5)) / this.view.scale;
        ctx.beginPath();
        ctx.arc(rp.cx, rp.cy, radius, 0, Math.PI * 2);
        ctx.stroke();
        ctx.restore();
      }
      this.ripples = alive;
    }

    destroy() {
      if (this.rafId !== null) {
        cancelAnimationFrame(this.rafId);
      }
      if (this.resizeObserver) {
        this.resizeObserver.disconnect();
      }
      this.canvas.removeEventListener("wheel", this._onWheel);
      this.canvas.removeEventListener("pointerdown", this._onPointerDown);
      this.canvas.removeEventListener("pointermove", this._onPointerMove);
      window.removeEventListener("pointerup", this._onPointerUp);
      this.canvas.removeEventListener("dblclick", this._onDoubleClick);
      this.canvas.removeEventListener("pointerleave", this._onPointerLeave);
      this.canvas.removeEventListener("keydown", this._onKeyDown);
    }
  }

  window.A11yWireframeCanvas = WireframeCanvas;
})();
