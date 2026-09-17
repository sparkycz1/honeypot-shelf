// Pan/zoom for the Map page's world-map SVG (see map/index.html,
// partials/_map_content.html) — wheel to zoom, drag (mouse or touch) to
// pan, two-finger pinch to zoom on touch, and +/−/reset buttons for
// anyone on a device/input that doesn't do any of those comfortably.
// No library: this is small enough (one rectangle of state, kept in the
// SVG's own `viewBox`) that adding a mapping/gesture dependency for it
// would cost more than it saves, and this app's CSP allows no CDN
// script anyway.
//
// Deliberately manipulates `viewBox` itself rather than a CSS transform
// on an inner `<g>` — panning/zooming this way needs no separate
// "undo the transform for hit-testing" bookkeeping, and a `<title>`
// tooltip on each dot keeps working unchanged throughout.
(function () {
  "use strict";

  const MIN_SCALE = 1; // 1x = the base viewBox, i.e. "fully zoomed out"
  const MAX_SCALE = 10;
  const WHEEL_ZOOM_FACTOR = 1.25;
  const BUTTON_ZOOM_FACTOR = 1.5;
  const DOUBLE_CLICK_ZOOM_FACTOR = 1.8;

  function parseViewBox(value) {
    const parts = value.split(/\s+/).map(Number);
    return { x: parts[0], y: parts[1], w: parts[2], h: parts[3] };
  }

  function setUp(viewport) {
    if (viewport.dataset.mapZoomReady) return;
    viewport.dataset.mapZoomReady = "1";

    const svg = viewport.querySelector("[data-map-svg]");
    if (!svg) return;
    const base = parseViewBox(svg.dataset.baseViewbox || svg.getAttribute("viewBox"));
    const minW = base.w / MAX_SCALE;
    const maxW = base.w;
    let view = { x: base.x, y: base.y, w: base.w, h: base.h };

    // Event dots keep a constant *on-screen* radius as you zoom, instead
    // of growing right along with the viewBox — a fixed geometry `r`
    // would otherwise make a single-event dot balloon into something
    // bigger than a small country the more you zoom in, the opposite of
    // "more precise" (see app.services.geoip_display.dot_radius's own
    // docstring for the same reasoning from the server side). Each dot's
    // server-rendered radius (data-base-r) is for the *base* (1x) view;
    // scaling it by view.w/base.w exactly cancels out the viewBox zoom.
    const dots = svg.querySelectorAll(".world-map-dot");

    function apply() {
      svg.setAttribute("viewBox", `${view.x} ${view.y} ${view.w} ${view.h}`);
      const scale = view.w / base.w;
      dots.forEach((dot) => {
        const baseR = Number.parseFloat(dot.dataset.baseR);
        if (Number.isFinite(baseR)) dot.setAttribute("r", (baseR * scale).toFixed(3));
      });
    }

    function clientToUserSpace(clientX, clientY) {
      const rect = svg.getBoundingClientRect();
      if (rect.width === 0 || rect.height === 0) return { x: view.x, y: view.y };
      return {
        x: view.x + ((clientX - rect.left) / rect.width) * view.w,
        y: view.y + ((clientY - rect.top) / rect.height) * view.h,
      };
    }

    function clampView(next) {
      let { x, y, w, h } = next;
      w = Math.min(Math.max(w, minW), maxW);
      h = (w / base.w) * base.h;
      x = Math.min(Math.max(x, base.x), base.x + base.w - w);
      y = Math.min(Math.max(y, base.y), base.y + base.h - h);
      return { x, y, w, h };
    }

    function zoomAt(clientX, clientY, factor) {
      const focus = clientToUserSpace(clientX, clientY);
      const newW = view.w / factor;
      const newH = view.h / factor;
      const newX = focus.x - ((focus.x - view.x) / view.w) * newW;
      const newY = focus.y - ((focus.y - view.y) / view.h) * newH;
      view = clampView({ x: newX, y: newY, w: newW, h: newH });
      apply();
    }

    function panByClientDelta(deltaClientX, deltaClientY) {
      const rect = svg.getBoundingClientRect();
      if (rect.width === 0 || rect.height === 0) return;
      const dx = -(deltaClientX / rect.width) * view.w;
      const dy = -(deltaClientY / rect.height) * view.h;
      view = clampView({ x: view.x + dx, y: view.y + dy, w: view.w, h: view.h });
      apply();
    }

    function reset() {
      view = { x: base.x, y: base.y, w: base.w, h: base.h };
      apply();
    }

    svg.addEventListener(
      "wheel",
      (event) => {
        event.preventDefault();
        const factor = event.deltaY < 0 ? WHEEL_ZOOM_FACTOR : 1 / WHEEL_ZOOM_FACTOR;
        zoomAt(event.clientX, event.clientY, factor);
      },
      { passive: false },
    );

    svg.addEventListener("dblclick", (event) => {
      event.preventDefault();
      zoomAt(event.clientX, event.clientY, DOUBLE_CLICK_ZOOM_FACTOR);
    });

    // One code path for mouse drag, single-finger touch pan, and
    // two-finger pinch-zoom: every active contact point is tracked by
    // its own Pointer Events `pointerId`. One pointer down+move pans;
    // a second pointer joining mid-gesture switches to pinch-zoom
    // (zooming around the pair's midpoint, factor = new/old distance).
    const pointers = new Map();

    function midpoint() {
      const pts = [...pointers.values()];
      return {
        x: (pts[0].x + pts[1].x) / 2,
        y: (pts[0].y + pts[1].y) / 2,
      };
    }

    function distance() {
      const pts = [...pointers.values()];
      return Math.hypot(pts[0].x - pts[1].x, pts[0].y - pts[1].y);
    }

    svg.addEventListener("pointerdown", (event) => {
      svg.setPointerCapture(event.pointerId);
      pointers.set(event.pointerId, { x: event.clientX, y: event.clientY });
      viewport.classList.add("world-map-viewport-dragging");
    });

    svg.addEventListener("pointermove", (event) => {
      const previous = pointers.get(event.pointerId);
      if (!previous) return;
      const current = { x: event.clientX, y: event.clientY };

      if (pointers.size === 1) {
        panByClientDelta(current.x - previous.x, current.y - previous.y);
      } else if (pointers.size === 2) {
        const before = distance();
        pointers.set(event.pointerId, current);
        const after = distance();
        const mid = midpoint();
        if (before > 0) zoomAt(mid.x, mid.y, after / before);
        return;
      }
      pointers.set(event.pointerId, current);
    });

    function endPointer(event) {
      pointers.delete(event.pointerId);
      if (pointers.size === 0) viewport.classList.remove("world-map-viewport-dragging");
    }
    svg.addEventListener("pointerup", endPointer);
    svg.addEventListener("pointercancel", endPointer);
    svg.addEventListener("pointerleave", (event) => {
      // Only a mouse actually "leaves" mid-drag (a lifted finger fires
      // pointerup/cancel first) — dropping the pointer here too means an
      // accidental drag off the map edge doesn't get stuck panning
      // forever with no pointerup to end it.
      if (event.pointerType === "mouse") endPointer(event);
    });

    const zoomInButton = viewport.querySelector("[data-map-zoom-in]");
    const zoomOutButton = viewport.querySelector("[data-map-zoom-out]");
    const resetButton = viewport.querySelector("[data-map-zoom-reset]");
    const center = () => {
      const rect = svg.getBoundingClientRect();
      return { x: rect.left + rect.width / 2, y: rect.top + rect.height / 2 };
    };
    zoomInButton?.addEventListener("click", () => {
      const c = center();
      zoomAt(c.x, c.y, BUTTON_ZOOM_FACTOR);
    });
    zoomOutButton?.addEventListener("click", () => {
      const c = center();
      zoomAt(c.x, c.y, 1 / BUTTON_ZOOM_FACTOR);
    });
    resetButton?.addEventListener("click", reset);
  }

  document.querySelectorAll("[data-map-viewport]").forEach(setUp);

  // Same reasoning as monitoring-chart.js's own htmx:afterSwap listener —
  // the Map page's live-refresh (map/index.html, data-live-fleet) swaps
  // this whole panel's DOM on every push/poll, so a freshly inserted
  // viewport needs setUp re-run on it, and MIN_SCALE=1 means resetting
  // to the base viewBox on every refresh (rather than trying to preserve
  // whatever the viewer had zoomed to) is an acceptable, simple choice —
  // the same one the Dashboard/Audit log's own live-refreshed tables
  // already make by fully re-rendering on every push.
  document.body.addEventListener("htmx:afterSwap", (event) => {
    const target = event.target;
    if (!(target instanceof Element)) return;
    target.querySelectorAll("[data-map-viewport]").forEach(setUp);
  });
})();
