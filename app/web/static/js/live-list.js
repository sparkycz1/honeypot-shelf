// Keeps the honeypot list current without a reload. live-updates.js owns
// the fleet WebSocket (the page's `[data-live-fleet]` anchor) and turns
// each push into a `live-<kind>` event on document.body; this listens for
// the kinds the list shows — reachability and update availability — and
// quietly re-fetches this same page, swapping in its `#honeypot-results`
// block. The push never says which honeypot changed; the re-fetch is the
// ordinary, scope-checked page load.
//
// Keeps what the viewer is doing: ticked checkboxes (by value) and the
// "select all" box survive the swap, and the bulk-action bar outside the
// block is left alone. Bursts are coalesced (a bulk check finishes one
// honeypot at a time), a backgrounded tab refreshes once when it's shown
// again, and a viewer mid-way through something inside the list (focus in
// it) is waited for.
(() => {
  "use strict";

  const RESULTS_ID = "honeypot-results";
  if (!document.getElementById(RESULTS_ID)) return;

  const QUIET_MS = 1500; // wait this long after the last push of a burst
  const MIN_GAP_MS = 5000; // and never refresh more often than this
  let timer = null;
  let lastRefresh = 0;
  let pendingWhileHidden = false;
  let inFlight = false;

  function schedule(delay) {
    if (timer !== null) window.clearTimeout(timer);
    timer = window.setTimeout(() => {
      timer = null;
      refresh();
    }, delay);
  }

  function onChange() {
    if (document.visibilityState === "hidden") {
      pendingWhileHidden = true;
      return;
    }
    const sinceLast = Date.now() - lastRefresh;
    schedule(Math.max(QUIET_MS, MIN_GAP_MS - sinceLast));
  }

  async function refresh() {
    const current = document.getElementById(RESULTS_ID);
    if (!current || inFlight) return;
    const active = document.activeElement;
    if (active && active !== document.body && current.contains(active)) {
      schedule(QUIET_MS); // the viewer is using the list — try again shortly
      return;
    }
    inFlight = true;
    lastRefresh = Date.now();
    try {
      const response = await fetch(window.location.href, {
        credentials: "same-origin",
        headers: { Accept: "text/html" },
      });
      if (!response.ok || response.redirected) return; // logged out, say
      const doc = new DOMParser().parseFromString(await response.text(), "text/html");
      const fresh = doc.getElementById(RESULTS_ID);
      if (!fresh) return; // the list emptied or changed shape — leave it
      const ticked = new Set(
        [...current.querySelectorAll("input[type=checkbox][value]:checked")].map((box) => box.value),
      );
      const allTicked = [...current.querySelectorAll("input[data-select-all]:checked")].map(
        (box) => box.getAttribute("data-select-all"),
      );
      current.replaceChildren(...[...fresh.childNodes].map((node) => document.importNode(node, true)));
      for (const box of current.querySelectorAll("input[type=checkbox][value]")) {
        box.checked = ticked.has(box.value);
      }
      for (const name of allTicked) {
        const box = current.querySelector(`input[data-select-all="${name}"]`);
        if (box) box.checked = true;
      }
      // bulk-select.js reacts to "change" like any other tick.
      current.dispatchEvent(new Event("change", { bubbles: true }));
    } catch {
      // Network hiccup — the next push (or a reload) catches up.
    } finally {
      inFlight = false;
    }
  }

  for (const kind of ["live-status", "live-updates"]) {
    document.body.addEventListener(kind, onChange);
  }
  document.addEventListener("visibilitychange", () => {
    if (document.visibilityState === "visible" && pendingWhileHidden) {
      pendingWhileHidden = false;
      onChange();
    }
  });
})();
