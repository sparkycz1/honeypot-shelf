// "Something changed, go check" — the browser half of app/services/
// live_updates.py and app/web/routes/live_ws.py. Opens one reconnecting
// WebSocket per live-scoped anchor found on the page and turns each
// `{"kind": "..."}` message it receives into a plain DOM event
// (`live-<kind>`) dispatched on `document.body`. Every htmx panel that
// used to poll on a fixed interval now also listens for its matching
// event (`hx-trigger="every 60s, live-facts from:body"`, say) — the
// interval stays only as a fallback for a missed/dropped push, so panels
// update within roughly a second of a background job finishing instead
// of waiting out the old ~20s poll.
//
// Four independent anchors, each opening its own socket to its own route
// (a page sets at most one of these):
//   - `[data-live-honeypot-id]`  -> /honeypots/{id}/live/ws   (one honeypot's
//     Overview/Monitoring/Activity/Updates tabs — also offers the
//     backgrounded-tab browser-notification toggle, see below)
//   - `[data-live-fleet]`        -> /live/fleet/ws            (Dashboard, Map)
//   - `[data-live-admin]`        -> /live/admin/ws            (Audit log,
//     Companies list — superadmin only, same as those pages)
//   - `[data-live-notifications]`-> /live/notifications/ws    (a user's own
//     Notification history)
//
// No-ops entirely on a page with none of these anchors — nothing loads
// this unconditionally, each page opts in by including it.
//
// **Found live, previously undetected**: this whole script silently never
// worked — a debcontrol leftover looked for `[data-live-machine-id]` (this
// app's templates all set `data-live-honeypot-id` instead) and built the
// socket URL as `/machines/{id}/live/ws` (the real route, still, is
// `/honeypots/{id}/live/ws` — see app/web/routes/live_ws.py). The selector
// mismatch meant `anchor` was always null, so the whole file no-opped on
// every single page, on every load, since this app's first commit — no
// page's htmx panel ever received a push, everything ran on its polling
// fallback alone the whole time. Same class of bug as the `machine_ids`/
// `honeypot_ids` bulk-select mixup CLAUDE.md already documents elsewhere.
(() => {
  "use strict";

  const INITIAL_RETRY_MS = 1000;
  const MAX_RETRY_MS = 30000;

  // Opens `url`, dispatching `live-<kind>` on document.body for every
  // `{"kind": "..."}` text frame received, and reconnects with capped
  // exponential backoff on any close/error — forever, since these sockets
  // are meant to outlive the page. `onKind(kind)` is called for the same
  // message, for callers that need the raw kind too (the honeypot-scoped
  // connection's background-notification logic below); other callers pass
  // a no-op.
  function openLiveSocket(url, onKind) {
    let retryDelayMs = INITIAL_RETRY_MS;
    let retryTimer = null;

    function scheduleReconnect() {
      if (retryTimer !== null) return; // already scheduled
      retryTimer = window.setTimeout(() => {
        retryTimer = null;
        connect();
      }, retryDelayMs);
      retryDelayMs = Math.min(retryDelayMs * 2, MAX_RETRY_MS);
    }

    function handleMessage(event) {
      let payload;
      try {
        payload = JSON.parse(event.data);
      } catch {
        return; // not JSON — ignore rather than crash the socket handler
      }
      if (!payload || typeof payload.kind !== "string") return;
      document.body.dispatchEvent(new Event(`live-${payload.kind}`));
      onKind(payload.kind);
    }

    function connect() {
      let socket;
      try {
        socket = new WebSocket(url);
      } catch {
        scheduleReconnect();
        return;
      }
      socket.addEventListener("open", () => {
        retryDelayMs = INITIAL_RETRY_MS; // a successful connection resets backoff
      });
      socket.addEventListener("message", handleMessage);
      socket.addEventListener("close", scheduleReconnect);
      // A socket that errors also fires "close" right after — closing it
      // explicitly here just avoids waiting on the browser's own timeout.
      socket.addEventListener("error", () => socket.close());
    }

    connect();

    // A backgrounded tab's WebSocket can go stale (some browsers/proxies
    // silently drop long-idle connections without ever firing "close") —
    // reconnecting on visibility is cheap insurance, not a fix for anything
    // observed, and the server-side idle cap is the real backstop either way.
    document.addEventListener("visibilitychange", () => {
      if (document.visibilityState === "visible") {
        retryDelayMs = INITIAL_RETRY_MS;
      }
    });
  }

  const scheme = window.location.protocol === "https:" ? "wss" : "ws";
  const host = window.location.host;

  // --- Honeypot-scoped: Overview/Monitoring/Activity/Updates tabs -------

  const honeypotAnchor = document.querySelector("[data-live-honeypot-id]");
  if (honeypotAnchor) {
    const honeypotId = honeypotAnchor.getAttribute("data-live-honeypot-id");
    const honeypotName =
      honeypotAnchor.getAttribute("data-live-honeypot-name") || "This honeypot";
    const url = `${scheme}://${host}/honeypots/${encodeURIComponent(honeypotId)}/live/ws`;

    // --- Browser notifications, for the same event when this tab is
    // backgrounded (`document.visibilityState === "hidden"`) and the
    // viewer opted in via the toggle button this injects next to the page
    // heading. Deliberately the plain Notification API, not the Push API:
    // no service worker, no server-side subscription storage, nothing
    // that would still fire with the tab fully closed. It only ever
    // surfaces something this same open tab already received over the
    // WebSocket above.

    const NOTIFY_PREF_KEY = "honeypotshelf:notifications-enabled";

    const KIND_MESSAGES = {
      status: "Reachability status changed",
      facts: "Facts refreshed",
      packages: "Installed packages refreshed",
      services: "Services refreshed",
      updates: "Update availability changed",
      monitoring: "New monitoring sample",
      activity: "New OpenCanary activity",
    };

    function notificationsWanted() {
      try {
        return window.localStorage.getItem(NOTIFY_PREF_KEY) === "1";
      } catch {
        return false; // private browsing / storage blocked — just skip it
      }
    }

    function setNotificationsWanted(value) {
      try {
        window.localStorage.setItem(NOTIFY_PREF_KEY, value ? "1" : "0");
      } catch {
        // Nothing to persist to — the toggle still reflects the in-memory
        // choice for the rest of this page view, it just won't survive a
        // reload. Not worth surfacing an error for.
      }
    }

    function notifyIfBackgrounded(kind) {
      if (!("Notification" in window)) return;
      if (Notification.permission !== "granted") return;
      if (!notificationsWanted()) return;
      if (document.visibilityState !== "hidden") return; // tab is frontmost — the DOM update is enough
      const body = KIND_MESSAGES[kind] || "Something changed";
      let notification;
      try {
        notification = new Notification(honeypotName, { body, tag: `honeypotshelf-${honeypotId}` });
      } catch {
        return; // some browsers throw if constructed from a background/service context
      }
      notification.onclick = () => {
        window.focus();
        notification.close();
      };
    }

    // --- The toggle button, injected next to the page heading rather than
    // duplicated in three separate templates. ---

    function buildToggle() {
      if (!("Notification" in window)) return; // unsupported browser — nothing to offer

      const button = document.createElement("button");
      button.type = "button";
      button.className = "link-button live-notify-toggle";

      function render() {
        if (Notification.permission === "denied") {
          button.textContent = "🔕 Notifications blocked";
          button.disabled = true;
          button.title = "Blocked in this browser's site settings.";
          return;
        }
        if (Notification.permission === "granted" && notificationsWanted()) {
          button.textContent = "🔔 Notifications on";
          button.title = "Click to turn off background notifications for this machine's page.";
        } else {
          button.textContent = "🔔 Enable notifications";
          button.title = "Get a browser notification when this page updates while backgrounded.";
        }
      }

      button.addEventListener("click", async () => {
        if (Notification.permission === "default") {
          let permission;
          try {
            permission = await Notification.requestPermission();
          } catch {
            return;
          }
          if (permission === "granted") setNotificationsWanted(true);
          render();
          return;
        }
        if (Notification.permission === "granted") {
          setNotificationsWanted(!notificationsWanted());
          render();
        }
      });

      render();
      honeypotAnchor.appendChild(button);
    }

    openLiveSocket(url, notifyIfBackgrounded);
    buildToggle();
  }

  // --- Fleet-wide: Dashboard, Map ----------------------------------------
  // "Some honeypot's reachability or activity changed somewhere in view" —
  // no per-connection scoping needed, see app/services/live_updates.py's
  // module docstring for why that's safe (the payload carries no identity;
  // the panel it re-fetches is scoped on its own).

  if (document.querySelector("[data-live-fleet]")) {
    openLiveSocket(`${scheme}://${host}/live/fleet/ws`, () => {});
  }

  // --- Admin-wide: Audit log, Companies list ------------------------------
  // "A new audit log entry was written" — covers company/user
  // create/edit/delete too, since those are always audit-logged.

  if (document.querySelector("[data-live-admin]")) {
    openLiveSocket(`${scheme}://${host}/live/admin/ws`, () => {});
  }

  // --- Per-user: Notification history -------------------------------------

  if (document.querySelector("[data-live-notifications]")) {
    openLiveSocket(`${scheme}://${host}/live/notifications/ws`, () => {});
  }
})();
