// Toggle an element's `hidden` attribute based on a checkbox/radio/select's
// state, without an inline `onchange="..."` attribute (the CSP here has no
// 'unsafe-inline' for script-src, so that attribute is silently ignored by
// the browser — same issue confirm.js documents for `onsubmit`, and
// auto-submit.js for the Monitoring tab's range picker).
// Add `data-toggle-hidden="<id>"` to a checkbox whose checked state should
// hide/show the element with that id (e.g. Users new/edit: checking
// "Superadmin" hides the company-scope fields, since a superadmin has
// none) — or to each radio in a same-`name` group (e.g. Initialize's VPN
// picker: None/NetBird/WireGuard), where selecting one shows its own
// target and hides every other radio-in-the-group's target — or to a
// `<select>`, alongside `data-toggle-hidden-unless-value="<value>"`, to
// show the target only when that exact option is selected (e.g. Users
// edit: the "switch to local" password field only matters while
// "auth_provider" is being set to "local").
// For a `<select>` with more than two options that each need their own
// target shown/hidden (e.g. Notifications: "Applies to" company vs.
// honeypot), use `data-toggle-hidden-map='{"value1":"id1","value2":"id2"}'`
// instead — every listed target is hidden except the one whose key matches
// the current value.
document.addEventListener("change", (event) => {
  const input = event.target;
  if (!input || !input.dataset) return;

  if (input.tagName === "SELECT" && input.dataset.toggleHiddenMap) {
    let map;
    try {
      map = JSON.parse(input.dataset.toggleHiddenMap);
    } catch {
      return;
    }
    for (const [value, id] of Object.entries(map)) {
      const target = document.getElementById(id);
      if (target) target.hidden = value !== input.value;
    }
    return;
  }

  if (!input.dataset.toggleHidden) return;

  if (input.type === "radio") {
    for (const sibling of document.getElementsByName(input.name)) {
      const target = sibling.dataset.toggleHidden
        ? document.getElementById(sibling.dataset.toggleHidden)
        : null;
      if (target) target.hidden = sibling !== input;
    }
    return;
  }

  const target = document.getElementById(input.dataset.toggleHidden);
  if (!target) return;

  if (input.tagName === "SELECT" && input.dataset.toggleHiddenUnlessValue !== undefined) {
    target.hidden = input.value !== input.dataset.toggleHiddenUnlessValue;
    return;
  }

  target.hidden = input.checked;
});
