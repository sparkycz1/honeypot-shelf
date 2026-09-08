// Toggle an element's `hidden` attribute based on a checkbox/radio's
// checked state, without an inline `onchange="..."` attribute (the CSP
// here has no 'unsafe-inline' for script-src, so that attribute is
// silently ignored by the browser — same issue confirm.js documents for
// `onsubmit`, and auto-submit.js for the Monitoring tab's range picker).
// Add `data-toggle-hidden="<id>"` to a checkbox whose checked state should
// hide/show the element with that id (e.g. Users new/edit: checking
// "Superadmin" hides the company-scope fields, since a superadmin has
// none) — or to each radio in a same-`name` group (e.g. Initialize's VPN
// picker: None/NetBird/WireGuard), where selecting one shows its own
// target and hides every other radio-in-the-group's target.
document.addEventListener("change", (event) => {
  const input = event.target;
  if (!input || !input.dataset || !input.dataset.toggleHidden) return;

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
  if (target) target.hidden = input.checked;
});
