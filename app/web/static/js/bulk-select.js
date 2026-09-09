// "Select all" checkbox for bulk-action tables (honeypots, users, ...):
// toggles every same-named checkbox inside the same <form>. The name to
// toggle comes from the checkbox's own `data-select-all` value (e.g.
// `data-select-all="honeypot_ids"`) rather than being hardcoded, so this
// one script works for every bulk-select table in the app. Kept as an
// external script, not an inline handler — the CSP here has no
// 'unsafe-inline' for script-src.
document.addEventListener("change", (event) => {
  const target = event.target;
  if (!(target instanceof HTMLInputElement) || !target.matches("[data-select-all]")) return;
  const form = target.closest("form");
  if (!form) return;
  const name = target.getAttribute("data-select-all");
  if (!name) return;
  for (const checkbox of form.querySelectorAll(`input[name="${name}"]`)) {
    checkbox.checked = target.checked;
  }
});
