// "Select all" checkbox for bulk-action tables (honeypots, users, ...):
// toggles every same-named checkbox associated with the same <form>. The
// name to toggle comes from the checkbox's own `data-select-all` value
// (e.g. `data-select-all="honeypot_ids"`) rather than being hardcoded, so
// this one script works for every bulk-select table in the app. Kept as an
// external script, not an inline handler — the CSP here has no
// 'unsafe-inline' for script-src.
//
// Uses the checkbox's `.form` IDL property, not `closest("form")`: a
// bulk-select table's own row checkboxes may live outside their form as
// plain siblings, associated via the HTML `form="..."` attribute instead
// of DOM nesting (see users/list.html) — nesting a per-row action <form>
// inside the bulk-select <form> is invalid HTML and gets silently mangled
// by the browser (found via a real "Sign in as" bug). `.form` resolves the
// same form either way, so this still works unchanged for a table (e.g.
// honeypots) whose checkboxes *are* plain DOM descendants of their form.
document.addEventListener("change", (event) => {
  const target = event.target;
  if (!(target instanceof HTMLInputElement) || !target.matches("[data-select-all]")) return;
  const form = target.form;
  if (!form) return;
  const name = target.getAttribute("data-select-all");
  if (!name) return;
  for (const checkbox of document.querySelectorAll(`input[name="${name}"]`)) {
    if (checkbox instanceof HTMLInputElement && checkbox.form === form) {
      checkbox.checked = target.checked;
    }
  }
});
