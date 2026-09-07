// Toggle an element's `hidden` attribute based on a checkbox's checked
// state, without an inline `onchange="..."` attribute (the CSP here has no
// 'unsafe-inline' for script-src, so that attribute is silently ignored by
// the browser — same issue confirm.js documents for `onsubmit`, and
// auto-submit.js for the Monitoring tab's range picker). Add
// `data-toggle-hidden="<id>"` to a checkbox whose checked state should
// hide/show the element with that id (e.g. Users new/edit: checking
// "Superadmin" hides the company-scope fields, since a superadmin has
// none).
document.addEventListener("change", (event) => {
  const checkbox = event.target;
  if (!checkbox || !checkbox.dataset || !checkbox.dataset.toggleHidden) return;
  const target = document.getElementById(checkbox.dataset.toggleHidden);
  if (target) target.hidden = checkbox.checked;
});
