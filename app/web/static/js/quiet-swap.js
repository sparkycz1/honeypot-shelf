// A panel that re-fetches itself on a timer or a live push mostly gets
// back exactly what it already shows. Swapping that in anyway rebuilds
// every chart and table in it — on a whole-page panel (Dashboard, Map,
// Audit log, Companies) the page visibly ripples for nothing. For a
// target marked `data-quiet-swap`, a response identical to the previous
// one is dropped instead of swapped.
(() => {
  "use strict";

  const lastResponse = new WeakMap();

  document.addEventListener("htmx:beforeSwap", (event) => {
    const target = event.detail && event.detail.target;
    if (!(target instanceof Element) || !target.hasAttribute("data-quiet-swap")) return;
    const xhr = event.detail.xhr;
    if (!xhr || typeof xhr.responseText !== "string") return;
    if (lastResponse.get(target) === xhr.responseText) {
      event.detail.shouldSwap = false;
      return;
    }
    lastResponse.set(target, xhr.responseText);
  });
})();
