// A drop-down list with a search box (`[data-combo]`): a text input and,
// under it, a list of options that htmx fills from the server as you
// type. This only opens and closes the list and moves through it with
// the keyboard — what an option does when picked is its own `hx-get`.
//
//   <div data-combo>
//     <input role="combobox" ...>
//     <div data-combo-list hidden> <button data-combo-value="..."> ... </div>
//   </div>
//
// Delegated from `document`, so a combo that arrives later inside an htmx
// fragment works without any setup.
(() => {
  "use strict";

  const comboOf = (node) => (node instanceof Element ? node.closest("[data-combo]") : null);
  const listOf = (combo) => combo.querySelector("[data-combo-list]");
  const inputOf = (combo) => combo.querySelector("input");
  const optionsOf = (combo) => [...combo.querySelectorAll("[data-combo-value]")];

  // Closed with Escape: stays closed, focus and late answers from the
  // server notwithstanding, until the box is typed in or opened on purpose.
  const dismissed = new WeakSet();

  function setOpen(combo, open) {
    const list = listOf(combo);
    const input = inputOf(combo);
    if (!list || !input) return;
    list.hidden = !open || list.children.length === 0;
    input.setAttribute("aria-expanded", String(!list.hidden));
  }

  // Fresh options from the server: show them, if the box is still in use.
  document.addEventListener("htmx:afterSwap", (event) => {
    const combo = comboOf(event.target);
    if (combo && event.target === listOf(combo)) {
      setOpen(combo, combo.contains(document.activeElement) && !dismissed.has(combo));
    }
  });

  document.addEventListener("focusin", (event) => {
    const combo = comboOf(event.target);
    if (combo && event.target === inputOf(combo) && !dismissed.has(combo)) setOpen(combo, true);
  });

  document.addEventListener("input", (event) => {
    const combo = comboOf(event.target);
    if (combo) dismissed.delete(combo);
  });

  // Picking an option: its name goes into the box, the list closes.
  document.addEventListener("click", (event) => {
    const option =
      event.target instanceof Element ? event.target.closest("[data-combo-value]") : null;
    if (option) {
      const combo = comboOf(option);
      inputOf(combo).value = option.getAttribute("data-combo-value") || "";
      setOpen(combo, false);
      return;
    }
    // A click anywhere else closes every open list but the one clicked in;
    // a click into a box opens its list again.
    const inside = comboOf(event.target);
    if (inside && event.target === inputOf(inside)) {
      dismissed.delete(inside);
      setOpen(inside, true);
    }
    for (const combo of document.querySelectorAll("[data-combo]")) {
      if (combo !== inside) setOpen(combo, false);
    }
  });

  document.addEventListener("keydown", (event) => {
    const combo = comboOf(event.target);
    if (!combo) return;
    const input = inputOf(combo);
    const options = optionsOf(combo);
    const index = options.indexOf(document.activeElement);

    if (event.key === "Escape") {
      dismissed.add(combo);
      setOpen(combo, false);
      input.focus();
    } else if (event.key === "ArrowDown") {
      event.preventDefault();
      dismissed.delete(combo);
      setOpen(combo, true);
      const next = options[index + 1] || options[0];
      if (next) next.focus();
    } else if (event.key === "ArrowUp") {
      event.preventDefault();
      if (index <= 0) input.focus();
      else options[index - 1].focus();
    }
  });

  // Tabbing out of the whole thing closes it too.
  document.addEventListener("focusout", (event) => {
    const combo = comboOf(event.target);
    if (!combo) return;
    window.setTimeout(() => {
      if (!combo.contains(document.activeElement)) setOpen(combo, false);
    }, 0);
  });
})();
