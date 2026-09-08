// Wires the Initialize run page up to its WebSocket
// (app/web/routes/initialize_ws.py). Protocol: text frames only, each a
// JSON object — {"kind": "step", "label": ...}, {"kind": "output", "text": ...},
// or {"kind": "done", "ok": ..., "error": ..., "fingerprint": ...}. See that
// module's own docstring for the exact shape.
(function () {
  const root = document.querySelector("[data-initialize-root]");
  if (!root) return;

  const stepBanner = document.querySelector("[data-initialize-step]");
  const stepText = stepBanner ? stepBanner.querySelector("p") : null;
  const output = document.querySelector("[data-initialize-output]");
  const result = document.querySelector("[data-initialize-result]");
  const resultBanner = document.querySelector("[data-initialize-result-banner]");
  const resultMessage = document.querySelector("[data-initialize-result-message]");
  const fingerprintPanel = document.querySelector("[data-initialize-fingerprint]");
  const fingerprintValue = document.querySelector("[data-initialize-fingerprint-value]");

  function appendOutput(text) {
    if (!output) return;
    output.textContent += text + "\n";
    output.scrollTop = output.scrollHeight;
  }

  function showResult(ok, message, fingerprint) {
    if (stepBanner) stepBanner.hidden = true;
    if (!result) return;
    result.hidden = false;
    if (resultBanner) {
      resultBanner.classList.remove("alert-ok", "alert-error");
      resultBanner.classList.add("alert", ok ? "alert-ok" : "alert-error");
    }
    if (resultMessage) resultMessage.textContent = message;
    if (fingerprint && fingerprintPanel && fingerprintValue) {
      fingerprintPanel.hidden = false;
      fingerprintValue.textContent = fingerprint;
    }
  }

  const protocol = window.location.protocol === "https:" ? "wss:" : "ws:";
  const wsUrl = protocol + "//" + window.location.host + root.dataset.wsPath;
  const socket = new WebSocket(wsUrl);
  let done = false;

  socket.addEventListener("message", (event) => {
    let message;
    try {
      message = JSON.parse(event.data);
    } catch (err) {
      return;
    }
    if (message.kind === "step") {
      if (stepText) stepText.textContent = message.label;
    } else if (message.kind === "output") {
      appendOutput(message.text);
    } else if (message.kind === "done") {
      done = true;
      const message_ = message.ok
        ? "Setup finished successfully."
        : message.error || "Setup failed.";
      showResult(message.ok, message_, message.fingerprint);
    }
  });

  socket.addEventListener("close", () => {
    if (!done) {
      showResult(false, "Connection lost before the run finished.", null);
    }
  });
})();
