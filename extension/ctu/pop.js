// popup.js (MV3-safe: no inline code)
document.addEventListener("DOMContentLoaded", () => {
  const out   = document.getElementById("out");
  const apiEl = document.getElementById("api");
  const uEl   = document.getElementById("u");
  const goBtn = document.getElementById("go");
  const saveBtn = document.getElementById("save");

  function write(msg){ out.textContent = msg; }

  chrome.storage.local.get(["apiBase"], s => {
    apiEl.value = s.apiBase || "http://127.0.0.1:5000";
  });

  saveBtn.addEventListener("click", () => {
    const base = (apiEl.value || "").trim() || "http://127.0.0.1:5000";
    chrome.storage.local.set({ apiBase: base }, () => write("Saved API base."));
  });

  goBtn.addEventListener("click", () => {
    const url = (uEl.value || "").trim();
    if (!url) return;
    chrome.runtime.sendMessage({ type:"scan", url }, (res) => {
      write(res && res.ok ? JSON.stringify(res.data, null, 2) : ("Error: " + (res && res.error)));
    });
  });
});
