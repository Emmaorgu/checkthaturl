// extension/ctu/content.js
(() => {
  const BADGE_CLASS = "ctu-badge";
  const POPOVER_CLASS = "ctu-popover";
  const SEEN = new Set();
  const CACHE = new Map(); // url -> { ok, data }
  const PENDING = new Set();
  const CONCURRENCY = 6;

  // Inject minimal CSS
  (function injectCSS(){
    if (document.getElementById("ctu-style")) return;
    const s = document.createElement("style");
    s.id = "ctu-style";
    s.textContent = `
      .${BADGE_CLASS}{
        display:inline-flex; align-items:center; gap:6px;
        font: 600 11px/1.2 system-ui, -apple-system, Segoe UI, Roboto, sans-serif;
        padding:3px 6px; margin-left:8px; border-radius:999px;
        background:rgba(15,23,42,.85); color:#e2e8f0;
        border:1px solid rgba(255,255,255,.12); cursor:pointer;
        vertical-align: baseline; user-select:none;
      }
      .${BADGE_CLASS}.legit    { background:#0a2f17; border-color:#15994a; color:#c6f6d5 }
      .${BADGE_CLASS}.sus      { background:#3a2b00; border-color:#f59e0b; color:#fde68a }
      .${BADGE_CLASS}.phish    { background:#3b0a0a; border-color:#ef4444; color:#fecaca }
      .${BADGE_CLASS}.loading  { opacity:.8 }
      .${POPOVER_CLASS}{
        position:absolute; z-index:2147483646; min-width:240px; max-width:340px;
        background:#0b1220; color:#e5e7eb; border:1px solid rgba(255,255,255,.12);
        border-radius:10px; padding:10px 12px; box-shadow:0 10px 30px rgba(0,0,0,.45);
      }
      .${POPOVER_CLASS} .head{ display:flex; justify-content:space-between; margin-bottom:6px; font-weight:700 }
      .${POPOVER_CLASS} .sub{ font-size:12px; color:#9ca3af; margin-bottom:8px }
      .${POPOVER_CLASS} ul{ margin:0; padding-left:16px; font-size:12px }
      .${POPOVER_CLASS} li{ margin:2px 0 }
    `;
    document.documentElement.appendChild(s);
  })();

  function absUrl(href){
    try { return new URL(href, location.href).href; } catch { return null; }
  }

  // Badge factory
  function ensureBadge(a){
    if (a.dataset.ctuHasBadge) return a.nextSibling;
    const b = document.createElement("span");
    b.className = BADGE_CLASS + " loading";
    b.textContent = "Scanning…";
    a.insertAdjacentElement("afterend", b);
    a.dataset.ctuHasBadge = "1";
    return b;
  }

  function setBadgeFromVerdict(badge, j){
    const v = (j && j.verdict) || "Suspicious";
    const conf = (j && typeof j.confidence === "number") ? `${j.confidence}%` : "";
    badge.classList.remove("loading","legit","sus","phish");
    if (v === "Legitimate") { badge.classList.add("legit");  badge.textContent = `✔ Legit ${conf}`; }
    else if (v === "Phishing"){ badge.classList.add("phish"); badge.textContent = `⚠ Phishing ${conf}`; }
    else { badge.classList.add("sus"); badge.textContent = `❓ Suspicious ${conf}`; }
  }

  function buildPopover(j){
    const pop = document.createElement("div");
    pop.className = POPOVER_CLASS;
    const v = j.verdict || "Suspicious";
    const conf = (typeof j.confidence === "number") ? `${j.confidence}%` : "—";
    const expl = (j.explanations && j.explanations.summary) || (j.explanation || "");
    const reasons = []
      .concat(j.domain_risks || [])
      .concat(j.content_risks || [])
      .concat(j.link_risks || [])
      .concat(j.behavior_risks || [])
      .slice(0, 5);

    pop.innerHTML = `
      <div class="head"><div>${v}</div><div>${conf}</div></div>
      <div class="sub">${expl || "Reasoning available."}</div>
      <ul>${reasons.map(r=>`<li>${String(r).replace(/[<>]/g,"")}</li>`).join("") || "<li>No notable issues.</li>"}</ul>
    `;
    return pop;
  }

  function placePopover(pop, badge){
    const rect = badge.getBoundingClientRect();
    const top = rect.bottom + 6 + window.scrollY;
    const left = Math.min(window.scrollX + rect.left, window.scrollX + window.innerWidth - pop.offsetWidth - 12);
    pop.style.top = `${top}px`; pop.style.left = `${left}px`;
  }

  // Hover interactions
  function attachHover(badge, res){
    let pop;
    function show(){
      if (pop) return;
      pop = buildPopover(res.data || {});
      document.body.appendChild(pop);
      // Wait one frame to measure
      requestAnimationFrame(()=>placePopover(pop, badge));
    }
    function hide(){
      if (!pop) return;
      pop.remove(); pop = null;
    }
    badge.addEventListener("mouseenter", show);
    badge.addEventListener("mouseleave", hide);
    window.addEventListener("scroll", ()=>{ if(pop) placePopover(pop, badge); }, { passive:true });
  }

  // Queue for concurrency
  const QUEUE = [];
  let running = 0;
  function enqueue(fn){
    QUEUE.push(fn);
    pump();
  }
  function pump(){
    while (running < CONCURRENCY && QUEUE.length){
      running++;
      const fn = QUEUE.shift();
      Promise.resolve().then(fn).finally(()=>{ running--; pump(); });
    }
  }

  async function scan(url){
    if (CACHE.has(url)) return CACHE.get(url);
    const p = new Promise((resolve) => {
      chrome.runtime.sendMessage({type:"scan", url}, (res)=>{
        const out = res && res.ok ? { ok:true, data:res.data } : { ok:false, error: (res && res.error) || "scan_failed" };
        CACHE.set(url, out);
        resolve(out);
      });
    });
    CACHE.set(url, p); // store promise to dedupe in-flight
    return p;
  }

  function handleLink(a){
    const url = absUrl(a.getAttribute("href"));
    if (!url || SEEN.has(a)) return;
    SEEN.add(a);

    const badge = ensureBadge(a);

    enqueue(async () => {
      try{
        const res = await scan(url);
        if (res && res.ok){
          setBadgeFromVerdict(badge, res.data);
          attachHover(badge, res);
          // Optional outlines for strong signals
          const v = res.data.verdict;
          if (v === "Phishing") { a.style.outline = "2px solid #ef4444"; a.style.outlineOffset="2px"; a.title = "CheckThatURL: Phishing"; }
          else if (v === "Suspicious") { a.style.outline = "2px dashed #f59e0b"; a.style.outlineOffset="2px"; a.title = "CheckThatURL: Suspicious"; }
          else { a.title = "CheckThatURL: Legitimate"; }
        } else {
          badge.classList.remove("loading"); badge.textContent = "CTU: error";
        }
      }catch(e){
        badge.classList.remove("loading"); badge.textContent = "CTU: error";
      }
    });
  }

  function scanVisible(){
    document.querySelectorAll('a[href]').forEach(handleLink);
  }

  // Observe DOM changes to rescan
  let idle;
  const mo = new MutationObserver(()=>{ clearTimeout(idle); idle = setTimeout(scanVisible, 400); });
  mo.observe(document.documentElement, { childList:true, subtree:true });

  // First pass
  scanVisible();

  // Also scan on hover (for newly created links or heavy pages)
  document.addEventListener("mouseover", (e)=>{
    const a = e.target.closest && e.target.closest("a[href]");
    if (a) handleLink(a);
  }, { passive:true });
})();
