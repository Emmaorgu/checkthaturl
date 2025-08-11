const DEFAULT_API = "http://127.0.0.1:5000";
chrome.runtime.onInstalled.addListener(()=>{ chrome.storage.local.get(["apiBase"], s => { if(!s.apiBase) chrome.storage.local.set({apiBase: DEFAULT_API}); }); });
chrome.runtime.onMessage.addListener((msg, _sender, sendResponse)=>{
  if(msg.type==="scan"){
    chrome.storage.local.get(["apiBase"], async s=>{
      try{
        const r = await fetch((s.apiBase||DEFAULT_API)+"/check", { method:"POST", headers:{ "Content-Type":"application/json" }, body: JSON.stringify({url: msg.url}) });
        sendResponse({ ok:true, data: await r.json() });
      }catch(e){ sendResponse({ ok:false, error:String(e) }); }
    });
    return true; // async
  }
});
