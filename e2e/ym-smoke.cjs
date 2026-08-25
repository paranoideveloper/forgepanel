const {chromium}=require('playwright');
(async()=>{
  const b=await chromium.launch({headless:true});
  const ctx=await b.newContext({viewport:{width:390,height:844},locale:'fa-IR'});
  const pg=await ctx.newPage();
  const errs=[],warns=[],pageerr=[];
  pg.on('console',m=>{ if(m.type()==='error') errs.push(m.text()); if(m.type()==='warning') warns.push(m.text()); });
  pg.on('pageerror',e=>pageerr.push(e.message));
  const url=process.argv[2];
  await pg.goto(url,{waitUntil:'load',timeout:45000});
  await pg.waitForTimeout(9000);
  const probe=await pg.evaluate(()=>({
    YM: typeof window.YM,
    SND: typeof SND, A11Y: typeof A11Y, NET: typeof NET, SHARE: typeof SHARE,
    RULES: (typeof RULE_TEXT!=='undefined')?RULE_TEXT.length:null,
    sndOn: (typeof SND!=='undefined')?SND.on:null,
    sndCtx: (typeof SND!=='undefined')?!!SND.ctx:null,
    audioCtxCount: (window.__ac||0),
    tank: !!document.getElementById('tank'),
    tankLabel: document.getElementById('tank')?.getAttribute('aria-label'),
    padLabel: document.getElementById('pad')?.getAttribute('aria-label'),
    padDesc: document.getElementById('pad')?.getAttribute('aria-describedby'),
    padNote: document.getElementById('pad-note')?.textContent,
    srLive: !!document.getElementById('sr-live'),
    srRoster: !!document.getElementById('sr-roster'),
    clearCd: (typeof A11Y!=='undefined')?typeof A11Y.clearCountdown:null,
    dialogs: document.querySelectorAll('[role="dialog"]').length,
    fishCount: (typeof fish!=='undefined')?fish.length:null,
  }));
  console.log(JSON.stringify({pageerr,errs:errs.slice(0,15),probe},null,1));
  await b.close();
})();
