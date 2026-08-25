const {chromium}=require('playwright');
(async()=>{
  const [user,pass]=process.argv.slice(2);
  const b=await chromium.launch({headless:true});
  const pg=await (await b.newContext({viewport:{width:390,height:844}})).newPage();
  await pg.goto('https://yemoshtmahi.eshkaftak.vip/',{waitUntil:'load',timeout:45000});
  await pg.waitForTimeout(2000);
  await pg.evaluate(()=>document.getElementById('au-sw').click());
  await pg.waitForTimeout(500);
  await pg.fill('#au-u',user); await pg.fill('#au-p',pass); await pg.click('#au-go');
  await pg.waitForTimeout(12000);
  if (await pg.evaluate(()=>!!document.querySelector('#onb.on'))) { await pg.click('#onb-skip'); await pg.waitForTimeout(1000); }

  // ONE synchronous block: JS is single-threaded, so the rAF loop (which calls
  // A11Y.spoke.clear() every frame while nothing is in danger) cannot interleave.
  const r = await pg.evaluate(()=>{
    const said=[]; const real=A11Y.say; A11Y.say=t=>said.push(t);
    const f={id:'probe-xyz',name:'ماهی آزمایشی'};
    A11Y.clearCountdown(f.id);
    A11Y.countdown(f,31);            // above 30 -> silent
    const a=said.length;
    A11Y.countdown(f,30);            // -> ۳۰
    A11Y.countdown(f,22);            // between -> silent
    A11Y.countdown(f,10);            // -> ۱۰
    A11Y.countdown(f,3);             // between -> silent
    A11Y.countdown(f,0);             // -> تموم شد
    const afterAll=[...said];
    A11Y.countdown(f,0); A11Y.countdown(f,30); A11Y.countdown(f,10);  // repeats
    const repeatsSilent = said.length===afterAll.length;
    A11Y.clearCountdown(f.id);       // THE FIX
    A11Y.countdown(f,30);            // must speak again
    const reannounced = said.length===afterAll.length+1;
    const leaked = A11Y.spoke.has(f.id);
    A11Y.clearCountdown(f.id); A11Y.say=real;
    return {above30Silent:a===0, said:afterAll, repeatsSilent, reannounced, mapHasEntry:leaked};
  });

  // where does a Latin digit appear in the chrome?
  const latin = await pg.evaluate(()=>{
    const out=[];
    const w=document.createTreeWalker(document.body,NodeFilter.SHOW_TEXT);
    let n; while(n=w.nextNode()){
      const t=n.nodeValue||''; if(/[0-9]/.test(t) && n.parentElement?.offsetParent!==null){
        out.push({txt:t.trim().slice(0,50), el:n.parentElement.id||n.parentElement.className||n.parentElement.tagName});
      }}
    return out.slice(0,12);
  });
  console.log(JSON.stringify({countdown:r,latinDigitNodes:latin},null,1));
  await b.close();
})();
