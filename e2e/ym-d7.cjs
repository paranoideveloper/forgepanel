const {chromium}=require('playwright');
(async()=>{
  const [user,pass]=process.argv.slice(2);
  const b=await chromium.launch({headless:true});
  const pg=await (await b.newContext({viewport:{width:390,height:844}})).newPage();
  const errs=[]; pg.on('pageerror',e=>errs.push('PAGEERROR: '+e.message));
  pg.on('console',m=>{if(m.type()==='error'&&!/status of 400/.test(m.text()))errs.push('console: '+m.text());});
  await pg.goto('https://yemoshtmahi.eshkaftak.vip/',{waitUntil:'load',timeout:45000});
  await pg.waitForTimeout(2000);
  await pg.evaluate(()=>document.getElementById('au-sw').click());
  await pg.waitForTimeout(500);
  await pg.fill('#au-u',user); await pg.fill('#au-p',pass); await pg.click('#au-go');
  await pg.waitForTimeout(12000);
  if (await pg.evaluate(()=>!!document.querySelector('#onb.on'))) { await pg.click('#onb-skip'); await pg.waitForTimeout(1000); }
  const R={};
  const openSheet=async(btn,sheet,shot)=>{
    await pg.evaluate(id=>document.getElementById(id)?.click(),btn);
    await pg.waitForTimeout(3000);
    const o=await pg.evaluate(s=>{const e=document.querySelector(s+'.on');
      return e?{open:true,text:e.innerText.replace(/\s+/g,' ').slice(0,220),
                role:e.getAttribute('role'),labelled:!!e.getAttribute('aria-labelledby')}:{open:false};},sheet);
    if(shot) await pg.screenshot({path:'/tmp/'+shot});
    await pg.keyboard.press('Escape'); await pg.waitForTimeout(900);
    o.escapeClosed=await pg.evaluate(s=>!document.querySelector(s+'.on'),sheet);
    return o;
  };
  R.notice = await openSheet('hub-notice','#s-notice','ym-notice.png');
  R.leaderboard_fame = await openSheet('c-board','#s-board','ym-board.png');
  // بدترین ماهی روز lives on the board or its own surface — capture whatever rendered
  R.worstOnPage = await pg.evaluate(()=>/بدترین/.test(document.body.innerText));
  R.fameOnPage  = await pg.evaluate(()=>/تالار مشاهیر/.test(document.body.innerText));
  console.log(JSON.stringify({errs,R},null,1));
  await b.close();
})();
