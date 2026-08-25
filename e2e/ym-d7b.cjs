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
  // بدترین ماهی روز — inside امروز
  await pg.evaluate(()=>document.getElementById('c-today').click());
  await pg.waitForTimeout(4000);
  R.worst = await pg.evaluate(()=>{const e=document.getElementById('worst');
    return {html:!!e.innerHTML.trim(), text:e.innerText.replace(/\s+/g,' ').slice(0,200)};});
  await pg.screenshot({path:'/tmp/ym-today.png'});
  await pg.keyboard.press('Escape'); await pg.waitForTimeout(900);
  // تالار مشاهیر — behind the leaderboard
  await pg.evaluate(()=>document.getElementById('c-board').click());
  await pg.waitForTimeout(3000);
  await pg.evaluate(()=>document.getElementById('board-hall').click());
  await pg.waitForTimeout(4000);
  R.fame = await pg.evaluate(()=>{const e=document.querySelector('#s-fame.on')||document.querySelector('#s-hall.on');
    return e?{open:true,id:e.id,role:e.getAttribute('role'),text:e.innerText.replace(/\s+/g,' ').slice(0,260)}
             :{open:false, anyOn:[...document.querySelectorAll('.sheet.on')].map(x=>x.id)};});
  await pg.screenshot({path:'/tmp/ym-fame.png'});
  console.log(JSON.stringify({errs,R},null,1));
  await b.close();
})();
