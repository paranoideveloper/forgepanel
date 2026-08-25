const {chromium}=require('playwright');
(async()=>{
  const [user,pass]=process.argv.slice(2);
  const b=await chromium.launch({headless:true});
  const pg=await (await b.newContext({viewport:{width:390,height:844}})).newPage();
  const bad=[];
  pg.on('response',async r=>{ if(r.status()>=400) bad.push({s:r.status(),u:r.url()}); });
  await pg.goto('https://yemoshtmahi.eshkaftak.vip/',{waitUntil:'load',timeout:45000});
  await pg.waitForTimeout(2000);
  await pg.evaluate(()=>document.getElementById('au-sw').click());
  await pg.waitForTimeout(500);
  await pg.fill('#au-u',user); await pg.fill('#au-p',pass); await pg.click('#au-go');
  await pg.waitForTimeout(15000);
  console.log(JSON.stringify(bad,null,1));
  await b.close();
})();
