const {chromium}=require('playwright');
(async()=>{
  const [user,pass]=process.argv.slice(2);
  const b=await chromium.launch({headless:true});
  const pg=await (await b.newContext({viewport:{width:390,height:844}})).newPage();
  const errs=[],rpc=[];
  pg.on('pageerror',e=>errs.push('PAGEERROR: '+e.message));
  pg.on('console',m=>{if(m.type()==='error')errs.push('console: '+m.text());});
  pg.on('response',r=>{const u=r.url(); const m=u.match(/rest\/v1\/rpc\/([a-z_]+)/); if(m) rpc.push(m[1]+':'+r.status());});
  await pg.goto('https://yemoshtmahi.eshkaftak.vip/',{waitUntil:'load',timeout:45000});
  await pg.waitForTimeout(2500);
  // sign in through the app's own UI
  await pg.evaluate(([u,p])=>{
    document.getElementById('au-sw').click();   // switch to «قبلاً ثبت‌نام کردم»
  },[user,pass]);
  await pg.waitForTimeout(600);
  await pg.fill('#au-u',user); await pg.fill('#au-p',pass);
  await pg.click('#au-go');
  await pg.waitForTimeout(14000);
  const st=await pg.evaluate(()=>({
    signedIn:!!DB.me, me:DB.me,
    authOn:document.getElementById('auth')?.classList.contains('on'),
    fish:fish.length,
    fishWithImg:fish.filter(f=>f.img&&f.img.complete&&f.img.naturalWidth).length,
    rafRunning:(typeof lastFrame!=='undefined')?true:'n/a',
    srRosterLabel:document.getElementById('tank')?.getAttribute('aria-label'),
    sndOn:SND.on, sndCtx:!!SND.ctx,
    smoothing:(()=>{const x=document.getElementById('tank').getContext('2d');
       return {imageSmoothingEnabled:x.imageSmoothingEnabled,filter:x.filter,globalAlpha:x.globalAlpha};})(),
  }));
  // now count a second poll cycle to prove world_snapshot keeps polling
  const before=rpc.filter(r=>r.startsWith('world_snapshot')).length;
  await pg.waitForTimeout(7000);
  const after=rpc.filter(r=>r.startsWith('world_snapshot')).length;
  console.log(JSON.stringify({errs,st,
    world_snapshot_calls:{before,after,polling:after>before},
    rpcSample:[...new Set(rpc)].slice(0,25)},null,1));
  await pg.screenshot({path:'/tmp/ym-live.png'});
  await b.close();
})();
