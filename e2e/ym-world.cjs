const {chromium}=require('playwright');
(async()=>{
  const b=await chromium.launch({headless:true});
  const pg=await (await b.newContext({viewport:{width:390,height:844}})).newPage();
  const calls=[];
  pg.on('response',async r=>{ const u=r.url();
    if(/rpc\/|auth\/v1/.test(u)) calls.push({u:u.split('/rest/v1/')[1]||u.split('/auth/v1/')[1],s:r.status()}); });
  const errs=[]; pg.on('pageerror',e=>errs.push(e.message)); pg.on('console',m=>{if(m.type()==='error')errs.push('console:'+m.text());});
  await pg.goto('https://yemoshtmahi.eshkaftak.vip/',{waitUntil:'load',timeout:45000});
  await pg.waitForTimeout(12000);
  const st=await pg.evaluate(()=>({
    fish:(typeof fish!=='undefined')?fish.length:null,
    authOn:document.getElementById('auth')?.classList.contains('on'),
    onbOn:document.getElementById('onb')?.classList.contains('on'),
    signedIn:(typeof DB!=='undefined')?!!DB.me:null,
    me:(typeof DB!=='undefined')?DB.me:null,
    canvasBlank:(()=>{const c=document.getElementById('tank');const x=c.getContext('2d');
      const d=x.getImageData(0,0,c.width,c.height).data; let n=0;
      for(let i=0;i<d.length;i+=4000) if(d[i]||d[i+1]||d[i+2]) n++; return n===0;})(),
    tankSize:[document.getElementById('tank').width,document.getElementById('tank').height],
  }));
  console.log(JSON.stringify({errs,calls,st},null,1));
  await b.close();
})();
