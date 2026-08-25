const {chromium}=require('playwright');
(async()=>{
  const [user,pass]=process.argv.slice(2);
  const b=await chromium.launch({headless:true,args:['--autoplay-policy=no-user-gesture-required']});
  const pg=await (await b.newContext({viewport:{width:390,height:844}})).newPage();
  const errs=[]; pg.on('pageerror',e=>errs.push('PAGEERROR: '+e.message));
  await pg.goto('https://yemoshtmahi.eshkaftak.vip/',{waitUntil:'load',timeout:45000});
  await pg.waitForTimeout(2000);
  await pg.evaluate(()=>document.getElementById('au-sw').click());
  await pg.waitForTimeout(500);
  await pg.fill('#au-u',user); await pg.fill('#au-p',pass); await pg.click('#au-go');
  await pg.waitForTimeout(12000);
  if (await pg.evaluate(()=>!!document.querySelector('#onb.on'))) { await pg.click('#onb-skip'); await pg.waitForTimeout(1000); }

  // BEFORE any gesture: no context at all
  const before = await pg.evaluate(()=>({on:SND.on,ctx:!!SND.ctx}));
  await pg.click('#snd-btn');                       // the real gesture
  await pg.waitForTimeout(1500);

  // tap an analyser on the master bus and measure actual signal
  const measure = await pg.evaluate(async()=>{
    const c=SND.ctx, an=c.createAnalyser(); an.fftSize=2048;
    SND.master.connect(an);
    const buf=new Float32Array(an.fftSize);
    const peak=()=>{an.getFloatTimeDomainData(buf);let m=0;for(const v of buf)m=Math.max(m,Math.abs(v));return m;};
    const samples=[];
    for(let i=0;i<12;i++){ await new Promise(r=>setTimeout(r,220)); samples.push(+peak().toFixed(5)); }
    const ambientPeak=Math.max(...samples);
    // fire a discrete cue and measure again
    SND.plop(); const cue=[];
    for(let i=0;i<8;i++){ await new Promise(r=>setTimeout(r,60)); cue.push(+peak().toFixed(5)); }
    SND.bread(); const cue2=[];
    for(let i=0;i<8;i++){ await new Promise(r=>setTimeout(r,60)); cue2.push(+peak().toFixed(5)); }
    return {ambientPeak, plopPeak:Math.max(...cue), breadPeak:Math.max(...cue2), sampleRate:c.sampleRate, state:c.state};
  });
  // switch OFF -> ambient must stop
  await pg.click('#snd-btn'); await pg.waitForTimeout(2000);
  const off = await pg.evaluate(async()=>{
    const c=SND.ctx, an=c.createAnalyser(); an.fftSize=2048; SND.master.connect(an);
    const buf=new Float32Array(an.fftSize); let m=0;
    for(let i=0;i<10;i++){await new Promise(r=>setTimeout(r,200));
      an.getFloatTimeDomainData(buf); for(const v of buf) m=Math.max(m,Math.abs(v));}
    return {on:SND.on, peakAfterOff:+m.toFixed(5), ambTimers:SND.ambTimers?SND.ambTimers.length:null};
  });
  console.log(JSON.stringify({errs,before,measure,off},null,1));
  await b.close();
})();
