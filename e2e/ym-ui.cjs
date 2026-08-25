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
  // first-run onboarding is modal; dismiss it before touching the top bar
  if (await pg.evaluate(()=>!!document.querySelector('#onb.on'))){
    await pg.click('#onb-skip'); await pg.waitForTimeout(1200);
  }
  const R={};

  // ── PART 17 · sound must be OFF and no AudioContext before any gesture
  R.sound_before={on:await pg.evaluate(()=>SND.on),ctx:await pg.evaluate(()=>!!SND.ctx)};
  // real user gesture on the top-bar control
  await pg.click('#snd-btn'); await pg.waitForTimeout(1200);
  R.sound_after_tap={on:await pg.evaluate(()=>SND.on),ctx:await pg.evaluate(()=>!!SND.ctx),
                     state:await pg.evaluate(()=>SND.ctx&&SND.ctx.state),
                     pressed:await pg.getAttribute('#snd-btn','aria-pressed')};
  await pg.click('#snd-btn'); await pg.waitForTimeout(800);
  R.sound_off_again={on:await pg.evaluate(()=>SND.on),pressed:await pg.getAttribute('#snd-btn','aria-pressed')};

  // ── PART 18 · the danger countdown announcement (the important one)
  R.countdown=await pg.evaluate(async()=>{
    const out=[]; const live=document.getElementById('sr-live');
    const mo=new MutationObserver(()=>{ if(live.textContent) out.push(live.textContent); });
    mo.observe(live,{childList:true,characterData:true,subtree:true});
    const f={id:'probe-fish-xyz',name:'ماهی آزمایشی'};
    A11Y.countdown(f,31); A11Y.countdown(f,30);
    await new Promise(r=>setTimeout(r,120));
    A11Y.countdown(f,12); A11Y.countdown(f,10);
    await new Promise(r=>setTimeout(r,120));
    A11Y.countdown(f,0);
    await new Promise(r=>setTimeout(r,120));
    A11Y.countdown(f,0); A11Y.countdown(f,30);   // repeats must stay silent
    await new Promise(r=>setTimeout(r,150));
    const afterRepeat=out.length;
    // now the FIX: clear, and the same fish must be announceable again
    A11Y.clearCountdown(f.id);
    A11Y.countdown(f,30);
    await new Promise(r=>setTimeout(r,150));
    mo.disconnect();
    return {spoken:out, repeatsAddedNothing: afterRepeat===out.length-1, reannounced: out.length>afterRepeat};
  });

  // ── D4 settings / PART 13.1 rules / D7 notice board
  await pg.evaluate(()=>document.getElementById('hub-settings')?.click());
  await pg.waitForTimeout(2500);
  R.settings={open:await pg.evaluate(()=>!!document.querySelector('#s-settings.on')),
    role:await pg.evaluate(()=>document.getElementById('s-settings')?.getAttribute('role')),
    rows:await pg.evaluate(()=>document.querySelectorAll('#s-settings input[type=checkbox]').length)};
  await pg.evaluate(()=>document.getElementById('st-rules')?.click());
  await pg.waitForTimeout(1200);
  R.rules={open:await pg.evaluate(()=>!!document.querySelector('#s-rules.on')),
    items:await pg.evaluate(()=>document.querySelectorAll('#rules-list li').length),
    first:await pg.evaluate(()=>document.querySelector('#rules-list li')?.innerText.slice(0,40)),
    last:await pg.evaluate(()=>[...document.querySelectorAll('#rules-list li')].pop()?.innerText.slice(0,40)),
    mentionsSecret:await pg.evaluate(()=>/عجیب|مخفی|راز/.test(document.getElementById('rules-list')?.innerText||''))};
  // Escape must close it (A11Y focus trap)
  await pg.keyboard.press('Escape'); await pg.waitForTimeout(600);
  R.rules.escapeClosed=await pg.evaluate(()=>!document.querySelector('#s-rules.on'));

  R.latin_digits_in_ui=await pg.evaluate(()=>{
    const t=document.body.innerText; const m=t.match(/\d+/g)||[]; return m.slice(0,10);
  });
  console.log(JSON.stringify({errs,R},null,1));
  await pg.screenshot({path:'/tmp/ym-ui.png',fullPage:false});
  await b.close();
})();
