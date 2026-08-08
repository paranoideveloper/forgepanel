/**
 * WARP / AmneziaWG generation.
 *
 * The product claim under test: a WARP tunnel registered against Cloudflare's
 * consumer API turns into BOTH a plain WireGuard node and an AmneziaWG "Pro"
 * node whose junk-packet obfuscation actually survives a real handshake, and
 * that AmneziaWG node reaches the clients that can use it (Amnezia-aware
 * mihomo/Clash.Meta) instead of being silently dropped.
 *
 * Two regressions this guards against, both of which produced a WARP-Pro config
 * that looked present but could never connect:
 *   1. normalize clobbering the deliberate s1=s2=0 (WARP's server is not
 *      AmneziaWG-aware) up to 86/574, corrupting the handshake.
 *   2. the Clash renderer having no `amneziawg` case, so the node threw
 *      ClashUnsupportedError and vanished from every Clash subscription.
 */

import { describe, expect, test } from 'bun:test';
import { defaultConfig } from '../src/config/schema';
import { warpNodes } from '../src/warp/config';
import type { WarpAccount } from '../src/warp/account';
import { classify, renderClash, renderJSON } from '../src/export/subscription';
import { clashProxy } from '../src/export/clash';

const ACCOUNT: WarpAccount = {
  privateKey: 'aFakeClientPrivateKeyBase64==',
  publicKey: 'aFakePeerPublicKeyBase64==',
  warpIPv6: '2606:4700:110:8000:1:2:3:4/128',
  reserved: 'AAAA',
};

describe('WARP AmneziaWG', () => {
  test('the Pro node keeps s1=s2=0 so the WARP handshake is not corrupted', () => {
    const cfg = defaultConfig();
    const [pro] = warpNodes([ACCOUNT], cfg.warp, true);
    expect(pro.protocol).toBe('amneziawg');
    // The junk PACKETS (Jc/Jmin/Jmax) are what a stock WireGuard server ignores.
    expect(pro.amneziawg?.jc).toBe(cfg.warp.amneziaNoiseCount);
    // The init-packet junk sizes MUST stay 0 for Cloudflare's non-Amnezia server.
    expect(pro.amneziawg?.s1).toBe(0);
    expect(pro.amneziawg?.s2).toBe(0);
  });

  test('a non-WARP AmneziaWG node still gets the general s1/s2 defaults', () => {
    // When s1/s2 are genuinely unset (undefined), normalize fills the standard
    // AmneziaWG defaults — only an explicit 0 is preserved.
    const p = clashProxy({
      tag: 'awg', remark: 'awg', protocol: 'amneziawg',
      address: '1.2.3.4', port: 51820,
      amneziawg: { private_key: 'k', public_key: 'p', local_address: ['10.0.0.2/32'] },
    } as never);
    const opt = p['amnezia-wg-option'] as Record<string, number>;
    expect(opt.s1).toBe(86);
    expect(opt.s2).toBe(574);
  });

  test('Clash renders AmneziaWG as a wireguard proxy with amnezia-wg-option', () => {
    const cfg = defaultConfig();
    const nodes = classify(warpNodes([ACCOUNT], cfg.warp, true), 'vps');
    const yaml = renderClash({ cfg, nodes, title: 'x' });
    expect(yaml).toContain('type: wireguard');
    expect(yaml).toContain('amnezia-wg-option');
    // the junk params must ride along
    expect(yaml).toMatch(/jc:\s*\d+/);
    expect(yaml).toMatch(/s1:\s*0/);
  });

  test('the canonical JSON dump carries the full AmneziaWG node losslessly', () => {
    const cfg = defaultConfig();
    const nodes = classify(warpNodes([ACCOUNT], cfg.warp, true), 'vps');
    const json = renderJSON({ cfg, nodes, title: 'x' });
    expect(json).toContain('"protocol": "amneziawg"');
    expect(json).toContain('"jc"');
  });
});
