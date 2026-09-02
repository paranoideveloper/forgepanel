import { describe, it, expect } from 'vitest';
import { buildNode, type Schema } from './nodebuild';

// PUT /admin/inbounds/:id binds a whole model.Node and REPLACES the stored row.
// buildNode only knows the fields the studio schema describes, so for a while an
// edit shipped a node missing everything the schema cannot describe — the Egress
// chain, the XHTTP xmux block, download_settings, ECH, WireGuard peer keys — and
// the backend dutifully replaced the real inbound with the truncated one. The
// operator saw a successful save and lost their chain.
//
// These tests pin both halves of the fix, because the naive repair breaks the
// other half: preserve what the form cannot show, and still let the form clear
// what it can.

const schema: Schema = {
  protocols: [
    {
      proto: 'vless',
      label: 'VLESS',
      engine: 'xray',
      fields: [
        { key: 'uuid', label: 'UUID', type: 'text' },
        { key: 'flow', label: 'Flow', type: 'text' },
      ],
      transports: ['tcp', 'xhttp'],
      securities: ['none', 'reality'],
    },
  ],
  transports: {
    tcp: [],
    xhttp: [{ key: 'transport.path', label: 'Path', type: 'text' }],
  },
  securities: {
    none: [],
    reality: [{ key: 'security.reality.dest', label: 'Dest', type: 'text' }],
  },
  fingerprints: ['chrome'],
};

// A stored inbound carrying fields no schema entry describes.
function storedNode() {
  return {
    id: 7,
    created_at: '2026-08-01T00:00:00Z',
    protocol: 'vless',
    remark: 'chained',
    address: '203.0.113.10',
    port: 443,
    uuid: 'b831381d-6324-4d53-ad4f-8cda48b30811',
    egress: 'vless://11111111-2222-4333-8444-555555555555@203.0.113.50:443#hop',
    transport: {
      network: 'xhttp',
      path: '/old',
      xmux: { max_concurrency: '16-32', max_connections: 0 },
      download_settings: { address: 'dl.example.com', port: 443 },
    },
    security: {
      type: 'reality',
      reality: { dest: 'www.cloudflare.com:443', private_key: 'SECRET', short_ids: ['0123abcd'] },
    },
  };
}

const values = {
  remark: 'chained',
  address: '203.0.113.10',
  port: 443,
  uuid: 'b831381d-6324-4d53-ad4f-8cda48b30811',
  'transport.path': '/new',
  'security.reality.dest': 'www.cloudflare.com:443',
};

describe('buildNode edit preservation', () => {
  it('keeps model fields the schema does not describe', () => {
    const out = buildNode(schema, 'vless', 'xhttp', 'reality', values, storedNode());

    // The regression that cost operators their chains.
    expect(out.egress).toBe('vless://11111111-2222-4333-8444-555555555555@203.0.113.50:443#hop');
    // Transport extras survive because the network did not change.
    expect(out.transport.xmux).toEqual({ max_concurrency: '16-32', max_connections: 0 });
    expect(out.transport.download_settings).toEqual({ address: 'dl.example.com', port: 443 });
    // Security extras likewise, including the key the form never renders.
    expect(out.security.reality.private_key).toBe('SECRET');
    expect(out.security.reality.short_ids).toEqual(['0123abcd']);
  });

  it('still lets the form change what it does describe', () => {
    const out = buildNode(schema, 'vless', 'xhttp', 'reality', values, storedNode());
    expect(out.transport.path).toBe('/new');
    expect(out.transport.network).toBe('xhttp');
  });

  it('clears a schema field the operator emptied instead of restoring it', () => {
    // The naive "merge over the stored node" fix makes clearing impossible: the
    // emptied value falls through and the old one is written straight back.
    const out = buildNode(
      schema,
      'vless',
      'xhttp',
      'reality',
      { ...values, 'transport.path': '', flow: '' },
      storedNode(),
    );
    expect(out.transport.path).toBeUndefined();
    expect(out.flow).toBeUndefined();
    // Clearing the last key of a container must not leave an empty object that
    // the backend would read as "configured, with nothing".
    expect(out.transport.network).toBe('xhttp');
  });

  it('drops transport extras when the operator switches network', () => {
    // xmux and download_settings describe XHTTP. Carrying them onto a TCP
    // inbound would ship settings for a transport that is no longer there.
    const out = buildNode(schema, 'vless', 'tcp', 'reality', values, storedNode());
    expect(out.transport.network).toBe('tcp');
    expect(out.transport.xmux).toBeUndefined();
    expect(out.transport.download_settings).toBeUndefined();
    // Fields outside the transport are untouched by a transport switch.
    expect(out.egress).toContain('203.0.113.50');
  });

  it('drops security extras when the operator switches security type', () => {
    const out = buildNode(schema, 'vless', 'xhttp', 'none', values, storedNode());
    expect(out.security.type).toBe('none');
    expect(out.security.reality).toBeUndefined();
  });

  it('never sends server-owned identity back', () => {
    const out = buildNode(schema, 'vless', 'xhttp', 'reality', values, storedNode());
    expect(out.id).toBeUndefined();
    expect(out.created_at).toBeUndefined();
  });

  it('builds a clean node when creating, with no base to inherit from', () => {
    const out = buildNode(schema, 'vless', 'tcp', 'none', values);
    expect(out.egress).toBeUndefined();
    expect(out.uuid).toBe('b831381d-6324-4d53-ad4f-8cda48b30811');
    expect(out.protocol).toBe('vless');
  });
});

// Multi-hop chains: one hop per LINE, never comma-separated. A share link's
// query string contains commas (alpn=h2,http/1.1 among others), so splitting on
// them would cut a hop in half and yield two unusable fragments.
describe('lines fields carry a chain', () => {
  const chainSchema: Schema = {
    protocols: [
      {
        proto: 'vless',
        label: 'VLESS',
        engine: 'xray',
        fields: [{ key: 'uuid', label: 'UUID', type: 'text' }],
        transports: ['tcp'],
        securities: ['none'],
        chainable: true
      }
    ],
    common: [{ key: 'egress', label: 'Relay chain', type: 'lines' }],
    transports: { tcp: [] },
    securities: { none: [] },
    fingerprints: ['chrome']
  };

  const base = { remark: 'r', port: 443, address: 'a', uuid: 'u' };

  it('splits on newlines and preserves commas inside a hop', () => {
    const hop = 'trojan://pw@203.0.113.5:443?security=tls&alpn=h2,http/1.1&sni=x.example#hop';
    const out = buildNode(chainSchema, 'vless', 'tcp', 'none', {
      ...base,
      egress: `vless://a@203.0.113.1:443#one\n${hop}\nss://b@203.0.113.9:8388#exit`
    });
    expect(out.egress).toEqual([
      'vless://a@203.0.113.1:443#one',
      hop,
      'ss://b@203.0.113.9:8388#exit'
    ]);
    // The comma-bearing hop must survive whole.
    expect(out.egress[1]).toContain('alpn=h2,http/1.1');
  });

  it('drops blank lines so a trailing newline does not break the chain', () => {
    const out = buildNode(chainSchema, 'vless', 'tcp', 'none', {
      ...base,
      egress: 'vless://a@203.0.113.1:443#one\n\n  \nss://b@203.0.113.9:8388#exit\n'
    });
    expect(out.egress).toHaveLength(2);
  });

  it('treats an empty chain as no chain rather than one blank hop', () => {
    const out = buildNode(chainSchema, 'vless', 'tcp', 'none', { ...base, egress: '   \n  ' });
    expect(out.egress).toBeUndefined();
  });

  it('is not offered for a protocol whose engine cannot honour it', () => {
    const noChain: Schema = {
      ...chainSchema,
      protocols: [{ ...chainSchema.protocols[0], chainable: false }]
    };
    const out = buildNode(noChain, 'vless', 'tcp', 'none', {
      ...base,
      egress: 'vless://a@203.0.113.1:443#one'
    });
    expect(out.egress).toBeUndefined();
  });
});
