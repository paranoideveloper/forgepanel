/**
 * The load-bearing test: byte equality with the REAL Go exporters.
 *
 * `testdata/golden.json` is produced by running
 * `internal/protocol/{model,export,render}` over 20 nodes covering every
 * protocol, transport and security layer the edge can be asked to render
 * (regenerate with `go run deploy/cloudflare/forgeedge/testdata/gen/main.go`).
 * Every assertion below compares the TypeScript mirror's output against what Go
 * actually produced — not against a hand-written expectation, which would only
 * prove the mirror agrees with whoever wrote the test.
 *
 * If this file fails after a change to the Go model, the mirror has drifted and
 * the edge and the VPS are about to emit different links for the same node.
 */

import { describe, expect, test } from 'bun:test';
import golden from '../testdata/golden.json';

import type { Node } from '../src/model/node';
import { normalized } from '../src/model/normalize';
import { nodeURI, plainLinks, UnsupportedURIError } from '../src/export/uri';
import { clashProxy, ClashUnsupportedError, toYAML, uniqueClashName, type YValue } from '../src/export/clash';
import type { JSONValue } from '../src/export/gojson';
import { singboxOutbound, SingboxUnsupportedError } from '../src/export/singbox';
import { xrayOutbound, XrayUnsupportedError } from '../src/export/xray';

interface GoldenCase {
  name: string;
  input: Node;
  normalized: Node;
  uri?: string;
  uri_error?: string;
  clash?: Record<string, YValue>;
  clash_error?: string;
  singbox?: Record<string, JSONValue>;
  singbox_error?: string;
  xray?: Record<string, JSONValue>;
  xray_error?: string;
}

interface GoldenFile {
  cases: GoldenCase[];
  clash_yaml: string;
  links: string;
}

const g = golden as unknown as GoldenFile;

/** Go's json.Marshal omits empty values; drop undefined so the shapes compare. */
function stripUndefined<T>(v: T): T {
  return JSON.parse(JSON.stringify(v)) as T;
}

describe('golden: parity with the Go canonical model', () => {
  test('the golden file covers every protocol the edge may render', () => {
    const protocols = new Set(g.cases.map((c) => c.input.protocol));
    for (const p of ['vless', 'vmess', 'trojan', 'shadowsocks', 'socks', 'http',
      'hysteria2', 'tuic', 'anytls', 'wireguard', 'shadowtls', 'ssh', 'brook', 'forgedns']) {
      expect(protocols.has(p as Node['protocol'])).toBe(true);
    }
    expect(g.cases.length).toBeGreaterThanOrEqual(20);
  });

  for (const c of g.cases) {
    describe(c.name, () => {
      test('normalize() matches (*model.Node).Normalize()', () => {
        expect(stripUndefined(normalized(c.input))).toEqual(c.normalized);
      });

      test('nodeURI() matches export.URI()', () => {
        if (c.uri_error) {
          expect(() => nodeURI(c.input)).toThrow(UnsupportedURIError);
          return;
        }
        expect(nodeURI(c.input)).toBe(c.uri!);
      });

      test('clashProxy() matches export.ClashProxy()', () => {
        if (c.clash_error) {
          expect(() => clashProxy(c.input)).toThrow(ClashUnsupportedError);
          return;
        }
        expect(stripUndefined(clashProxy(c.input))).toEqual(c.clash!);
      });

      test('singboxOutbound() matches render.SingboxOutbound()', () => {
        if (c.singbox_error) {
          expect(() => singboxOutbound(c.input)).toThrow(SingboxUnsupportedError);
          return;
        }
        expect(stripUndefined(singboxOutbound(c.input))).toEqual(c.singbox!);
      });

      test('xrayOutbound() matches render.XrayOutbound()', () => {
        if (c.xray_error) {
          expect(() => xrayOutbound(c.input)).toThrow(XrayUnsupportedError);
          return;
        }
        expect(stripUndefined(xrayOutbound(c.input))).toEqual(c.xray!);
      });
    });
  }

  test('plainLinks() matches api.plainLinks() over the whole set', () => {
    expect(plainLinks(g.cases.map((c) => c.input))).toBe(g.links);
  });

  test('the Clash YAML emitter is byte-identical to export.ClashYAML()', () => {
    // Rebuild the document exactly as ClashYAML does: skip unrepresentable
    // nodes, dedupe names, one select group, one MATCH rule.
    const proxies: YValue[] = [];
    const names: YValue[] = [];
    const seen = new Map<string, number>();
    for (const c of g.cases) {
      let p: Record<string, YValue>;
      try {
        p = clashProxy(c.input);
      } catch (e) {
        if (e instanceof ClashUnsupportedError) continue;
        throw e;
      }
      p.name = uniqueClashName(String(p.name), seen);
      proxies.push(stripUndefined(p));
      names.push(p.name);
    }
    const doc: Record<string, YValue> = {
      proxies,
      'proxy-groups': [{ name: 'PROXY', type: 'select', proxies: names.length ? names : ['DIRECT'] }],
      rules: ['MATCH,PROXY'],
    };
    expect(toYAML(doc)).toBe(g.clash_yaml);
  });
});
