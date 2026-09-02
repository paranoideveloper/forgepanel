/**
 * `encoding/json`-compatible serialisation.
 *
 * Go's `json.Marshal` on a `map[string]any` sorts keys and HTML-escapes `<`,
 * `>` and `&`. `JSON.stringify` does neither. The vmess:// link is base64 of
 * exactly that JSON, so a differently-ordered or differently-escaped object is a
 * different link — and the whole point of ForgeEdge is that a node exported at
 * the edge is byte-identical to the same node exported by the VPS panel.
 */

export type JSONValue = string | number | boolean | null | JSONValue[] | { [k: string]: JSONValue };

function escapeString(s: string): string {
  let out = '"';
  for (const ch of s) {
    const c = ch.codePointAt(0)!;
    switch (ch) {
      case '"': out += '\\"'; continue;
      case '\\': out += '\\\\'; continue;
      case '\n': out += '\\n'; continue;
      case '\r': out += '\\r'; continue;
      case '\t': out += '\\t'; continue;
      // Go's default HTMLEscape, so the JSON is safe to embed in a <script>.
      case '<': out += '\\u003c'; continue;
      case '>': out += '\\u003e'; continue;
      case '&': out += '\\u0026'; continue;
    }
    if (c < 0x20) {
      out += '\\u' + c.toString(16).padStart(4, '0');
    } else if (c === 0x2028 || c === 0x2029) {
      out += '\\u' + c.toString(16).padStart(4, '0');
    } else {
      out += ch;
    }
  }
  return out + '"';
}

function marshalValue(v: JSONValue, indent: string, depth: number): string {
  if (v === null) return 'null';
  switch (typeof v) {
    case 'string': return escapeString(v);
    case 'boolean': return v ? 'true' : 'false';
    case 'number': return Number.isInteger(v) ? String(v) : String(v);
  }
  const nl = indent ? '\n' : '';
  const padIn = indent ? indent.repeat(depth + 1) : '';
  const padOut = indent ? indent.repeat(depth) : '';

  if (Array.isArray(v)) {
    if (v.length === 0) return '[]';
    const items = v.map((x) => padIn + marshalValue(x, indent, depth + 1));
    return '[' + nl + items.join(',' + nl) + nl + padOut + ']';
  }

  const keys = Object.keys(v).sort();
  if (keys.length === 0) return '{}';
  const sep = indent ? ': ' : ':';
  const items = keys.map((k) => padIn + escapeString(k) + sep + marshalValue(v[k], indent, depth + 1));
  return '{' + nl + items.join(',' + nl) + nl + padOut + '}';
}

/** Go `json.Marshal`: compact, sorted keys, HTML-escaped. */
export function goMarshal(v: JSONValue): string {
  return marshalValue(v, '', 0);
}

/** Go `json.MarshalIndent(v, "", indent)` — the form `sub.go` uses for xray/sing-box docs. */
export function goMarshalIndent(v: JSONValue, indent = '  '): string {
  return marshalValue(v, indent, 0);
}
