// nodebuild.ts — turn the schema-driven flat form model into the canonical
// model.Node JSON the backend expects, and back. The schema's Field.key is a
// dot-path (e.g. "security.reality.dest"), so the form keeps a flat map of
// key -> value and this module assembles/reads the nested node.

export type FieldType =
  | 'text' | 'number' | 'bool' | 'textarea' | 'select' | 'iselect' | 'csv' | 'csvint' | 'kv' | 'lines';

export interface Field {
  key: string;
  label: string;
  type: FieldType;
  options?: string[];
  default?: unknown;
  keygen?: string;
  placeholder?: string;
  help?: string;
}

export interface ProtoSchema {
  proto: string;
  label: string;
  engine: string;
  fields: Field[];
  transports: string[];
  securities: string[];
  // Whether this protocol's engine can honour an upstream hop. Protocols whose
  // builder would ignore a chain must not be offered one.
  chainable?: boolean;
  /** False when no core can LISTEN on this protocol; the form must not offer it. */
  serves_inbound?: boolean;
  // False when THIS deployment cannot serve it, as opposed to the panel not
  // implementing it anywhere. Behind a platform edge that is most of the
  // catalogue, and here_note says why.
  serves_here?: boolean;
  here_note?: string;
}

export interface Schema {
  protocols: ProtoSchema[];
  // Node-level fields belonging to no protocol/transport/security layer.
  common?: Field[];
  transports: Record<string, Field[]>;
  securities: Record<string, Field[]>;
  fingerprints: string[];
}

// parseKV turns "Name: value" lines into the map the model wants. Blank lines
// and lines with no colon are skipped rather than becoming empty header names,
// which the core rejects with an error that does not name the offending line.
export function parseKV(text: string): Record<string, string> | undefined {
  const out: Record<string, string> = {};
  for (const line of String(text).split('\n')) {
    const i = line.indexOf(':');
    if (i <= 0) continue;
    const k = line.slice(0, i).trim();
    const v = line.slice(i + 1).trim();
    if (k) out[k] = v;
  }
  return Object.keys(out).length ? out : undefined;
}

// formatKV is parseKV's inverse, used to prefill the textarea from a stored node.
export function formatKV(v: unknown): string {
  if (!v || typeof v !== 'object' || Array.isArray(v)) return '';
  return Object.entries(v as Record<string, string>)
    .map(([k, val]) => `${k}: ${val}`)
    .join('\n');
}

// coerce a raw form value to the type the node JSON needs.
export function coerce(type: FieldType, v: unknown): unknown {
  if (v === undefined || v === null || v === '') {
    return type === 'bool' ? false : undefined;
  }
  switch (type) {
    case 'number':
    case 'iselect':
      return typeof v === 'number' ? v : parseInt(String(v), 10);
    case 'bool':
      return v === true || v === 'true';
    case 'csv':
      return String(v).split(',').map((s) => s.trim()).filter(Boolean);
    case 'csvint':
      return String(v).split(',').map((s) => parseInt(s.trim(), 10)).filter((n) => !Number.isNaN(n));
    case 'kv':
      return typeof v === 'object' ? v : parseKV(String(v));
    case 'lines': {
      // One value per line, NOT comma-separated: these carry share links whose
      // query strings contain commas, and splitting on those would cut a hop in
      // half and produce two unusable fragments.
      if (Array.isArray(v)) return v.length ? v : undefined;
      const out = String(v)
        .split('\n')
        .map((s) => s.trim())
        .filter(Boolean);
      return out.length ? out : undefined;
    }
    default:
      return v;
  }
}

// set a dot-path into a nested object, creating intermediate objects.
export function setPath(obj: Record<string, any>, path: string, value: unknown): void {
  if (value === undefined) return;
  const parts = path.split('.');
  let cur = obj;
  for (let i = 0; i < parts.length - 1; i++) {
    if (typeof cur[parts[i]] !== 'object' || cur[parts[i]] === null) cur[parts[i]] = {};
    cur = cur[parts[i]];
  }
  cur[parts[parts.length - 1]] = value;
}

// read a dot-path from a nested object.
export function getPath(obj: Record<string, any>, path: string): unknown {
  return path.split('.').reduce<any>((o, k) => (o == null ? undefined : o[k]), obj);
}

// Remove a dot-path, pruning containers that the removal leaves empty.
//
// This is what keeps an EDIT honest. buildNode starts from the stored node so
// fields the schema cannot describe survive; without this, a field the operator
// deliberately CLEARED would be silently restored from that same stored node and
// the form would refuse to let anything be unset.
function deletePath(obj: Record<string, any>, path: string) {
  const parts = path.split('.');
  const chain: Record<string, any>[] = [obj];
  let cur: any = obj;
  for (let i = 0; i < parts.length - 1; i++) {
    if (typeof cur[parts[i]] !== 'object' || cur[parts[i]] === null) return;
    cur = cur[parts[i]];
    chain.push(cur);
  }
  delete cur[parts[parts.length - 1]];
  // Walk back up dropping containers that now hold nothing, so a cleared
  // reality.private_key does not leave `security.reality: {}` behind for the
  // backend to interpret as "REALITY, configured with nothing".
  for (let i = chain.length - 1; i > 0; i--) {
    if (Object.keys(chain[i]).length === 0) delete chain[i - 1][parts[i - 1]];
    else break;
  }
}

// Build the canonical node from the current form selections + flat values.
// `values` is keyed by the schema Field.key across the protocol's own fields,
// the selected transport's fields and the selected security's fields, plus the
// common keys remark/address/port.
export function buildNode(
  schema: Schema,
  proto: string,
  transport: string,
  security: string,
  values: Record<string, unknown>,
  base?: Record<string, any> | null,
): Record<string, any> {
  // `base` is the node being EDITED, and passing it is what stops an edit from
  // destroying data.
  //
  // PUT /admin/inbounds/:id binds a whole model.Node and replaces the stored
  // one, while this function only knows the fields the studio schema describes.
  // Anything the model carries that the schema does not — Egress (the multi-hop
  // chain), the XHTTP xmux block, download_settings, ECH, WireGuard peer keys —
  // was therefore absent from the payload and silently wiped the first time an
  // operator opened an inbound and pressed Update. Starting from the stored node
  // preserves those fields; the schema-described ones below still overwrite it,
  // so editing remains authoritative for everything the form actually shows.
  const node: Record<string, any> = base ? structuredClone(base) : {};
  node.protocol = proto;
  // Identity and bookkeeping belong to the server, not to a form submission.
  delete node.id;
  delete node.created_at;
  delete node.updated_at;
  const ps = schema.protocols.find((p) => p.proto === proto);
  const collect: Field[] = [];
  if (ps) collect.push(...ps.fields);
  // Node-level fields, but only where the engine can actually honour them.
  if (ps?.chainable && schema.common?.length) collect.push(...schema.common);
  if (ps && ps.transports?.length && transport) {
    // Keep the stored transport's extra keys when the network is unchanged, so
    // xmux and download_settings survive an edit. Switching network legitimately
    // discards them: they describe the transport being replaced.
    const keep = base?.transport?.network === transport ? structuredClone(base.transport) : {};
    node.transport = { ...keep, network: transport };
    collect.push(...(schema.transports[transport] || []));
  } else {
    delete node.transport;
  }
  const secList = ps?.securities || [];
  if (secList.length && security) {
    // Same rule for the security layer: an unchanged type keeps its extra keys
    // (ECH settings, pinned certificates), a changed one starts clean.
    const keep = base?.security?.type === security ? structuredClone(base.security) : {};
    node.security = { ...keep, type: security };
    collect.push(...(schema.securities[security] || []));
  } else {
    delete node.security;
  }
  // Common fields. The form always shows these, so an empty one means the
  // operator cleared it and the stored value must go with it.
  if (values['remark'] !== undefined && values['remark'] !== '') node.remark = values['remark'];
  else delete node.remark;
  if (values['address'] !== undefined && values['address'] !== '') node.address = values['address'];
  else delete node.address;
  // ISO alpha-2 country, upper-cased, feeds {FLAG}/{COUNTRY} in the sub template.
  if (values['country'] !== undefined && String(values['country']).trim() !== '')
    node.country = String(values['country']).trim().toUpperCase();
  else delete node.country;
  const port = coerce('number', values['port']);
  if (port !== undefined) node.port = port;

  for (const f of collect) {
    const raw = values[f.key];
    const val = coerce(f.type, raw);
    // Every field in `collect` is one the form actually RENDERS, so the form is
    // the authority on it: empty means unset, not "keep whatever was stored".
    if (val === undefined || (val === false && f.type === 'bool')) {
      deletePath(node, f.key);
      continue;
    }
    setPath(node, f.key, val);
  }
  return node;
}

// Every field the form should render for the current selections, in order:
// common, protocol-specific, transport, security.
export function fieldsFor(
  schema: Schema,
  proto: string,
  transport: string,
  security: string,
): { section: string; fields: Field[] }[] {
  const ps = schema.protocols.find((p) => p.proto === proto);
  const out: { section: string; fields: Field[] }[] = [];
  if (ps) out.push({ section: 'Protocol', fields: ps.fields });
  if (ps?.chainable && schema.common?.length) out.push({ section: 'Chain', fields: schema.common });
  if (ps?.transports?.length && transport) {
    const tf = schema.transports[transport] || [];
    if (tf.length) out.push({ section: `Transport · ${transport}`, fields: tf });
  }
  if (ps?.securities?.length && security) {
    const sf = schema.securities[security] || [];
    if (sf.length) out.push({ section: `Security · ${security}`, fields: sf });
  }
  return out;
}
