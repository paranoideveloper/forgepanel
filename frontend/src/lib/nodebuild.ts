// nodebuild.ts — turn the schema-driven flat form model into the canonical
// model.Node JSON the backend expects, and back. The schema's Field.key is a
// dot-path (e.g. "security.reality.dest"), so the form keeps a flat map of
// key -> value and this module assembles/reads the nested node.

export type FieldType =
  | 'text' | 'number' | 'bool' | 'textarea' | 'select' | 'iselect' | 'csv' | 'csvint';

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
}

export interface Schema {
  protocols: ProtoSchema[];
  transports: Record<string, Field[]>;
  securities: Record<string, Field[]>;
  fingerprints: string[];
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
): Record<string, any> {
  const node: Record<string, any> = { protocol: proto };
  const ps = schema.protocols.find((p) => p.proto === proto);
  const collect: Field[] = [];
  if (ps) collect.push(...ps.fields);
  if (ps && ps.transports?.length && transport) {
    node.transport = { network: transport };
    collect.push(...(schema.transports[transport] || []));
  }
  const secList = ps?.securities || [];
  if (secList.length && security) {
    node.security = { type: security };
    collect.push(...(schema.securities[security] || []));
  }
  // common fields
  if (values['remark'] !== undefined && values['remark'] !== '') node.remark = values['remark'];
  if (values['address'] !== undefined && values['address'] !== '') node.address = values['address'];
  // ISO alpha-2 country, upper-cased, feeds {FLAG}/{COUNTRY} in the sub template.
  if (values['country'] !== undefined && String(values['country']).trim() !== '')
    node.country = String(values['country']).trim().toUpperCase();
  const port = coerce('number', values['port']);
  if (port !== undefined) node.port = port;

  for (const f of collect) {
    const raw = values[f.key];
    const val = coerce(f.type, raw);
    if (val === undefined) continue;
    if (val === false && f.type === 'bool') continue; // omit false bools
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
