import { describe, expect, test } from 'bun:test';
import { GROUPS, allPaths } from '../src/panel/fields';
import { defaultConfig } from '../src/config/schema';

/**
 * The panel's field table must cover the configuration.
 *
 * Before this, the whole config was one JSON textarea, so every key was equally
 * (in)visible and nothing could drift. Now that there are real controls, the
 * failure mode is a key added to EdgeConfig with no row here: it keeps working,
 * it appears in the Expert tab's raw JSON, and it is invisible in the UI — which
 * is indistinguishable from not having shipped it.
 */

/** Dotted paths for every leaf of the default config. */
function leafPaths(obj: unknown, prefix = ''): string[] {
  if (obj === null || typeof obj !== 'object' || Array.isArray(obj)) {
    return prefix ? [prefix] : [];
  }
  return Object.entries(obj as Record<string, unknown>).flatMap(([k, v]) =>
    leafPaths(v, prefix ? `${prefix}.${k}` : k),
  );
}

// Keys the form deliberately does not render, each with the reason. Anything
// else missing is a bug, not a decision.
const NOT_IN_THE_FORM: Record<string, string> = {
  version: 'the schema version; the store migrates it and an operator editing it corrupts the record',
  udpNoises: 'an array of objects, not a leaf — edited in the Expert tab until it earns a repeater control',
};

describe('the panel form covers the configuration', () => {
  test('every config key has a control or a stated reason', () => {
    const bound = new Set(allPaths());
    const missing = leafPaths(defaultConfig()).filter(
      (p) => !bound.has(p) && !(p in NOT_IN_THE_FORM) && !NOT_IN_THE_FORM[p.split('.')[0]],
    );
    expect(missing).toEqual([]);
  });

  test('no control binds a key the config does not have', () => {
    const real = new Set(leafPaths(defaultConfig()));
    // A path is legitimate if it is a leaf, or the parent of leaves (an array
    // rendered as lines shows up as its own leaf only when non-empty).
    const cfg = defaultConfig() as unknown as Record<string, unknown>;
    const resolves = (path: string): boolean => {
      let cur: unknown = cfg;
      for (const part of path.split('.')) {
        if (cur === null || typeof cur !== 'object') return false;
        if (!(part in (cur as Record<string, unknown>))) return false;
        cur = (cur as Record<string, unknown>)[part];
      }
      return true;
    };
    const bogus = allPaths().filter((p) => !real.has(p) && !resolves(p));
    expect(bogus).toEqual([]);
  });

  test('no path is bound twice', () => {
    const paths = allPaths();
    expect(paths.length).toBe(new Set(paths).size);
  });

  test('every group and field is labelled', () => {
    for (const g of GROUPS) {
      expect(g.title.length).toBeGreaterThan(0);
      expect(g.fields.length).toBeGreaterThan(0);
      for (const f of g.fields) {
        expect(f.label.length).toBeGreaterThan(0);
        // A select with no options renders an empty dropdown, which reads as a
        // broken control rather than an unset one.
        if (f.kind === 'select') expect(f.options?.length ?? 0).toBeGreaterThan(0);
      }
    }
  });

  test('group ids are unique, since they address the nav', () => {
    const ids = GROUPS.map((g) => g.id);
    expect(ids.length).toBe(new Set(ids).size);
  });
});

/**
 * The table is only useful if the page actually renders from it. These assert on
 * the served document, because "the descriptor exists" and "the operator can see
 * the control" are different claims and only the second one matters.
 */
describe('the served panel renders the table', () => {
  test('every field path appears in the document', async () => {
    const { panelHTML } = await import('../src/panel/ui');
    const html = panelHTML('secret-path', false);
    for (const p of allPaths()) {
      expect(html).toContain(p);
    }
  });

  test('the page carries no external asset reference', async () => {
    const { panelHTML } = await import('../src/panel/ui');
    const html = panelHTML('secret-path', false);
    // A Worker serves no static assets, and a panel that pulls a CDN is a panel
    // that stops working on exactly the networks this product exists for.
    expect(html).not.toMatch(/<script[^>]+src=/i);
    expect(html).not.toMatch(/<link[^>]+stylesheet/i);
    expect(html).not.toMatch(/https?:\/\/cdn\./i);
  });

  test('the secure path is not reflected unescaped into the document', async () => {
    const { panelHTML } = await import('../src/panel/ui');
    const html = panelHTML('</script><img src=x onerror=alert(1)>', false);
    expect(html).not.toContain('<img src=x onerror=alert(1)>');
  });

  test('both themes define every colour token they use', async () => {
    const { panelHTML } = await import('../src/panel/ui');
    const html = panelHTML('p', false);
    const css = html.slice(html.indexOf('<style>'), html.indexOf('</style>'));
    // Tokens referenced by var() must be defined on bare :root, or the light
    // theme inherits a value that only the dark block ever set.
    const used = new Set([...css.matchAll(/var\((--[a-z0-9-]+)\)/g)].map((m) => m[1]));
    const rootBlock = css.slice(css.indexOf(':root{'), css.indexOf('}', css.indexOf(':root{')));
    const missing = [...used].filter((t) => !rootBlock.includes(t + ':'));
    expect(missing).toEqual([]);
  });
});

/**
 * The switch is the field's own <label>, and `.f label{display:block}` outranks
 * a bare `.sw` class. That tie left all 22 toggles as blocks, the track computed
 * `display:inline`, and an inline box ignores width and height — so every switch
 * collapsed to a stray knob drawn on top of its own text. Every test passed
 * while the page was visibly broken, which is why this one asserts on the
 * selector rather than on behaviour a string cannot show.
 */
describe('the switch survives its specificity tie', () => {
  test('the switch rule is qualified past .f label', async () => {
    const { panelHTML } = await import('../src/panel/ui');
    const css = panelHTML('p', false);
    expect(css).toContain('.f label.sw{display:flex');
  });

  test('every foreground token that pairs with a flipping background is defined', async () => {
    const { panelHTML } = await import('../src/panel/ui');
    const html = panelHTML('p', false);
    const css = html.slice(html.indexOf('<style>'), html.indexOf('</style>'));
    // --bad flips from a dark red to a light red between themes, so a button
    // painted with it needs a foreground that flips too.
    expect(css).toContain('--bad-fg');
    expect(css).not.toMatch(/button\.danger\{background:var\(--bad\);color:#fff\}/);
  });
});
