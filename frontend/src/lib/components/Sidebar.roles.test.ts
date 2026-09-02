import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { render, screen } from '@testing-library/svelte';
import Sidebar from './Sidebar.svelte';
import { session, TAB_ROLES, canSeeTab, type Role } from '$lib/session.svelte';

// Both POST /login and GET /admin/me have always returned the caller's role, and
// nothing in the frontend read it. All sixteen tabs rendered for every
// principal, so a reseller saw Certificates, Admins, the Audit trail, Nodes,
// Routing and ForgeDNS, clicked one, and got a 403 toast from a route the panel
// already knew they could not use.

function mount(role: Role) {
  session.set({ admin_id: 1, username: 'x', role });
  (globalThis as any).fetch = async () => ({ ok: true, json: async () => ({ version: 'v1.0.0' }) }) as Response;
  render(Sidebar, { props: { activeTab: 'overview', onTabChange: () => {} } });
}

// By tab id, not by label. The nodes tab reads "Node Cluster", so asserting
// that a reseller's navigation does not contain "Nodes" passed while the tab was
// right there — a test that could not fail against the bug it was written for.
const shown = () =>
  screen.queryAllByTestId(/^nav-/).map((b) => b.getAttribute('data-testid')!.slice(4));

describe('Sidebar role gating', () => {
  beforeEach(() => session.set(null));
  afterEach(() => {
    session.set(null);
    vi.restoreAllMocks();
  });

  it('shows an owner everything', () => {
    mount('owner');
    for (const tab of Object.keys(TAB_ROLES)) {
      expect(canSeeTab(tab, 'owner')).toBe(true);
    }
  });

  it('hides owner-only tabs from an admin', () => {
    mount('admin');
    const tabs = shown();
    // Accounts, the panel's own TLS material and backups are owner-only in
    // internal/api/authz.go.
    expect(tabs).not.toContain('admins');
    expect(tabs).not.toContain('certs');
    expect(tabs).not.toContain('system');
    // But infrastructure is an admin's job and must still be there.
    expect(tabs).toContain('inbounds');
    expect(tabs).toContain('nodes');
    expect(tabs).toContain('audit');
  });

  it('leaves a reseller with customer management and nothing else', () => {
    mount('reseller');
    const tabs = shown();
    expect(tabs).toContain('users');
    expect(tabs).toContain('overview');
    expect(tabs).toContain('usage');
    for (const gone of ['inbounds', 'routing', 'nodes', 'audit', 'forgedns', 'certs', 'admins', 'edge', 'studio']) {
      expect(tabs).not.toContain(gone);
    }
  });

  it('leaves a viewer with the dashboards it may read', () => {
    mount('viewer');
    const tabs = shown();
    expect(tabs).toContain('overview');
    // A viewer may read /admin/overview but not manage users, and the online
    // and usage views are tenant management.
    for (const gone of ['users', 'online', 'usage', 'inbounds', 'admins', 'certs']) {
      expect(tabs).not.toContain(gone);
    }
  });

  // The failure mode of guessing too wide is a 403 the operator would have got
  // anyway. The failure mode of guessing too narrow is a panel that looks
  // broken for someone entitled to use it, so an unknown role gets everything.
  it('offers everything while the role is still unknown', () => {
    session.set(null);
    expect(canSeeTab('certs', session.role)).toBe(true);
    expect(session.role).toBe('owner');
  });

  // A tab nobody classified must fail loudly for a developer (the Go guard),
  // not quietly for an operator.
  it('shows a tab that has no rule', () => {
    expect(canSeeTab('a-tab-nobody-classified', 'viewer')).toBe(true);
  });
});
