// Who is signed in, and what they are allowed to reach.
//
// The panel had no concept of this. Both POST /login and GET /admin/me return
// the caller's role and nothing read it, so every one of the sixteen navigation
// tabs rendered for every principal — a reseller saw Certificates, Admins, the
// Audit trail, Nodes, Routing and ForgeDNS, clicked one, and got a 403 toast
// from a route the panel already knew they could not use. A viewer saw the same.
//
// The rule this encodes is the SERVER's, mirrored: internal/api/authz.go is the
// authority, and TestNavigationMatchesTheAuthzPolicy compares the two so a tab
// cannot drift into offering something the API refuses, nor hide something it
// would allow.

import { apiFetch } from '$lib/api';

export type Role = 'owner' | 'admin' | 'reseller' | 'viewer';

export interface Me {
	admin_id: number;
	username: string;
	role: Role;
	two_factor_enabled?: boolean;
	recovery_codes_remaining?: number;
}

class Session {
	me = $state<Me | null>(null);
	loaded = $state(false);
	error = $state('');

	/** The role, or the widest one while it is still unknown.
	 *
	 * Unknown resolves to 'owner' on purpose. The server enforces the policy;
	 * this only decides what to OFFER, and hiding a control an operator is
	 * entitled to — because a fetch was slow or failed — is a panel that looks
	 * broken. The failure mode of guessing too wide is a 403 they would have
	 * got anyway. */
	get role(): Role {
		return this.me?.role ?? 'owner';
	}

	get isOwner() { return this.role === 'owner'; }
	get isAdmin() { return this.role === 'owner' || this.role === 'admin'; }
	/** Owner, admin and reseller: the roles that manage customers. */
	get canManageTenants() { return this.role !== 'viewer'; }

	async load() {
		try {
			this.me = await apiFetch<Me>('/admin/me');
			this.error = '';
		} catch (e: any) {
			this.error = e?.message ?? 'could not read the current session';
		} finally {
			this.loaded = true;
		}
	}

	/** Test seam: set the role without a network round trip. */
	set(me: Me | null) {
		this.me = me;
		this.loaded = true;
	}
}

export const session = new Session();

/** Which roles may reach each navigation tab.
 *
 * Every entry mirrors internal/api/authz.go. Where a tab covers several routes
 * it takes the NARROWEST, because a tab that opens onto a page whose every
 * action 403s is worse than one that is absent.
 */
export const TAB_ROLES: Record<string, Role[]> = {
	// Dashboards a viewer may read.
	overview: ['owner', 'admin', 'reseller', 'viewer'],
	usage: ['owner', 'admin', 'reseller'],
	online: ['owner', 'admin', 'reseller'],

	// Customer management: the reseller's job.
	users: ['owner', 'admin', 'reseller'],

	// Infrastructure.
	inbounds: ['owner', 'admin'],
	routing: ['owner', 'admin'],
	nodes: ['owner', 'admin'],
	domains: ['owner', 'admin'],
	forgedns: ['owner', 'admin'],
	edge: ['owner', 'admin'],
	studio: ['owner', 'admin'],
	wizard: ['owner', 'admin'],
	audit: ['owner', 'admin'],

	// Owner only: accounts, the panel's own address and TLS material, backups.
	admins: ['owner'],
	certs: ['owner'],
	system: ['owner']
};

export function canSeeTab(tab: string, role: Role): boolean {
	const allowed = TAB_ROLES[tab];
	// An unlisted tab is shown. A new tab that nobody classified must not
	// disappear silently; the Go guard fails on it instead, which is a message
	// to a developer rather than a missing feature for an operator.
	return !allowed || allowed.includes(role);
}
