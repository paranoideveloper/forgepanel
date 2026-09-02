// Where this panel is deployed, and therefore which of its controls can do
// anything.
//
// The panel assumes a server the operator owns — its own ports, its own TLS, its
// own systemd, its own DNS. Deployed on Railway or Render, a third of the UI is
// controls for things the platform owns and the panel cannot touch. Showing them
// is worse than hiding them: an operator sets a port that will never be routed,
// or requests a certificate for a hostname the platform already terminates, and
// the failure surfaces far from the switch they flipped.
//
// So sections are REMOVED, not disabled. A disabled control still says "this
// exists and you may not use it", which is the wrong message when the truth is
// "the platform does this for you, and better".
//
// The rule is the SERVER's, mirrored: internal/deploy/surface.go owns the table
// of which section needs which capability, and GET /api/admin/deployment sends
// the already-computed answer — this holds no copy of the policy, only the
// verdict, so the two cannot drift.

import { apiFetch } from '$lib/api';

export interface DeploySurface {
	kind: 'vps' | 'paas';
	platform?: string;
	domain?: string;
	cdn_fronted?: boolean;
	can: Record<string, boolean>;
	why?: Record<string, string>;
}

class Deployment {
	surface = $state<DeploySurface | null>(null);
	/** Tab id -> why it is not shown here. */
	hidden = $state<Record<string, string>>({});
	loaded = $state(false);

	async load(): Promise<void> {
		try {
			const r = await apiFetch<{ surface: DeploySurface; hidden_sections: Record<string, string> }>(
				'/admin/deployment'
			);
			this.surface = r?.surface ?? null;
			this.hidden = r?.hidden_sections ?? {};
		} catch (_) {
			// A panel that cannot read its own deployment shows everything. Hiding
			// sections because ONE request failed would look like features
			// disappearing at random, and the failure mode of showing too much is
			// a control that does nothing — far milder than a control that is
			// gone.
			this.surface = null;
			this.hidden = {};
		} finally {
			this.loaded = true;
		}
	}
}

export const deployment = new Deployment();

/** Whether a navigation section applies to this deployment. */
export function sectionApplies(id: string): boolean {
	return !(id in deployment.hidden);
}

/** Why a section is absent, for anywhere that wants to say so. */
export function whySectionHidden(id: string): string {
	return deployment.hidden[id] ?? '';
}

/** Whether the environment permits a capability, e.g. 'own_tls'. */
export function can(capability: string): boolean {
	const s = deployment.surface;
	if (!s) return true;
	return s.can?.[capability] !== false;
}
