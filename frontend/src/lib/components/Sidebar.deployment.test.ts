import { describe, expect, it, beforeEach, vi } from 'vitest';
import { render } from '@testing-library/svelte';
import Sidebar from './Sidebar.svelte';
import { deployment } from '$lib/deployment.svelte';
import { session } from '$lib/session.svelte';

// A section the platform owns is REMOVED, not disabled. A disabled control
// still says "this exists and you may not use it", which is the wrong message
// when the truth is "the platform does this for you".

vi.mock('$lib/api', () => ({
	apiFetch: vi.fn(async () => ({ version: '1.0.0' })),
	setAuthToken: vi.fn(),
	getAuthToken: vi.fn(() => 't'),
	setSession: vi.fn(),
	clearSession: vi.fn()
}));

function mount() {
	return render(Sidebar, {
		props: { activeTab: 'overview', onTabChange: () => {} }
	});
}

describe('the sidebar follows the deployment', () => {
	beforeEach(() => {
		session.me = { admin_id: 1, username: 'owner', role: 'owner' };
		deployment.loaded = true;
		deployment.surface = null;
		deployment.hidden = {};
	});

	it('shows the infrastructure tabs on a server the operator owns', () => {
		const { getAllByText } = mount();
		// Certificates and Domains only make sense where the panel owns TLS.
		expect(getAllByText(/Certificates|گواهی/i).length).toBeGreaterThan(0);
	});

	it('removes the sections a platform owns', () => {
		deployment.surface = { kind: 'paas', platform: 'railway', can: { own_tls: false } };
		deployment.hidden = {
			certs: 'railway terminates TLS at its own edge',
			domains: 'railway owns the hostname',
			system: 'this is a container, not a host'
		};
		const { queryAllByText } = mount();
		expect(queryAllByText(/Certificates|گواهی/i).length).toBe(0);
	});

	it('keeps everything when the deployment cannot be read', () => {
		// One failed request must not look like features disappearing at random.
		deployment.surface = null;
		deployment.hidden = {};
		const { getAllByText } = mount();
		expect(getAllByText(/Certificates|گواهی/i).length).toBeGreaterThan(0);
	});

	it('still hides what the ROLE forbids, independently of the platform', () => {
		session.me = { admin_id: 2, username: 'v', role: 'viewer' };
		const { queryAllByText } = mount();
		// A viewer never sees Admins, regardless of where the panel runs.
		expect(queryAllByText(/Admins|مدیران/i).length).toBe(0);
	});
});
