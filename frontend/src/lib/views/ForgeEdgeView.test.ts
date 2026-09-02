import { describe, it, expect } from 'vitest';
import { render, screen, fireEvent, waitFor } from '@testing-library/svelte';
import ForgeEdgeView from './ForgeEdgeView.svelte';

/** Bodies of every POST /admin/edge/deploy the view made. */
function mockEdge(deployReply: (body: any) => { ok?: boolean; status?: number; body?: any }) {
  const sent: any[] = [];
  (globalThis as any).fetch = async (url: string, opts?: any) => {
    let res: { ok?: boolean; status?: number; body?: any } = { body: {} };
    if (url.includes('/admin/edge/deploy') && opts?.method === 'POST') {
      const parsed = JSON.parse(opts.body);
      sent.push(parsed);
      res = deployReply(parsed);
    } else if (url.includes('/admin/edge/deployments')) res = { body: [] };
    else if (url.includes('/admin/edge/bundle')) res = { body: { embedded: true } };
    else if (url.includes('/admin/edge/token-url')) res = { body: { url: 'https://dash.cloudflare.com/token' } };
    return {
      ok: res.ok !== false,
      status: res.status || 200,
      json: async () => res.body ?? {}
    } as Response;
  };
  return sent;
}

/** Fill the two required credential fields, after the view's own load() has
 *  resolved — typing earlier is overwritten when `loading` flips and the form
 *  is rendered for the first time. */
async function fillCredentials() {
  const token = await screen.findByPlaceholderText('Cloudflare API token');
  await fireEvent.input(token, { target: { value: 'cf-token' } });
  await fireEvent.input(screen.getByPlaceholderText('32-char account id'), { target: { value: 'acct-1' } });
}

const okDeploy = {
  body: {
    deployment: {
      name: 'forgeedge-a1', origin: 'https://forgeedge-a1.acme.workers.dev',
      secure_path: 'abcdefgh', panel_url: '', subscription_template: '', doh_url: ''
    },
    registered: true
  }
};

describe('ForgeEdgeView deploy', () => {
  it('sends force:true when the overwrite box is ticked', async () => {
    // The form used to post only api_token/account_id/name/proxy_ip. `force`
    // was accepted by the handler and had no control, so an operator could
    // never redeploy over their own worker from the panel.
    const sent = mockEdge(() => okDeploy);
    render(ForgeEdgeView);
    await fillCredentials();

    await fireEvent.click(screen.getByTestId('edge-force'));
    await fireEvent.click(screen.getByTestId('edge-deploy'));

    await waitFor(() => expect(sent.length).toBe(1));
    expect(sent[0].force).toBe(true);
  });

  it('does not force by default', async () => {
    // Silently overwriting somebody else's worker is worse than the 409, so the
    // overwrite has to be asked for.
    const sent = mockEdge(() => okDeploy);
    render(ForgeEdgeView);
    await fillCredentials();

    await fireEvent.click(screen.getByTestId('edge-deploy'));

    await waitFor(() => expect(sent.length).toBe(1));
    expect(sent[0].force).toBe(false);
  });

  it('sends self_manage:true when the box is ticked', async () => {
    // The worker's own Deployment panel reads CF_API_TOKEN/CF_ACCOUNT_ID and
    // reports "no Cloudflare credential bound" without them. Nothing ever bound
    // them, so that panel has always been dark.
    const sent = mockEdge(() => okDeploy);
    render(ForgeEdgeView);
    await fillCredentials();

    await fireEvent.click(screen.getByTestId('edge-self-manage'));
    await fireEvent.click(screen.getByTestId('edge-deploy'));

    await waitFor(() => expect(sent.length).toBe(1));
    expect(sent[0].self_manage).toBe(true);
  });

  it('does not self-manage by default', async () => {
    // A token written into a worker is readable by anyone who can deploy to the
    // account, so it has to be asked for — never implied.
    const sent = mockEdge(() => okDeploy);
    render(ForgeEdgeView);
    await fillCredentials();

    await fireEvent.click(screen.getByTestId('edge-deploy'));

    await waitFor(() => expect(sent.length).toBe(1));
    expect(sent[0].self_manage).toBe(false);
  });

  it('offers an overwrite retry after a 409 and retries with force:true', async () => {
    // The dead end: 409 "a Worker named X already exists", a toast, and no
    // control anywhere in the view that could get past it.
    const sent = mockEdge((body) =>
      body.force
        ? okDeploy
        : { ok: false, status: 409, body: { error: 'a Worker named forgeedge-a1 already exists in this account', kind: 'conflict' } }
    );
    render(ForgeEdgeView);
    await fillCredentials();

    await fireEvent.click(screen.getByTestId('edge-deploy'));

    const retry = await screen.findByTestId('edge-force-retry');
    expect(screen.getByText(/already exists in this account/)).toBeTruthy();

    await fireEvent.click(retry);
    await waitFor(() => expect(sent.length).toBe(2));
    expect(sent[0].force).toBe(false);
    expect(sent[1].force).toBe(true);
    // The retry succeeded, so the offer must go away rather than sitting there
    // telling the operator about a collision they have already cleared.
    await waitFor(() => expect(screen.queryByTestId('edge-force-retry')).toBeNull());
  });

  it('does not offer the overwrite retry for a failure overwriting cannot fix', async () => {
    // A bad token is a 401. Offering "overwrite and redeploy" there would send
    // the operator round the same failure with a destructive flag set.
    const sent = mockEdge(() => ({ ok: false, status: 401, body: { error: 'Authentication error' } }));
    render(ForgeEdgeView);
    await fillCredentials();

    await fireEvent.click(screen.getByTestId('edge-deploy'));

    await waitFor(() => expect(sent.length).toBe(1));
    expect(screen.queryByTestId('edge-force-retry')).toBeNull();
  });
});
