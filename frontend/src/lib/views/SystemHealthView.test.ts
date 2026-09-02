import { describe, it, expect, beforeEach } from 'vitest';
import { render, screen, fireEvent } from '@testing-library/svelte';
import SystemHealthView from './SystemHealthView.svelte';

describe('SystemHealthView Component', () => {
  beforeEach(() => {
    (globalThis as any).confirm = () => true;
  });

  it('loads health details and audit logs including unhealthy subsystems', async () => {
    (globalThis as any).fetch = async (url: string) => {
      if (url.includes('/admin/health/detail')) {
        return {
          ok: true,
          json: async () => ({
            subsystems: [
              { key: 'database', label: 'Database', state: 'healthy', summary: 'SQLite operational', detail: 'SQLite operational' },
              { key: 'xray', label: 'Xray Core', state: 'error', summary: 'Core process stopped', detail: 'Core process stopped' }
            ]
          })
        } as Response;
      }
      if (url.includes('/admin/stats')) {
        return { ok: true, json: async () => [] } as Response;
      }
      if (url.includes('/admin/me')) {
        return { ok: true, json: async () => ({ two_factor_enabled: false }) } as Response;
      }
      return { ok: true, json: async () => ({}) } as Response;
    };

    render(SystemHealthView);

    expect(await screen.findByText('Database')).toBeTruthy();
    expect(screen.getByText('Xray Core')).toBeTruthy();
    expect(screen.getByText('Core process stopped')).toBeTruthy();
  });

  it('sets up 2FA TOTP, verifies code, and disables 2FA', async () => {
    let enableCalled = false;
    let disableCalled = false;
    (globalThis as any).fetch = async (url: string, opts?: any) => {
      if (url.includes('/admin/2fa/setup') && opts?.method === 'POST') {
        return {
          ok: true,
          json: async () => ({ secret: 'MYSECRET123', qr_code_url: 'otpauth://totp/test' })
        } as Response;
      }
      if (url.includes('/admin/2fa/enable') && opts?.method === 'POST') {
        enableCalled = true;
        return { ok: true, json: async () => ({ enabled: true }) } as Response;
      }
      if (url.includes('/admin/2fa/disable') && opts?.method === 'POST') {
        disableCalled = true;
        return { ok: true, json: async () => ({ enabled: false }) } as Response;
      }
      if (url.includes('/admin/me')) {
        return { ok: true, json: async () => ({ two_factor_enabled: false }) } as Response;
      }
      return { ok: true, json: async () => ({ subsystems: [] }) } as Response;
    };

    render(SystemHealthView);

    const enableSetupBtn = await screen.findByText('Enable 2FA Authenticator');
    await fireEvent.click(enableSetupBtn);

    expect(await screen.findByText('Set Up 2FA Authenticator')).toBeTruthy();
    expect(screen.getByText('Secret key:')).toBeTruthy();

    const totpInput = screen.getByPlaceholderText('6-digit TOTP code');
    await fireEvent.input(totpInput, { target: { value: '123456' } });

    const verifyBtn = screen.getByText('Verify & Activate');
    await fireEvent.click(verifyBtn);

    expect(enableCalled).toBe(true);
  });

  // Disabling 2FA now asks for a current authenticator code rather than a bare
  // confirm(). The handler has always verified one; posting no body meant every
  // attempt 400'd and the Disable button simply did not work.
  it('does not disable 2FA until a current code is supplied, then sends it', async () => {
    let disableBody: any = null;
    (globalThis as any).fetch = async (url: string, opts?: any) => {
      if (opts?.method === 'POST' && url.includes('/2fa/disable')) {
        disableBody = JSON.parse(opts.body);
        return { ok: true, json: async () => ({ enabled: false }) } as Response;
      }
      if (url.includes('/admin/me')) {
        return { ok: true, json: async () => ({ two_factor_enabled: true, recovery_codes_remaining: 8 }) } as Response;
      }
      return { ok: true, json: async () => ({ subsystems: [] }) } as Response;
    };

    render(SystemHealthView);

    // Opening the dialog must not itself disable anything.
    await fireEvent.click(await screen.findByText('Disable 2FA'));
    expect(disableBody).toBeNull();

    // Submitting with no code must not reach the API either.
    const buttons = screen.getAllByText('Disable 2FA');
    await fireEvent.click(buttons[buttons.length - 1]);
    expect(disableBody).toBeNull();

    await fireEvent.input(screen.getByTestId('disable-2fa-code'), { target: { value: '654321' } });
    const again = screen.getAllByText('Disable 2FA');
    await fireEvent.click(again[again.length - 1]);
    expect(disableBody).toEqual({ code: '654321' });
  });

  // The recovery codes are stored ONLY as SHA-256 hashes, so the enable response
  // is the single moment they exist in plaintext. Discarding it — which the view
  // used to do — destroyed them, and because enabling also revokes every session,
  // it locked the operator out with no way back in.
  it('shows the recovery codes returned when 2FA is enabled', async () => {
    (globalThis as any).fetch = async (url: string, opts?: any) => {
      if (url.includes('/admin/2fa/setup') && opts?.method === 'POST') {
        return { ok: true, json: async () => ({ secret: 'S', qr_code_url: 'otpauth://totp/t' }) } as Response;
      }
      if (url.includes('/admin/2fa/enable') && opts?.method === 'POST') {
        return {
          ok: true,
          json: async () => ({
            enabled: true,
            recovery_codes: ['aaaa-1111', 'bbbb-2222', 'cccc-3333'],
            access_token: 'fresh-token',
            sessions_revoked: true
          })
        } as Response;
      }
      if (url.includes('/admin/me')) {
        return { ok: true, json: async () => ({ two_factor_enabled: false }) } as Response;
      }
      return { ok: true, json: async () => ({ subsystems: [] }) } as Response;
    };

    render(SystemHealthView);
    await fireEvent.click(await screen.findByText('Enable 2FA Authenticator'));
    await screen.findByText('Set Up 2FA Authenticator');
    await fireEvent.input(screen.getByPlaceholderText('6-digit TOTP code'), { target: { value: '123456' } });
    await fireEvent.click(screen.getByText('Verify & Activate'));

    const codes = await screen.findByTestId('recovery-codes');
    expect(codes.textContent).toContain('aaaa-1111');
    expect(codes.textContent).toContain('cccc-3333');
    // Enabling revokes every session; without adopting the fresh token this tab
    // is signed out and every later request 401s.
    expect(localStorage.getItem('forge_token')).toBe('fresh-token');
  });

  // handleMe never returned two_factor_enabled, so the card read undefined and
  // showed 2FA as OFF for an admin who had it ON.
  it('reflects the enabled state and remaining recovery codes from /admin/me', async () => {
    (globalThis as any).fetch = async (url: string) => {
      if (url.includes('/admin/me')) {
        return { ok: true, json: async () => ({ two_factor_enabled: true, recovery_codes_remaining: 2 }) } as Response;
      }
      return { ok: true, json: async () => ({ subsystems: [] }) } as Response;
    };

    render(SystemHealthView);

    expect(await screen.findByText('2FA Enabled')).toBeTruthy();
    expect(screen.getByText(/2 recovery codes left/)).toBeTruthy();
    // Two left is close enough to zero that the operator must be told plainly.
    expect(screen.getByText(/Regenerate now/)).toBeTruthy();
  });

  it('changes admin password with validation and error handling', async () => {
    let passCalled = false;
    (globalThis as any).fetch = async (url: string, opts?: any) => {
      if (url.includes('/admin/change-password') && opts?.method === 'POST') {
        passCalled = true;
        return { ok: true, json: async () => ({ success: true }) } as Response;
      }
      return { ok: true, json: async () => ({ subsystems: [] }) } as Response;
    };

    render(SystemHealthView);

    const updateBtn = await screen.findByText('Update Password');
    await fireEvent.click(updateBtn);
    expect(await screen.findByText('Both old and new passwords are required')).toBeTruthy();

    const oldInput = screen.getByPlaceholderText('Current Password');
    const newInput = screen.getByPlaceholderText('New Password');

    await fireEvent.input(oldInput, { target: { value: 'oldsecret' } });
    await fireEvent.input(newInput, { target: { value: 'newsecret' } });

    await fireEvent.click(updateBtn);
    expect(passCalled).toBe(true);
  });

  it('generates Docker Compose YAML configuration and handles error paths', async () => {
    let callCount = 0;
    (globalThis as any).fetch = async (url: string) => {
      if (url.includes('/deploy/compose')) {
        callCount++;
        if (callCount === 1) {
          return { ok: true, json: async () => ({ compose: 'services:\n  forgepanel:\n    image: forgepanel' }) } as Response;
        }
        throw new Error('Compose API failed');
      }
      return { ok: true, json: async () => ({ subsystems: [] }) } as Response;
    };

    render(SystemHealthView);

    const genBtn = await screen.findByText('Generate YAML');
    await fireEvent.click(genBtn);

    expect(await screen.findByText(/services:/)).toBeTruthy();

    await fireEvent.click(genBtn);
  });
});
