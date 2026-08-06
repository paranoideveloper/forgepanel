import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, fireEvent } from '@testing-library/svelte';
import SystemHealthView from './SystemHealthView.svelte';

describe('SystemHealthView Component', () => {
  beforeEach(() => {
    vi.restoreAllMocks();
    vi.stubGlobal('confirm', () => true);
  });

  it('loads health details and audit logs including unhealthy subsystems', async () => {
    vi.stubGlobal('fetch', vi.fn().mockImplementation((url: string) => {
      if (url.includes('/admin/health/detail')) {
        return Promise.resolve({
          ok: true,
          json: async () => ({
            subsystems: [
              { name: 'Database', healthy: true, detail: 'SQLite operational' },
              { name: 'Xray Core', healthy: false, detail: 'Core process stopped' }
            ]
          })
        });
      }
      if (url.includes('/admin/stats')) {
        return Promise.resolve({ ok: true, json: async () => [] });
      }
      if (url.includes('/admin/me')) {
        return Promise.resolve({ ok: true, json: async () => ({ two_factor_enabled: false }) });
      }
      return Promise.resolve({ ok: true, json: async () => ({}) });
    }));

    render(SystemHealthView);

    expect(await screen.findByText('Database')).toBeTruthy();
    expect(screen.getByText('Xray Core')).toBeTruthy();
    expect(screen.getByText('Core process stopped')).toBeTruthy();
  });

  it('sets up 2FA TOTP, verifies code, and disables 2FA', async () => {
    vi.stubGlobal('fetch', vi.fn().mockImplementation((url: string, opts?: any) => {
      if (url.includes('/admin/2fa/setup') && opts?.method === 'POST') {
        return Promise.resolve({
          ok: true,
          json: async () => ({ secret: 'MYSECRET123', qr_code_url: 'otpauth://totp/test' })
        });
      }
      if (url.includes('/admin/2fa/enable') && opts?.method === 'POST') {
        return Promise.resolve({ ok: true, json: async () => ({ enabled: true }) });
      }
      if (url.includes('/admin/2fa/disable') && opts?.method === 'POST') {
        return Promise.resolve({ ok: true, json: async () => ({ enabled: false }) });
      }
      if (url.includes('/admin/me')) {
        return Promise.resolve({ ok: true, json: async () => ({ two_factor_enabled: false }) });
      }
      return Promise.resolve({ ok: true, json: async () => ({ subsystems: [] }) });
    }));

    render(SystemHealthView);

    const enableSetupBtn = await screen.findByText('Enable 2FA Authenticator');
    await fireEvent.click(enableSetupBtn);

    expect(await screen.findByText('Set Up 2FA Authenticator')).toBeTruthy();
    expect(screen.getByText('Secret key:')).toBeTruthy();

    const totpInput = screen.getByPlaceholderText('6-digit TOTP code');
    await fireEvent.input(totpInput, { target: { value: '123456' } });

    const verifyBtn = screen.getByText('Verify & Activate');
    await fireEvent.click(verifyBtn);

    expect(fetch).toHaveBeenCalledWith('/api/admin/2fa/enable', expect.objectContaining({ method: 'POST' }));
  });

  it('handles 2FA disable confirm cancel and errors', async () => {
    vi.stubGlobal('confirm', () => false);
    vi.stubGlobal('fetch', vi.fn().mockImplementation((url: string) => {
      if (url.includes('/admin/me')) {
        return Promise.resolve({ ok: true, json: async () => ({ two_factor_enabled: true }) });
      }
      return Promise.resolve({ ok: true, json: async () => ({ subsystems: [] }) });
    }));

    render(SystemHealthView);

    const disableBtn = await screen.findByText('Disable 2FA');
    await fireEvent.click(disableBtn);
    expect(fetch).not.toHaveBeenCalledWith('/api/admin/2fa/disable', expect.objectContaining({ method: 'POST' }));
  });

  it('changes admin password with validation and error handling', async () => {
    vi.stubGlobal('fetch', vi.fn().mockImplementation((url: string, opts?: any) => {
      if (url.includes('/admin/change-password') && opts?.method === 'POST') {
        return Promise.resolve({ ok: true, json: async () => ({ success: true }) });
      }
      return Promise.resolve({ ok: true, json: async () => ({ subsystems: [] }) });
    }));

    render(SystemHealthView);

    const updateBtn = await screen.findByText('Update Password');
    await fireEvent.click(updateBtn);
    expect(await screen.findByText('Both old and new passwords are required')).toBeTruthy();

    const oldInput = screen.getByPlaceholderText('Current Password');
    const newInput = screen.getByPlaceholderText('New Password');

    await fireEvent.input(oldInput, { target: { value: 'oldsecret' } });
    await fireEvent.input(newInput, { target: { value: 'newsecret' } });

    await fireEvent.click(updateBtn);
    expect(fetch).toHaveBeenCalledWith('/api/admin/change-password', expect.objectContaining({ method: 'POST' }));
  });

  it('generates Docker Compose YAML configuration and handles error paths', async () => {
    let callCount = 0;
    vi.stubGlobal('fetch', vi.fn().mockImplementation((url: string) => {
      if (url.includes('/deploy/compose')) {
        callCount++;
        if (callCount === 1) {
          return Promise.resolve({ ok: true, json: async () => ({ compose: 'services:\n  forgepanel:\n    image: forgepanel' }) });
        }
        return Promise.reject(new Error('Compose API failed'));
      }
      return Promise.resolve({ ok: true, json: async () => ({ subsystems: [] }) });
    }));

    render(SystemHealthView);

    const genBtn = await screen.findByText('Generate YAML');
    await fireEvent.click(genBtn);

    expect(await screen.findByText(/services:/)).toBeTruthy();

    await fireEvent.click(genBtn);
  });
});
