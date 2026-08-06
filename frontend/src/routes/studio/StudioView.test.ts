import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, fireEvent } from '@testing-library/svelte';
import StudioView from './StudioView.svelte';

describe('StudioView Component', () => {
  beforeEach(() => {
    vi.restoreAllMocks();
    vi.stubGlobal('navigator', {
      clipboard: {
        writeText: vi.fn().mockResolvedValue(undefined)
      }
    });
  });

  it('loads presets, selects preset, updates input forms, generates keypair, and copies JSON', async () => {
    vi.stubGlobal('fetch', vi.fn().mockImplementation((url: string) => {
      if (url.includes('/keygen')) {
        return Promise.resolve({
          ok: true,
          json: async () => ({
            public_key: 'pub_key_123',
            private_key: 'priv_key_456'
          })
        });
      }
      return Promise.resolve({
        ok: true,
        json: async () => [
          { id: 'vless-reality', name: 'VLESS Reality', engine: 'xray', description: 'VLESS protocol', config: {} },
          { id: 'tuic-v5', name: 'TUIC v5', engine: 'tuic', description: 'TUIC protocol', config: {} }
        ]
      });
    }));

    render(StudioView);

    expect(await screen.findByText('VLESS Reality')).toBeTruthy();

    const tuicBtn = screen.getByText('TUIC v5');
    await fireEvent.click(tuicBtn);

    const portInput = screen.getByLabelText('Listen Port');
    await fireEvent.input(portInput, { target: { value: '8443' } });

    const keygenBtn = screen.getByText('Generate Keypair');
    await fireEvent.click(keygenBtn);

    expect(await screen.findByText('pub_key_123')).toBeTruthy();

    const copyBtn = screen.getByText('Copy JSON');
    await fireEvent.click(copyBtn);

    expect(navigator.clipboard.writeText).toHaveBeenCalled();
  });
});
