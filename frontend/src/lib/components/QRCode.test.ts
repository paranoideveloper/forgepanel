import { describe, it, expect } from 'vitest';
import { render } from '@testing-library/svelte';
import QRCode from './QRCode.svelte';

describe('QRCode Component', () => {
  it('renders SVG for subscription value', () => {
    const { container } = render(QRCode, {
      value: 'sub-token-value',
      size: 150
    });
    expect(container.querySelector('svg')).toBeTruthy();
  });
});
