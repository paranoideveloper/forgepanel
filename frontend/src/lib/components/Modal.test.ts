import { describe, it, expect, vi } from 'vitest';
import { render, fireEvent, screen } from '@testing-library/svelte';
import Modal from './Modal.svelte';

describe('Modal Component', () => {
  it('renders modal when isOpen is true and handles backdrop click', async () => {
    const onClose = vi.fn();
    render(Modal, {
      title: 'Test Modal',
      isOpen: true,
      onClose
    });

    expect(screen.getByText('Test Modal')).toBeTruthy();

    const closeBtn = screen.getByText('✕');
    await fireEvent.click(closeBtn);
    expect(onClose).toHaveBeenCalledTimes(1);

    const backdrop = screen.getByTestId('backdrop');
    await fireEvent.click(backdrop);
    expect(onClose).toHaveBeenCalledTimes(2);

    await fireEvent.keyDown(backdrop, { key: 'Escape' });
    expect(onClose).toHaveBeenCalledTimes(3);
  });

  it('does not trigger close on dialog body click', async () => {
    const onClose = vi.fn();
    render(Modal, {
      title: 'Modal Title',
      isOpen: true,
      onClose
    });

    const dialog = screen.getByRole('dialog');
    await fireEvent.click(dialog);
    expect(onClose).not.toHaveBeenCalled();
  });
});
