import { describe, it, expect, vi } from 'vitest';
import { render, fireEvent, screen } from '@testing-library/svelte';
import Sidebar from './Sidebar.svelte';

describe('Sidebar Component', () => {
  it('renders tabs and triggers tab change on click', async () => {
    const onTabChange = vi.fn();
    render(Sidebar, {
      activeTab: 'overview',
      onTabChange
    });

    expect(screen.getByText('ForgePanel')).toBeTruthy();
    expect(screen.getByText('Overview')).toBeTruthy();

    const usersTab = screen.getByText('Users & Subscriptions');
    await fireEvent.click(usersTab);
    expect(onTabChange).toHaveBeenCalledWith('users');
  });
});
