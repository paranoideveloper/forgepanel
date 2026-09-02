<script lang="ts">
	import { tr } from '$lib/i18n';
  import { onMount, onDestroy } from 'svelte';
  import { apiFetch } from '$lib/api';
  import { isPresent } from '$lib/presence';
  import type { User, UserGroup } from '$lib/types';
  import Modal from '$lib/components/Modal.svelte';
  import QRCode from '$lib/components/QRCode.svelte';
  import { showToast } from '$lib/components/Toast.svelte';

  interface Inbound { id: number; remark: string; protocol: string; port: number; }
  // A saved plan. Only the fields this view renders or sends are declared; the
  // stamping itself happens server-side from template_id.
  interface UserTemplate {
    id: number; name: string; note?: string; data_limit?: number; expire_days?: number;
    reset_strategy?: string; status?: string; group_id?: number; inbound_ids?: number[];
    ip_limit?: number; username_prefix?: string; username_suffix?: string;
  }

  let users = $state<User[]>([]);
  let groups = $state<UserGroup[]>([]);
  let inbounds = $state<Inbound[]>([]);
  let templates = $state<UserTemplate[]>([]);
  let loading = $state(true);

  // create user
  let newUsername = $state('');
  let newGroupId = $state<number | undefined>(undefined);
  let newTemplateId = $state<number | undefined>(undefined);
  let newLimitGB = $state(0);
  let newExpireDays = $state(0);
  let createErr = $state('');

  // sub modal
  let subModalOpen = $state(false);
  let activeSubUser = $state<User | null>(null);
  let subFormat = $state('v2ray');
  // Subscription-fetch telemetry, loaded when the modal opens. Without it the
  // panel could not tell "imported the link and it is broken" from "never
  // imported the link", which is the first thing support has to establish.
  interface SubRequestRow { created_at: string; format: string; user_agent: string; ip: string; }
  let subReqs = $state<SubRequestRow[]>([]);
  let subLastFetch = $state<string | null>(null);
  let subLastUA = $state('');
  // Client app names, not prose: "Quantumult X" is what the app is called in
  // every language. An unknown format still renders under its wire name, so a
  // format added server-side appears here without a frontend change.
  const SUB_FORMAT_NAMES: Record<string, string> = {
    'v2ray': 'v2rayN / v2rayNG', 'clash': 'Clash', 'clash-meta': 'Clash.Meta / Mihomo',
    'sing-box': 'sing-box', 'xray': 'Xray JSON', 'surge': 'Surge', 'loon': 'Loon',
    'quantumultx': 'Quantumult X', 'links': 'Plain links', 'json': 'JSON'
  };
  const subFormatLabel = (f: string) => SUB_FORMAT_NAMES[f] ?? f;

  const subUrl = $derived.by(() => {
    if (!activeSubUser) return '';
    const base = `${window.location.origin}/sub/${activeSubUser.sub_token}`;
    return subFormat === 'v2ray' ? base : `${base}/${subFormat}`;
  });

  // manage (edit + assign) modal
  let manageOpen = $state(false);
  let mUser = $state<User | null>(null);
  let mLimitGB = $state(0);
  let mExpireDays = $state(0);
  let mIPLimit = $state(0);
  let mReset = $state('no_reset');
  let mExpireAt = $state('');       // absolute, yyyy-mm-dd; '' clears
  let mTelegramID = $state('');
  let mNote = $state('');
  let mUpdatedAt = $state('');      // optimistic-concurrency token
  let mSubRevoked = $state(false);
  let mStatus = $state('active');
  let mGroupId = $state<number | undefined>(undefined);
  let mAssigned = $state<Set<number>>(new Set());
  let mInherited = $state<Set<number>>(new Set());

  // saved-plan modal
  let planOpen = $state(false);
  let pEditing = $state<UserTemplate | null>(null);
  let pName = $state('');
  let pNote = $state('');
  let pLimitGB = $state(0);
  let pExpireDays = $state(0);
  let pIPLimit = $state(0);
  let pReset = $state('no_reset');
  let pStatus = $state('active');
  let pGroupId = $state<number | undefined>(undefined);
  let pPrefix = $state('');
  let pSuffix = $state('');
  let pInbounds = $state<Set<number>>(new Set());

  // groups modal
  let groupOpen = $state(false);
  let gEditing = $state<UserGroup | null>(null);
  let gName = $state('');
  let gDesc = $state('');
  let gIsDefault = $state(false);
  let gInbounds = $state<Set<number>>(new Set());

  // subscription defaults applied to every generated config. Routing reaches all
  // three cores; TLS fragmentation only the two that can express it.
  interface FancyTheme { id: string; label: string; template: string; front: string; proto: string; sample: string; }
  interface SubSettings { routing_preset: string; fragment: boolean; presets: string[]; name_template?: string; name_tokens?: string[]; pattern?: string; pattern_modes?: string[]; front_domain?: string; front_mode?: string; front_modes?: string[]; fancy_themes?: FancyTheme[]; formats?: string[]; expand_sni?: boolean; front_clean_ip?: boolean; clean_ips?: string; fragment_level?: string; fragment_levels?: string[]; fragment_cores?: string; fragment_cores_supported?: string[]; }
  let subSettings = $state<SubSettings | null>(null);
  // The panel refuses a settings save per KEY now, with a reason for each one.
  // Kept here rather than shown only as a toast: this card writes nine settings
  // at once, and "invalid value" in a banner that disappears in three seconds
  // does not tell an operator which of the nine it was.
  let subErrors = $state<Record<string, string>>({});
  const frontKeys = ['sub_front_domain', 'sub_front_mode'];
  const subCardErrors = $derived(Object.entries(subErrors).filter(([k]) => !frontKeys.includes(k)));
  const frontCardErrors = $derived(Object.entries(subErrors).filter(([k]) => frontKeys.includes(k)));
  // The formats come from the server, which is the only thing that knows what it
  // can render. Hardcoding them here left six of nine renderers unreachable from
  // the panel, Surge/Loon/Quantumult X among them.
  const subFormats = $derived(subSettings?.formats ?? ['v2ray', 'clash', 'sing-box']);

  interface Quota {
    role: string;
    unlimited: boolean;
    user_quota: number;
    users_used: number;
    users_remaining?: number;
    traffic_credit: number;
    traffic_allocated: number;
    traffic_remaining?: number;
  }
  let quota = $state<Quota | null>(null);
  let groupDeleteOpen = $state(false);
  let pendingGroupDelete = $state<UserGroup | null>(null);
  let groupDeleteMembers = $state<User[]>([]);
  let groupReassignTo = $state(0);
  let role = $state('');
  // Group routes are owner/admin-only. Rendering their controls to a reseller
  // offers buttons the handler refuses — the UI promising something the API
  // will not do.
  let canManageGroups = $derived(role === 'owner' || role === 'admin');
  // The fragment core list is one comma-joined string on the wire — that is how
  // the settings registry stores a list — and a checkbox per core here. Only the
  // cores the server says can fragment are offered: Clash-Meta has no fragment
  // primitive, so a checkbox for it would promise something no generated Clash
  // config could deliver.
  const fragmentCoresSupported = $derived(subSettings?.fragment_cores_supported ?? ['xray', 'sing-box']);
  const fragmentCores = $derived(
    (subSettings?.fragment_cores ?? '').split(',').map((c) => c.trim().toLowerCase()).filter(Boolean)
  );
  function toggleFragmentCore(core: string) {
    if (!subSettings) return;
    const on = new Set(fragmentCores);
    if (on.has(core)) on.delete(core);
    else on.add(core);
    // Rebuilt from the supported list so the stored order is stable whichever
    // box was clicked first.
    subSettings.fragment_cores = fragmentCoresSupported.filter((c) => on.has(c)).join(', ');
  }


  // Saved plans are tenant management, so unlike groups a reseller may keep
  // their own. A viewer may not, and rendering the controls to one would offer
  // buttons the handler refuses.
  let canManagePlans = $derived(role === 'owner' || role === 'admin' || role === 'reseller');
  const routingLabels: Record<string, string> = {
    iran: 'Iran (bypass Iran + block ads/malware)',
    full: 'Full (bypass Iran + block ads/malware/porn/QUIC)',
    block: 'Block-only (ads/malware, no Iran bypass)',
    off: 'Off (no routing rules)'
  };

  async function saveSubSettings() {
    if (!subSettings) return;
    subErrors = {};
    try {
      await apiFetch('/admin/settings/subscription', {
        method: 'POST',
        body: JSON.stringify({
          routing_preset: subSettings.routing_preset,
          fragment: subSettings.fragment,
          name_template: subSettings.name_template ?? '',
          pattern: subSettings.pattern ?? 'off',
          front_domain: subSettings.front_domain ?? '',
          front_mode: subSettings.front_mode ?? 'none',
          fragment_level: subSettings.fragment_level ?? 'medium',
          fragment_cores: subSettings.fragment_cores ?? 'xray, sing-box',
          // Three settings the renderer reads on every request. Two could only
          // be written as a side effect of applying a Preset Wizard theme, and
          // the clean-IP list could not be seen at all.
          expand_sni: subSettings.expand_sni ?? true,
          front_clean_ip: subSettings.front_clean_ip ?? false,
          clean_ips: subSettings.clean_ips ?? ''
        })
      });
      showToast(tr('users.subscription_defaults_saved'), 'success');
    } catch (err: any) {
      subErrors = err.fields ?? {};
      showToast(err.message || tr('users.failed_to_save'), 'error');
    }
  }

  // Fancy wizard: apply a styled theme (sets the name template + fronting model
  // server-side in one step) together with the operator's camouflage domain.
  async function applyFancyTheme(theme: FancyTheme) {
    if (!subSettings) return;
    subErrors = {};
    try {
      const res = await apiFetch<{ name_template?: string; front_domain?: string; front_mode?: string }>('/admin/settings/subscription', {
        method: 'POST',
        body: JSON.stringify({ fancy_theme: theme.id, front_domain: subSettings.front_domain ?? '' })
      });
      subSettings.name_template = res.name_template ?? theme.template;
      subSettings.front_mode = res.front_mode ?? theme.front;
      showToast(tr('users.applied_theme_label_p2', { label: theme.label, p2: theme.front === 'none' ? tr('users.no_fronting') : theme.front.toUpperCase() }), 'success');
    } catch (err: any) {
      subErrors = err.fields ?? {};
      showToast(err.message || tr('users.failed_to_apply_theme'), 'error');
    }
  }

  async function loadData() {
    loading = true;
    try {
      // Quota first: it is the one endpoint every role may call, and its
      // response carries the caller's ROLE — which decides what the rest of
      // this view may even ask for.
      try {
        quota = await apiFetch<Quota>('/admin/quota');
        role = quota?.role ?? '';
      } catch (_) {
        quota = null;
      }

      users = await apiFetch<User[]>('/admin/users');
      inbounds = await apiFetch<Inbound[]>('/admin/inbounds');

      // Groups and subscription settings are owner/admin-only. They used to be
      // awaited inline, so for a reseller or viewer the 403 threw out of
      // loadData and the ENTIRE view failed with an "insufficient role" toast —
      // no users, no inbounds, nothing. A permission they were never meant to
      // have took away the part they were.
      try {
        groups = await apiFetch<UserGroup[]>('/admin/groups');
      } catch (_) {
        groups = [];
      }
      try {
        subSettings = await apiFetch<SubSettings>('/admin/settings/subscription');
      } catch (_) {
        subSettings = null;
      }
      // Saved plans are tenant management, so a viewer is refused them. Same
      // treatment as groups above: an endpoint this role was never meant to
      // reach must not take away the part of the view they were.
      try {
        templates = await apiFetch<UserTemplate[]>('/admin/user-templates');
      } catch (_) {
        templates = [];
      }
    } catch (err: any) {
      showToast(err.message || tr('users.failed_to_load_users'), 'error');
    } finally {
      loading = false;
    }
  }

  async function createUser() {
    createErr = '';
    if (!newUsername.trim()) { createErr = 'Username is required'; return; }
    try {
      await apiFetch('/admin/users', {
        method: 'POST',
        body: JSON.stringify({ username: newUsername.trim(), group_id: newGroupId,
          // The saved plan supplies the BASE limits; anything typed here still
          // wins, so picking a plan never discards what is in the boxes.
          template_id: newTemplateId || 0,
          // Bytes, not whole gigabytes: a 500 MB trial sent as data_limit_gb
          // truncates to 0, and 0 is UNLIMITED.
          data_limit: Math.round((newLimitGB || 0) * 1024 ** 3),
          expire_days: newExpireDays || 0 }),
      });
      newUsername = ''; newLimitGB = 0; newExpireDays = 0;
      showToast(tr('users.user_created'), 'success');
      await loadData();
    } catch (err: any) { createErr = err.message || tr('users.failed_to_create_user'); }
  }

  async function setStatus(user: User, status: string) {
    try {
      await apiFetch(`/admin/users/${user.id}`, { method: 'PATCH', body: JSON.stringify({ status }) });
      showToast(tr('users.user_status', { status }), 'info');
      await loadData();
    } catch (err: any) { showToast(err.message || tr('users.failed_to_update_user'), 'error'); }
  }

  // Rotation is SELECTIVE. The API has always taken three independent flags,
  // and the panel sent all three every time — so an operator who only wanted to
  // hand out a fresh subscription link (a leaked URL, a departing housemate) also
  // rotated the UUID and password, breaking every client config the user had
  // already imported. Those are different blast radii and they need different
  // buttons.
  let rotateOpen = $state(false);
  let rotateUser = $state<User | null>(null);
  let rotateSub = $state(true);
  let rotateUUID = $state(false);
  let rotatePassword = $state(false);
  let rotating = $state(false);

  function openRotate(user: User) {
    rotateUser = user;
    // Default to the narrow one: it is the common case and the only one that
    // does not invalidate configs already in people's hands.
    rotateSub = true;
    rotateUUID = false;
    rotatePassword = false;
    rotateOpen = true;
  }

  const rotateNothing = $derived(!rotateSub && !rotateUUID && !rotatePassword);

  async function doRotate() {
    if (!rotateUser || rotateNothing) return;
    rotating = true;
    try {
      // The handler refuses a request that names nothing to rotate
      // ("specify at least one of uuid, password, sub_token"), so posting an
      // empty body made credential rotation impossible from the panel.
      const res = await apiFetch<{ sub_url: string }>(
        `/admin/users/${rotateUser.id}/reset-credentials`,
        {
          method: 'POST',
          body: JSON.stringify({ uuid: rotateUUID, password: rotatePassword, sub_token: rotateSub })
        }
      );
      rotateOpen = false;
      // The new subscription URL is the point of the operation; making the
      // operator hunt for it afterwards is how the old link keeps being sent.
      if (rotateSub && res?.sub_url) {
        try {
          await navigator.clipboard.writeText(res.sub_url);
          showToast(tr('users.rotated_new_subscription_link_copied'), 'success');
        } catch {
          showToast(tr('users.rotated_the_subscription_link_is_in'), 'success');
        }
      } else {
        showToast(tr('users.rotated'), 'success');
      }
      await loadData();
    } catch (err: any) {
      showToast(err.message || tr('users.failed_to_rotate'), 'error');
    } finally {
      rotating = false;
    }
  }

  // toggleSubRevoked stops (or restores) a leaked subscription URL WITHOUT
  // invalidating the credentials in every config the user already imported,
  // which is what rotating does.
  async function toggleSubRevoked(u: User, revoked: boolean) {
    try {
      await apiFetch(`/admin/users/${u.id}/sub-revoked`, {
        method: 'POST', body: JSON.stringify({ revoked })
      });
      showToast(revoked ? tr('users.sub_revoked') : tr('users.sub_restored'), 'success');
      await loadData();
    } catch (err: any) {
      showToast(err.message || tr('users.failed_to_save'), 'error');
    }
  }

  async function deleteUser(id: number) {
    if (!confirm(tr('users.delete_this_user'))) return;
    try {
      await apiFetch(`/admin/users/${id}`, { method: 'DELETE' });
      showToast(tr('users.user_deleted'), 'info');
      await loadData();
    } catch (err: any) { showToast(err.message || tr('users.failed_to_delete'), 'error'); }
  }

  async function openSubModal(user: User) {
    // Open first, then load: a telemetry failure must never withhold the URL and
    // QR the operator actually came here for.
    activeSubUser = user; subModalOpen = true;
    subReqs = []; subLastFetch = null; subLastUA = '';
    try {
      const r = await apiFetch<{ items: SubRequestRow[]; last_fetch_at: string | null; last_user_agent: string }>(
        `/admin/users/${user.id}/sub-requests`
      );
      subReqs = r.items ?? [];
      subLastFetch = r.last_fetch_at ?? null;
      subLastUA = r.last_user_agent ?? '';
    } catch (_) { /* the modal still shows the URL and QR */ }
  }
  async function copySubUrl() {
    try { await navigator.clipboard.writeText(subUrl); showToast(tr('users.copied'), 'success'); }
    catch (_) { showToast(tr('users.failed_to_copy'), 'error'); }
  }

  // Applying a saved plan to an account that already exists. The endpoint was
  // routed and store-backed with nothing in the UI reaching it, so half of what
  // "saved plans" means — restamping an account onto a different plan — was
  // available only to somebody writing the REST call by hand.
  let mTemplateId = $state<number | undefined>(undefined);
  let mApplyBusy = $state(false);

  async function applyPlan() {
    if (!mUser || !mTemplateId) return;
    mApplyBusy = true;
    try {
      await apiFetch(`/admin/users/${mUser.id}/apply-template`, {
        method: 'POST',
        body: JSON.stringify({ template_id: mTemplateId })
      });
      showToast(tr('users.plan_applied'), 'success');
      mUser = null;
      await loadData();
    } catch (e: any) {
      showToast(e.message || tr('users.plan_apply_failed'), 'error');
    } finally {
      mApplyBusy = false;
    }
  }

  // --- manage (edit + assign inbounds) ---
  async function openManage(user: User) {
    mUser = user;
    mTemplateId = undefined;
    mLimitGB = Number(((((user as any).data_limit || 0) / (1024 ** 3)).toFixed(3)));
    mStatus = (user as any).status || 'active';
    mGroupId = user.group_id;
    mExpireDays = 0;
    mIPLimit = (user as any).ip_limit || 0;
    mReset = (user as any).reset_strategy || 'no_reset';
    // The current expiry was never shown anywhere: it was write-only and
    // relative-only, so an operator could extend an expiry they could not see
    // and could never set an exact date or clear one.
    mExpireAt = (user as any).expire_at ? String((user as any).expire_at).slice(0, 10) : '';
    mTelegramID = String((user as any).telegram_id ?? '');
    mNote = (user as any).note ?? '';
    mUpdatedAt = (user as any).updated_at ?? '';
    mSubRevoked = Boolean((user as any).sub_revoked_at);
    mAssigned = new Set();
    mInherited = new Set();
    try {
      const res = await apiFetch<{ assignments: { direct: number[]; inherited: number[] } }>(`/admin/users/${user.id}`);
      mAssigned = new Set(res.assignments?.direct || []);
      mInherited = new Set(res.assignments?.inherited || []);
    } catch (_) {}
    manageOpen = true;
  }

  // A held user is still "active": the hold is transient and self-clearing, and
  // folding it into status would overwrite the account's real state.
  function isIPHeld(u: User): boolean {
    const until = (u as any).ip_limited_until;
    if (!until) return false;
    const t = new Date(until).getTime();
    return !Number.isNaN(t) && t > Date.now();
  }

  function toggleAssign(id: number) {
    const s = new Set(mAssigned);
    if (s.has(id)) s.delete(id); else s.add(id);
    mAssigned = s;
  }

  async function saveManage() {
    if (!mUser) return;
    try {
      // group_id is sent as a NUMBER, and "no group" is 0.
      //
      // It used to be `mGroupId` straight through, which is undefined for "No
      // group" — and JSON.stringify DROPS an undefined value, so the PATCH
      // carried no group_id at all and a user could never be taken out of a
      // group. The control worked, the request simply did not contain it.
      const patch: Record<string, any> = {
        status: mStatus,
        group_id: mGroupId ?? 0,
        ip_limit: mIPLimit
      };
      // data_limit only when it actually changed, and never for a reseller: it
      // is outside resellerUserFields, so including it untouched made EVERY
      // reseller edit fail with a 422 about a field they had not touched.
      // GB may be fractional. It was parsed as a whole number, so a 500 MB
      // trial became 0 — and 0 means UNLIMITED, the exact opposite of the
      // intent. Rounded to bytes, not truncated to gigabytes.
      const originalGB = ((mUser as any).data_limit || 0) / (1024 ** 3);
      if (Math.abs(mLimitGB - originalGB) > 1e-9) patch.data_limit = Math.round(mLimitGB * 1024 ** 3);

      patch.reset_strategy = mReset;
      patch.telegram_id = Number(mTelegramID) || 0;
      patch.note = mNote;

      // Expiry: an absolute date wins, a relative extension is still offered,
      // and an empty date CLEARS it — which was previously impossible.
      if (mExpireDays > 0) {
        patch.expire_at = new Date(Date.now() + mExpireDays * 86400_000).toISOString();
      } else if (mExpireAt) {
        patch.expire_at = new Date(mExpireAt + 'T00:00:00Z').toISOString();
      } else {
        patch.expire_at = '';
      }

      // The optimistic-concurrency token. The UI read updated_at and never sent
      // it, so the backend's ifUnchanged check never engaged and two admins
      // editing the same user silently overwrote each other — last write wins,
      // no warning to either.
      if (mUpdatedAt) patch.updated_at = mUpdatedAt;
      await apiFetch(`/admin/users/${mUser.id}`, { method: 'PATCH', body: JSON.stringify(patch) });
      await apiFetch(`/admin/users/${mUser.id}/inbounds`, { method: 'PUT', body: JSON.stringify({ inbound_ids: [...mAssigned] }) });
      showToast(tr('users.user_updated_inbounds_assigned'), 'success');
      manageOpen = false;
      await loadData();
    } catch (err: any) { showToast(err.message || tr('users.failed_to_save'), 'error'); }
  }

  // --- saved plans ---
  // Built here rather than inline in the template: the affixes surround the
  // typed name, and showing them as "tr-…-x" is the only rendering that makes
  // the shape of the generated username obvious at a glance.
  const affixLabel = (t: UserTemplate) => `${t.username_prefix ?? ''}…${t.username_suffix ?? ''}`;
  function openPlanNew() {
    pEditing = null; pName = ''; pNote = ''; pLimitGB = 0; pExpireDays = 0; pIPLimit = 0;
    pReset = 'no_reset'; pStatus = 'active'; pGroupId = undefined; pPrefix = ''; pSuffix = '';
    pInbounds = new Set(); planOpen = true;
  }
  function openPlanEdit(t: UserTemplate) {
    pEditing = t; pName = t.name; pNote = t.note ?? '';
    pLimitGB = (t.data_limit ?? 0) / 1024 ** 3;
    pExpireDays = t.expire_days ?? 0; pIPLimit = t.ip_limit ?? 0;
    pReset = t.reset_strategy || 'no_reset'; pStatus = t.status || 'active';
    pGroupId = t.group_id || undefined;
    pPrefix = t.username_prefix ?? ''; pSuffix = t.username_suffix ?? '';
    pInbounds = new Set(t.inbound_ids ?? []); planOpen = true;
  }
  function togglePlanInbound(id: number) {
    const s = new Set(pInbounds); if (s.has(id)) s.delete(id); else s.add(id); pInbounds = s;
  }
  async function savePlan() {
    if (!pName.trim()) { showToast(tr('users.plan_name_required'), 'error'); return; }
    const body = JSON.stringify({
      name: pName.trim(), note: pNote,
      // Bytes, like the create form: a 500 MB plan expressed in whole
      // gigabytes truncates to 0, and 0 is UNLIMITED.
      data_limit: Math.round((pLimitGB || 0) * 1024 ** 3),
      expire_days: pExpireDays || 0, ip_limit: pIPLimit || 0,
      reset_strategy: pReset, status: pStatus, group_id: pGroupId || 0,
      inbound_ids: [...pInbounds],
      username_prefix: pPrefix, username_suffix: pSuffix
    });
    try {
      if (pEditing) {
        await apiFetch(`/admin/user-templates/${pEditing.id}`, { method: 'PATCH', body });
      } else {
        await apiFetch('/admin/user-templates', { method: 'POST', body });
      }
      showToast(tr('users.plan_saved'), 'success'); planOpen = false; await loadData();
    } catch (err: any) { showToast(err.message || tr('users.failed_to_save_plan'), 'error'); }
  }
  async function deletePlan(t: UserTemplate) {
    // No confirmation beyond this one: deleting a plan cannot touch an account.
    // A plan is stamped at creation, so the users made from it hold values, not
    // a reference, and keep exactly the limits they were sold.
    if (!confirm(tr('users.delete_plan_name', { name: t.name }))) return;
    try {
      await apiFetch(`/admin/user-templates/${t.id}`, { method: 'DELETE' });
      if (newTemplateId === t.id) newTemplateId = undefined;
      showToast(tr('users.plan_deleted'), 'info'); await loadData();
    } catch (err: any) { showToast(err.message || tr('users.failed_to_delete_plan'), 'error'); }
  }

  // --- groups ---
  function openGroupNew() { gEditing = null; gName = ''; gDesc = ''; gIsDefault = false; gInbounds = new Set(); groupOpen = true; }
  function openGroupEdit(g: UserGroup) {
    gEditing = g; gName = g.name; gDesc = (g as any).description || '';
    gIsDefault = Boolean((g as any).is_default);
    gInbounds = new Set(((g as any).inbound_ids || []) as number[]); groupOpen = true;
  }
  function toggleGroupInbound(id: number) {
    const s = new Set(gInbounds); if (s.has(id)) s.delete(id); else s.add(id); gInbounds = s;
  }
  async function saveGroup() {
    if (!gName.trim()) { showToast(tr('users.group_name_required'), 'error'); return; }
    try {
      if (gEditing) {
        await apiFetch(`/admin/groups/${gEditing.id}`, { method: 'PATCH',
          body: JSON.stringify({ name: gName, description: gDesc, is_default: gIsDefault, inbound_ids: [...gInbounds] }) });
      } else {
        const g = await apiFetch<{ id: number }>('/admin/groups', { method: 'POST',
          body: JSON.stringify({ name: gName, description: gDesc, is_default: gIsDefault }) });
        if (gInbounds.size) {
          await apiFetch(`/admin/groups/${g.id}`, { method: 'PATCH', body: JSON.stringify({ inbound_ids: [...gInbounds] }) });
        }
      }
      showToast(tr('users.group_saved'), 'success'); groupOpen = false; await loadData();
    } catch (err: any) { showToast(err.message || tr('users.failed_to_save_group'), 'error'); }
  }
  async function deleteGroup(g: UserGroup) {
    if (!confirm(tr('users.delete_group_name', { name: g.name }))) return;
    try {
      await apiFetch(`/admin/groups/${g.id}`, { method: 'DELETE' });
      showToast(tr('users.group_deleted'), 'info');
      await loadData();
      return;
    } catch (err: any) {
      // A group with members returns 409 group_in_use, and the backend requires
      // a DISPOSITION for those members — it will not guess. The UI used to
      // show the raw error and offer neither, so a group with members simply
      // could not be deleted from the panel. Members are never deleted either
      // way; they are moved or left with no group.
      if (err?.code !== 'group_in_use') {
        showToast(err.message || tr('users.failed_to_delete_group'), 'error');
        return;
      }
      pendingGroupDelete = g;
      groupDeleteMembers = ((err?.body?.members as User[]) ?? []) as User[];
      groupReassignTo = 0;
      groupDeleteOpen = true;
    }
  }

  // confirmGroupDelete carries out the disposition the operator chose.
  async function confirmGroupDelete() {
    const g = pendingGroupDelete;
    if (!g) return;
    const q = groupReassignTo > 0
      ? `?reassign_to=${groupReassignTo}`
      : '?remove_members_from_group=true';
    try {
      await apiFetch(`/admin/groups/${g.id}${q}`, { method: 'DELETE' });
      showToast(tr('users.group_deleted'), 'info');
      groupDeleteOpen = false;
      pendingGroupDelete = null;
      await loadData();
    } catch (err: any) {
      showToast(err.message || tr('users.failed_to_delete_group'), 'error');
    }
  }

  function fmtBytes(b?: number) {
    if (!b) return '∞';
    const gb = b / 1024 ** 3;
    return gb >= 1 ? `${gb.toFixed(1)} GB` : `${(b / 1024 ** 2).toFixed(0)} MB`;
  }

  // "Online" = the user moved traffic within the presence window (the poll cycle
  // stamps last_seen_at whenever they transfer).
  //
  // The window is the shared one in $lib/presence, not a constant of this view's
  // own. This dot used to use a generous three minutes while the Online screen
  // used the backend's two, so a user idle for 2m30s was green here and missing
  // there — two screens disagreeing about the same person.
  function isOnline(u: any): boolean {
    return isPresent(u?.last_seen_at);
  }
  function lastSeenLabel(u: any): string {
    if (!u?.last_seen_at) return 'never seen';
    const s = Math.floor((Date.now() - new Date(u.last_seen_at).getTime()) / 1000);
    if (s < 60) return `active ${s}s ago`;
    const m = Math.floor(s / 60);
    if (m < 60) return `last seen ${m}m ago`;
    const h = Math.floor(m / 60);
    if (h < 24) return `last seen ${h}h ago`;
    return `last seen ${Math.floor(h / 24)}d ago`;
  }

  // Refresh just the user rows periodically so the presence dots stay live
  // without a full reload or a page refresh. Silent — never toasts on failure.
  let presenceTimer: ReturnType<typeof setInterval> | undefined;
  async function refreshUsers() {
    try { users = await apiFetch<User[]>('/admin/users'); } catch (_) { /* keep last good */ }
  }
  onMount(() => {
    loadData();
    presenceTimer = setInterval(refreshUsers, 30_000);
  });
  onDestroy(() => { if (presenceTimer) clearInterval(presenceTimer); });
</script>

<div class="view-header">
  <h2>{tr('users.users_amp_subscriptions')}</h2>
</div>

{#if subSettings}
  <div class="card" data-testid="sub-settings">
    <h3>{tr('users.subscription_defaults')}</h3>
    <p class="hint">{tr('users.applied_to_every_generated_sing_box')} <code>{tr('users.routing')}</code> {tr('users.and')} <code>{tr('users.fragment')}</code>.</p>
    <div class="row">
      <label class="field">
        <span>{tr('users.routing_rules')}</span>
        <select bind:value={subSettings.routing_preset} data-testid="routing-preset">
          {#each subSettings.presets as p}<option value={p}>{routingLabels[p] || p}</option>{/each}
        </select>
      </label>
      <label class="field checkbox">
        <input type="checkbox" bind:checked={subSettings.fragment} data-testid="fragment-toggle" />
        <span>{tr('users.tls_fragment_xray_dpi_evasion')}</span>
      </label>
      <label class="field">
        <span>{tr('users.fragment_level')}</span>
        <select bind:value={subSettings.fragment_level} data-testid="fragment-level" disabled={!subSettings.fragment}>
          {#each (subSettings.fragment_levels ?? ['light','medium','aggressive']) as m}<option value={m}>{m === 'light' ? tr('users.fragment_level_light') : m === 'medium' ? tr('users.fragment_level_medium') : tr('users.fragment_level_aggressive')}</option>{/each}
        </select>
      </label>
      <label class="field">
        <span>{tr('users.pattern_unsafe_utls')}</span>
        <select bind:value={subSettings.pattern} data-testid="pattern-mode" title={tr('users.adds_cs_fm_fp_unsafe_to')}>
          {#each (subSettings.pattern_modes ?? ['off','only','both']) as m}<option value={m}>{m === 'off' ? tr('users.off_normal') : m === 'only' ? tr('users.pattern_only') : tr('users.both_normal_pattern')}</option>{/each}
        </select>
      </label>
      <button class="primary" data-testid="save-sub-settings" onclick={saveSubSettings}>{tr('users.save')}</button>
    </div>
    <div class="row" style="margin-top:10px">
      <span class="hint" style="margin:0;align-self:center">{tr('users.fragment_cores')}</span>
      {#each fragmentCoresSupported as c}
        <label class="field checkbox" style="flex:none">
          <input type="checkbox" data-testid="fragment-core-{c}" disabled={!subSettings.fragment}
            checked={fragmentCores.includes(c)} onchange={() => toggleFragmentCore(c)} />
          <span>{c}</span>
        </label>
      {/each}
    </div>
    <p class="hint">{tr('users.fragment_clash_unsupported')}</p>
    <div class="row" style="margin-top:10px">
      <label class="field checkbox">
        <input type="checkbox" bind:checked={subSettings.expand_sni} data-testid="expand-sni" />
        <span>{tr('users.expand_sni')}</span>
      </label>
      <label class="field checkbox">
        <input type="checkbox" bind:checked={subSettings.front_clean_ip} data-testid="front-clean-ip" />
        <span>{tr('users.front_clean_ip')}</span>
      </label>
    </div>
    <p class="hint">{tr('users.expand_sni_hint')}</p>
    <div class="row" style="margin-top:10px">
      <label class="field" style="flex:1;min-width:280px">
        <span>{tr('users.clean_ips')} <span class="hint" style="font-weight:400">{tr('users.clean_ips_hint')}</span></span>
        <input bind:value={subSettings.clean_ips} placeholder={tr('users.clean_ips_placeholder')} data-testid="clean-ips" />
      </label>
    </div>
    {#if (subSettings.front_clean_ip ?? false) && !(subSettings.clean_ips ?? '').trim()}
      <p class="hint warn-hint" data-testid="clean-ip-empty">{tr('users.front_clean_ip_needs_a_list')}</p>
    {/if}
    <p class="hint">{tr('users.pattern_adds')} <code>{tr('users.cs')}</code> {tr('users.cipher_suites')} <code>{tr('users.fm')}</code> {tr('users.tls_fragment')} <code>{tr('users.fp_unsafe')}</code> {tr('users.to_vless_trojan_vmess_links_the')} <code>{tr('users.patt_1')}</code> {tr('users.pattern_or')} <code>{tr('users.patt_both')}</code>{tr('users.needs_a_recent_xray_client_v2rayng')}</p>
    <div class="row" style="margin-top:10px">
      <label class="field" style="flex:1;min-width:280px">
        <span>{tr('users.config_name_template')} <span class="hint" style="font-weight:400">{tr('users.blank_keep_each_inbound_s_own')}</span></span>
        <input bind:value={subSettings.name_template} placeholder="{'{FLAG} {NAME}'}" data-testid="name-template" />
      </label>
    </div>
    <p class="hint">{tr('users.tokens', {  })} {#each (subSettings.name_tokens ?? []) as tk}<code style="margin-inline-end:4px">{tk}</code>{/each} — e.g. <code>{'{FLAG} {NAME} · {NET}'}</code> → <b>{tr('users.berlin_ws')}</b>{tr('users.set_a_country_per_inbound_for')}</p>
    {#if subCardErrors.length}
      <ul class="field-errs" data-testid="sub-settings-errors">
        {#each subCardErrors as [key, why]}<li><code>{key}</code> — {why}</li>{/each}
      </ul>
    {/if}
  </div>

  <div class="card" data-testid="fancy-wizard">
    <h3>{tr('users.fancy_config_wizard')}</h3>
    <p class="hint">{tr('users.set_a_camouflage_domain_pick_a')}</p>
    <div class="row">
      <label class="field" style="flex:1;min-width:240px">
        <span>{tr('users.camouflage_domain')} <span class="hint" style="font-weight:400">{tr('users.e_g_aparat_com_taskulu_com')}</span></span>
        <input bind:value={subSettings.front_domain} placeholder={tr('users.aparat_com')} data-testid="front-domain" />
      </label>
      <label class="field">
        <span>{tr('users.fronting_model')}</span>
        <select bind:value={subSettings.front_mode} data-testid="front-mode" title={tr('users.how_the_domain_is_applied_to')}>
          {#each (subSettings.front_modes ?? ['none','sni','cdn']) as m}<option value={m}>{m === 'none' ? tr('users.none_raw') : m === 'sni' ? tr('users.sni_host_camouflage') : tr('users.cdn_domain_fronting')}</option>{/each}
        </select>
      </label>
      <button class="primary" data-testid="save-front" onclick={saveSubSettings}>{tr('users.save_domain')}</button>
    </div>
    <p class="hint"><b>{tr('users.sni_host')}</b>{tr('users.keep_the_real_server_address_but')} <b>CDN</b>{tr('users.set_only_the_host_header_and')}</p>
    {#if frontCardErrors.length}
      <ul class="field-errs" data-testid="front-settings-errors">
        {#each frontCardErrors as [key, why]}<li><code>{key}</code> — {why}</li>{/each}
      </ul>
    {/if}
    {#if subSettings.fancy_themes && subSettings.fancy_themes.length}
      <div class="theme-grid">
        {#each subSettings.fancy_themes as th}
          <button type="button" class="theme-card" class:active={subSettings.name_template === th.template} data-testid={'theme-' + th.id} onclick={() => applyFancyTheme(th)} title={`${th.label} · ${th.front} · suits ${th.proto}`}>
            <span class="theme-sample">{th.sample}</span>
            <span class="theme-meta">{th.label} · <b>{th.front === 'none' ? 'raw' : th.front.toUpperCase()}</b></span>
          </button>
        {/each}
      </div>
    {/if}
  </div>
{/if}

<div class="card">
  <h3>{tr('users.add_user')}</h3>
  <div class="row">
    <input placeholder={tr('users.username')} bind:value={newUsername} />
    <select bind:value={newGroupId}>
      <option value={undefined}>{tr('users.no_group')}</option>
      {#each groups as g}<option value={g.id}>{g.name}</option>{/each}
    </select>
    {#if templates.length}
      <select bind:value={newTemplateId} title={tr('users.saved_plan_hint')} data-testid="create-template">
        <option value={undefined}>{tr('users.no_saved_plan')}</option>
        {#each templates as t}<option value={t.id}>{t.name}</option>{/each}
      </select>
    {/if}
    <input type="number" step="0.001" min="0" placeholder={tr('users.limit_gb_0')} bind:value={newLimitGB} title={tr('users.data_limit_in_gb')} data-testid="create-limit" />
    <input type="number" placeholder={tr('users.expire_days_0_never')} bind:value={newExpireDays} title={tr('users.expire_in_n_days')} />
    <button class="primary" data-testid="create-user" onclick={createUser}>{tr('users.create')}</button>
  </div>
  {#if createErr}<p class="err">{createErr}</p>{/if}
  {#if quota && !quota.unlimited}
    <!-- A reseller had no view of their own headroom, so exhaustion arrived as
         an opaque 409 quota_exceeded on the create they had already filled in. -->
    <p class="quota" data-testid="quota-strip">
      {#if quota.users_remaining !== undefined}
        <span class:low={quota.users_remaining <= 3}>
          {tr('users.quota_users', { remaining: quota.users_remaining, total: quota.user_quota })}
        </span>
      {/if}
      {#if quota.traffic_remaining !== undefined}
        <span class:low={quota.traffic_remaining <= 0}>
          {tr('users.quota_traffic', { remaining: fmtBytes(quota.traffic_remaining), total: fmtBytes(quota.traffic_credit) })}
        </span>
      {/if}
    </p>
  {/if}
</div>

<div class="card">
  {#if loading}<p class="muted">{tr('users.loading')}</p>
  {:else}
    <table data-testid="users-table">
      <thead><tr><th>{tr('users.user')}</th><th>{tr('users.group')}</th><th>{tr('users.limit')}</th><th>{tr('users.used')}</th><th>{tr('users.status')}</th><th>{tr('users.sub_token')}</th><th>{tr('users.actions')}</th></tr></thead>
      <tbody>
        {#each users as u (u.id)}
          <tr>
            <td>
              <span class="presence {isOnline(u) ? 'online' : 'offline'}" data-testid="presence-{u.id}" title={lastSeenLabel(u)}></span>
              <strong>{u.username}</strong>
            </td>
            <td>{groups.find(g => g.id === u.group_id)?.name || '—'}</td>
            <td>{fmtBytes((u as any).data_limit)}</td>
            <td>
              {fmtBytes((u as any).used_traffic)}
              <!-- used_traffic alone is ambiguous the moment a reset strategy is
                   set: it is the CURRENT period only, and without knowing when
                   that period began the number cannot be read. lifetime is what
                   the account has ever moved. -->
              {#if (u as any).lifetime_traffic && (u as any).lifetime_traffic !== (u as any).used_traffic}
                <span class="muted sub" data-testid="lifetime">{tr('users.lifetime_total', { total: fmtBytes((u as any).lifetime_traffic) })}</span>
              {/if}
              {#if (u as any).last_reset_at}
                <span class="muted sub">{tr('users.since_reset', { when: new Date((u as any).last_reset_at).toLocaleDateString() })}</span>
              {/if}
            </td>
            <td>
              <span class="badge {(u as any).status === 'active' ? 'ok' : 'off'}">{(u as any).status || 'active'}</span>
              <!-- The hold is separate from status on purpose, so it is shown
                   separately too: an operator seeing "active" on an account the
                   panel is deliberately refusing has no way to explain it. -->
              {#if isIPHeld(u)}
                <span class="badge held" data-testid="ip-held" title={tr('users.over_the_device_limit_released_automatically')}>
                  {tr('users.device_limit')}
                </span>
              {/if}
            </td>
            <td><code>{u.sub_token}</code></td>
            <td class="acts">
              <button class="sm" data-testid="manage-user" onclick={() => openManage(u)}>{tr('users.manage')}</button>
              <button class="sm" data-testid="open-sub" onclick={() => openSubModal(u)}>{tr('users.sub')}</button>
              <button class="sm" onclick={() => setStatus(u, (u as any).status === 'active' ? 'disabled' : 'active')}>{(u as any).status === 'active' ? tr('users.disable') : tr('users.enable')}</button>
              <button class="sm" data-testid="rotate" onclick={() => openRotate(u)}>{tr('users.rotate')}</button>
              <button class="sm danger" onclick={() => deleteUser(u.id)}>{tr('users.delete')}</button>
            </td>
          </tr>
        {/each}
      </tbody>
    </table>
  {/if}
</div>

{#if canManagePlans}
<div class="card">
  <div class="ghead"><h3>{tr('users.saved_plans')}</h3><button class="sm" data-testid="new-plan" onclick={openPlanNew}>{tr('users.new_plan')}</button></div>
  {#if templates.length === 0}<p class="muted">{tr('users.no_plans_hint')}</p>
  {:else}
    <table>
      <thead><tr><th>{tr('users.name')}</th><th>{tr('users.data_limit')}</th><th>{tr('users.expiry')}</th><th>{tr('users.username_affixes')}</th><th></th></tr></thead>
      <tbody>
        {#each templates as t (t.id)}
          <tr>
            <td><strong>{t.name}</strong></td>
            <td>{t.data_limit ? fmtBytes(t.data_limit) : tr('users.unlimited')}</td>
            <td>{t.expire_days ? tr('users.n_days', { n: t.expire_days }) : tr('users.never')}</td>
            <td class="muted">{affixLabel(t)}</td>
            <td class="acts">
              <button class="sm" onclick={() => openPlanEdit(t)}>{tr('users.edit')}</button>
              <button class="sm danger" data-testid="plan-delete" onclick={() => deletePlan(t)}>{tr('users.delete')}</button>
            </td>
          </tr>
        {/each}
      </tbody>
    </table>
  {/if}
</div>
{/if}

{#if canManageGroups}
<div class="card">
  <div class="ghead"><h3>{tr('users.groups')}</h3><button class="sm" data-testid="new-group" onclick={openGroupNew}>{tr('users.new_group')}</button></div>
  {#if groups.length === 0}<p class="muted">{tr('users.no_groups_a_group_bundles_inbounds')}</p>
  {:else}
    <table>
      <thead><tr><th>{tr('users.name')}</th><th>{tr('users.description')}</th><th>{tr('users.inbounds')}</th><th></th></tr></thead>
      <tbody>
        {#each groups as g (g.id)}
          <tr>
            <td><strong>{g.name}</strong>{#if (g as any).is_default}<span class="badge">{tr('users.default_badge')}</span>{/if}</td>
            <td class="muted">{(g as any).description || '—'}</td>
            <td>{((g as any).inbound_ids || []).length}</td>
            <td class="acts">
              <button class="sm" onclick={() => openGroupEdit(g)}>{tr('users.edit')}</button>
              <button class="sm danger" data-testid="group-delete" onclick={() => deleteGroup(g)}>{tr('users.delete')}</button>
            </td>
          </tr>
        {/each}
      </tbody>
    </table>
  {/if}
</div>
{/if}

<!-- Group delete needs a disposition for its members: the backend refuses to
     guess, and members are never deleted either way. -->
<Modal title={tr('users.delete_group_title')} isOpen={groupDeleteOpen} onClose={() => (groupDeleteOpen = false)}>
  <p class="hint">{tr('users.delete_group_has_members', { count: groupDeleteMembers.length })}</p>
  <label class="lbl">{tr('users.move_members_to')}
    <select bind:value={groupReassignTo} data-testid="group-reassign">
      <option value={0}>{tr('users.leave_with_no_group')}</option>
      {#each groups.filter((g) => g.id !== pendingGroupDelete?.id) as g}
        <option value={g.id}>{g.name}</option>
      {/each}
    </select>
  </label>
  <div class="row-actions">
    <button class="primary danger" data-testid="group-delete-confirm" onclick={confirmGroupDelete}>{tr('users.delete')}</button>
    <button class="sm" onclick={() => (groupDeleteOpen = false)}>{tr('users.cancel')}</button>
  </div>
</Modal>

<!-- Manage user modal -->
<Modal
  title={tr('users.rotate_credentials') + (rotateUser?.username || '')}
  isOpen={rotateOpen}
  onClose={() => (rotateOpen = false)}
>
  <p class="rot-intro">
    {tr('users.pick_what_to_replace_each_one')}
  </p>
  <label class="rot">
    <input type="checkbox" bind:checked={rotateSub} data-testid="rotate-sub" />
    <span>
      <strong>{tr('users.subscription_token')}</strong>
      <em>{tr('users.the_old_subscription_url_stops_resolving')}</em>
    </span>
  </label>
  <label class="rot">
    <input type="checkbox" bind:checked={rotateUUID} data-testid="rotate-uuid" />
    <span>
      <strong>UUID</strong>
      <em>{tr('users.every_vless_vmess_config_this_user')}</em>
    </span>
  </label>
  <label class="rot">
    <input type="checkbox" bind:checked={rotatePassword} data-testid="rotate-password" />
    <span>
      <strong>{tr('users.password')}</strong>
      <em>{tr('users.every_trojan_shadowsocks_hysteria_config_this')}</em>
    </span>
  </label>
  <div class="rot-actions">
    <button class="sm" onclick={() => (rotateOpen = false)}>{tr('users.cancel')}</button>
    <button
      class="sm danger"
      disabled={rotateNothing || rotating}
      data-testid="rotate-confirm"
      onclick={doRotate}
    >
      {rotating ? tr('users.rotating') : tr('users.rotate')}
    </button>
  </div>
</Modal>

<Modal title={tr('users.manage_2') + (mUser?.username || '')} isOpen={manageOpen} onClose={() => manageOpen = false}>
  <div class="mgrid">
    <label>{tr('users.status')}<select bind:value={mStatus}><option value="active">{tr('users.active')}</option><option value="disabled">{tr('users.disabled')}</option></select></label>
    <label>{tr('users.group')}<select bind:value={mGroupId} data-testid="manage-group"><option value={undefined}>{tr('users.no_group')}</option>{#each groups as g}<option value={g.id}>{g.name}</option>{/each}</select></label>
    <label>{tr('users.data_limit_gb_0')}<input type="number" step="0.001" min="0" bind:value={mLimitGB} data-testid="manage-limit" /></label>
    <label>{tr('users.reset_strategy')}
      <select bind:value={mReset} data-testid="manage-reset">
        <option value="no_reset">{tr('users.reset_no')}</option>
        <option value="day">{tr('users.reset_day')}</option>
        <option value="week">{tr('users.reset_week')}</option>
        <option value="month">{tr('users.reset_month')}</option>
        <option value="year">{tr('users.reset_year')}</option>
        <option value="on_expire">{tr('users.reset_on_expire')}</option>
      </select>
    </label>
    <label>{tr('users.expires_on')}
      <input type="date" bind:value={mExpireAt} data-testid="manage-expire-at" />
      <small>{tr('users.expiry_blank_clears')}</small>
    </label>
    <label>{tr('users.extend_expiry_days_from_now_0')}<input type="number" bind:value={mExpireDays} /></label>
    <label>{tr('users.telegram_id')}<input bind:value={mTelegramID} data-testid="manage-telegram" /></label>
    <label>{tr('users.note')}<input bind:value={mNote} data-testid="manage-note" /></label>
    <label>
      {tr('users.devices_max_addresses_at_once_0')}
      <input type="number" min="0" bind:value={mIPLimit} data-testid="ip-limit" />
      <!-- An address counts while it has connected within the last couple of
           minutes, not while a socket is open. Saying so here is the difference
           between an operator trusting the number and filing a bug. -->
      <small>
        {tr('users.counts_distinct_source_addresses_seen_in')}
      </small>
    </label>
  </div>
  <h4>{tr('users.assign_inbounds_to_this_user')}</h4>
  <div class="assign" data-testid="assign-inbounds">
    {#each inbounds as inb}
      <label class="chk">
        <input type="checkbox" checked={mAssigned.has(inb.id)} disabled={mInherited.has(inb.id)} onchange={() => toggleAssign(inb.id)} />
        {inb.remark || inb.protocol} <span class="muted">:{inb.port} {inb.protocol}{mInherited.has(inb.id) ? tr('users.from_group') : ''}</span>
      </label>
    {/each}
    {#if inbounds.length === 0}<p class="muted">{tr('users.no_inbounds_yet_create_one_in')}</p>{/if}
  </div>
  <h4>{tr('users.subscription_access')}</h4>
  <p class="hint">{tr('users.revoke_explainer')}</p>
  {#if mUser}
    <button class="sm" class:danger={!mSubRevoked} data-testid="toggle-sub-revoked"
      onclick={() => toggleSubRevoked(mUser!, !mSubRevoked)}>
      {mSubRevoked ? tr('users.restore_subscription') : tr('users.revoke_subscription')}
    </button>
  {/if}
  {#if mUser && canManagePlans && templates.length > 0}
    <select bind:value={mTemplateId} data-testid="manage-template" title={tr('users.apply_plan_hint')}>
      <option value={undefined}>{tr('users.apply_a_plan')}</option>
      {#each templates as t (t.id)}<option value={t.id}>{t.name}</option>{/each}
    </select>
    <button class="sm" data-testid="apply-plan" disabled={!mTemplateId || mApplyBusy} onclick={applyPlan}>
      {tr('users.apply_plan')}
    </button>
  {/if}
  <button class="primary" data-testid="save-manage" onclick={saveManage}>{tr('users.save')}</button>
</Modal>

<!-- Saved-plan modal -->
<Modal title={pEditing ? tr('users.edit_plan') : tr('users.new_plan_2')} isOpen={planOpen} onClose={() => planOpen = false}>
  <div class="mgrid">
    <label>{tr('users.name')}<input data-testid="plan-name" bind:value={pName} /></label>
    <label>{tr('users.note')}<input bind:value={pNote} /></label>
    <label>{tr('users.limit_gb_0')}<input type="number" step="0.001" min="0" bind:value={pLimitGB} /></label>
    <label>{tr('users.expire_days_0_never')}<input type="number" min="0" bind:value={pExpireDays} /></label>
    <label>{tr('users.ip_limit')}<input type="number" min="0" bind:value={pIPLimit} /></label>
    <label>{tr('users.reset_strategy')}<select bind:value={pReset}>
      {#each ['no_reset', 'day', 'week', 'month', 'year', 'on_expire'] as r}<option value={r}>{r}</option>{/each}
    </select></label>
    <!-- limited and expired are states the panel DERIVES from usage and the
         clock, so a plan may not stamp one: it would create an account already
         dead that no top-up brings back. The handler refuses them too. -->
    <label>{tr('users.status')}<select bind:value={pStatus} data-testid="plan-status">
      {#each ['active', 'disabled', 'on_hold'] as st}<option value={st}>{st}</option>{/each}
    </select></label>
    <label>{tr('users.group')}<select bind:value={pGroupId}>
      <option value={undefined}>{tr('users.no_group')}</option>
      {#each groups as g}<option value={g.id}>{g.name}</option>{/each}
    </select></label>
    <label>{tr('users.username_prefix')}<input maxlength="20" bind:value={pPrefix} data-testid="plan-prefix" /></label>
    <label>{tr('users.username_suffix')}<input maxlength="20" bind:value={pSuffix} /></label>
  </div>
  <h4>{tr('users.inbounds_stamped_by_this_plan')}</h4>
  <div class="assign">
    {#each inbounds as inb}
      <label class="chk"><input type="checkbox" checked={pInbounds.has(inb.id)} onchange={() => togglePlanInbound(inb.id)} /> {inb.remark || inb.protocol} <span class="muted">:{inb.port}</span></label>
    {/each}
  </div>
  <button class="primary" data-testid="save-plan" onclick={savePlan}>{tr('users.save_plan')}</button>
</Modal>

<!-- Group modal -->
<Modal title={gEditing ? tr('users.edit_group') : tr('users.new_group_2')} isOpen={groupOpen} onClose={() => groupOpen = false}>
  <div class="mgrid">
    <label>{tr('users.name')}<input data-testid="group-name" bind:value={gName} /></label>
    <label>{tr('users.description')}<input bind:value={gDesc} /></label>
    <!-- is_default has a whole transactional single-writer implementation
         behind it — setting one group default clears the others in the same
         transaction — and no way to reach it. -->
    <label class="chk"><input type="checkbox" bind:checked={gIsDefault} data-testid="group-default" /> {tr('users.is_default_group')}</label>
  </div>
  <h4>{tr('users.inbounds_in_this_group_assigned_to')}</h4>
  <div class="assign">
    {#each inbounds as inb}
      <label class="chk"><input type="checkbox" checked={gInbounds.has(inb.id)} onchange={() => toggleGroupInbound(inb.id)} /> {inb.remark || inb.protocol} <span class="muted">:{inb.port}</span></label>
    {/each}
  </div>
  <button class="primary" data-testid="save-group" onclick={saveGroup}>{tr('users.save_group')}</button>
</Modal>

<!-- Sub modal -->
<Modal title={tr('users.subscription') + (activeSubUser?.username || '')} isOpen={subModalOpen} onClose={() => subModalOpen = false}>
  <div class="mgrid">
    <label>{tr('users.format')}<select bind:value={subFormat} data-testid="sub-format">
      {#each subFormats as f (f)}<option value={f}>{subFormatLabel(f)}</option>{/each}
    </select></label>
  </div>
  <div class="uri-row"><code data-testid="sub-url">{subUrl}</code><button class="sm" onclick={copySubUrl}>{tr('users.copy')}</button></div>
  {#if subUrl}<div class="qr"><QRCode value={subUrl} size={190} /></div>{/if}
  <div class="sub-telemetry">
    <div class="sub-last" data-testid="sub-last-fetch">
      {#if subLastFetch}
        {tr('users.sub_last_fetched')} {new Date(subLastFetch).toLocaleString()} — {subLastUA}
      {:else}
        {tr('users.sub_never_fetched')}
      {/if}
    </div>
    {#if subReqs.length}
      <table>
        <thead><tr>
          <th>{tr('users.sub_when')}</th><th>{tr('users.format')}</th>
          <th>{tr('users.sub_client')}</th><th>{tr('users.sub_ip')}</th>
        </tr></thead>
        <tbody>
          {#each subReqs as q (q.created_at + q.ip)}
            <tr data-testid="sub-request-row">
              <td>{new Date(q.created_at).toLocaleString()}</td>
              <td>{q.format}</td><td class="ua">{q.user_agent}</td><td>{q.ip}</td>
            </tr>
          {/each}
        </tbody>
      </table>
    {/if}
  </div>
</Modal>

<style>
  .warn-hint { color: var(--acc-2); }
  /* Server-supplied text: the reason names the key the API rejected, so it is
     not translated here any more than the toast that carries the same words. */
  .field-errs { margin: 8px 0 0; padding-inline-start: 18px; color: var(--bad-3); font-size: 13px; }
  .field-errs code { color: inherit; }
  .badge.held { background: rgba(217,155,43,0.18); color: var(--warn); border: 1px solid rgba(217,155,43,0.4); margin-inline-start: 6px; }
  label small { display: block; margin-top: 4px; color: var(--t-7); font-size: 11px; line-height: 1.5; }

  .rot-intro { color: var(--t-5); font-size: 13px; margin: 0 0 14px; }
  .rot { display: flex; gap: 10px; align-items: flex-start; padding: 10px 0; border-bottom: 1px solid var(--ln-2); }
  .rot span { display: flex; flex-direction: column; gap: 3px; }
  .rot strong { font-size: 13px; }
  .rot em { font-style: normal; font-size: 12px; color: var(--t-6); line-height: 1.5; }
  .rot-actions { display: flex; justify-content: flex-end; gap: 8px; margin-top: 16px; }
  .rot-actions button:disabled { opacity: 0.4; cursor: default; }

  .view-header h2 { margin: 0 0 20px; font-size: 20px; }
  .card { background: var(--card); border: 1px solid var(--ln-3); border-radius: 14px; padding: 20px; margin-bottom: 20px; }
  .card h3 { margin: 0 0 14px; font-size: 14px; }
  .ghead { display: flex; justify-content: space-between; align-items: center; margin-bottom: 12px; }
  .row { display: flex; gap: 10px; flex-wrap: wrap; }
  .row input, .row select { flex: 1; min-width: 120px; }
  input, select { background: var(--bg); border: 1px solid var(--ln-5); color: var(--fg); padding: 9px 10px; border-radius: 8px; font: inherit; font-size: 13px; box-sizing: border-box; width: 100%; }
  .primary { background: var(--acc); color: var(--acc-soft); border: none; font-weight: 700; padding: 10px 16px; border-radius: 8px; cursor: pointer; white-space: nowrap; }
  .hint { color: var(--t-6); font-size: 13px; margin: 0 0 12px; }
  .field { display: flex; flex-direction: column; gap: 4px; font-size: 12px; color: var(--t-5); flex: 1; min-width: 160px; }
  .field.checkbox { flex-direction: row; align-items: center; gap: 8px; font-size: 13px; color: var(--t-2); }
  .field.checkbox input { flex: none; width: 16px; height: 16px; }
  table { width: 100%; border-collapse: collapse; }
  th, td { padding: 10px; text-align: start; border-bottom: 1px solid var(--ln-3); font-size: 13px; }
  th { color: var(--t-6); font-size: 12px; }
  .acts { display: flex; gap: 6px; flex-wrap: wrap; }
  .sm { padding: 5px 10px; font-size: 12px; border-radius: 6px; background: var(--raised); color: var(--fg); border: 1px solid var(--ln-4); cursor: pointer; }
  .sm.danger { background: rgba(255,77,77,0.15); color: var(--bad); border-color: rgba(255,77,77,0.3); }
  .badge { padding: 3px 9px; border-radius: 12px; font-size: 11px; font-weight: 600; }
  .badge.ok { background: rgba(39,209,124,0.15); color: var(--ok); }
  .badge.off { background: var(--ln-4); color: var(--t-5); }
  .presence { display: inline-block; width: 8px; height: 8px; border-radius: 50%; margin-inline-end: 8px; vertical-align: middle; cursor: help; }
  .presence.online { background: var(--ok); box-shadow: 0 0 6px var(--ok); }
  .presence.offline { background: var(--ln-5); }
  .muted { color: var(--t-8); }
  .err { color: var(--bad); font-size: 13px; margin-top: 8px; }
  .mgrid { display: grid; grid-template-columns: 1fr 1fr; gap: 12px; margin-bottom: 14px; }
  .mgrid label { display: flex; flex-direction: column; gap: 5px; font-size: 12px; color: var(--t-3); }
  h4 { margin: 8px 0 10px; font-size: 13px; color: var(--acc-2); }
  .assign { display: flex; flex-direction: column; gap: 7px; max-height: 260px; overflow-y: auto; margin-bottom: 14px; }
  .chk { display: flex; align-items: center; gap: 8px; font-size: 13px; color: var(--fg); }
  .chk input { width: auto; }
  .uri-row { display: flex; gap: 8px; align-items: center; margin-bottom: 10px; }
  .uri-row code { flex: 1; background: var(--bg); padding: 10px; border-radius: 8px; font-size: 12px; word-break: break-all; color: var(--ok); }
  .qr { display: flex; justify-content: center; padding: 10px; background: #fff; border-radius: 10px; }
  .sub-telemetry { margin-top: 16px; }
  .sub-telemetry .sub-last { color: var(--t-5); font-size: 12px; margin-bottom: 10px; }
  .sub-telemetry table { width: 100%; border-collapse: collapse; font-size: 12px; }
  .sub-telemetry th { text-align: start; color: var(--t-8); font-weight: 500; padding: 6px 8px; }
  .sub-telemetry td { padding: 6px 8px; border-top: 1px solid var(--ln-2); }
  .sub-telemetry td.ua { max-width: 220px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
  .theme-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(220px, 1fr)); gap: 10px; margin-top: 12px; }
  .sub { display: block; font-size: 11px; }
  .quota { display: flex; gap: 14px; flex-wrap: wrap; margin: 8px 0 0; font-size: 12px; color: var(--t-4); }
  .quota .low { color: var(--warn); }
  .lbl { display: flex; flex-direction: column; gap: 4px; font-size: 13px; margin: 10px 0; }
  .theme-card { display: flex; flex-direction: column; gap: 6px; align-items: flex-start; text-align: start; background: var(--bg); border: 1px solid var(--ln-4); border-radius: 10px; padding: 12px; cursor: pointer; transition: border-color .15s, background .15s; }
  .theme-card:hover { border-color: rgba(39,209,124,0.5); background: #121a26; }
  .theme-card.active { border-color: var(--ok); background: rgba(39,209,124,0.10); }
  .theme-sample { font-size: 14px; color: var(--fg); word-break: break-word; }
  .theme-meta { font-size: 11px; color: var(--t-6); }
  .theme-meta b { color: var(--ok); font-weight: 600; }
</style>
