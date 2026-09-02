<script lang="ts">
	import { tr } from '$lib/i18n';
  import { onMount } from 'svelte';
  import { apiFetch, setAuthToken } from '$lib/api';
  import type { HealthDetail, TwoFASetup } from '$lib/types';
  import Modal from '$lib/components/Modal.svelte';
  import QRCode from '$lib/components/QRCode.svelte';
  import WebhooksCard from '$lib/components/WebhooksCard.svelte';
  import { showToast } from '$lib/components/Toast.svelte';

  let healthDetail = $state<HealthDetail | null>(null);
  let loading = $state(true);

  // Telegram alerts.
  //
  // The token was read once from FORGEPANEL_TELEGRAM_TOKEN at process start and
  // nowhere else, so configuring alerts meant editing a compose file and
  // restarting the panel — for the feature whose whole purpose is telling an
  // operator about things that happen while they are not looking.
  interface TelegramSettings {
    configured: boolean;
    has_token: boolean;
    token_source: string;
    chat_ids: string;
    running: boolean;
    backup_delivery: boolean;
  }
  let tg = $state<TelegramSettings | null>(null);
  let tgToken = $state('');
  let tgChats = $state('');
  let tgBackup = $state(false);
  let tgBusy = $state(false);
  let tgErr = $state('');
  let tgRemedy = $state('');

  async function loadTelegram() {
    try {
      tg = await apiFetch<TelegramSettings>('/admin/settings/telegram');
      tgChats = tg.chat_ids ?? '';
      tgBackup = !!tg.backup_delivery;
      // The token is never sent back, so the field starts empty and an empty
      // field means "keep what is stored" rather than "clear it".
      tgToken = '';
    } catch (_) { /* an older panel has no telegram settings endpoint */ }
  }

  function tgBody(withTest: boolean) {
    return JSON.stringify({
      // Only send a token when one was typed. An empty field must not wipe a
      // working token the panel deliberately never showed back.
      ...(tgToken.trim() ? { token: tgToken.trim() } : {}),
      chat_ids: tgChats,
      backup_delivery: tgBackup,
      test: withTest
    });
  }

  async function saveTelegram(withTest: boolean) {
    tgBusy = true;
    tgErr = '';
    tgRemedy = '';
    try {
      await apiFetch('/admin/settings/telegram', { method: 'POST', body: tgBody(withTest) });
      tgToken = '';
      showToast(tr('systemhealth.telegram_saved'), 'success');
      await loadTelegram();
    } catch (e: any) {
      tgErr = e.message || tr('systemhealth.telegram_failed');
      tgRemedy = e.remediation ?? '';
    } finally {
      tgBusy = false;
    }
  }

  async function testTelegram() {
    tgBusy = true;
    tgErr = '';
    tgRemedy = '';
    try {
      await apiFetch('/admin/settings/telegram/test', { method: 'POST', body: tgBody(false) });
      showToast(tr('systemhealth.telegram_test_delivered'), 'success');
    } catch (e: any) {
      tgErr = e.message || tr('systemhealth.telegram_failed');
      tgRemedy = e.remediation ?? '';
    } finally {
      tgBusy = false;
    }
  }

  // Off-box backups to an S3-compatible bucket.
  //
  // The scheduled backup was written to a directory on the machine it had just
  // backed up, which covers a bad migration and nothing else: losing the disk
  // loses the panel and every backup of it at once.
  interface BackupS3Settings {
    enabled: boolean;
    endpoint: string;
    region: string;
    bucket: string;
    prefix: string;
    access_key: string;
    has_secret_key: boolean;
    path_style: boolean;
    configured: boolean;
    key_fingerprint: string;
  }
  let s3 = $state<BackupS3Settings | null>(null);
  let s3Enabled = $state(false);
  let s3Endpoint = $state('');
  let s3Region = $state('');
  let s3Bucket = $state('');
  let s3Prefix = $state('');
  let s3AccessKey = $state('');
  let s3SecretKey = $state('');
  let s3PathStyle = $state(true);
  let s3Busy = $state(false);
  let s3Err = $state('');
  let s3Remedy = $state('');

  async function loadBackupS3() {
    try {
      s3 = await apiFetch<BackupS3Settings>('/admin/settings/backup/s3');
      s3Enabled = !!s3.enabled;
      s3Endpoint = s3.endpoint ?? '';
      s3Region = s3.region ?? '';
      s3Bucket = s3.bucket ?? '';
      s3Prefix = s3.prefix ?? '';
      s3AccessKey = s3.access_key ?? '';
      s3PathStyle = !!s3.path_style;
      // The secret key is never sent back, so the field starts empty and an
      // empty field means "keep what is stored" rather than "clear it".
      s3SecretKey = '';
    } catch (_) { /* an older panel has no S3 backup endpoint */ }
  }

  function s3Body() {
    return JSON.stringify({
      enabled: s3Enabled,
      endpoint: s3Endpoint.trim(),
      region: s3Region.trim(),
      bucket: s3Bucket.trim(),
      prefix: s3Prefix.trim(),
      access_key: s3AccessKey.trim(),
      // Only send a key when one was typed: an empty field must not wipe a
      // working credential the panel deliberately never showed back.
      ...(s3SecretKey.trim() ? { secret_key: s3SecretKey.trim() } : {}),
      path_style: s3PathStyle
    });
  }

  async function saveBackupS3() {
    s3Busy = true;
    s3Err = '';
    s3Remedy = '';
    try {
      await apiFetch('/admin/settings/backup/s3', { method: 'POST', body: s3Body() });
      s3SecretKey = '';
      showToast(tr('systemhealth.s3_saved'), 'success');
      await loadBackupS3();
    } catch (e: any) {
      s3Err = e.message || tr('systemhealth.s3_failed');
      s3Remedy = e.remediation ?? '';
    } finally {
      s3Busy = false;
    }
  }

  async function testBackupS3() {
    s3Busy = true;
    s3Err = '';
    s3Remedy = '';
    try {
      await apiFetch('/admin/settings/backup/s3/test', { method: 'POST', body: s3Body() });
      showToast(tr('systemhealth.s3_test_uploaded'), 'success');
    } catch (e: any) {
      s3Err = e.message || tr('systemhealth.s3_failed');
      s3Remedy = e.remediation ?? '';
    } finally {
      s3Busy = false;
    }
  }

  // Host network tuning (BBR + fq).
  //
  // Rendered from the LIVE host state, not from the stored toggle. A switch that
  // says "on" over a host still running cubic is the exact failure this feature
  // is about: the panel can be refused the sysctl by its own systemd hardening,
  // or the kernel can have no BBR at all, and neither shows up anywhere else.
  interface NetTune {
    enabled: boolean;
    congestion: string;
    qdisc: string;
    bbr_available: boolean;
    active: boolean;
    persisted: boolean;
    kernel: string;
    remediation?: string;
  }
  let netTune = $state<NetTune | null>(null);
  // Bound to the checkbox, and deliberately not derived from netTune: when the
  // host refuses the change the response value is the same one the checkbox
  // started at, so a `checked={...}` expression would never re-render and the
  // box would stay where the click left it — showing BBR on over a host that
  // rejected it.
  let netTuneWanted = $state(false);
  let netTuneBusy = $state(false);
  let netTuneErr = $state('');
  let netTuneRemedy = $state('');
  // An em dash for a value the host would not tell us — /proc is unreadable
  // under some hardening, and a blank gap there reads as "fine".
  const unreadable = '\u2014';
  let netTuneCongestion = $derived(netTune?.congestion || unreadable);
  let netTuneQdisc = $derived(netTune?.qdisc || unreadable);
  let netTuneKernel = $derived(netTune?.kernel || unreadable);

  async function loadNetTune() {
    try {
      netTune = await apiFetch<NetTune>('/admin/settings/nettune');
      netTuneWanted = netTune.enabled;
    } catch (_) { /* an older panel has no network tuning endpoint */ }
  }

  async function saveNetTune(enabled: boolean) {
    netTuneBusy = true;
    netTuneErr = '';
    netTuneRemedy = '';
    try {
      netTune = await apiFetch<NetTune>('/admin/settings/nettune', {
        method: 'POST',
        body: JSON.stringify({ enabled })
      });
      netTuneWanted = netTune.enabled;
      showToast(enabled ? tr('systemhealth.nettune_enabled') : tr('systemhealth.nettune_disabled'), 'success');
    } catch (e: any) {
      netTuneErr = e.message || tr('systemhealth.nettune_failed');
      netTuneRemedy = e.remediation ?? '';
      // Re-read so the checkbox goes back to what the host really is. Leaving it
      // where the operator clicked would claim a change that did not happen.
      await loadNetTune();
      netTuneWanted = netTune?.enabled ?? false;
    } finally {
      netTuneBusy = false;
    }
  }

  // Panel self-update.
  //
  // The panel could only be updated by shelling into the host and running
  // `forgectl update`, which reads /releases/latest — so an operator on a
  // release candidate could not see the next one at all. Applying is still
  // forgectl's job (the unit's ProtectSystem=full makes /usr/local/bin
  // read-only to the panel), which is why apply_hint is rendered rather than
  // an Install button that could never work.
  interface UpdateInfo {
    current: string;
    latest: string;
    update_available: boolean;
    channel: string;
    prerelease?: boolean;
    html_url?: string;
    apply_hint?: string;
  }
  let upd = $state<UpdateInfo | null>(null);
  let updChannel = $state('stable');
  let updBusy = $state(false);
  let updErr = $state('');
  let updStaged = $state<{ tag: string; path: string } | null>(null);

  async function loadUpdate() {
    updBusy = true;
    updErr = '';
    try {
      upd = await apiFetch<UpdateInfo>('/admin/update');
      updChannel = upd.channel || 'stable';
    } catch (e: any) {
      updErr = e.message || tr('systemhealth.update_check_failed');
    } finally {
      updBusy = false;
    }
  }

  async function saveChannel() {
    updBusy = true;
    updErr = '';
    try {
      await apiFetch('/admin/update/channel', {
        method: 'POST',
        body: JSON.stringify({ channel: updChannel })
      });
      // Re-check on the new channel: the whole point of switching is to see a
      // different answer, and leaving the old one on screen claims it applies.
      await loadUpdate();
    } catch (e: any) {
      updErr = e.message || tr('systemhealth.update_channel_failed');
      // Put the selector back on what the panel actually stored.
      updChannel = upd?.channel || 'stable';
    } finally {
      updBusy = false;
    }
  }

  async function stageUpdate() {
    updBusy = true;
    updErr = '';
    updStaged = null;
    try {
      updStaged = await apiFetch<{ tag: string; path: string }>('/admin/update/stage', { method: 'POST' });
      showToast(tr('systemhealth.update_staged_ok', { tag: updStaged.tag }), 'success');
    } catch (e: any) {
      updErr = e.message || tr('systemhealth.update_stage_failed');
    } finally {
      updBusy = false;
    }
  }

  // Panel Doctor
  let doctor = $state<any>(null);
  let doctorBusy = $state(false);
  async function runDoctor() {
    doctorBusy = true;
    try { doctor = await apiFetch('/admin/doctor'); }
    catch (e: any) { showToast(e.message || tr('systemhealth.doctor_failed'), 'error'); }
    finally { doctorBusy = false; }
  }

  // 2FA state
  let twoFAEnabled = $state(false);
  let twoFAData = $state<TwoFASetup | null>(null);
  let twoFAModalOpen = $state(false);
  let verifyCode = $state('');

  // Change Password state
  // 2FA state. recoveryCodes holds plaintext that exists ONLY in this response;
  // it is never persisted and is cleared when the modal closes.
  let recoveryCodes = $state<string[]>([]);
  let recoveryModalOpen = $state(false);
  let recoveryRemaining = $state<number | null>(null);
  let disableOpen = $state(false);
  let disableCode = $state('');
  let disableErr = $state('');
  let regenOpen = $state(false);
  let regenCode = $state('');
  let regenErr = $state('');

  let oldPass = $state('');
  let newPass = $state('');
  let passErr = $state('');

  // Docker Compose state
  let composeYaml = $state('');
  let composeProfiles = $state('default');

  async function loadData() {
    loading = true;
    try {
      healthDetail = await apiFetch<HealthDetail>('/admin/health/detail');
      await runDoctor();
      const user = await apiFetch<{ two_factor_enabled?: boolean; recovery_codes_remaining?: number }>('/admin/me');
      twoFAEnabled = !!user.two_factor_enabled;
      recoveryRemaining = user.recovery_codes_remaining ?? null;
    } catch (err: any) {
      showToast(err.message || tr('systemhealth.failed_to_load_system_state'), 'error');
    } finally {
      loading = false;
    }
  }

  async function setup2FA() {
    try {
      twoFAData = await apiFetch<TwoFASetup>('/admin/2fa/setup', { method: 'POST' });
      twoFAModalOpen = true;
    } catch (err: any) {
      showToast(err.message || tr('systemhealth.failed_to_initiate_2fa_setup'), 'error');
    }
  }

  async function enable2FA() {
    if (!verifyCode.trim()) return;
    try {
      // The response is the ONLY time these values exist. The recovery codes are
      // stored as SHA-256 hashes and can never be shown again; enabling 2FA also
      // revokes every existing session, so the fresh access token is the only
      // way this tab stays signed in. Discarding the response — which is what
      // this did — locked the operator out AND destroyed the codes that were
      // their way back in.
      const res = await apiFetch<{
        recovery_codes?: string[];
        access_token?: string;
        sessions_revoked?: boolean;
      }>('/admin/2fa/enable', {
        method: 'POST',
        body: JSON.stringify({ code: verifyCode.trim() })
      });
      if (res.access_token) setAuthToken(res.access_token);
      twoFAEnabled = true;
      twoFAModalOpen = false;
      verifyCode = '';
      if (res.recovery_codes?.length) {
        recoveryCodes = res.recovery_codes;
        recoveryRemaining = res.recovery_codes.length;
        // Shown in a modal the operator has to dismiss deliberately, not a
        // toast that disappears on its own.
        recoveryModalOpen = true;
      }
      showToast(tr('systemhealth.two_factor_authentication_enabled'), 'success');
    } catch (err: any) {
      showToast(err.message || tr('systemhealth.invalid_2fa_code'), 'error');
    }
  }

  function copyRecoveryCodes() {
    navigator.clipboard
      .writeText(recoveryCodes.join('\n'))
      .then(() => showToast(tr('systemhealth.recovery_codes_copied'), 'success'))
      .catch(() => showToast(tr('systemhealth.could_not_copy_select_and_copy'), 'error'));
  }

  async function disable2FA() {
    // The handler verifies a CURRENT TOTP code before turning 2FA off. Posting
    // no body meant every attempt 400'd, so the Disable button could not work.
    // Requiring the code here is also the correct security boundary: a hijacked
    // session must not be able to strip a factor.
    disableErr = '';
    if (!disableCode.trim()) {
      disableErr = tr('systemhealth.enter_a_current_code_from_your');
      return;
    }
    try {
      await apiFetch('/admin/2fa/disable', {
        method: 'POST',
        body: JSON.stringify({ code: disableCode.trim() })
      });
      twoFAEnabled = false;
      recoveryRemaining = null;
      disableOpen = false;
      disableCode = '';
      showToast(tr('systemhealth.two_factor_authentication_disabled_sign_in'), 'info');
    } catch (err: any) {
      disableErr = err.message || tr('systemhealth.invalid_code');
    }
  }

  async function regenerateRecoveryCodes() {
    regenErr = '';
    if (!regenCode.trim()) {
      regenErr = tr('systemhealth.enter_a_current_code_or_your');
      return;
    }
    try {
      const res = await apiFetch<{ recovery_codes?: string[] }>('/admin/2fa/recovery/regenerate', {
        method: 'POST',
        body: JSON.stringify({ code: regenCode.trim() })
      });
      regenOpen = false;
      regenCode = '';
      if (res.recovery_codes?.length) {
        recoveryCodes = res.recovery_codes;
        recoveryRemaining = res.recovery_codes.length;
        recoveryModalOpen = true;
      }
      showToast(tr('systemhealth.new_recovery_codes_issued_the_previous'), 'success');
    } catch (err: any) {
      regenErr = err.message || tr('systemhealth.could_not_regenerate_recovery_codes');
    }
  }

  async function changePassword() {
    passErr = '';
    if (!oldPass || !newPass) {
      passErr = 'Both old and new passwords are required';
      return;
    }
    try {
      await apiFetch('/admin/change-password', {
        method: 'POST',
        // The handler binds {old,new} (internal/api). Sending old_password/
        // new_password left both empty, so every change 400'd with a
        // misleading length error and the password could never be changed.
        body: JSON.stringify({ old: oldPass, new: newPass })
      });
      oldPass = '';
      newPass = '';
      showToast(tr('systemhealth.password_changed_successfully'), 'success');
    } catch (err: any) {
      passErr = err.message || tr('systemhealth.failed_to_change_password');
    }
  }

  async function fetchCompose() {
    try {
      const res = await apiFetch<{ compose: string }>(`/deploy/compose?profiles=${encodeURIComponent(composeProfiles)}`);
      composeYaml = res.compose || '';
      showToast(tr('systemhealth.docker_compose_config_generated'), 'success');
    } catch (err: any) {
      showToast(tr('systemhealth.failed_to_generate_compose_config'), 'error');
    }
  }

  onMount(() => {
    loadData();
    loadTelegram();
    loadBackupS3();
    loadNetTune();
    loadUpdate();
  });
</script>

<div class="view-header">
  <h2>{tr('systemhealth.system_diagnostics_amp_security')}</h2>
  <button class="btn-primary" onclick={loadData}>{tr('systemhealth.refresh')}</button>
</div>

<div class="card" data-testid="doctor-panel">
  <div class="doctor-head">
    <h3>{tr('systemhealth.panel_doctor')}</h3>
    <button class="btn-sm" onclick={runDoctor} disabled={doctorBusy}>{doctorBusy ? tr('systemhealth.running') : tr('systemhealth.run_diagnostics')}</button>
  </div>
  {#if doctor?.health}
    <p class="doctor-state">
      {tr('systemhealth.overall')} <span class="badge {doctor.health.state === 'healthy' ? 'ok' : doctor.health.state === 'not_configured' ? 'warn' : 'err'}">{doctor.health.label || doctor.health.state}</span>
    </p>
    {#if doctor.health.subsystems}
      <div class="doctor-grid">
        {#each doctor.health.subsystems as sub}
          <div class="doctor-item">
            <span class="badge {sub.state === 'healthy' ? 'ok' : sub.state === 'not_configured' ? 'warn' : 'err'}">{sub.state}</span>
            <div><strong>{sub.label}</strong><span class="muted">{sub.summary}</span></div>
          </div>
        {/each}
      </div>
    {/if}
    {#if doctor.inbounds?.length}
      <p class="muted" style="margin-top:12px">{tr('systemhealth.inbound_s_checked', { length: doctor.inbounds.length })}</p>
    {/if}
  {:else}
    <p class="muted">{tr('systemhealth.click_run_diagnostics_to_check_the')}</p>
  {/if}
</div>

<div class="card">
  <h3>{tr('systemhealth.two_factor_authentication_2fa')}</h3>
  <p class="muted">{tr('systemhealth.protect_administrative_access_with_time_based')}</p>
  <div>
    {#if twoFAEnabled}
      <span class="badge badge-ok">{tr('systemhealth.2fa_enabled')}</span>
      {#if recoveryRemaining !== null}
        <span class="badge {recoveryRemaining <= 2 ? 'badge-warn' : ''}" style="margin-inline-start:8px"
          title={tr('systemhealth.single_use_codes_left_regenerate_before')}>
          {tr('systemhealth.recovery_code_left', { recoveryRemaining, p2: recoveryRemaining === 1 ? '' : 's' })}
        </span>
      {/if}
      <button class="btn-secondary" style="margin-inline-start:12px" onclick={() => { regenOpen = true; regenErr = ''; }}>
        {tr('systemhealth.regenerate_recovery_codes')}
      </button>
      <button class="btn-secondary danger" style="margin-inline-start:8px" onclick={() => { disableOpen = true; disableErr = ''; }}>
        {tr('systemhealth.disable_2fa')}
      </button>
      {#if recoveryRemaining !== null && recoveryRemaining <= 2}
        <p class="err-text">
          {tr('systemhealth.only_recovery_code_remain_regenerate_now', { recoveryRemaining, p2: recoveryRemaining === 1 ? '' : 's' })}
        </p>
      {/if}
    {:else}
      <button class="btn-primary" onclick={setup2FA}>{tr('systemhealth.enable_2fa_authenticator')}</button>
    {/if}
  </div>
</div>

<!-- Recovery codes. Shown exactly once: the server keeps only SHA-256 hashes,
     so there is no second chance to display them. -->
<Modal isOpen={recoveryModalOpen} title={tr('systemhealth.save_your_recovery_codes')} onClose={() => { recoveryModalOpen = false; recoveryCodes = []; }}>
  <p class="err-text">
    {tr('systemhealth.these_codes_are_shown_once_and')}
  </p>
  <pre class="recovery-codes" data-testid="recovery-codes">{recoveryCodes.join('\n')}</pre>
  <div class="form-grid">
    <button class="btn-secondary" onclick={copyRecoveryCodes}>{tr('systemhealth.copy_all')}</button>
    <button class="btn-primary" onclick={() => { recoveryModalOpen = false; recoveryCodes = []; }}>
      {tr('systemhealth.i_have_saved_them')}
    </button>
  </div>
</Modal>

<Modal isOpen={disableOpen} title={tr('systemhealth.disable_two_factor_authentication')} onClose={() => { disableOpen = false; disableCode = ''; }}>
  <p class="muted">
    {tr('systemhealth.enter_a_current_code_from_your')}
  </p>
  <div class="form-grid">
    <input bind:value={disableCode} placeholder={tr('systemhealth.6_digit_code')} data-testid="disable-2fa-code" />
    <button class="btn-secondary danger" onclick={disable2FA}>{tr('systemhealth.disable_2fa')}</button>
  </div>
  {#if disableErr}<p class="err-text">{disableErr}</p>{/if}
</Modal>

<Modal isOpen={regenOpen} title={tr('systemhealth.regenerate_recovery_codes')} onClose={() => { regenOpen = false; regenCode = ''; }}>
  <p class="muted">
    {tr('systemhealth.confirm_with_a_current_authenticator_code')}
  </p>
  <div class="form-grid">
    <input bind:value={regenCode} placeholder={tr('systemhealth.6_digit_code_or_password')} data-testid="regen-code" />
    <button class="btn-primary" onclick={regenerateRecoveryCodes}>{tr('systemhealth.issue_new_codes')}</button>
  </div>
  {#if regenErr}<p class="err-text">{regenErr}</p>{/if}
</Modal>

<div class="card" data-testid="telegram-card">
  <h3>{tr('systemhealth.telegram_alerts')}</h3>
  <p class="hint">{tr('systemhealth.telegram_hint')}</p>
  <div class="form-grid">
    <input type="password" bind:value={tgToken} data-testid="tg-token"
           placeholder={tg?.has_token ? tr('systemhealth.telegram_token_set') : tr('systemhealth.telegram_token_placeholder')} />
    <input bind:value={tgChats} data-testid="tg-chats" placeholder={tr('systemhealth.telegram_chats_placeholder')} />
    <button class="btn-secondary" data-testid="tg-test" onclick={testTelegram} disabled={tgBusy}>
      {tgBusy ? tr('systemhealth.telegram_working') : tr('systemhealth.telegram_send_test')}
    </button>
    <button class="btn-primary" data-testid="tg-save" onclick={() => saveTelegram(true)} disabled={tgBusy}>
      {tr('systemhealth.telegram_test_and_save')}
    </button>
  </div>
  <label class="chk">
    <input type="checkbox" bind:checked={tgBackup} data-testid="tg-backup" />
    <span>{tr('systemhealth.telegram_send_backups')}</span>
  </label>
  <p class="hint">{tr('systemhealth.telegram_backup_hint')}</p>
  {#if tgErr}
    <p class="err-text" data-testid="tg-error">{tgErr}</p>
    {#if tgRemedy}<p class="hint" data-testid="tg-remedy">{tgRemedy}</p>{/if}
  {/if}
  {#if tg}
    <p class="hint" data-testid="tg-status">
      {tg.running ? tr('systemhealth.telegram_running') : tr('systemhealth.telegram_not_running')}
      {#if tg.token_source === 'environment'}· {tr('systemhealth.telegram_from_env')}{/if}
    </p>
  {/if}
</div>

<div class="card" data-testid="backup-s3-card">
  <h3>{tr('systemhealth.s3_title')}</h3>
  <p class="hint">{tr('systemhealth.s3_hint')}</p>
  <label class="chk">
    <input type="checkbox" bind:checked={s3Enabled} data-testid="s3-enabled" />
    <span>{tr('systemhealth.s3_enable')}</span>
  </label>
  <div class="form-grid">
    <input bind:value={s3Endpoint} data-testid="s3-endpoint" placeholder={tr('systemhealth.s3_endpoint_placeholder')} />
    <input bind:value={s3Bucket} data-testid="s3-bucket" placeholder={tr('systemhealth.s3_bucket_placeholder')} />
    <input bind:value={s3Region} data-testid="s3-region" placeholder={tr('systemhealth.s3_region_placeholder')} />
    <input bind:value={s3Prefix} data-testid="s3-prefix" placeholder={tr('systemhealth.s3_prefix_placeholder')} />
    <input bind:value={s3AccessKey} data-testid="s3-access-key" placeholder={tr('systemhealth.s3_access_key_placeholder')} />
    <input type="password" bind:value={s3SecretKey} data-testid="s3-secret-key"
           placeholder={s3?.has_secret_key ? tr('systemhealth.s3_secret_key_set') : tr('systemhealth.s3_secret_key_placeholder')} />
    <button class="btn-secondary" data-testid="s3-test" onclick={testBackupS3} disabled={s3Busy}>
      {s3Busy ? tr('systemhealth.s3_working') : tr('systemhealth.s3_test_upload')}
    </button>
    <button class="btn-primary" data-testid="s3-save" onclick={saveBackupS3} disabled={s3Busy}>
      {tr('systemhealth.s3_save')}
    </button>
  </div>
  <label class="chk">
    <input type="checkbox" bind:checked={s3PathStyle} data-testid="s3-path-style" />
    <span>{tr('systemhealth.s3_path_style')}</span>
  </label>
  {#if s3Err}
    <p class="err-text" data-testid="s3-error">{s3Err}</p>
    {#if s3Remedy}<p class="hint" data-testid="s3-remedy">{s3Remedy}</p>{/if}
  {/if}
  {#if s3}
    <p class="hint" data-testid="s3-status">
      {s3.enabled && s3.configured ? tr('systemhealth.s3_uploading') : tr('systemhealth.s3_not_uploading')}
      {#if s3.key_fingerprint}· {tr('systemhealth.s3_key_fingerprint', { fingerprint: s3.key_fingerprint })}{/if}
    </p>
  {/if}
</div>

<WebhooksCard />

<div class="card" data-testid="nettune-card">
  <h3>{tr('systemhealth.nettune_title')}</h3>
  <p class="hint">{tr('systemhealth.nettune_hint')}</p>
  <label class="chk">
    <input type="checkbox" data-testid="nettune-toggle" disabled={netTuneBusy}
           bind:checked={netTuneWanted}
           onchange={() => saveNetTune(netTuneWanted)} />
    <span>{tr('systemhealth.nettune_enable')}</span>
  </label>
  {#if netTune}
    <p class="hint" data-testid="nettune-status">
      <span class="badge {netTune.active ? 'ok' : 'warn'}">{netTuneCongestion}</span>
      {tr('systemhealth.nettune_current', { qdisc: netTuneQdisc, kernel: netTuneKernel })}
      · {netTune.persisted ? tr('systemhealth.nettune_persisted') : tr('systemhealth.nettune_not_persisted')}
    </p>
    {#if !netTune.bbr_available && netTune.remediation}
      <p class="hint" data-testid="nettune-unavailable">{netTune.remediation}</p>
    {/if}
  {/if}
  {#if netTuneErr}
    <p class="err-text" data-testid="nettune-error">{netTuneErr}</p>
    {#if netTuneRemedy}<p class="hint" data-testid="nettune-remedy">{netTuneRemedy}</p>{/if}
  {/if}
</div>

<div class="card" data-testid="update-card">
  <h3>{tr('systemhealth.update_title')}</h3>
  <p class="hint">{tr('systemhealth.update_hint')}</p>
  <div class="form-row">
    <select bind:value={updChannel} onchange={saveChannel} disabled={updBusy}
            data-testid="update-channel" aria-label={tr('systemhealth.update_channel_label')}>
      <option value="stable">{tr('systemhealth.update_channel_stable')}</option>
      <option value="prerelease">{tr('systemhealth.update_channel_prerelease')}</option>
    </select>
    <button class="btn-secondary" data-testid="update-check" onclick={loadUpdate} disabled={updBusy}>
      {updBusy ? tr('systemhealth.update_working') : tr('systemhealth.update_check')}
    </button>
    <button class="btn-primary" data-testid="update-stage" onclick={stageUpdate}
            disabled={updBusy || !upd?.update_available}>
      {tr('systemhealth.update_stage')}
    </button>
  </div>
  {#if upd}
    <p class="hint" data-testid="update-status">
      <span class="badge {upd.update_available ? 'warn' : 'ok'}">{upd.latest}</span>
      {tr('systemhealth.update_running', { current: upd.current })}
      {#if upd.update_available}· {tr('systemhealth.update_available')}{:else}· {tr('systemhealth.update_current')}{/if}
    </p>
    {#if upd.apply_hint}
      <p class="hint" data-testid="update-apply-hint">{tr('systemhealth.update_apply', { cmd: upd.apply_hint })}</p>
    {/if}
  {/if}
  {#if updStaged}
    <p class="hint" data-testid="update-staged">{tr('systemhealth.update_staged', { tag: updStaged.tag, path: updStaged.path })}</p>
  {/if}
  {#if updErr}<p class="err-text" data-testid="update-error">{updErr}</p>{/if}
</div>

<div class="card">
  <h3>{tr('systemhealth.change_administrator_password')}</h3>
  <div class="form-grid">
    <input type="password" bind:value={oldPass} placeholder={tr('systemhealth.current_password')} />
    <input type="password" bind:value={newPass} placeholder={tr('systemhealth.new_password')} />
    <button class="btn-primary" onclick={changePassword}>{tr('systemhealth.update_password')}</button>
  </div>
  {#if passErr}<p class="err-text">{passErr}</p>{/if}
</div>

{#if healthDetail}
  <div class="card">
    <h3>{tr('systemhealth.subsystem_health_matrix')}</h3>
    <div class="subsystem-grid">
      {#each healthDetail.subsystems as s}
        <div class="subsystem-card">
          <span class="dot {s.state === 'healthy' ? 'ok' : s.state === 'not_configured' ? 'warn' : 'err'}"></span>
          <div class="subsystem-info">
            <strong>{s.label || s.key}</strong>
            <span class="detail">{s.detail || s.summary}</span>
          </div>
        </div>
      {/each}
    </div>
  </div>
{/if}

<div class="card">
  <h3>{tr('systemhealth.export_docker_compose_configuration')}</h3>
  <div class="form-row">
    <input type="text" bind:value={composeProfiles} placeholder={tr('systemhealth.profiles_default_dns_all')} />
    <button class="btn-secondary" onclick={fetchCompose}>{tr('systemhealth.generate_yaml')}</button>
  </div>
  {#if composeYaml}
    <pre><code>{composeYaml}</code></pre>
  {/if}
</div>

<Modal title={tr('systemhealth.set_up_2fa_authenticator')} isOpen={twoFAModalOpen} onClose={() => twoFAModalOpen = false}>
  {#if twoFAData}
    <div class="twofa-content">
      <p class="muted">{tr('systemhealth.scan_this_qr_code_with_google')}</p>
      {#if twoFAData.qr_code_url}
        <QRCode value={twoFAData.qr_code_url} size={200} />
      {/if}
      <p class="secret-text">{tr('systemhealth.secret_key')} <code>{twoFAData.secret}</code></p>
      <div class="form-row" style="margin-top:12px">
        <input type="text" bind:value={verifyCode} placeholder={tr('systemhealth.6_digit_totp_code')} />
        <button class="btn-primary" onclick={enable2FA}>{tr('systemhealth.verify_amp_activate')}</button>
      </div>
    </div>
  {/if}
</Modal>

<style>
  .chk { display: flex; align-items: center; gap: 8px; margin-top: 12px; font-size: 13px; }
  .view-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 24px; }
  .view-header h2 { margin: 0; font-size: 20px; font-weight: 650; }
  .card { background: var(--card); border: 1px solid var(--ln-3); border-radius: 14px; padding: 20px; margin-bottom: 20px; }
  .card h3 { margin: 0 0 16px; font-size: 14px; text-transform: uppercase; color: var(--t-3); }
  .form-grid { display: grid; grid-template-columns: 1fr 1fr auto; gap: 12px; }
  .form-row { display: flex; gap: 12px; }
  .form-row input { flex: 1; }
  input { background: var(--bg); border: 1px solid var(--ln-5); color: var(--fg); padding: 10px; border-radius: 8px; font: inherit; }
  .btn-primary { background: var(--acc); color: var(--acc-soft); border: none; font-weight: 700; padding: 10px 16px; border-radius: 8px; cursor: pointer; }
  .btn-secondary { background: var(--raised); color: var(--fg); border: 1px solid var(--ln-4); padding: 10px 16px; border-radius: 8px; cursor: pointer; font-weight: 600; }
  .btn-secondary.danger { color: var(--bad); border-color: rgba(255,77,77,0.3); }
  .badge { padding: 4px 8px; border-radius: 12px; font-size: 11px; font-weight: 600; }
  .badge-ok { background: rgba(39,209,124,0.15); color: var(--ok); }
  .subsystem-grid { display: grid; grid-template-columns: repeat(2, 1fr); gap: 12px; }
  .subsystem-card { display: flex; align-items: center; gap: 12px; background: var(--bg); padding: 12px; border-radius: 8px; }
  .dot { width: 10px; height: 10px; border-radius: 50%; flex: none; }
  .dot.ok { background: var(--ok); }
  .dot.warn { background: var(--warn-2); }
  .dot.err { background: var(--bad); }
  .subsystem-info { display: flex; flex-direction: column; }
  .detail { font-size: 12px; color: var(--t-7); }
  .err-text { color: var(--bad); font-size: 13px; margin-top: 8px; }
  .muted { color: var(--t-5); }
  pre { background: var(--bg); padding: 14px; border-radius: 8px; overflow-x: auto; color: var(--acc); font-family: monospace; margin-top: 12px; }
  .twofa-content { display: flex; flex-direction: column; align-items: center; gap: 12px; text-align: center; }
  .secret-text { font-size: 13px; color: var(--t-3); }
  .doctor-head { display: flex; justify-content: space-between; align-items: center; }
  .btn-sm { background: var(--raised); color: var(--fg); border: 1px solid var(--ln-5); padding: 6px 12px; border-radius: 6px; cursor: pointer; font-size: 12px; }
  .doctor-state { margin: 8px 0 12px; font-size: 14px; }
  .doctor-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(240px, 1fr)); gap: 10px; }
  .doctor-item { display: flex; gap: 10px; align-items: flex-start; background: var(--bg); padding: 10px 12px; border-radius: 8px; }
  .doctor-item strong { display: block; font-size: 13px; }
  .doctor-item .muted { font-size: 11px; }
  .badge.ok { background: rgba(39,209,124,0.15); color: var(--ok); }
  .badge.warn { background: rgba(255,180,0,0.15); color: var(--warn-2); }
  .badge.err { background: rgba(255,77,77,0.15); color: var(--bad); }
  .subsystem-info strong { word-break: break-word; }
  .subsystem-info .detail { font-size: 12px; color: var(--t-6); word-break: break-word; }

  /* Mobile: stack multi-column grids and rows so nothing runs off-screen. */
  @media (max-width: 768px) {
    .form-grid { grid-template-columns: 1fr; }
    .form-row { flex-direction: column; align-items: stretch; }
    .form-row input, .form-row button { width: 100%; }
    .subsystem-grid { grid-template-columns: 1fr; }
    .doctor-grid { grid-template-columns: 1fr; }
    .view-header { flex-wrap: wrap; gap: 10px; }
  }

  /* Recovery codes are the one thing on this page an operator must be able to
     read character-for-character and copy without transcription errors. */
  .recovery-codes {
    font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
    font-size: 0.95rem;
    line-height: 1.8;
    letter-spacing: 0.04em;
    background: var(--bg-input);
    border: 1px solid var(--border);
    border-radius: 6px;
    padding: 12px 16px;
    margin: 12px 0;
    white-space: pre;
    overflow-x: auto;
    user-select: all;
  }
  .badge-warn {
    background: rgba(217, 155, 43, 0.15);
    color: var(--warn);
    border: 1px solid rgba(217, 155, 43, 0.4);
  }
</style>
