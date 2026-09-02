/**
 * Telegram control surface.
 *
 * Scope, deliberately narrow: the bot reports state and hands out URLs. It does
 * NOT deploy from a chat message, because deploying needs a Cloudflare
 * credential and putting one behind a chat authorisation check means a single
 * `telegramUserID` typo hands the account to a stranger. The deploy path stays
 * on `forgectl edge deploy` (OAuth on the operator's machine) — see
 * `docs/FORGECTL_EDGE_SPEC.md` §"Telegram deploy path" for the split.
 *
 * Every update is checked against the configured owner id before ANY work: an
 * unauthenticated webhook is a public endpoint by construction.
 */

import type { EdgeConfig, EdgeSecrets } from '../config/schema';
import { HttpStatus } from '../common/http';

interface TgUpdate {
  message?: {
    message_id: number;
    chat: { id: number };
    from?: { id: number };
    text?: string;
  };
}

async function send(token: string, chatID: number, text: string): Promise<void> {
  await fetch(`https://api.telegram.org/bot${token}/sendMessage`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ chat_id: chatID, text, parse_mode: 'HTML', disable_web_page_preview: true }),
  });
}

export interface TelegramContext {
  cfg: EdgeConfig;
  secrets: EdgeSecrets;
  origin: string;
  /** Subscription tokens known to the edge, for `/subs`. */
  subTokens: string[];
  rotateSecurePath: () => Promise<string>;
}

const HELP = [
  '<b>ForgeEdge</b>',
  '/status — deployment and config summary',
  '/panel — the panel URL (contains the secure path)',
  '/subs — subscription URLs for known users',
  '/rotate — regenerate the secure path (invalidates every old URL)',
  '/help — this message',
].join('\n');

export async function handleTelegram(request: Request, ctx: TelegramContext): Promise<Response> {
  const { cfg, secrets } = ctx;
  if (!cfg.telegramBotToken || !cfg.telegramUserID) {
    return new Response('telegram not configured', { status: HttpStatus.NOT_FOUND });
  }
  if (request.method !== 'POST') {
    return new Response('Method Not Allowed', { status: HttpStatus.METHOD_NOT_ALLOWED });
  }

  let update: TgUpdate;
  try {
    update = (await request.json()) as TgUpdate;
  } catch {
    return new Response('bad update', { status: HttpStatus.BAD_REQUEST });
  }

  const msg = update.message;
  if (!msg?.text) return new Response('ok');

  // Owner-only, checked before anything else is read from the message.
  if (String(msg.from?.id ?? '') !== String(cfg.telegramUserID)) {
    return new Response('ok');
  }

  const token = cfg.telegramBotToken;
  const chat = msg.chat.id;
  const command = msg.text.trim().split(/\s+/)[0].toLowerCase();

  switch (command) {
    case '/start':
    case '/help':
      await send(token, chat, HELP);
      break;

    case '/status': {
      const lines = [
        '<b>ForgeEdge status</b>',
        `Protocols: ${cfg.protocols.join(', ')}`,
        `Ports: ${cfg.ports.join(', ')}`,
        `Backend mode: ${cfg.backend.enabled ? `on → ${cfg.backend.url}` : 'off (edge terminates; TCP only, DNS-over-UDP only)'}`,
        `Chain proxy: ${cfg.chainProxy ? 'configured' : 'none'}`,
        `Clean IPs: ${cfg.cleanIPs.length}`,
        `WARP endpoints: ${cfg.warp.endpoints.length}`,
        `Secure path rotated: ${secrets.rotatedAt}`,
      ];
      await send(token, chat, lines.join('\n'));
      break;
    }

    case '/panel':
      await send(token, chat, `${ctx.origin}/${secrets.securePath}/panel`);
      break;

    case '/subs': {
      if (ctx.subTokens.length === 0) {
        await send(token, chat, 'No users in the canonical feed yet. Push one from the ForgePanel VPS.');
        break;
      }
      const lines = ctx.subTokens
        .slice(0, 20)
        .map((t) => `${ctx.origin}/${secrets.securePath}/sub/${t}`);
      await send(token, chat, lines.join('\n'));
      break;
    }

    case '/rotate': {
      const fresh = await ctx.rotateSecurePath();
      await send(token, chat, `New panel URL:\n${ctx.origin}/${fresh}/panel\n\nEvery previous URL, including every subscription, is now dead.`);
      break;
    }

    default:
      await send(token, chat, HELP);
  }

  return new Response('ok');
}
