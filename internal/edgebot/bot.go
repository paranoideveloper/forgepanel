package edgebot

import (
	"context"
	"fmt"
	"log"
	"strings"
	"time"
)

// Bot wires the transport, the store and the router together and runs the
// long-poll loop. Each update is handled in its own goroutine so a slow deploy
// (which can take the best part of a minute against Cloudflare) never blocks
// polling or other users; the store serialises all shared state internally.
type Bot struct {
	tg     *tgClient
	store  *Store
	router *Router
}

// New builds a bot from a token, a store and an Ops implementation.
func New(token string, store *Store, ops Ops) *Bot {
	return &Bot{
		tg:     newTGClient(token),
		store:  store,
		router: NewRouter(store, ops),
	}
}

// slowCommands get an immediate "working…" acknowledgement because they make a
// blocking Cloudflare round-trip that can take many seconds.
var slowCommands = map[string]bool{
	"deploy": true, "update": true, "destroy": true, "warp": true,
	"rotate": true, "refreships": true, "status": true, "probeip": true,
}

// Run connects and processes updates until ctx is cancelled.
func (b *Bot) Run(ctx context.Context) error {
	username, err := b.tg.GetMe(ctx)
	if err != nil {
		return fmt.Errorf("edgebot: could not connect to Telegram (check the token): %w", err)
	}
	b.router.SetBotUsername(username)
	// Populate Telegram's "Menu" button + "/" autocomplete so the bot is
	// discoverable without reading help. Best-effort: a failure here doesn't stop
	// the bot from serving.
	if err := b.tg.SetMyCommands(ctx, menuCommands()); err != nil {
		log.Printf("edgebot: setMyCommands: %v", err)
	}
	log.Printf("edgebot: connected as @%s — owner is %d", username, b.store.Owner())

	for {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		updates, err := b.tg.GetUpdates(ctx)
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			log.Printf("edgebot: getUpdates: %v", err)
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(3 * time.Second):
			}
			continue
		}
		for _, u := range updates {
			go b.dispatch(ctx, u)
		}
	}
}

// dispatch normalises one update, runs the router, and applies the result.
func (b *Bot) dispatch(parent context.Context, u tgUpdate) {
	in, ok := toIncoming(u)
	if !ok {
		return
	}
	// A deploy can run for the better part of a minute; give handlers room.
	ctx, cancel := context.WithTimeout(parent, 8*time.Minute)
	defer cancel()

	// Pre-acknowledge the slow commands so the user isn't left staring at nothing.
	if !in.IsCallback {
		if cmd, _ := parseCommand(strings.TrimSpace(in.Text), b.router.botUsername); slowCommands[cmd] {
			_ = b.tg.Send(ctx, Out{ChatID: in.ChatID, Text: "⏳ Working on it…"})
		}
	}

	res := b.router.Handle(ctx, in)

	if res.DeleteIncoming && in.MessageID != 0 {
		if err := b.tg.DeleteMessage(ctx, in.ChatID, in.MessageID); err != nil {
			log.Printf("edgebot: could not delete message %d: %v", in.MessageID, err)
		}
	}
	for _, out := range res.Outs {
		if err := b.tg.Send(ctx, out); err != nil {
			log.Printf("edgebot: send to %d: %v", out.ChatID, err)
		}
	}
	if in.IsCallback {
		_ = b.tg.AnswerCallback(ctx, in.CallbackID, res.CallbackAnswer)
	}
}

// toIncoming maps a raw Telegram update to the router's normalised Incoming.
func toIncoming(u tgUpdate) (Incoming, bool) {
	if u.CallbackQuery != nil {
		cb := u.CallbackQuery
		in := Incoming{
			UserID:       cb.From.ID,
			Username:     cb.From.Username,
			Name:         cb.From.displayName(),
			IsCallback:   true,
			CallbackID:   cb.ID,
			CallbackData: cb.Data,
		}
		if cb.Message != nil {
			in.ChatID = cb.Message.Chat.ID
			in.MessageID = cb.Message.MessageID
		} else {
			in.ChatID = cb.From.ID
		}
		return in, true
	}
	if u.Message != nil && u.Message.From != nil {
		m := u.Message
		return Incoming{
			UserID:    m.From.ID,
			ChatID:    m.Chat.ID,
			Username:  m.From.Username,
			Name:      m.From.displayName(),
			Text:      m.Text,
			MessageID: m.MessageID,
		}, true
	}
	return Incoming{}, false
}
