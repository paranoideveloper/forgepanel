package upstream

// The per-adapter option tables behind Manifest. Every entry is attributed to a
// section of docs/FORGEDNS_UPSTREAM_SETUP.md; Verified=false marks a key the
// panel emits (or offers as an override) for a fork whose OWN shipped sample did
// not show it, so an operator debugging a rejected config can see at a glance
// which keys are inherited from the shared dialect (§0) rather than read from
// that fork.
//
// The Managed set here is the renderer's key set, exactly. TestManifestMatchesRenderer
// (manifest_test.go) asserts that in both directions: if a key is added to RenderServer/RenderClient
// without a manifest entry (or vice versa) the build stays green but the test
// fails, which is the only cheap way to keep an editable surface honest about
// what the panel actually writes.

// serverOpt/clientOpt stamp the scope and the restart semantics so the tables
// below stay readable. Server keys are read once when the process starts, so
// every one of them restarts the zone; a client key only takes effect when the
// USER restarts their client, which the panel neither controls nor can report.
func serverOpt(o Option) Option { o.Scope, o.Restart = ScopeServer, true; return o }
func clientOpt(o Option) Option { o.Scope = ScopeClient; return o }

// cipherChoices is the DATA_ENCRYPTION_METHOD scale, identical across all three
// forks (§1–§3).
func cipherChoices() []Choice {
	return []Choice{
		{0, "None"}, {1, "XOR"}, {2, "ChaCha20"},
		{3, "AES-128-GCM"}, {4, "AES-192-GCM"}, {5, "AES-256-GCM"},
	}
}

func compressionChoices() []Choice {
	return []Choice{{0, "off"}, {1, "ZSTD"}, {2, "LZ4"}, {3, "ZLIB"}}
}

func protocolChoices() []Choice {
	return []Choice{{"SOCKS5", "SOCKS5 proxy"}, {"TCP", "fixed TCP forward"}}
}

func logLevelChoices() []Choice {
	return []Choice{{"DEBUG", "DEBUG"}, {"INFO", "INFO"}, {"WARN", "WARN"}, {"ERROR", "ERROR"}}
}

// serverOptions builds one fork's server manifest. Order matches RenderServer.
func serverOptions(d Descriptor) []Option {
	// The chained-egress trio is verbatim in the MasterDnsVPN and StormDNS
	// samples (§1, §2); the CottenDNS excerpt in §3 does not show it, but the
	// panel emits it there too because §4b treats it as part of the shared
	// dialect. Flagged unverified rather than quietly promoted.
	egressVerified := d.Adapter != AdapterCottenDNS

	out := []Option{
		serverOpt(Option{
			Key: "DOMAIN", Type: TypeStringList, Managed: true, Verified: true,
			Help: "Tunnel domains this server answers. Must match the client's DOMAINS, " +
				"and every one must be NS-delegated to this host.",
		}),
		serverOpt(Option{
			Key: "PROTOCOL_TYPE", Type: TypeString, Default: "SOCKS5", Choices: protocolChoices(),
			Managed: true, Verified: true,
			Help: "SOCKS5 serves a proxy to tunnel clients; TCP forwards every session to FORWARD_IP:FORWARD_PORT.",
		}),
		serverOpt(Option{
			Key: "UDP_HOST", Type: TypeString, Default: DefaultUDPHost, Managed: true, Verified: true,
			Help: "Address the authoritative DNS listener binds. Bind the public IP when systemd-resolved holds 0.0.0.0:53.",
		}),
		serverOpt(Option{
			Key: "UDP_PORT", Type: TypeInt, Default: DefaultUDPPort, Min: intPtr(1), Max: intPtr(65535),
			Managed: true, Verified: true,
			Help: "UDP port for the tunnel. 53 is the only port a delegated zone is queried on; anything else needs a port-forward in front.",
		}),
	}

	if d.HasListenerToggles { // CottenDNS only (§3)
		out = append(out,
			serverOpt(Option{
				Key: "TCP_LISTENER_ENABLED", Type: TypeBool, Default: true, Managed: true, Verified: true,
				Help: "Also answer DNS over TCP/53. Resolvers fall back to TCP for large answers, so leaving this off costs throughput.",
			}),
			serverOpt(Option{
				Key: "DOT_LISTENER_ENABLED", Type: TypeBool, Default: false, Managed: true, Verified: true,
				Help: "DNS-over-TLS listener on :853. Needs the port free and reachable.",
			}),
			serverOpt(Option{
				Key: "DOT_LISTEN_PORT", Type: TypeInt, Default: DefaultDoTPort, Min: intPtr(1), Max: intPtr(65535),
				Managed: true, Verified: true,
				Help: "Port for this zone's DoT listener. Leave it at 853 if this is the only zone serving DoT; " +
					"give each zone its own private port to share the public 853 behind the front router.",
			}),
			serverOpt(Option{
				Key: "DOT_LISTEN_HOST", Type: TypeString, Default: "", Managed: true, Runtime: true, Verified: true,
				Help: "Panel-owned. Pinned to 127.0.0.1 whenever DOT_LISTEN_PORT is private, because a private " +
					"port on a public interface is still reachable directly and silently bypasses the router.",
			}),
			serverOpt(Option{
				Key: "DOH_LISTENER_ENABLED", Type: TypeBool, Default: false, Managed: true, Verified: true,
				Help: "DNS-over-HTTPS listener on :443. Conflicts with any web server or proxy already on that port.",
			}),
			serverOpt(Option{
				Key: "DOH_LISTEN_PORT", Type: TypeInt, Default: DefaultDoHPort, Min: intPtr(1), Max: intPtr(65535),
				Managed: true, Verified: true,
				Help: "Port for this zone's DoH listener. Leave it at 443 if this is the only zone serving DoH; " +
					"give each zone its own private port to share the public 443 behind the front router.",
			}),
			serverOpt(Option{
				Key: "DOH_LISTEN_HOST", Type: TypeString, Default: "", Managed: true, Runtime: true, Verified: true,
				Help: "Panel-owned. Pinned to 127.0.0.1 whenever DOH_LISTEN_PORT is private.",
			}),
		)
	}

	out = append(out,
		serverOpt(Option{
			Key: "USE_EXTERNAL_SOCKS5", Type: TypeBool, Default: false, Managed: true, Verified: egressVerified,
			Help: "Chain tunnel traffic out through an upstream SOCKS5 proxy named by FORWARD_IP/FORWARD_PORT.",
		}),
		serverOpt(Option{
			Key: "FORWARD_IP", Type: TypeString, Default: "", Managed: true, Verified: egressVerified,
			Help: "Fixed TCP target in PROTOCOL_TYPE=TCP mode, or the upstream proxy host when USE_EXTERNAL_SOCKS5 is set.",
		}),
		serverOpt(Option{
			Key: "FORWARD_PORT", Type: TypeInt, Default: 0, Min: intPtr(0), Max: intPtr(65535),
			Managed: true, Verified: egressVerified,
			Help: "Port that goes with FORWARD_IP.",
		}),
		serverOpt(Option{
			Key: "DATA_ENCRYPTION_METHOD", Type: TypeInt, Default: d.DefaultCipher,
			Min: intPtr(0), Max: intPtr(5), Choices: cipherChoices(), Managed: true, Verified: true,
			Help: "Payload cipher. The client must use the same value unless the server auto-detects.",
		}),
	)

	if d.HasAutoDetect { // CottenDNS only (§3)
		out = append(out, serverOpt(Option{
			Key: "ENCRYPTION_AUTO_DETECT", Type: TypeBool, Default: true, Managed: true, Verified: true,
			Help: "Accept any cipher a client offers under the shared key, instead of requiring an exact DATA_ENCRYPTION_METHOD match.",
		}))
	}
	if d.HasARecordDelivery { // CottenDNS only (§3)
		out = append(out, serverOpt(Option{
			Key: "A_RECORD_DATA_DELIVERY", Type: TypeBool, Default: false, Managed: true, Verified: true,
			Help: "Also deliver payload bytes inside A records. Raises throughput on resolvers that mangle TXT, at the cost of a far more unusual answer shape.",
		}))
	}

	out = append(out,
		serverOpt(Option{
			Key: "ENCRYPTION_KEY_FILE", Type: TypeString, Default: EncryptKeyFile,
			Managed: true, Runtime: true, Verified: true,
			Help: "Path to the shared key, relative to the config directory. The panel is the key authority: it writes this file and this key, so an override of this path is ignored.",
		}),
		serverOpt(Option{
			Key: "LOG_LEVEL", Type: TypeString, Default: "INFO", Choices: logLevelChoices(),
			Managed: true, Verified: true,
			Help: "Verbosity of the supervised process's log, which is what the panel shows when a zone has no health endpoint.",
		}),
		serverOpt(Option{
			Key: "CONFIG_VERSION", Type: TypeString, Default: d.ConfigVersion,
			Managed: true, Runtime: true, Verified: true,
			Help: "Config dialect this fork accepts (" + d.ConfigVersion + "). The binary rejects a file stamped with any other version, so the panel stamps it and ignores overrides.",
		}),
	)
	return out
}

// clientOptions builds one fork's client manifest. Order matches RenderClient.
func clientOptions(d Descriptor) []Option {
	out := []Option{
		clientOpt(Option{
			Key: "DOMAINS", Type: TypeStringList, Managed: true, Verified: true,
			Help: "Tunnel domains to query. All of them must be served by the SAME server; mixing servers breaks session reassembly.",
		}),
	}

	if d.HasQueryTypes { // CottenDNS only (§3)
		out = append(out, clientOpt(Option{
			Key: "QUERY_TYPES", Type: TypeStringList, Default: []string{"TXT"},
			Members: QueryTypeChoices(), Managed: true, Verified: true,
			Help: "Query types to rotate through. A single type is a stable fingerprint; rotating costs a little efficiency and buys a much less distinctive query pattern.",
		}))
	}

	out = append(out,
		clientOpt(Option{
			Key: "DATA_ENCRYPTION_METHOD", Type: TypeInt, Default: d.DefaultCipher,
			Min: intPtr(0), Max: intPtr(5), Choices: cipherChoices(), Managed: true, Verified: true,
			Help: "Must match the server (or rely on the server's ENCRYPTION_AUTO_DETECT where that exists).",
		}),
		clientOpt(Option{
			Key: "ENCRYPTION_KEY", Type: TypeString, Secret: true, Managed: true, Runtime: true, Verified: true,
			Help: "The zone's shared secret, inline because this file IS the credential (§4d). Minted by the panel; masked in every response and never accepted from an override.",
		}),
		clientOpt(Option{
			Key: "PROTOCOL_TYPE", Type: TypeString, Default: "SOCKS5", Choices: protocolChoices(),
			Managed: true, Verified: true,
			Help: "Must match the server's PROTOCOL_TYPE.",
		}),
		clientOpt(Option{
			Key: "LISTEN_IP", Type: TypeString, Default: DefaultClientListenIP, Managed: true, Verified: true,
			Help: "Where the client's SOCKS5 proxy listens. 0.0.0.0 shares it with the LAN and should be paired with SOCKS5_AUTH.",
		}),
		clientOpt(Option{
			Key: "LISTEN_PORT", Type: TypeInt, Default: DefaultClientPort, Min: intPtr(1), Max: intPtr(65535),
			Managed: true, Verified: true,
			Help: "Local SOCKS5 port applications point at.",
		}),
		clientOpt(Option{
			Key: "STARTUP_MODE", Type: TypeString, Default: "resolvers",
			Choices: []Choice{{"ask", "prompt for a resolver"}, {"resolvers", "use client_resolvers.txt"}, {"logs", "reuse a cached resolver/MTU log"}},
			Managed: true, Verified: d.Adapter != AdapterMasterDNS,
			Help: "How the client picks a resolver at start. \"resolvers\" reads client_resolvers.txt, which is what the panel ships in the bundle.",
		}),
	)

	if d.HasResolverTransp { // CottenDNS only (§3)
		out = append(out, clientOpt(Option{
			Key: "RESOLVER_TRANSPORT", Type: TypeString, Default: "auto",
			Choices: []Choice{{"auto", "UDP first, escalate to TCP"}, {"udp", "UDP only"}, {"tcp", "TCP only"}},
			Managed: true, Verified: true,
			Help: "Transport used to reach the recursive resolver.",
		}))
	}
	if d.HasBalancing { // StormDNS sample (§2)
		out = append(out, clientOpt(Option{
			Key: "RESOLVER_BALANCING_STRATEGY", Type: TypeInt, Default: 3, Min: intPtr(1), Max: intPtr(8),
			Managed: true, Verified: true,
			Help: "How queries are spread over the resolver list: 1=random 2=round-robin 3=least-loss 4=lowest-latency (the family documents up to 8).",
		}))
	}
	if d.HasCompression { // StormDNS (§2) and CottenDNS (§3)
		out = append(out,
			clientOpt(Option{
				Key: "UPLOAD_COMPRESSION_TYPE", Type: TypeInt, Default: 2, Min: intPtr(0), Max: intPtr(3),
				Choices: compressionChoices(), Managed: true, Verified: true,
				Help: "Compression applied to bytes leaving the client. Every byte saved is a shorter QNAME, so this matters more here than on a normal transport.",
			}),
			clientOpt(Option{
				Key: "DOWNLOAD_COMPRESSION_TYPE", Type: TypeInt, Default: 2, Min: intPtr(0), Max: intPtr(3),
				Choices: compressionChoices(), Managed: true, Verified: true,
				Help: "Compression applied to bytes coming back in the answer.",
			}),
		)
	}

	out = append(out, clientOpt(Option{
		Key: "CONFIG_VERSION", Type: TypeString, Default: d.ConfigVersion,
		Managed: true, Runtime: true, Verified: true,
		Help: "Config dialect this fork's client accepts (" + d.ConfigVersion + ").",
	}))
	return append(out, clientOverrideOnly(d)...)
}

// clientOverrideOnly lists real client knobs the panel does NOT write. They are
// in the manifest so the advanced editor can validate and describe them instead
// of treating them as unknown text — but they stay out of the managed layer,
// because emitting a key a fork may not know is the §4b risk.
func clientOverrideOnly(d Descriptor) []Option {
	cotten := d.Adapter == AdapterCottenDNS
	out := []Option{
		clientOpt(Option{
			Key: "BASE_ENCODE_DATA", Type: TypeBool, Default: false,
			Verified: d.Adapter != AdapterMasterDNS,
			Help:     "Base-encode payload bytes (lowerbase32 / lowerbase36 / rawbase64) instead of packing them raw into the QNAME.",
		}),
	}
	if !d.HasBalancing {
		// The README of the original documents eight balancing strategies (§1)
		// but its shipped sample does not show the key, and the CottenDNS sample
		// does not either — offer it, unverified, rather than emit it.
		out = append(out, clientOpt(Option{
			Key: "RESOLVER_BALANCING_STRATEGY", Type: TypeInt, Min: intPtr(1), Max: intPtr(8),
			Help: "Resolver selection strategy. Not present in this fork's shipped sample; set it only if your build accepts it.",
		}))
	}
	if !d.HasCompression {
		out = append(out,
			clientOpt(Option{Key: "UPLOAD_COMPRESSION_TYPE", Type: TypeInt, Min: intPtr(0), Max: intPtr(3),
				Choices: compressionChoices(), Help: "Upload compression. Not shown in this fork's shipped sample."}),
			clientOpt(Option{Key: "DOWNLOAD_COMPRESSION_TYPE", Type: TypeInt, Min: intPtr(0), Max: intPtr(3),
				Choices: compressionChoices(), Help: "Download compression. Not shown in this fork's shipped sample."}),
		)
	}
	if !cotten {
		return out
	}
	return append(out,
		clientOpt(Option{
			Key: "QNAME_LABEL_LENGTH", Type: TypeInt, Min: intPtr(1), Max: intPtr(63), Verified: true,
			Help: "Bytes per DNS label in the outgoing query name. 63 is the protocol maximum; shorter labels look more ordinary and carry less payload.",
		}),
		clientOpt(Option{
			Key: "DUPLICATION_PREFER_DISTINCT_DOMAINS", Type: TypeBool, Default: false, Verified: true,
			Help: "Spread duplicated queries across DOMAINS instead of repeating one. No effect with a single domain or a duplication count of 1.",
		}),
		clientOpt(Option{
			Key: "SOCKS5_AUTH", Type: TypeBool, Default: false, Verified: true,
			Help: "Require username/password on the client's SOCKS5 listener. Set this whenever LISTEN_IP is not loopback.",
		}),
		clientOpt(Option{
			Key: "SOCKS5_USER", Type: TypeString, Verified: true,
			Help: "Username for the client's SOCKS5 listener when SOCKS5_AUTH is on.",
		}),
		clientOpt(Option{
			Key: "SOCKS5_PASS", Type: TypeString, Secret: true, Verified: true,
			Help: "Password for the client's SOCKS5 listener. Masked in every response.",
		}),
	)
}
