package adapter

import (
	"testing"

	"github.com/forgepanel/forgepanel/internal/core/engine"
	"github.com/forgepanel/forgepanel/internal/protocol/model"
)

// The whole adapter refactor rests on one claim: feeding engine.BuildMulti only
// ONE core's inbounds produces byte-identical output to feeding it all of them
// and taking that core's half. If that is false, splitting the reload across
// adapters silently changes the configs the cores are given — which is a change,
// not a refactor, and the kind that shows up as an outage rather than a test
// failure.
//
// This pins it for a mixed inbound set spanning both supervised cores.

func mixedSpecs() []engine.InboundSpec {
	mk := func(p model.Protocol, port int, remark string) engine.InboundSpec {
		n := &model.Node{
			Protocol: p, Address: "0.0.0.0", Port: port, Remark: remark,
			UUID:     "b831381d-6324-4d53-ad4f-8cda48b30811",
			Password: "hunter2hunter2",
		}
		switch p {
		case model.ProtoHysteria2, model.ProtoTUIC, model.ProtoAnyTLS:
			n.Security = model.Security{Type: model.SecTLS, ServerName: "example.com"}
		}
		n.Normalize()
		return engine.InboundSpec{Node: n, Clients: []engine.ClientCred{
			{Email: "u1", UUID: "11111111-2222-4333-8444-555555555555", Password: "pw1"},
		}}
	}
	return []engine.InboundSpec{
		mk(model.ProtoVLESS, 21001, "x1"),
		mk(model.ProtoHysteria2, 21002, "s1"),
		mk(model.ProtoVMess, 21003, "x2"),
		mk(model.ProtoTUIC, 21004, "s2"),
		mk(model.ProtoTrojan, 21005, "x3"),
		mk(model.ProtoAnyTLS, 21006, "s3"),
	}
}

func splitByEngine(specs []engine.InboundSpec, engineName string) []engine.InboundSpec {
	var out []engine.InboundSpec
	for _, sp := range specs {
		if model.EngineFor(sp.Node.Protocol) == engineName {
			out = append(out, sp)
		}
	}
	return out
}

func TestBuildMultiSubsetMatchesTheCombinedBuild(t *testing.T) {
	all := mixedSpecs()
	combined, err := engine.BuildMulti(all, 10085, "/c.pem", "/k.pem")
	if err != nil {
		t.Fatalf("combined build: %v", err)
	}

	xrayOnly, err := engine.BuildMulti(splitByEngine(all, model.EngineXray), 10085, "/c.pem", "/k.pem")
	if err != nil {
		t.Fatalf("xray-only build: %v", err)
	}
	if string(xrayOnly.Xray) != string(combined.Xray) {
		t.Errorf("the xray config differs when built from its own inbounds only.\n"+
			"Splitting the reload across adapters would therefore CHANGE what the core is given.\n"+
			"subset len=%d combined len=%d", len(xrayOnly.Xray), len(combined.Xray))
	}
	if xrayOnly.XrayN != combined.XrayN {
		t.Errorf("xray inbound count differs: subset %d, combined %d", xrayOnly.XrayN, combined.XrayN)
	}

	sbOnly, err := engine.BuildMulti(splitByEngine(all, model.EngineSingBox), 10085, "/c.pem", "/k.pem")
	if err != nil {
		t.Fatalf("sing-box-only build: %v", err)
	}
	if string(sbOnly.Singbox) != string(combined.Singbox) {
		t.Errorf("the sing-box config differs when built from its own inbounds only.\n"+
			"subset len=%d combined len=%d", len(sbOnly.Singbox), len(combined.Singbox))
	}
	if sbOnly.SingboxN != combined.SingboxN {
		t.Errorf("sing-box inbound count differs: subset %d, combined %d", sbOnly.SingboxN, combined.SingboxN)
	}
}
