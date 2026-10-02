package config

import "testing"

// A Railway deployment stamps its links with the default Custom profile.
func TestARailwayDeploymentCarriesTheDefaultDesync(t *testing.T) {
	t.Setenv("RAILWAY_PUBLIC_DOMAIN", "app.up.railway.app")
	got := DetectPaaS().Desync
	if got != (Desync{Profile: "Custom", Args: DefaultDesyncArgs}) {
		t.Fatalf("got %+v", got)
	}
}

// Railway only: no other platform, a forced generic PaaS or a normal install
// changes its links.
func TestNoOtherDeploymentCarriesDesync(t *testing.T) {
	for _, env := range [][2]string{
		{"RENDER_EXTERNAL_HOSTNAME", "app.onrender.com"},
		{"FLY_APP_NAME", "app"},
		{"KOYEB_PUBLIC_DOMAIN", "app.koyeb.app"},
		{"FORGEPANEL_PAAS", "1"},
		{"PORT", "8080"},
	} {
		t.Run(env[0], func(t *testing.T) {
			t.Setenv(env[0], env[1])
			t.Setenv("FORGEPANEL_PINGNG_PROFILE", "Severe")
			if got := DetectPaaS().Desync; got != (Desync{}) {
				t.Fatalf("%s=%s produced %+v", env[0], env[1], got)
			}
		})
	}
}

// FORGEPANEL_PAAS=0 turns the whole mode off, Desync included.
func TestForcingPaaSOffDropsDesync(t *testing.T) {
	t.Setenv("RAILWAY_PUBLIC_DOMAIN", "app.up.railway.app")
	t.Setenv("FORGEPANEL_PAAS", "0")
	if got := DetectPaaS().Desync; got != (Desync{}) {
		t.Fatalf("got %+v", got)
	}
}

func TestTheDesyncProfileIsChosenByEnvironment(t *testing.T) {
	cases := []struct {
		profile, args string
		want          Desync
	}{
		// PingNG matches names case sensitively, so they are re-spelled its way.
		{"balanced", "", Desync{Profile: "Balanced"}},
		{"SEVERE", "", Desync{Profile: "Severe"}},
		// A built-in profile brings its own arguments; pngargs would be ignored.
		{"Light", "--split 2", Desync{Profile: "Light"}},
		{"off", "--split 2", Desync{}},
		{"Off", "", Desync{}},
		{"custom", "--split 2+s\n  --tlsrec 1+s", Desync{Profile: "Custom", Args: "--split 2+s --tlsrec 1+s"}},
		{"", "--disorder 1", Desync{Profile: "Custom", Args: "--disorder 1"}},
		// A name PingNG does not know would switch Desync off on every phone.
		{"aggressive-ish", "", Desync{Profile: "Custom", Args: DefaultDesyncArgs, Rejected: "aggressive-ish"}},
	}
	for _, c := range cases {
		t.Run(c.profile+"|"+c.args, func(t *testing.T) {
			t.Setenv("RAILWAY_PUBLIC_DOMAIN", "app.up.railway.app")
			t.Setenv("FORGEPANEL_PINGNG_PROFILE", c.profile)
			t.Setenv("FORGEPANEL_PINGNG_ARGS", c.args)
			if got := DetectPaaS().Desync; got != c.want {
				t.Fatalf("got %+v, want %+v", got, c.want)
			}
		})
	}
}
