package main

import "testing"

func TestInstallerChecksum(t *testing.T) {
	checksum, err := installerChecksum([]byte("abc123  forgepanel-linux-amd64\n0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef  install.sh\n"))
	if err != nil {
		t.Fatal(err)
	}
	if checksum != "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef" {
		t.Fatalf("checksum = %q", checksum)
	}
}

func TestInstallerChecksumRejectsMissingAsset(t *testing.T) {
	if _, err := installerChecksum([]byte("0123  other-file\n")); err == nil {
		t.Fatal("missing installer checksum was accepted")
	}
}
