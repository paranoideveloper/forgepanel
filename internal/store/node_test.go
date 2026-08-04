package store

import "testing"

func TestNodeEnrollFlow(t *testing.T) {
	s, _ := Open(":memory:")
	n := &Node{Name: "s7", Address: "203.0.113.10", EnrollToken: "tok-abc"}
	if err := s.CreateNode(n); err != nil {
		t.Fatal(err)
	}
	got, err := s.NodeByToken("tok-abc")
	if err != nil || got.Name != "s7" {
		t.Fatalf("node by token failed: %v", err)
	}
	got.Enrolled = true
	got.Healthy = true
	if err := s.SaveNode(got); err != nil {
		t.Fatal(err)
	}
	list, _ := s.ListNodes()
	if len(list) != 1 || !list[0].Enrolled {
		t.Fatal("node not enrolled/persisted")
	}
	if _, err := s.NodeByToken("wrong"); err == nil {
		t.Fatal("wrong token must fail")
	}
}
