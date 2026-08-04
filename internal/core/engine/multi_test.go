package engine
import ("encoding/json";"strings";"testing"
 "github.com/forgepanel/forgepanel/internal/protocol/model")
func TestBuildMultiExpandsClients(t *testing.T){
 n:=&model.Node{Protocol:model.ProtoVLESS,Address:"0.0.0.0",Port:443,UUID:"tmpl",Transport:model.Transport{Network:model.NetTCP}}
 n.Normalize()
 sp:=InboundSpec{Node:n,Clients:[]ClientCred{{Email:"u1",UUID:"11111111-2222-3333-4444-555555555555"},{Email:"u2",UUID:"66666666-7777-8888-9999-000000000000"}}}
 b,err:=BuildMulti([]InboundSpec{sp},10085,"",""); if err!=nil{t.Fatal(err)}
 var cfg map[string]any; json.Unmarshal(b.Xray,&cfg)
 s:=string(b.Xray)
 if !strings.Contains(s,"u1")||!strings.Contains(s,"u2"){t.Fatal("both users must be clients in served config")}
 if !strings.Contains(s,"statsUserUplink"){t.Fatal("per-user stats policy must be enabled")}
}
