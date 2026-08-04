package telegram
import ("strings";"testing")
type fakeSender struct{ last string }
func (f *fakeSender) Send(_ int64, text string) error { f.last=text; return nil }
type fakeData struct{}
func (fakeData) Stats()(int,int,int){return 3,5,2}
func (fakeData) UserByName(n string)(string,string,float64,float64,bool){ if n=="alice"{return "alice","active",1.5,10,true}; return "","",0,0,false }
func (fakeData) SubURLForToken(t string)(string,bool){ if t=="tok"{return "https://p/sub/tok",true}; return "",false }
func TestBotRouting(t *testing.T){
 fs:=&fakeSender{}
 b:=New("",[]int64{42},fakeData{}); b.sender=fs
 // non-admin /stats blocked
 b.Handle(99,"/stats"); if !strings.Contains(fs.last,"admin only"){t.Fatalf("non-admin stats: %q",fs.last)}
 // admin /stats
 b.Handle(42,"/stats"); if !strings.Contains(fs.last,"Inbounds: 3"){t.Fatalf("admin stats: %q",fs.last)}
 // admin /user alice
 b.Handle(42,"/user alice"); if !strings.Contains(fs.last,"active")||!strings.Contains(fs.last,"1.50"){t.Fatalf("user: %q",fs.last)}
 // /sub self-service (any chat)
 b.Handle(7,"/sub tok"); if !strings.Contains(fs.last,"/sub/tok"){t.Fatalf("sub: %q",fs.last)}
 b.Handle(7,"/sub bad"); if !strings.Contains(fs.last,"unknown"){t.Fatalf("bad sub: %q",fs.last)}
 // help
 b.Handle(7,"/help"); if !strings.Contains(fs.last,"subscription"){t.Fatalf("help: %q",fs.last)}
 if New("",nil,fakeData{}).Enabled(){t.Fatal("empty token must be disabled")}
}
