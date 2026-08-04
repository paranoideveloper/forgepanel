package backup
import ("os";"path/filepath";"testing";"bytes")
func TestBackupRestoreCycle(t *testing.T){
 dir:=t.TempDir()
 db:=filepath.Join(dir,"forgepanel.db"); sec:=filepath.Join(dir,"secrets.json")
 os.WriteFile(db,[]byte("SQLITE-DATA-here"),0600)
 os.WriteFile(sec,[]byte(`{"master":"x"}`),0600)
 blob,err:=Create("master-key",[]string{db,sec,filepath.Join(dir,"absent")}); if err!=nil{t.Fatal(err)}
 if len(blob)<10{t.Fatal("empty blob")}
 // wipe
 os.Remove(db); os.Remove(sec)
 rd:=t.TempDir()
 files,err:=Restore("master-key",blob,rd); if err!=nil{t.Fatal(err)}
 if len(files)!=2{t.Fatalf("expected 2 files restored, got %d",len(files))}
 got,_:=os.ReadFile(filepath.Join(rd,"forgepanel.db"))
 if !bytes.Equal(got,[]byte("SQLITE-DATA-here")){t.Fatal("db not restored intact")}
 // wrong key must fail
 if _,err:=Restore("WRONG-key",blob,rd);err==nil{t.Fatal("wrong key must fail to decrypt")}
 // tampered magic
 if _,err:=Restore("master-key",[]byte("garbage"),rd);err==nil{t.Fatal("bad blob must fail")}
}
