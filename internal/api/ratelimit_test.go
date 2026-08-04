package api
import ("testing";"time")
func TestLoginLimiter(t *testing.T){
 l:=newLoginLimiter(); base:=time.Unix(1700000000,0); l.now=func()time.Time{return base}
 ip:="1.2.3.4"
 for i:=0;i<4;i++{ if !l.Allowed(ip){t.Fatalf("should allow attempt %d",i)}; if d:=l.Fail(ip);d!=0{t.Fatalf("no lockout in first 4, got %v",d)} }
 if d:=l.Fail(ip); d==0 {t.Fatal("5th failure should lock out")}
 if l.Allowed(ip){t.Fatal("should be locked out now")}
 // success clears
 l.Success(ip); if !l.Allowed(ip){t.Fatal("success must clear lockout")}
}
