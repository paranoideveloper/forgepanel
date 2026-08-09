package model

import "strings"

// CountryFlag turns an ISO-3166 alpha-2 country code into its flag emoji by
// mapping each letter to its Regional Indicator Symbol (U+1F1E6..U+1F1FF).
// Anything that is not exactly two ASCII letters returns "" — an unknown or
// unset country simply contributes no flag rather than a broken glyph.
func CountryFlag(code string) string {
	code = strings.TrimSpace(code)
	if len(code) != 2 {
		return ""
	}
	var b strings.Builder
	for i := 0; i < 2; i++ {
		c := code[i]
		switch {
		case c >= 'a' && c <= 'z':
			c -= 'a' - 'A'
		case c >= 'A' && c <= 'Z':
		default:
			return ""
		}
		b.WriteRune(rune(0x1F1E6 + int(c-'A')))
	}
	return b.String()
}

// NameFields are the values a subscription naming template can interpolate.
type NameFields struct {
	Name     string // the inbound's own remark
	Country  string // ISO alpha-2, upper-cased
	Flag     string // flag emoji for Country
	Protocol string // vless, trojan, …
	Net      string // transport network: tcp, ws, grpc, …
	TLS      string // security type: tls, reality, none
	Port     string
	Host     string // domain/SNI if any, else address
	User     string // subscriber username
	Num      string // 1-based index within the subscription
	Date     string // caller-supplied date stamp (YYYY-MM-DD)
}

// ExpandNameTemplate substitutes {PLACEHOLDER} tokens in tmpl. Unknown tokens
// are left verbatim so a typo is visible rather than silently eaten. The result
// is trimmed and its inner whitespace collapsed, so an empty {FLAG} or {COUNTRY}
// does not leave a double space or a leading gap.
func ExpandNameTemplate(tmpl string, f NameFields) string {
	r := strings.NewReplacer(
		"{NAME}", f.Name,
		"{COUNTRY}", f.Country,
		"{CC}", f.Country,
		"{FLAG}", f.Flag,
		"{PROTOCOL}", f.Protocol,
		"{PROTO}", f.Protocol,
		"{NET}", f.Net,
		"{TRANSPORT}", f.Net,
		"{TLS}", f.TLS,
		"{SECURITY}", f.TLS,
		"{PORT}", f.Port,
		"{HOST}", f.Host,
		"{USER}", f.User,
		"{NUM}", f.Num,
		"{DATE}", f.Date,
	)
	return strings.Join(strings.Fields(r.Replace(tmpl)), " ")
}

// NameFieldsFromNode derives the template fields from a finalized node (after
// address/identity are stamped). date is supplied by the caller so the pure
// function stays deterministic and testable.
func NameFieldsFromNode(n *Node, baseName, user string, num int, date string) NameFields {
	host := n.Domain
	if host == "" {
		host = n.Address
	}
	cc := strings.ToUpper(strings.TrimSpace(n.Country))
	net := string(n.Transport.Network)
	if net == "" {
		net = "tcp"
	}
	return NameFields{
		Name:     baseName,
		Country:  cc,
		Flag:     CountryFlag(cc),
		Protocol: string(n.Protocol),
		Net:      net,
		TLS:      string(n.Security.Type),
		Port:     itoa(n.Port),
		Host:     host,
		User:     user,
		Num:      itoa(num),
		Date:     date,
	}
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	neg := i < 0
	if neg {
		i = -i
	}
	var buf [20]byte
	p := len(buf)
	for i > 0 {
		p--
		buf[p] = byte('0' + i%10)
		i /= 10
	}
	if neg {
		p--
		buf[p] = '-'
	}
	return string(buf[p:])
}
