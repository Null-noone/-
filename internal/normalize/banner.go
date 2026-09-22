package normalize

import (
	"strconv"
	"strings"
	"unicode/utf8"
)

// Banner 同时保留原始串和扫描器常见转义解开后的串，规则对两者任一命中即可。
type Banner struct {
	Raw       string
	Unescaped string
}

func NewBanner(raw string) Banner {
	return Banner{Raw: raw, Unescaped: Unescape(raw)}
}

func (b Banner) Texts() []string {
	if b.Raw == b.Unescaped {
		return []string{b.Raw}
	}
	return []string{b.Raw, b.Unescaped}
}

// Unescape 解开扫描器常见的字面转义：\xHH、\n、\r、\t、\uXXXX。
func Unescape(s string) string {
	if !strings.Contains(s, `\`) {
		return s
	}
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); i++ {
		if s[i] != '\\' || i+1 >= len(s) {
			b.WriteByte(s[i])
			continue
		}
		switch s[i+1] {
		case 'x', 'X':
			if i+3 < len(s) && isHex(s[i+2]) && isHex(s[i+3]) {
				v, err := strconv.ParseUint(s[i+2:i+4], 16, 8)
				if err == nil {
					b.WriteByte(byte(v))
					i += 3
					continue
				}
			}
		case 'u', 'U':
			if i+5 < len(s) && isHex(s[i+2]) && isHex(s[i+3]) && isHex(s[i+4]) && isHex(s[i+5]) {
				v, err := strconv.ParseUint(s[i+2:i+6], 16, 32)
				if err == nil {
					var buf [4]byte
					n := utf8.EncodeRune(buf[:], rune(v))
					b.Write(buf[:n])
					i += 5
					continue
				}
			}
		case 'n':
			b.WriteByte('\n')
			i++
			continue
		case 'r':
			b.WriteByte('\r')
			i++
			continue
		case 't':
			b.WriteByte('\t')
			i++
			continue
		case '\\':
			b.WriteByte('\\')
			i++
			continue
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

func isHex(c byte) bool {
	return c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F'
}
