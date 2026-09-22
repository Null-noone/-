package fingerprint

import (
	"regexp"
	"strings"

	"bannerfp/internal/normalize"
)

type Engine struct {
	rules []Rule
}

func NewEngine(rules []Rule) *Engine {
	return &Engine{rules: rules}
}

func (e *Engine) Identify(in Input) (out Result) {
	defer func() {
		if rec := recover(); rec != nil {
			out = unknown(in)
		}
	}()
	out = unknown(in)
	if e == nil || len(e.rules) == 0 {
		return out
	}
	banner := normalize.NewBanner(in.Banner)
	for _, rule := range e.rules {
		if hit, version, product, osHint := matchRule(rule, in.Port, banner); hit {
			out.Protocol = rule.Protocol
			out.Product = firstNonEmpty(product, rule.Product)
			out.Version = cleanVersion(version, rule.VersionStripSuffix)
			out.OSHint = osHint
			out.Confidence = clamp(rule.Confidence)
			return out
		}
	}
	return out
}

func (e *Engine) IdentifyBatch(items []Input) []Result {
	out := make([]Result, len(items))
	for i, item := range items {
		out[i] = e.Identify(item)
	}
	return out
}

func matchRule(rule Rule, port int, banner normalize.Banner) (bool, string, string, string) {
	if len(rule.PortIn) > 0 && !containsInt(rule.PortIn, port) {
		return false, "", "", ""
	}
	if len(rule.PortNotIn) > 0 && containsInt(rule.PortNotIn, port) {
		return false, "", "", ""
	}

	var matchedText string
	ok := false
	for _, text := range banner.Texts() {
		if ruleMatchesText(rule, text) {
			matchedText = text
			ok = true
			break
		}
	}
	if !ok {
		return false, "", "", ""
	}

	version, product := "", ""
	if rule.re != nil {
		if m := namedGroups(rule.re, matchedText); m != nil {
			version = m["version"]
			product = m["product"]
		}
		if version == "" {
			for _, text := range banner.Texts() {
				if m := namedGroups(rule.re, text); m != nil {
					if version == "" {
						version = m["version"]
					}
					if product == "" {
						product = m["product"]
					}
				}
			}
		}
	}
	return true, version, product, pickOSHint(rule, banner)
}

func ruleMatchesText(rule Rule, text string) bool {
	if rule.re != nil && !rule.re.MatchString(text) {
		return false
	}
	lower := strings.ToLower(text)
	for _, part := range rule.BannerContains {
		if part != "" && !strings.Contains(lower, strings.ToLower(part)) {
			return false
		}
	}
	for _, part := range rule.BannerNotContains {
		if part != "" && strings.Contains(lower, strings.ToLower(part)) {
			return false
		}
	}
	if rule.re == nil && len(rule.BannerContains) == 0 {
		return false
	}
	return true
}

func namedGroups(re *regexp.Regexp, text string) map[string]string {
	if re == nil {
		return nil
	}
	idx := re.FindStringSubmatchIndex(text)
	if idx == nil {
		return nil
	}
	out := map[string]string{}
	for _, name := range re.SubexpNames() {
		if name == "" {
			continue
		}
		i := re.SubexpIndex(name)
		if i < 0 || i*2+1 >= len(idx) || idx[i*2] < 0 {
			continue
		}
		out[name] = text[idx[i*2]:idx[i*2+1]]
	}
	return out
}

func pickOSHint(rule Rule, banner normalize.Banner) string {
	for _, h := range rule.OSHints {
		if h.re == nil {
			continue
		}
		for _, text := range banner.Texts() {
			if h.re.MatchString(text) {
				return h.Value
			}
		}
	}
	return ""
}

func cleanVersion(v, strip string) string {
	v = strings.TrimSpace(v)
	v = strings.Trim(v, "()[]<>\"'`")
	if strip != "" {
		if i := strings.Index(strings.ToLower(v), strings.ToLower(strip)); i > 0 {
			v = v[:i]
		}
	}
	v = strings.TrimRight(v, ".,;:/\\-_")
	return v
}

func containsInt(list []int, v int) bool {
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
}

func firstNonEmpty(a, b string) string {
	if strings.TrimSpace(a) != "" {
		return a
	}
	return b
}

func clamp(v float64) float64 {
	if v < 0 {
		return 0
	}
	if v > 1 {
		return 1
	}
	return v
}
