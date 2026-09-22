package fingerprint

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

// Rule 是一条外部规则。匹配逻辑全在 YAML 里，代码只负责加载与执行。
type Rule struct {
	ID                 string   `yaml:"id"`
	Protocol           string   `yaml:"protocol"`
	Product            string   `yaml:"product"`
	Priority           int      `yaml:"priority"`
	Confidence         float64  `yaml:"confidence"`
	BannerRegex        string   `yaml:"banner_regex"`
	BannerContains     []string `yaml:"banner_contains"`
	BannerNotContains  []string `yaml:"banner_not_contains"`
	PortIn             []int    `yaml:"port_in"`
	PortNotIn          []int    `yaml:"port_not_in"`
	OSHints            []OSHint `yaml:"os_hints"`
	VersionStripSuffix string   `yaml:"version_strip_suffix"`

	re *regexp.Regexp
}

type OSHint struct {
	Value string `yaml:"value"`
	Regex string `yaml:"regex"`
	re    *regexp.Regexp
}

func LoadRulesDir(dir string) ([]Rule, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("read rules dir %s: %w", dir, err)
	}
	var rules []Rule
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		ext := strings.ToLower(filepath.Ext(name))
		if ext != ".yaml" && ext != ".yml" {
			continue
		}
		path := filepath.Join(dir, name)
		raw, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("read %s: %w", path, err)
		}
		var part []Rule
		if err := yaml.Unmarshal(raw, &part); err != nil {
			return nil, fmt.Errorf("parse %s: %w", path, err)
		}
		rules = append(rules, part...)
	}
	if err := compileRules(rules); err != nil {
		return nil, err
	}
	sort.SliceStable(rules, func(i, j int) bool {
		if rules[i].Priority != rules[j].Priority {
			return rules[i].Priority > rules[j].Priority
		}
		return rules[i].Confidence > rules[j].Confidence
	})
	return rules, nil
}

func compileRules(rules []Rule) error {
	for i := range rules {
		r := &rules[i]
		if r.ID == "" {
			return fmt.Errorf("rule missing id")
		}
		if r.Protocol == "" {
			return fmt.Errorf("rule %s missing protocol", r.ID)
		}
		if r.Confidence <= 0 {
			r.Confidence = 0.5
		}
		if r.Confidence > 1 {
			r.Confidence = 1
		}
		if r.BannerRegex != "" {
			re, err := regexp.Compile(r.BannerRegex)
			if err != nil {
				return fmt.Errorf("rule %s banner_regex: %w", r.ID, err)
			}
			r.re = re
		}
		for j := range r.OSHints {
			h := &r.OSHints[j]
			if h.Regex == "" || h.Value == "" {
				continue
			}
			re, err := regexp.Compile(h.Regex)
			if err != nil {
				return fmt.Errorf("rule %s os_hint %s: %w", r.ID, h.Value, err)
			}
			h.re = re
		}
	}
	return nil
}
