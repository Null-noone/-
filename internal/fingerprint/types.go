package fingerprint

// Input 是一条扫描原始记录。缺字段是合法输入，引擎不得因此失败。
type Input struct {
	IP     string
	Port   int
	Banner string
}

// Result 是题目要求的识别输出。认不出时 Protocol 必须为 unknown。
type Result struct {
	IP         string  `json:"ip"`
	Port       int     `json:"port"`
	Protocol   string  `json:"protocol"`
	Product    string  `json:"product"`
	Version    string  `json:"version"`
	OSHint     string  `json:"os_hint"`
	Confidence float64 `json:"confidence"`
}

func unknown(in Input) Result {
	return Result{
		IP:         in.IP,
		Port:       in.Port,
		Protocol:   "unknown",
		Product:    "",
		Version:    "",
		OSHint:     "",
		Confidence: 0,
	}
}
