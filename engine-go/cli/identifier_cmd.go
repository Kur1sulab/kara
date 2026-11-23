// identifier_cmd.go — `sweep identifier`：从文件或 stdin 里提取结构化标识符。
//
// 为什么单独一个子命令而不是塞进 report：它回答的是一个独立问题——「这份文件里
// 有没有能确认是真的身份证/银行卡/信用代码」。报告侧要的是「谁、在哪一行」，
// 而这里的判据只有一条：校验位算不算得通（见 identifier 包注释）。
package cli

import (
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/Kur1sulab/kara/engine-go/identifier"
	"github.com/Kur1sulab/kara/engine-go/jsonx"
)

// identifierDoc 是 --json 的输出结构。
//
// Matches 与 Candidates 分开而不是混在一起：下游脚本默认只消费 matches，
// 永远不会因为「顺手」把候选倒进报告；要看候选必须显式 --candidates。
type identifierDoc struct {
	File       string             `json:"file"`
	Bytes      int                `json:"bytes"`
	Lines      int                `json:"lines"`
	Matches    []identifier.Match `json:"matches"`
	Candidates []identifier.Match `json:"candidates,omitempty"`
}

func cmdIdentifier(args []string) int {
	const usage = "identifier <文件|-> [--json] [--candidates]"

	fs := newFlagSet()
	jsonOut := fs.Bool("json", false, "以 JSON 输出（供脚本/流水线消费）")
	showCandidates := fs.Bool("candidates", false, "同时列出未通过校验的候选（默认不输出）")
	// Go 的 flag 包在遇到第一个位置参数时就停止解析，而人的自然写法是
	// `kara identifier 某文件 --json`。这里把布尔旗标挪到前面再解析（"-" 表示
	// stdin，是位置参数不是旗标，必须留在原位）。新增带值旗标时要同步改这里。
	if code := parseOrUsage(fs, flagsFirst(args), "identifier", usage); code != -1 {
		return code
	}
	rest := fs.Args()
	if len(rest) != 1 {
		return missingArgs("identifier", usage)
	}

	path := rest[0]
	name := path
	var data []byte
	var err error
	if path == "-" {
		name = "<stdin>"
		data, err = io.ReadAll(os.Stdin)
	} else {
		data, err = os.ReadFile(path)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "[!] 读取失败: %v\n", err)
		return 1
	}

	text := string(data)
	all := identifier.DetectAll(text)
	matches := make([]identifier.Match, 0, len(all))
	candidates := make([]identifier.Match, 0, len(all))
	for _, m := range all {
		if m.Validated {
			matches = append(matches, m)
			continue
		}
		candidates = append(candidates, m)
	}
	lines := lineCount(text)

	if *jsonOut {
		doc := identifierDoc{File: name, Bytes: len(data), Lines: lines, Matches: matches}
		if *showCandidates {
			doc.Candidates = candidates
		}
		fmt.Println(jsonx.Pretty(doc))
		return 0
	}

	fmt.Printf("文件  %s · %d 行 · %d 字节\n", name, lines, len(data))
	fmt.Printf("命中  %d 条（校验位全部通过）\n", len(matches))
	if *showCandidates {
		fmt.Printf("候选  %d 条（未通过校验或本身无校验位，不计入命中）\n", len(candidates))
	} else if len(candidates) > 0 {
		fmt.Printf("候选  %d 条未通过校验，默认不输出（--candidates 查看）\n", len(candidates))
	} else {
		fmt.Printf("候选  0 条\n")
	}
	fmt.Println()

	if len(matches) > 0 {
		fmt.Printf("%s%s%s%s%s\n", padDisplay("类型", 10), padDisplay("脱敏值", 22), padDisplay("位置", 10), padDisplay("次数", 6), "校验依据")
		for _, m := range matches {
			fmt.Printf("%s%s%s%s%s\n",
				padDisplay(m.Kind.Label(), 10),
				padDisplay(m.Value, 22),
				padDisplay(fmt.Sprintf("%d:%d", m.Line, m.Column), 10),
				padDisplay(fmt.Sprintf("%d", m.Count), 6),
				m.Detail,
			)
		}
	} else if len(candidates) == 0 {
		fmt.Println("（没有发现任何结构化标识符）")
	}

	if *showCandidates && len(candidates) > 0 {
		fmt.Println()
		fmt.Println("候选（未通过校验 / 无校验位，不计入命中）：")
		fmt.Printf("%s%s%s%s\n", padDisplay("类型", 10), padDisplay("脱敏值", 22), padDisplay("位置", 10), "未通过原因")
		for _, m := range candidates {
			fmt.Printf("%s%s%s%s\n",
				padDisplay(m.Kind.Label(), 10),
				padDisplay(m.Value, 22),
				padDisplay(fmt.Sprintf("%d:%d", m.Line, m.Column), 10),
				m.Reason,
			)
		}
	}
	return 0
}

func lineCount(text string) int {
	if text == "" {
		return 0
	}
	n := strings.Count(text, "\n")
	if !strings.HasSuffix(text, "\n") {
		n++
	}
	return n
}

// displayWidth 终端显示宽度：CJK / 全角字符占 2 格。
// 不引 golang.org/x/text/width——标准库够用，也守住「零第三方依赖」这条线。
func displayWidth(s string) int {
	w := 0
	for _, r := range s {
		switch {
		case r >= 0x1100 && r <= 0x115F, // 韩文字母
			r >= 0x2E80 && r <= 0xA4CF, // CJK 部首 / 汉字 / 假名
			r >= 0xAC00 && r <= 0xD7A3, // 韩文音节
			r >= 0xF900 && r <= 0xFAFF, // CJK 兼容汉字
			r >= 0xFE30 && r <= 0xFE6F, // CJK 兼容形式
			r >= 0xFF00 && r <= 0xFF60, // 全角 ASCII
			r >= 0xFFE0 && r <= 0xFFE6: // 全角符号
			w += 2
		default:
			w++
		}
	}
	return w
}

func padDisplay(s string, width int) string {
	if d := displayWidth(s); d < width {
		return s + strings.Repeat(" ", width-d)
	}
	return s
}

// flagsFirst 把布尔旗标挪到位置参数之前，只为抵消 Go flag 包的「遇到第一个
// 非旗标就停止解析」语义。只适用于无值旗标（本命令的 --json / --candidates）；
// 将来加带值旗标时必须改成带参数搬移，别在这里偷懒。
func flagsFirst(args []string) []string {
	flags := make([]string, 0, len(args))
	pos := make([]string, 0, len(args))
	for _, a := range args {
		if len(a) > 1 && strings.HasPrefix(a, "-") {
			flags = append(flags, a)
			continue
		}
		pos = append(pos, a)
	}
	return append(flags, pos...)
}
