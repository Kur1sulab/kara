package cli

// identifier 子命令的契约测试：
//   - `identifier <文件>` 默认只输出校验通过的命中，候选不出现；
//   - `--candidates` 才把未通过校验的候选列出来；
//   - `--json` 的结构稳定（matches / candidates 分开），且脱敏值里没有原文；
//   - 缺参数 exit 2、文件读不到 exit 1、stdin 用 "-"；
//   - 旗标写在文件名之后也要生效（Go flag 包默认不认，本命令做了重排）。
//
// 校验位算法的正确性在 identifier 包里测，这里只钉 CLI 的接线与输出契约。

import (
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// makeID 按 GB 11643 算校验位，只为造输入数据（不是被测对象）。
func makeID(prefix17 string) string {
	weights := [17]int{7, 9, 10, 5, 8, 4, 2, 1, 6, 3, 7, 9, 10, 5, 8, 4, 2}
	sum := 0
	for i := 0; i < 17; i++ {
		sum += int(prefix17[i]-'0') * weights[i]
	}
	return prefix17 + string("10X98765432"[sum%11])
}

// luhnOK 用于挑「脏身份证」：18 位数字里恰好有 1/10 会过 Luhn，
// 那种串被报成 bank_card 是正确行为，不适合拿来做「只该有 1 条命中」的用例。
func luhnOK(s string) bool {
	sum := 0
	for i := len(s) - 1; i >= 0; i-- {
		d := int(s[i] - '0')
		if (len(s)-1-i)%2 == 1 {
			d *= 2
			if d > 9 {
				d -= 9
			}
		}
		sum += d
	}
	return sum%10 == 0
}

// badID 返回一个校验位被改错、且不会顺带过 Luhn 的身份证串（保证它只能是候选）。
func badID(good string) string {
	for _, d := range "0123456789X" {
		cand := good[:17] + string(d)
		if cand == good {
			continue
		}
		if !luhnOK(cand) {
			return cand
		}
	}
	return good[:17] + "X"
}

// captureRun 跑一次 Run 并把 stdout 收回来（本包输出量小，不会写满管道）。
func captureRun(t *testing.T, args ...string) (int, string) {
	t.Helper()
	old := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout = w
	code := Run(args)
	w.Close()
	os.Stdout = old
	b, _ := io.ReadAll(r)
	r.Close()
	return code, string(b)
}

func writeTemp(t *testing.T, name, content string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestIdentifierCLIJSONStrictByDefault(t *testing.T) {
	good := makeID("11010119900307123")
	bad := badID(good)
	path := writeTemp(t, "ids.txt", "真值 "+good+"\n脏值 "+bad+"\n")

	code, out := captureRun(t, "identifier", path, "--json")
	if code != 0 {
		t.Fatalf("exit 应为 0，得 %d：%s", code, out)
	}
	var doc struct {
		File    string `json:"file"`
		Lines   int    `json:"lines"`
		Matches []struct {
			Kind      string `json:"kind"`
			Value     string `json:"value"`
			Validated bool   `json:"validated"`
		} `json:"matches"`
		Candidates []any `json:"candidates"`
	}
	if err := json.Unmarshal([]byte(out), &doc); err != nil {
		t.Fatalf("JSON 解析失败: %v\n%s", err, out)
	}
	if len(doc.Matches) != 1 || doc.Matches[0].Kind != "id_card" || !doc.Matches[0].Validated {
		t.Fatalf("默认只应报 1 条身份证命中，得 %+v", doc.Matches)
	}
	if doc.Candidates != nil {
		t.Errorf("未加 --candidates 时不应出现 candidates 字段：%s", out)
	}
	if strings.Contains(out, good) || strings.Contains(doc.Matches[0].Value, good) {
		t.Error("输出里出现了完整身份证号，脱敏失效")
	}
	if !strings.Contains(doc.Matches[0].Value, "*") {
		t.Errorf("脱敏值应含星号，得 %q", doc.Matches[0].Value)
	}
	if doc.Lines != 2 {
		t.Errorf("行数应为 2，得 %d", doc.Lines)
	}
}

func TestIdentifierCLICandidatesFlagAfterPath(t *testing.T) {
	good := makeID("31011520000229001")
	bad := badID(good)
	path := writeTemp(t, "ids.txt", "真值 "+good+"\n脏值 "+bad+"\n")

	// 旗标写在路径之后：Go flag 默认会当成位置参数，本命令必须自己重排。
	code, out := captureRun(t, "identifier", path, "--candidates")
	if code != 0 {
		t.Fatalf("exit 应为 0，得 %d：%s", code, out)
	}
	if !strings.Contains(out, "候选（未通过校验") {
		t.Fatalf("应打印候选表：\n%s", out)
	}
	if !strings.Contains(out, "命中  1 条") {
		t.Errorf("脏值不该进命中：\n%s", out)
	}
}

func TestIdentifierCLIMissingArgs(t *testing.T) {
	if code, _ := captureRun(t, "identifier"); code != 2 {
		t.Errorf("缺文件参数应 exit 2，得 %d", code)
	}
}

func TestIdentifierCLIMissingFile(t *testing.T) {
	if code, out := captureRun(t, "identifier", filepath.Join(t.TempDir(), "nope.txt")); code != 1 {
		t.Errorf("文件读不到应 exit 1，得 %d：%s", code, out)
	}
}

func TestIdentifierCLIStdin(t *testing.T) {
	good := makeID("44030519930707123")
	f, err := os.CreateTemp(t.TempDir(), "stdin")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString("身份证 " + good + "\n"); err != nil {
		t.Fatal(err)
	}
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		t.Fatal(err)
	}
	old := os.Stdin
	os.Stdin = f
	defer func() { os.Stdin = old; f.Close() }()

	code, out := captureRun(t, "identifier", "-")
	if code != 0 {
		t.Fatalf("exit 应为 0，得 %d：%s", code, out)
	}
	if !strings.Contains(out, "<stdin>") || !strings.Contains(out, "命中  1 条") {
		t.Errorf("stdin 模式输出不对：\n%s", out)
	}
}

func TestIdentifierHelpMentionsCommand(t *testing.T) {
	if !strings.Contains(helpText, "identifier <文件|->") {
		t.Error("helpText 应含 identifier 用法行（否则 kara --help 里看不到）")
	}
}
