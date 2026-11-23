package identifier

// 本文件的测试数据分两层：
//   - 正例：真的能过校验位的值（含闰日、校验位 X、小写 x、真实企业信用代码）；
//   - 反例：格式与长度都对、只错一处（校验位差一位 / 2 月 30 日 / 行政区划 99 /
//     未来生日 / 全 0 卡号）。反例是重点：它们长得跟真值一模一样，
//     只有校验位和结构校验能把它们挡住。
//
// 钉死的一条契约：Detect 永远不返回 Validated=false 的项。校验位不过就不许报，
// 这是 precision≈1 的唯一支点（自由文本正则只有 0.6）。

import (
	"encoding/json"
	"regexp"
	"strings"
	"testing"
)

// ── 身份证 ──

func TestIDCard(t *testing.T) {
	cases := []struct {
		name string
		text string
		want int
	}{
		{"正例/普通", "身份证：" + id1, 1},
		{"正例/闰日 2000-02-29", "身份证：" + id2, 1},
		{"正例/校验位为 X", "身份证：" + idX, 1},
		{"正例/小写 x", "身份证：" + idLowerX, 1},
		{"反例/校验位差一位", idBadSum, 0},
		{"反例/2 月 30 日（校验位却是对的）", idBadDate, 0},
		{"反例/行政区划 99（校验位也是对的）", idBadProv, 0},
		{"反例/未来生日", idFuture, 0},
		{"反例/只有 17 位", idShort, 0},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := Detect(c.text)
			if len(got) != c.want {
				t.Fatalf("命中 %d 条，期望 %d：%+v", len(got), c.want, got)
			}
			for _, m := range got {
				if m.Kind != KindIDCard {
					t.Errorf("类型应为 id_card，得 %s", m.Kind)
				}
				if !m.Validated {
					t.Error("Detect 不应返回未通过校验的项")
				}
			}
		})
	}
}

// TestIDCardChecksumPinned 用标准向量把 MOD 11-2 钉死：同一前 17 位，
// 校验位只有唯一一个答案。
//
// 这里刻意分两层断言，因为 18 位数字同时是「合法银行卡号」的概率是 1/10：
// 换掉校验位后，某个数字完全可能刚好过 Luhn。那是**真的**合法卡号形状，
// Detect 把它报成 bank_card 不算误报；但绝不能报成 id_card。
func TestIDCardChecksumPinned(t *testing.T) {
	base := id1[:17]
	ok := 0
	for _, d := range "0123456789X" {
		v := checkIDCard(base + string(d))
		if !v.ok {
			continue
		}
		ok++
		if base+string(d) != id1 {
			t.Errorf("校验位 %c 不该通过 GB 11643", d)
		}
	}
	if ok != 1 {
		t.Fatalf("11 个候选校验位里应恰好 1 个通过，得 %d", ok)
	}
	// 集成层：无论换哪个校验位，Detect 都不许把它标成身份证。
	for _, d := range "0123456789X" {
		cand := base + string(d)
		if cand == id1 {
			continue
		}
		for _, m := range Detect(cand) {
			if m.Kind == KindIDCard {
				t.Fatalf("校验位 %c 错误却被报成身份证：%+v", d, m)
			}
		}
	}
}

// ── 银行卡 ──

func TestBankCard(t *testing.T) {
	cases := []struct {
		name string
		text string
		want int
	}{
		{"正例/16 位工行 BIN", "卡号：" + bank16a, 1},
		{"正例/19 位", "卡号：" + bank19, 1},
		{"正例/13 位", "卡号：" + bank13, 1},
		{"正例/BIN 不在离线表（unknown）", "卡号：" + bankNoBIN, 1},
		{"反例/Luhn 差一位", bankBadSum, 0},
		{"反例/全 0（能过 Luhn，靠首位与全同规则挡）", bankZero, 0},
		{"反例/20 位（超长，边界不干净）", bank20, 0},
		{"反例/12 位（太短）", bankShort, 0},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := Detect(c.text)
			if len(got) != c.want {
				t.Fatalf("命中 %d 条，期望 %d：%+v", len(got), c.want, got)
			}
			for _, m := range got {
				if m.Kind != KindBankCard {
					t.Errorf("类型应为 bank_card，得 %s", m.Kind)
				}
			}
		})
	}
}

func TestBankCardIssuer(t *testing.T) {
	got := Detect(bank16a)
	if len(got) != 1 {
		t.Fatalf("应命中 1 条，得 %d", len(got))
	}
	if !strings.Contains(got[0].Detail, "工商银行") {
		t.Errorf("BIN 622202 应识别为工商银行，得 %q", got[0].Detail)
	}
	// 离线表没收录的 BIN 必须写 unknown，不能猜一个银行名。
	got = Detect(bankNoBIN)
	if len(got) != 1 || !strings.Contains(got[0].Detail, "unknown") {
		t.Errorf("未知 BIN 应写 unknown，得 %+v", got)
	}
}

// ── 手机号 ──

func TestMobile(t *testing.T) {
	cases := []struct {
		name string
		text string
		want int
	}{
		{"正例/移动号段", "联系：" + mob1, 1},
		{"正例/联通号段", "联系：" + mob2, 1},
		{"正例/电信号段", "联系：" + mob3, 1},
		{"反例/12 开头不是手机号", "12845678901", 0},
		{"反例/运营商公开测试号", "138" + "00138000", 0},
		{"反例/只有 10 位", "1380013800", 0},
		{"反例/后 8 位全同（占位串）", "138" + "88888888", 0},
		{"反例/连号（12345678）", "138" + "01234567", 0},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := Detect(c.text)
			if len(got) != c.want {
				t.Fatalf("命中 %d 条，期望 %d：%+v", len(got), c.want, got)
			}
			for _, m := range got {
				if m.Kind != KindMobile {
					t.Errorf("类型应为 mobile，得 %s", m.Kind)
				}
				// 手机号没有校验位，详情必须写明，不能冒充「校验通过」。
				if !strings.Contains(m.Detail, "无校验位") {
					t.Errorf("详情应注明无校验位，得 %q", m.Detail)
				}
			}
		})
	}
}

// ── 统一社会信用代码 ──

func TestUSCC(t *testing.T) {
	cases := []struct {
		name string
		text string
		want int
	}{
		{"正例/工商登记 9", "信用代码：" + uscc1, 1},
		{"正例/真实企业（阿里巴巴）", "91330100716105852F", 1},
		{"正例/其他登记部门 Y", "信用代码：" + uscc2, 1},
		{"反例/校验位差一位", usccBadSum, 0},
		{"反例/登记管理部门代码 2", usccBadDept, 0},
		{"反例/行政区划 99（校验位对的）", usccBadProv, 0},
		{"反例/只有 17 位", usccShort, 0},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := Detect(c.text)
			if len(got) != c.want {
				t.Fatalf("命中 %d 条，期望 %d：%+v", len(got), c.want, got)
			}
			for _, m := range got {
				if m.Kind != KindUSCC {
					t.Errorf("类型应为 uscc，得 %s", m.Kind)
				}
			}
		})
	}
}

// ── 车牌（只做候选）──

func TestPlateOnlyCandidate(t *testing.T) {
	for _, p := range []string{"京A12345", "粤B88888", "沪C00001"} {
		if got := Detect("车牌号：" + p); len(got) != 0 {
			t.Errorf("车牌没有校验位，Detect 不该报：%s → %+v", p, got)
		}
		all := DetectAll("车牌号：" + p)
		if len(all) != 1 {
			t.Fatalf("%s 应产生 1 条候选，得 %d", p, len(all))
		}
		if all[0].Validated || all[0].Kind != KindPlate {
			t.Errorf("%s 应是未验证的车牌候选，得 %+v", p, all[0])
		}
		if !strings.Contains(all[0].Reason, "无校验位") {
			t.Errorf("候选原因应说明无校验位，得 %q", all[0].Reason)
		}
	}
	for _, bad := range []string{"京I12345", "京A1234", "甲A12345", "京A123456"} {
		if got := DetectAll(bad); len(got) != 0 {
			t.Errorf("%s 不是合法车牌形状，不该进候选：%+v", bad, got)
		}
	}
}

// ── 核心契约：校验位不过，一条都不许报 ──

func TestInvalidChecksumNeverReported(t *testing.T) {
	dirty := []struct {
		name string
		raw  string
		kind Kind
	}{
		{"身份证 校验位差一位", idBadSum, KindIDCard},
		{"身份证 生日 2 月 30 日", idBadDate, KindIDCard},
		{"身份证 行政区划 99", idBadProv, KindIDCard},
		{"银行卡 Luhn 差一位", bankBadSum, KindBankCard},
		{"信用代码 校验位差一位", usccBadSum, KindUSCC},
	}
	for _, d := range dirty {
		t.Run(d.name, func(t *testing.T) {
			if got := Detect("值：" + d.raw); len(got) != 0 {
				t.Fatalf("校验位不过却报了 %d 条：%+v", len(got), got)
			}
			all := DetectAll("值：" + d.raw)
			if len(all) != 1 {
				t.Fatalf("候选应恰好 1 条，得 %d：%+v", len(all), all)
			}
			if all[0].Validated {
				t.Error("候选不能标记为 validated")
			}
			if all[0].Kind != d.kind {
				t.Errorf("候选类型应为 %s，得 %s", d.kind, all[0].Kind)
			}
			if all[0].Reason == "" {
				t.Error("候选必须写明未通过的原因")
			}
		})
	}
}

// ── 跨类型去重：同一片段只算一种 ──

func TestOverlapPriority(t *testing.T) {
	// 这串同时过 GB 11643 与 Luhn（两张算法撞在同一条 18 位数字上）。
	// 只能报一条，且必须是身份证——否则同一串数字会在报告里出现两次。
	got := Detect(idAlsoLuhn)
	if len(got) != 1 || got[0].Kind != KindIDCard {
		t.Fatalf("同时符合身份证与银行卡时应只报身份证，得 %+v", got)
	}
	// 这串同时过 GB 11643 与 GB 32100（18 位纯数字也能满足信用代码字符集）。
	got = Detect(idAlsoUSCC)
	if len(got) != 1 || got[0].Kind != KindIDCard {
		t.Fatalf("同时符合身份证与信用代码时应只报身份证，得 %+v", got)
	}
}

// 脏值也不许把真值挤掉：一段文本里既有「18 位但校验错」的串，也有真正的卡号。
func TestCandidateNeverDisplacesValid(t *testing.T) {
	text := "A=" + idBadSum + " B=" + idAlsoLuhn
	got := Detect(text)
	if len(got) != 1 || got[0].Kind != KindIDCard || !got[0].Validated {
		t.Fatalf("真值被脏值挤掉了：%+v", got)
	}
}

// 两个真命中之间夹一条脏值：脏值必须作为候选保留下来。
// 这条钉的是区间判定的边界——「只看最后一个已接受区间」的实现会把夹在中间的
// 候选误判成相交（前面的区间早就结束了），候选表里就凭空少一条。
func TestCandidateInGapBetweenValidated(t *testing.T) {
	text := "甲 " + bank16a + " " + strings.Repeat("x", 20) + " " + idBadSum + " " + strings.Repeat("y", 20) + " " + bank19
	got := Detect(text)
	if len(got) != 2 {
		t.Fatalf("应命中 2 张银行卡，得 %d：%+v", len(got), got)
	}
	all := DetectAll(text)
	cands := 0
	for _, m := range all {
		if !m.Validated {
			cands++
		}
	}
	if cands != 1 {
		t.Fatalf("夹在两个真命中之间的脏值应保留 1 条候选，得 %d：%+v", cands, all)
	}
}

// ── 脱敏 ──

func TestMasking(t *testing.T) {
	text := strings.Join([]string{id1, bank16a, mob1, uscc1}, "\n")
	matches := Detect(text)
	if len(matches) != 4 {
		t.Fatalf("应命中 4 类各 1 条，得 %d：%+v", len(matches), matches)
	}
	raws := map[Kind]string{KindIDCard: id1, KindBankCard: bank16a, KindMobile: mob1, KindUSCC: uscc1}
	for _, m := range matches {
		raw := raws[m.Kind]
		if m.Value == raw {
			t.Errorf("%s 未脱敏，原值泄露", m.Kind)
		}
		if strings.Contains(m.Value, raw) {
			t.Errorf("%s 的脱敏值包含完整原文", m.Kind)
		}
		if len([]rune(m.Value)) != len([]rune(raw)) {
			t.Errorf("%s 脱敏后长度应不变（便于核对同一条），得 %q", m.Kind, m.Value)
		}
		if !strings.Contains(m.Value, "*") {
			t.Errorf("%s 脱敏值应含掩码星号，得 %q", m.Kind, m.Value)
		}
	}
	byKind := map[Kind]Match{}
	for _, m := range matches {
		byKind[m.Kind] = m
	}
	// 身份证/银行卡/信用代码：前 6 后 4。
	for _, k := range []Kind{KindIDCard, KindBankCard, KindUSCC} {
		if ok, _ := regexp.MatchString(`^\w{6}\*+\w{4}$`, byKind[k].Value); !ok {
			t.Errorf("%s 应保留前 6 后 4，得 %q", k, byKind[k].Value)
		}
	}
	// 手机号：3-4-4。
	if ok, _ := regexp.MatchString(`^\d{3}\*{4}\d{4}$`, byKind[KindMobile].Value); !ok {
		t.Errorf("手机号应为 3-4-4 掩码，得 %q", byKind[KindMobile].Value)
	}
	// 车牌：留省份简称 + 字母 + 末 2 位。
	plates := DetectAll("京A12345")
	if len(plates) != 1 {
		t.Fatalf("车牌候选应 1 条，得 %d", len(plates))
	}
	if plates[0].Value != "京A***45" {
		t.Errorf("车牌掩码应为 京A***45，得 %q", plates[0].Value)
	}
}

// TestJSONCarriesNoRawValue JSON 是给脚本/流水线消费的，脱敏必须在这一层也成立。
func TestJSONCarriesNoRawValue(t *testing.T) {
	text := strings.Join([]string{id1, bank16a, mob1, uscc1}, "\n")
	b, err := json.Marshal(DetectAll(text))
	if err != nil {
		t.Fatal(err)
	}
	for _, raw := range []string{id1, bank16a, mob1, uscc1} {
		if strings.Contains(string(b), raw) {
			t.Fatalf("JSON 里出现了完整原文：%s", b)
		}
	}
}

// ── 位置与去重 ──

func TestPosition(t *testing.T) {
	text := "第一行\n身份证号：" + id1 + "。"
	got := Detect(text)
	if len(got) != 1 {
		t.Fatalf("应命中 1 条，得 %d", len(got))
	}
	wantOff := strings.Index(text, id1)
	if got[0].Offset != wantOff {
		t.Errorf("offset 应为 %d，得 %d", wantOff, got[0].Offset)
	}
	if got[0].Line != 2 {
		t.Errorf("line 应为 2，得 %d", got[0].Line)
	}
	// 「身份证号：」5 个 rune → 列号从 6 起。中文按 rune 计，不按字节。
	if got[0].Column != 6 {
		t.Errorf("column 应为 6，得 %d", got[0].Column)
	}
}

func TestDedup(t *testing.T) {
	text := "第一处 " + bank16a + "\n第二处 " + bank16a
	got := Detect(text)
	if len(got) != 1 {
		t.Fatalf("同一卡号应只报 1 条，得 %d", len(got))
	}
	if got[0].Count != 2 {
		t.Errorf("Count 应记 2 次，得 %d", got[0].Count)
	}
	if got[0].Line != 1 {
		t.Errorf("位置应记首次出现（第 1 行），得第 %d 行", got[0].Line)
	}
}

// ── 边界：长数字串、字母紧邻 ──

func TestBoundary(t *testing.T) {
	// 25 位流水号里截不出任何「边界干净」的卡号——否则每个订单号都会进候选。
	if got := DetectAll("订单号 " + strings.Repeat("9", 25)); len(got) != 0 {
		t.Errorf("长数字串不该命中：%+v", got)
	}
	// 前后紧挨字母视为同一个 token（哈希、拼接 ID）。
	if got := DetectAll("hash:" + bank16a + "abc"); len(got) != 0 {
		t.Errorf("字母紧邻的数字串不该命中：%+v", got)
	}
	// 中文紧邻没问题：真实文档里「身份证1101…」不会有空格。
	if got := Detect("身份证" + id1 + "号"); len(got) != 1 {
		t.Errorf("中文紧邻应能命中，得 %d 条", len(got))
	}
}

// ── 测试数据 ──
//
// 生成方式：先用独立实现（Python）按 GB 11643 / Luhn / GB 32100 算好，
// 再以字面量钉在这里——Go 侧的校验实现若与标准有偏差，这些值会立刻报不出来。
const (
	id1        = "110101199003070003" // 110101 19900307 123X
	id2        = "310115200002290013" // 310115 20000229 001X（闰日）
	idX        = "11010119880615007X" // 校验位为 X
	idLowerX   = "44030519930707003x" // 校验位 x（小写）
	idBadSum   = "110101199003070000" // 校验位差一位
	idBadDate  = "110101199002300006" // 生日 2 月 30 日，校验位却是对的
	idBadProv  = "990101199003070007" // 行政区划 99，校验位对的
	idFuture   = "110101209901010009" // 2099 年生日
	idShort    = "11010119900307000"  // 17 位
	idAlsoLuhn = "110101199003070054" // 同时过 GB 11643 与 Luhn
	idAlsoUSCC = "113101199003070778" // 同时过 GB 11643 与 GB 32100

	bank16a    = "6222020000000007"     // 622202 开头，16 位
	bank19     = "6216610000000000008"  // 19 位
	bank13     = "6222021234566"        // 13 位
	bankNoBIN  = "6200001234567892"     // 620000 开头（不在离线表）
	bankBadSum = "6222020000000008"     // Luhn 差一位
	bankZero   = "0000000000000000"     // 全 0，能过 Luhn
	bank20     = "62220200000000000001" // 20 位
	bankShort  = "62220212345"          // 12 位

	mob1 = "13800001234"
	mob2 = "18600005678"
	mob3 = "19900009012"

	uscc1       = "91110108MA01ABCD1E" // 9 工商 + MA 组织机构码
	uscc2       = "Y1110108MA01ABCD1Q" // Y 其他登记部门
	usccBadSum  = "91110108MA01ABCD1F"
	usccBadDept = "21110108MA01ABCD1M"
	usccBadProv = "91990108MA01ABCD15"
	usccShort   = "91110108MA01ABCD1"
)
