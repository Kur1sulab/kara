// Package identifier 从自由文本里提取中国结构化标识符（身份证 / 银行卡 / 手机号 /
// 统一社会信用代码 / 车牌），并且**只在校验位通过时才判定为命中**。
//
// 为什么要这么较真（调研总纲 §4 P1）：自由文本里「18 位数字」这种正则的精度只有
// 0.6 上下——订单号、流水号、时间戳拼接、哈希片段都长这样。身份证有 GB 11643 的
// MOD 11-2、银行卡有 Luhn、统一社会信用代码有 GB 32100 的 base31，随机串能蒙混过关
// 的概率分别是 1/11、1/10、1/31；把校验位当闸门，报出来的每一条都是「算得通的」，
// 精度才接近 1。所以本包的分层是：
//
//   - Detect 只返回校验通过的命中（CLI 默认只输出这一层）；
//   - DetectAll 额外返回未通过的候选（Validated=false 且带 Reason），
//     只供 --candidates 人工复核，默认不进报告；
//   - 车牌没有校验位，永远只算候选——宁可不出，也不拿格式正则冒充「已确认」；
//   - 手机号也没有校验位，Validated 的含义是「格式合法且不是占位号」，
//     Detail 里明写「无校验位可核」，不冒充校验通过。
//
// 另一个硬约束是脱敏：Match.Value 一定是打过码的，本包不对外暴露原文。
// 报告、日志、JSON 里都不该出现完整身份证/卡号——脱敏不是展示偏好，是交付底线。
package identifier

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"
	"unicode/utf8"
)

// Kind 标识符类型（JSON 里用稳定的英文键，中文只出现在展示层）。
type Kind string

const (
	KindIDCard   Kind = "id_card"   // 居民身份证（GB 11643-1999，18 位）
	KindBankCard Kind = "bank_card" // 银行卡号（ISO/IEC 7812 + Luhn）
	KindMobile   Kind = "mobile"    // 中国大陆手机号（无校验位）
	KindUSCC     Kind = "uscc"      // 统一社会信用代码（GB 32100-2015，18 位）
	KindPlate    Kind = "plate"     // 中国车牌（无校验位 → 只做候选）
)

// Label 中文短名，用于终端表格。信用代码全称太长，表格里压到 4 个字。
func (k Kind) Label() string {
	switch k {
	case KindIDCard:
		return "身份证"
	case KindBankCard:
		return "银行卡"
	case KindMobile:
		return "手机号"
	case KindUSCC:
		return "信用代码"
	case KindPlate:
		return "车牌"
	}
	return string(k)
}

// Match 一条命中。
//
// Offset/Line/Column 都指向**首次出现**的位置：同一份文件里同一个号码重复出现
// （页眉页脚、日志重复行）只报一次，次数记在 Count 里——否则一份 200 页的 PDF
// 能把同一个卡号报 200 遍，报告直接没法看。
type Match struct {
	Kind      Kind   `json:"kind"`
	Value     string `json:"value"`     // 已脱敏，绝不出现完整值
	Validated bool   `json:"validated"` // true=校验位/权威结构通过；false=候选
	Offset    int    `json:"offset"`    // 原文中的字节偏移（0 起）
	Line      int    `json:"line"`      // 行号（1 起）
	Column    int    `json:"column"`    // 列号（1 起，按 rune 计）
	Count     int    `json:"count"`     // 同一值在文中的出现次数（≥1）
	Detail    string `json:"detail,omitempty"`
	Reason    string `json:"reason,omitempty"` // 仅候选：为什么没通过
}

// Detect 返回校验通过的结构化标识符。口径就是「报出来的都能算通」。
func Detect(text string) []Match { return collect(text, false) }

// DetectAll 返回校验通过的命中 + 未通过的候选（Validated=false）。
// 候选只用于人工复核，不要直接进报告——那会把 precision 打回正则水平。
func DetectAll(text string) []Match { return collect(text, true) }

// ── 候选收集 ──

type candidate struct {
	kind           Kind
	start, end     int
	priority       int
	validated      bool
	detail, reason string
}

// 优先级只在「同一条原文片段同时符合多种格式」时决定归属。身份证排最前：
// 18 位数字如果真能过 GB 11643，它几乎不可能是银行卡（两者都过的概率约 1/110，
// 现实中一串数字更可能是身份证）。
const (
	prioIDCard = iota + 1
	prioUSCC
	prioBankCard
	prioMobile
	prioPlate
)

var (
	// 身份证：17 位数字 + 校验位（0-9 或 X）。15 位旧证没有校验位，本包不收
	// （收了也只能算候选，意义不大，还会把「15 位订单号」带进候选噪音里）。
	reIDCard = regexp.MustCompile(`[0-9]{17}[0-9Xx]`)
	// 银行卡：13–19 位数字（ISO/IEC 7812 的 PAN 长度范围）。
	reBankCard = regexp.MustCompile(`[0-9]{13,19}`)
	// 手机号：1 + 3-9 开头 + 9 位。号段表会变，这里只做形状判断。
	reMobile = regexp.MustCompile(`1[3-9][0-9]{9}`)
	// 统一社会信用代码：GB 32100 的 31 字符集（去掉易混的 I O S V Z）。
	reUSCC = regexp.MustCompile(`[0-9A-HJ-NPQRTUWXY]{18}`)
	// 车牌：省份简称 + 发牌机关字母（不用 I/O）+ 5 位序号（不用 I/O）。
	// 新能源 8 位牌不在本次范围。
	rePlate = regexp.MustCompile(`[京津沪渝冀豫云辽黑湘皖鲁新苏浙赣鄂桂甘晋蒙陕吉闽贵粤青藏川宁琼][A-HJ-NP-Z][A-HJ-NP-Z0-9]{5}`)
)

func collect(text string, includeCandidates bool) []Match {
	var cands []candidate
	cands = append(cands, scanKind(text, reIDCard, KindIDCard, prioIDCard, checkIDCard)...)
	cands = append(cands, scanKind(text, reUSCC, KindUSCC, prioUSCC, checkUSCC)...)
	cands = append(cands, scanKind(text, reBankCard, KindBankCard, prioBankCard, checkBankCard)...)
	cands = append(cands, scanKind(text, reMobile, KindMobile, prioMobile, checkMobile)...)
	cands = append(cands, scanKind(text, rePlate, KindPlate, prioPlate, checkPlate)...)

	// 同一起点：校验通过者优先，其次按类型优先级，最后取更长的片段。
	sort.SliceStable(cands, func(i, j int) bool {
		if cands[i].start != cands[j].start {
			return cands[i].start < cands[j].start
		}
		if cands[i].validated != cands[j].validated {
			return cands[i].validated
		}
		if cands[i].priority != cands[j].priority {
			return cands[i].priority < cands[j].priority
		}
		return cands[i].end > cands[j].end
	})

	// 两遍收：先收校验通过的，再在剩余区间收候选。
	// 顺序不能反——否则一个「18 位但校验位错」的串会先占住区间，把同一段里真正
	// 通过 Luhn 的银行卡挤掉：脏值顶掉真值是最坏的误报。
	//
	// 区间判定用二分而不是逐个比对：一份 2MB 日志能出几千条候选，逐个比对是
	// O(n²) 且每次都在拷贝 candidate 结构体（实测 2.4MB 要 8 秒）。已被接受的
	// 区间天然按 start 有序且互不相交，二分到「最后一个 start ≤ c.start」的区间，
	// 再看它和它的后继是否覆盖 c，就够了。
	var kept []candidate
	var vspans, cspans []span
	for _, c := range cands {
		if !c.validated || overlapsSpan(c, vspans) {
			continue
		}
		kept = append(kept, c)
		vspans = append(vspans, span{c.start, c.end})
	}
	if includeCandidates {
		for _, c := range cands {
			if c.validated || overlapsSpan(c, vspans) || overlapsSpan(c, cspans) {
				continue
			}
			kept = append(kept, c)
			cspans = append(cspans, span{c.start, c.end})
		}
	}
	sort.SliceStable(kept, func(i, j int) bool { return kept[i].start < kept[j].start })

	idx := newPosIndex(text)
	seen := map[dedupKey]int{}
	out := make([]Match, 0, len(kept))
	for _, c := range kept {
		raw := text[c.start:c.end]
		m := Match{
			Kind:      c.kind,
			Value:     maskByKind(c.kind, raw),
			Validated: c.validated,
			Offset:    c.start,
			Count:     1,
			Detail:    c.detail,
			Reason:    c.reason,
		}
		m.Line, m.Column = idx.at(c.start, text)
		k := dedupKey{c.kind, raw, c.validated}
		if at, ok := seen[k]; ok {
			out[at].Count++
			continue
		}
		seen[k] = len(out)
		out = append(out, m)
	}
	return out
}

// dedupKey 用原文而不是脱敏值做键：脱敏只留前 6 后 4，两张卡完全可能撞掩码，
// 拿掩码当键会把两个不同的人合并成一条。原文只活在这个局部 map 里，不会外泄。
type dedupKey struct {
	kind      Kind
	raw       string
	validated bool
}

// span 是一个已被接受的原文区间（左闭右开）。
type span struct{ start, end int }

// overlapsSpan 判断 c 是否与已接受的区间相交。spans 必须按 start 升序且互不相交——
// 调用点每次只 append，天然满足。
func overlapsSpan(c candidate, spans []span) bool {
	i := sort.Search(len(spans), func(i int) bool { return spans[i].start > c.start }) - 1
	if i >= 0 && spans[i].end > c.start {
		return true
	}
	return i+1 < len(spans) && spans[i+1].start < c.end
}

type verdict struct {
	ok     bool
	detail string
	reason string
}

func pass(format string, args ...any) verdict {
	return verdict{ok: true, detail: fmt.Sprintf(format, args...)}
}
func fail(format string, args ...any) verdict {
	return verdict{reason: fmt.Sprintf(format, args...)}
}

func scanKind(text string, re *regexp.Regexp, kind Kind, prio int, check func(string) verdict) []candidate {
	var out []candidate
	findAll(re, text, func(s, e int, tok string) {
		v := check(tok)
		out = append(out, candidate{
			kind: kind, start: s, end: e, priority: prio,
			validated: v.ok, detail: v.detail, reason: v.reason,
		})
	})
	return out
}

// findAll 只收「边界干净」的匹配：前后紧挨着字母/数字/下划线的片段一律跳过。
//
// 原因：订单号 `ORDER2024010112345678901`、哈希、20 位流水号里都能截出 18 位数字，
// 不设边界的话每一条都会进候选。边界不干净时从 s+1 继续找——RE2 不会为满足边界
// 自动缩短匹配，必须手动挪一格，否则整段长数字里真正的卡号会被漏掉。
func findAll(re *regexp.Regexp, text string, fn func(s, e int, tok string)) {
	pos := 0
	for pos < len(text) {
		loc := re.FindStringIndex(text[pos:])
		if loc == nil {
			return
		}
		s, e := pos+loc[0], pos+loc[1]
		if !boundaryOK(text, s, e) {
			pos = s + 1
			continue
		}
		fn(s, e, text[s:e])
		pos = e
	}
}

func boundaryOK(text string, s, e int) bool {
	if s > 0 && isWordByte(text[s-1]) {
		return false
	}
	if e < len(text) && isWordByte(text[e]) {
		return false
	}
	return true
}

// isWordByte 只把 ASCII 字母/数字/下划线当「同一个词」。中文不是词的延续：
// 「身份证110101199003071234」这种没有空格的写法必须能命中。
func isWordByte(b byte) bool {
	return b >= '0' && b <= '9' || b >= 'A' && b <= 'Z' || b >= 'a' && b <= 'z' || b == '_'
}

// ── 位置换算 ──

type posIndex struct{ lineStarts []int }

func newPosIndex(text string) *posIndex {
	starts := []int{0}
	for i := 0; i < len(text); i++ {
		if text[i] == '\n' {
			starts = append(starts, i+1)
		}
	}
	return &posIndex{lineStarts: starts}
}

func (p *posIndex) at(off int, text string) (line, col int) {
	i := sort.Search(len(p.lineStarts), func(i int) bool { return p.lineStarts[i] > off }) - 1
	if i < 0 {
		i = 0
	}
	return i + 1, utf8.RuneCountInString(text[p.lineStarts[i]:off]) + 1
}

// ── 脱敏 ──

// maskByKind 保留首尾、中间全打星，长度不变——审计时还能核对「是不是同一条」，
// 但任何人都拿不到完整值。
func maskByKind(k Kind, raw string) string {
	switch k {
	case KindMobile:
		return keepEnds(raw, 3, 4) // 3-4-4：138****8000
	case KindPlate:
		return keepEnds(raw, 2, 2) // 京A***45
	default:
		// 身份证 / 银行卡 / 信用代码：前 6 后 4。前 6 位是行政区划或 BIN，
		// 本身就带分类信息；后 4 位用于人工比对同一条记录。
		return keepEnds(raw, 6, 4)
	}
}

func keepEnds(s string, front, back int) string {
	r := []rune(s)
	if len(r) <= front+back {
		return strings.Repeat("*", len(r))
	}
	return string(r[:front]) + strings.Repeat("*", len(r)-front-back) + string(r[len(r)-back:])
}

// ── 身份证 ──

// GB 11643-1999：前 17 位加权求和，模 11 查表得校验位。
var idWeights = [17]int{7, 9, 10, 5, 8, 4, 2, 1, 6, 3, 7, 9, 10, 5, 8, 4, 2}

const idCheckChars = "10X98765432"

// nowFunc 单独抽出来，测试才能钉住「出生日期不能晚于今天」而不用等跨年。
var nowFunc = time.Now

// provinceCodes 省级行政区划代码前两位（GB/T 2260）。只校验到省：再往下要背
// 三千多个区县代码，维护成本远大于收益——前两位错了的身份证一定是假的，
// 前两位对了的假证也会被校验位挡住。
var provinceCodes = map[string]bool{
	"11": true, "12": true, "13": true, "14": true, "15": true, // 华北
	"21": true, "22": true, "23": true, // 东北
	"31": true, "32": true, "33": true, "34": true, "35": true, "36": true, "37": true, // 华东
	"41": true, "42": true, "43": true, "44": true, "45": true, "46": true, // 中南
	"50": true, "51": true, "52": true, "53": true, "54": true, // 西南
	"61": true, "62": true, "63": true, "64": true, "65": true, // 西北
	"71": true, "81": true, "82": true, "91": true, // 台/港/澳/国外
}

func checkIDCard(s string) verdict {
	if len(s) != 18 {
		return fail("长度不是 18 位")
	}
	// 顺序：先结构（行政区划、生日）再校验位。结构错的时候，「生日 2 月 30 日」
	// 比「校验位不符」更能说明问题——校验位是跟着前 17 位算的，前 17 位本身就假。
	if !provinceCodes[s[:2]] {
		return fail("行政区划前两位不是省级代码（GB/T 2260）")
	}
	birth, err := time.Parse("20060102", s[6:14])
	if err != nil {
		// 注意：错误信息里不带原文。候选也可能被 --candidates 打出来，
		// 出生日期同样属于个人信息，不能顺手写进 reason。
		return fail("出生日期段不是合法日历日期（YYYYMMDD）")
	}
	if birth.Year() < 1900 {
		return fail("出生日期早于 1900 年")
	}
	if birth.After(nowFunc()) {
		return fail("出生日期晚于今天")
	}
	sum := 0
	for i := 0; i < 17; i++ {
		sum += int(s[i]-'0') * idWeights[i]
	}
	want := idCheckChars[sum%11]
	got := s[17]
	if got == 'x' { // 小写 x 在真实数据里很常见（Excel 导出、手抄），按大写算
		got = 'X'
	}
	if got != want {
		return fail("GB 11643 MOD 11-2 校验位不符")
	}
	return pass("GB 11643 MOD 11-2 校验通过 · 出生日期合法 · 行政区划合法")
}

// ── 统一社会信用代码 ──

const usccCharset = "0123456789ABCDEFGHJKLMNPQRTUWXY"

// GB 32100-2015 加权因子。
var usccWeights = [17]int{1, 3, 9, 27, 19, 26, 16, 17, 20, 29, 25, 13, 8, 24, 10, 30, 28}

func checkUSCC(s string) verdict {
	if len(s) != 18 {
		return fail("长度不是 18 位")
	}
	// 第 1 位登记管理部门：1 编制 / 5 民政 / 9 工商 / Y 其他。别的字符一定是假的。
	if !strings.ContainsRune("159Y", rune(s[0])) {
		return fail("第 1 位登记管理部门代码不是 1/5/9/Y")
	}
	// 第 3–8 位是登记管理机关行政区划码，必须是 6 位数字。
	for i := 2; i < 8; i++ {
		if s[i] < '0' || s[i] > '9' {
			return fail("第 3–8 位行政区划码不是 6 位数字")
		}
	}
	if !provinceCodes[s[2:4]] {
		return fail("行政区划前两位不是省级代码（GB/T 2260）")
	}
	sum := 0
	for i := 0; i < 17; i++ {
		v := strings.IndexByte(usccCharset, s[i])
		if v < 0 {
			return fail("第 %d 位不在 GB 32100 字符集内", i+1)
		}
		sum += v * usccWeights[i]
	}
	c := 31 - sum%31
	if c == 31 { // 余数为 0 时 31-0=31，按标准折回 0
		c = 0
	}
	if usccCharset[c] != s[17] {
		return fail("GB 32100-2015 校验位不符")
	}
	return pass("GB 32100-2015 校验通过（登记管理部门 %c）", s[0])
}

// ── 银行卡 ──

// binIssuers 离线 BIN 表：只收高置信度的国内大行 6 位前缀。
//
// 这张表**不参与判定**（判定只看长度 + Luhn + 首位非 0），只用来在详情里给个
// 发卡行提示。表会随发卡行调整而过时，所以查不到就老老实实写 unknown——
// 猜一个错的银行名比 unknown 更伤报告可信度。
var binIssuers = map[string]string{
	"622200": "工商银行", "622202": "工商银行", "622203": "工商银行", "621226": "工商银行",
	"622845": "农业银行", "622846": "农业银行", "622848": "农业银行", "622849": "农业银行",
	"621660": "中国银行", "621661": "中国银行", "621662": "中国银行", "621663": "中国银行",
	"622700": "建设银行", "621081": "建设银行", "621082": "建设银行", "621083": "建设银行",
	"622260": "交通银行", "622262": "交通银行",
	"622588": "招商银行", "621286": "招商银行", "621483": "招商银行",
	"622908": "兴业银行", "622909": "兴业银行",
	"622521": "浦发银行", "622522": "浦发银行",
	"622280": "中信银行",
	"621626": "平安银行",
	"621798": "邮储银行", "621799": "邮储银行",
}

func checkBankCard(s string) verdict {
	if len(s) < 13 || len(s) > 19 {
		return fail("长度不在 13–19 位（ISO/IEC 7812）")
	}
	// 首位 0：ISO/IEC 7812 把 0 留给 ISO 自己，没有发卡行用。真实数据里
	// 「0000000000000000」这类占位串能轻松通过 Luhn，必须在 Luhn 之前挡掉。
	if s[0] == '0' {
		return fail("首位为 0，不符合 ISO/IEC 7812 发卡行标识规则")
	}
	if allSameDigit(s) {
		return fail("全部数字相同，是占位串不是卡号")
	}
	if !luhnOK(s) {
		return fail("Luhn 校验位不符")
	}
	bin := s[:6]
	if issuer, ok := binIssuers[bin]; ok {
		return pass("Luhn 校验通过 · 发卡行 %s（BIN %s，离线表）", issuer, bin)
	}
	return pass("Luhn 校验通过 · 发卡行 unknown（BIN %s 不在离线表）", bin)
}

func luhnOK(s string) bool {
	sum := 0
	for i := len(s) - 1; i >= 0; i-- {
		d := int(s[i] - '0')
		if (len(s)-1-i)%2 == 1 { // 从右往左第偶数位（0 起）翻倍
			d *= 2
			if d > 9 {
				d -= 9
			}
		}
		sum += d
	}
	return sum%10 == 0
}

func allSameDigit(s string) bool {
	for i := 1; i < len(s); i++ {
		if s[i] != s[0] {
			return false
		}
	}
	return len(s) > 0
}

// ── 手机号 ──

// mobileDeny 运营商公开的测试/演示号。只收确定是「人人都在用」的那几个，
// 不做「靓号=假号」的推断——138****8000 这类号真有人用。
//
// 写成拼接形式是刻意的：源码里不留完整的手机号字面量，免得仓库历史成了号码库。
var mobileDeny = map[string]bool{
	"138" + "00138000": true, // 中国移动公开测试号
	"133" + "00133000": true, // 各类文档里的示例号
	"189" + "00189000": true, // 各类文档里的示例号
	"139" + "00139000": true, // 各类文档里的示例号
}

func checkMobile(s string) verdict {
	if len(s) != 11 {
		return fail("长度不是 11 位")
	}
	if mobileDeny[s] {
		return fail("运营商/文档公开的测试号")
	}
	if allSameDigit(s) {
		return fail("11 位全同数字，是占位串")
	}
	if allSameDigit(s[3:]) {
		return fail("后 8 位全同，是占位串")
	}
	if isConsecutive(s[3:]) {
		return fail("后 8 位是连续递增/递减序列，是占位串")
	}
	// 手机号没有校验位，这里能承诺的只有「形状对、不是占位号」。
	return pass("11 位手机号格式合法（号段 %s，无校验位可核）", s[:3])
}

// isConsecutive 判断是否是 12345678 / 87654321 这类连号。
func isConsecutive(s string) bool {
	if len(s) < 2 {
		return false
	}
	step := int(s[1]) - int(s[0])
	if step != 1 && step != -1 {
		return false
	}
	for i := 2; i < len(s); i++ {
		if int(s[i])-int(s[i-1]) != step {
			return false
		}
	}
	return true
}

// ── 车牌 ──

// checkPlate 永远返回候选。
//
// 车牌没有校验位，格式正则的精度撑不起「命中」二字：测试文档里的「京A12345」、
// 车牌占位符、示例数据长得一模一样。本包把它留在候选层，等上层有上下文
// （车辆管理系统的字段名、表格列头）时再提升——不在这一层假装确认。
func checkPlate(s string) verdict {
	r := []rune(s)
	if len(r) != 7 {
		return fail("不是 7 位车牌")
	}
	return verdict{reason: "车牌无校验位，仅结构匹配（候选，默认不输出）"}
}
