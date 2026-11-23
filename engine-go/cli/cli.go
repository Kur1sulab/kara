// Package cli：sweep（空境 Kara 的扫描内核）的全部 CLI 逻辑（子命令分发表与公共小工具）。
// 从根 main.go 拆出，供两个薄入口共用：
//   - cmd/sweep/main.go（标准布局入口，go build ./cmd/sweep）
//   - 根 main.go（兼容旧验收命令 go build -o yata.exe .）
package cli

import (
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/Kur1sulab/kara/engine-go/apiunauth"
	"github.com/Kur1sulab/kara/engine-go/baseline"
	"github.com/Kur1sulab/kara/engine-go/brute"
	"github.com/Kur1sulab/kara/engine-go/cve"
	"github.com/Kur1sulab/kara/engine-go/fingerprint"
	"github.com/Kur1sulab/kara/engine-go/netutil"
	"github.com/Kur1sulab/kara/engine-go/patchdiff"
	"github.com/Kur1sulab/kara/engine-go/paths"
	"github.com/Kur1sulab/kara/engine-go/poc"
	"github.com/Kur1sulab/kara/engine-go/replay"
	"github.com/Kur1sulab/kara/engine-go/report"
	"github.com/Kur1sulab/kara/engine-go/subdomain"
)

const helpText = `sweep — 空境 Kara 的扫描内核（Go 单文件；断网/内网可用，零外联）

用法（DOMAIN 或 IP 都吃，工具自动识别）:
  sweep all -t example.com             # 一键全流程（IP/域名自动分支，10 步）
  sweep subdomain -d example.com [--verify] [--resolver 10.0.0.2:53] [--words file]
  sweep verify -d example.com [-w 8]
  sweep api -u https://example.com     # API 文档暴露/未授权（含取证模式）
  sweep jsintel -u https://example.com # 外链 JS 情报（≤6 并发/≤2MB，只 GET）
  sweep portscan -t 203.0.113.7        # 端口扫描（常用端口表，并发 ≤32）
  sweep brute -t 10.0.0.5 [-p 22,3306,6379] [--service redis] [--users u.txt] [--passes p.txt]
                                         # 内网弱口令验证（ftp/mysql/postgres/redis/telnet/http-basic）
  sweep cve -u http://10.0.0.5         # 离线 CVE 匹配（版本指纹 → 本地规则库，L1）
  sweep fingerprint -u https://example.com
  sweep paths -u https://example.com   # 敏感路径探测（软 404 基线过滤）
  sweep baseline -d example.com [--checks secheaders,webfiles,sslchain]  # 暴露面基线 3 检查（只打目标）
  sweep strike -t http://example.com [--intensity normal] [--ports top100]  # 深度验证（真发请求）
  sweep poc -t https://example.com -p pocs/example.yaml  # YAML POC 引擎
  sweep replay -u http://127.0.0.1:8080/ok [--data 'a=1'] [--header 'K: V'] [--no-redirect]
                                         # 单次精确请求 → replay.json（复验流水线传输层，不探测）
  sweep patchdiff -r /path/to/repo [--commit SHA|--range A..B] [--limit N] [--emit-rule f.yaml]
                                         # 补丁差分 → 变种狩猎（本地 git 仓库，零外联）
  sweep identifier <文件|-> [--json] [--candidates]
                                         # 结构化标识符：身份证 / 银行卡 / 手机号 / 信用代码
                                         # （只报校验位算得通的；候选默认不输出）
  sweep report -t example.com          # 资产档案 + 证据包
  sweep version                        # 版本与构建平台自省（不发请求/不写产物）
  sweep -v | --version                 # 同上，全局形态（等价 version 子命令）

全局参数: --progress-file <path> | -h/--help | -v/--version（须位于子命令之前）
`

// Version 版本号，由构建时 ldflags 注入：
//
//	go build -ldflags "-X github.com/Kur1sulab/kara/engine-go/cli.Version=v3.0.0"
//
// 未注入时保持 "dev"——本地 `go run` 与 `go build` 都不该伪装成正式版。
// 存在的理由很实在：装了二进制却无法自证版本，报障时只能靠猜。
var Version = "dev"

// printVersion 版本自省输出。`version` 子命令与全局 -v/--version 共用，
// 保证两种入口的字符串逐字一致（否则脚本解析版本要写两条正则）。
func printVersion() {
	fmt.Printf("sweep %s · kara-engine (%s %s/%s)\n", Version, runtime.Version(), runtime.GOOS, runtime.GOARCH)
}

// knownCmds 合法子命令集合（argparse 在解析阶段即拒绝未知子命令，进度事件
// 不发——故 Run 只对集合内子命令包事件流）。与 yata.py:164-187 的子解析器
// 一一对应；llm 槽位已随终修轮公开面清理删除（产品铁律：纯本地无 AI——
// 原占位「llm 已弃用」提示一并退役，输 unknown 走 argparse 同款 exit 2）。
var knownCmds = map[string]bool{
	"all": true, "subdomain": true, "verify": true,
	"api": true, "fingerprint": true, "paths": true, "jsintel": true,
	"portscan": true, "poc": true, "patchdiff": true, "report": true,
	"baseline":   true, // 域名暴露面基线（report §5.9；桌面第二子进程，非 Python yata.py 对齐项）
	"strike":     true, // 深度验证（内建 litmus 内核，非只读模式的延伸）
	"brute":      true, // 弱口令验证（协议握手，命中即停）
	"cve":        true, // 离线 CVE 版本匹配
	"replay":     true, // 单次精确 HTTP 请求 → replay.json（Python 三层复验流水线的传输层）
	"identifier": true, // 结构化标识符检测（调研总纲 §4 P1：校验位通过才报）
	"version":    true, // 版本自省（Go 侧独有，Python yata.py 无对应子命令）
}

// Run 处理全局参数与子命令（args 不含程序名），返回进程退出码。
// 14 个子命令与 Python yata.py:137-212 一一对齐；本轮（c1）真实现
// subdomain / verify / fingerprint，其余注册占位并 exit 2（防静默走错分支）；
// llm 按铁律不移植（终修轮起连弃用占位槽位一并删除，见 knownCmds）。
//
// fix1（审计 medium#4）：补齐 --progress-file 全局参数层——桌面壳
// desktop-go/internal/engine/runner.go 以「--progress-file 在子命令之前」为契约
// 驱动进度状态机，事件键序与 yata.py:31-62 逐项对齐（见 progress.go）。
func Run(args []string) int {
	if len(args) < 1 {
		fmt.Print(helpText)
		return 1
	}
	rest, code := applyProgressFile(args)
	if rest == nil {
		if code == -1 { // -h/--help/help：等价 argparse 阶段退出，不发事件
			fmt.Print(helpText)
			return 0
		}
		if code == -2 { // -v/--version：同属解析阶段退出，只读自省，不建目录/不发请求/不写产物
			printVersion()
			return 0
		}
		return code
	}
	if progressFile == "" {
		// 对齐 yata.py:191：CLI 参数缺省时回退环境变量 RECON_PROGRESS_FILE
		progressFile = os.Getenv("RECON_PROGRESS_FILE")
	}
	cmd := rest[0]
	// fix3（audit low#6）：argparse 无 help 子命令——`yata.py help` 是未知
	// 选择，解析阶段 exit 2（不发事件）；-h/--help 全局帮助仍 exit 0
	if !knownCmds[cmd] {
		// 对齐 argparse：未知子命令在解析阶段 exit 2，事件流不启动
		fmt.Printf("[*] 未知子命令: %q\n\n", cmd)
		fmt.Print(helpText)
		return 2
	}
	emit("pipeline_start", "pipeline", cmd)
	if cmd != "all" {
		emit("start", cmd, "")
	}
	code = dispatch(cmd, rest[1:])
	switch {
	case cmd == "all": // yata.py:250-256：all 无模块级收尾事件
		if code == 0 {
			emit("pipeline_end", "pipeline", "done")
		} else {
			emit("pipeline_end", "pipeline", "fail")
		}
	case code == 0:
		emit("done", cmd, "")
		emit("pipeline_end", "pipeline", "done")
	default:
		emit("fail", cmd, fmt.Sprintf("exit %d", code))
		emit("pipeline_end", "pipeline", "fail")
	}
	return code
}

func dispatch(cmd string, rest []string) int {
	switch cmd {
	case "subdomain": // 本地 DNS 字典爆破（断网可用；不查任何证书日志服务）
		fs := newFlagSet()
		d := fs.String("d", "", "")
		dAlias := fs.String("domain", "", "")
		verify := fs.Bool("verify", false, "命中后做一次 HTTP 探活")
		workers := fs.Int("w", subdomain.DefaultWorkers, "并发查询数")
		resolver := fs.String("resolver", "", "内网 DNS，如 10.0.0.2:53（空 = 系统解析器）")
		wordsFile := fs.String("words", "", "自定义字典文件（一行一个标签；空 = 内置约 4.8k 条）")
		usage := "subdomain -d <domain> [--verify] [--resolver ip:53] [--words file] [-w N]"
		if c := parseOrUsage(fs, rest, cmd, usage); c != -1 {
			return c
		}
		domain := pickAliasLastWins(rest, map[string]*string{"-d": d, "--domain": dAlias})
		if domain == "" {
			return missingArgs(cmd, usage)
		}
		if bad, why := invalidDomainShape(domain); bad {
			fmt.Printf("[!] 非法域名（%s）: %q\n", why, domain)
			return 2
		}
		opt := subdomain.Options{Workers: *workers, Resolver: *resolver}
		if path := strings.TrimSpace(*wordsFile); path != "" {
			b, err := os.ReadFile(path)
			if err != nil {
				fmt.Printf("[!] --words 读取失败: %v\n", err)
				return 2
			}
			for _, ln := range strings.Split(string(b), "\n") {
				if w := strings.TrimSpace(ln); w != "" {
					opt.Words = append(opt.Words, w)
				}
			}
		}
		out, err := MakeOutdir(domain)
		if err != nil {
			fmt.Printf("[!] 输出目录创建失败: %v\n", err)
			return 1
		}
		res, err := subdomain.RunOptions(nil, domain, out, opt)
		if err != nil {
			fmt.Printf("[!] subdomain: %v\n", err)
			return 1
		}
		fmt.Printf("[+] 子域枚举完成：字典 %d 条 / 命中 %d 个 / 泛解析 %v -> %s\n",
			res.Words, len(res.Found), res.Wildcard, out+"/subdomains.json")
		if *verify && len(res.Found) > 0 {
			subdomain.RunVerify(out, 8, true)
		}
		return 0

	case "verify":
		fs := newFlagSet()
		domain := fs.String("d", "", "")
		domainAlias := fs.String("domain", "", "")
		workers := fs.Int("w", 8, "")
		workersAlias := fs.Int("workers", 8, "")
		if c := parseOrUsage(fs, rest, cmd, "verify -d <domain> [-w workers]"); c != -1 {
			return c
		}
		d := pickAliasLastWins(rest, map[string]*string{"-d": domain, "--domain": domainAlias})
		if d == "" {
			return missingArgs(cmd, "verify -d <domain> [-w workers]")
		}
		out, err := MakeOutdir(d)
		if err != nil {
			fmt.Printf("[!] 输出目录创建失败: %v\n", err)
			return 1
		}
		subdomain.RunVerify(out, pickIntAliasLastWins(rest, 8, map[string]*int{"-w": workers, "--workers": workersAlias}), true)
		return 0

	case "fingerprint":
		fs := newFlagSet()
		u := fs.String("u", "", "")
		uAlias := fs.String("url", "", "")
		if c := parseOrUsage(fs, rest, cmd, "fingerprint -u <url>"); c != -1 {
			return c
		}
		url := pickAliasLastWins(rest, map[string]*string{"-u": u, "--url": uAlias})
		if url == "" {
			return missingArgs(cmd, "fingerprint -u <url>")
		}
		out, err := MakeOutdir(url)
		if err != nil {
			fmt.Printf("[!] 输出目录创建失败: %v\n", err)
			return 1
		}
		fingerprint.RunFingerprint(url, out)
		return 0

	case "api": // yata.py:185-186：api -u/--url（含取证模式）
		fs := newFlagSet()
		u := fs.String("u", "", "")
		uAlias := fs.String("url", "", "")
		if c := parseOrUsage(fs, rest, cmd, "api -u <url>"); c != -1 {
			return c
		}
		url := pickAliasLastWins(rest, map[string]*string{"-u": u, "--url": uAlias})
		if url == "" {
			return missingArgs(cmd, "api -u <url>")
		}
		out, err := MakeOutdir(url)
		if err != nil {
			fmt.Printf("[!] 输出目录创建失败: %v\n", err)
			return 1
		}
		if _, err := apiunauth.RunAPI(url, out, true); err != nil {
			return 1 // fix3：写盘失败 → fail 事件 + exit 1
		}
		return 0

	case "paths": // yata.py:191-192：paths -u/--url（Go 侧补 --extra 补充字典，report §5.2）
		fs := newFlagSet()
		u := fs.String("u", "", "")
		uAlias := fs.String("url", "", "")
		extraFile := fs.String("extra", "", "补充字典文件（一行一路径，如 baseline webfiles 的 paths_extra.txt）")
		if c := parseOrUsage(fs, rest, cmd, "paths -u <url> [--extra <file>]"); c != -1 {
			return c
		}
		url := pickAliasLastWins(rest, map[string]*string{"-u": u, "--url": uAlias})
		if url == "" {
			return missingArgs(cmd, "paths -u <url> [--extra <file>]")
		}
		var extra []string
		if path := strings.TrimSpace(*extraFile); path != "" {
			b, rerr := os.ReadFile(path)
			if rerr != nil {
				fmt.Printf("[!] --extra 文件读取失败: %v\n", rerr)
				return 2
			}
			for _, ln := range strings.Split(string(b), "\n") {
				extra = append(extra, strings.TrimSpace(ln))
			}
		}
		out, err := MakeOutdir(url)
		if err != nil {
			fmt.Printf("[!] 输出目录创建失败: %v\n", err)
			return 1
		}
		if _, err := paths.RunPaths(url, out, extra...); err != nil {
			return 1 // fix3：写盘失败 → fail 事件 + exit 1
		}
		return 0

	case "replay": // 单次精确请求 → out/<host>/replay.json（Python 三层复验流水线的传输层）
		fs := newFlagSet()
		u := fs.String("u", "", "")
		uAlias := fs.String("url", "", "")
		m := fs.String("m", "GET", "HTTP 方法（默认 GET；给了 --data 也不自动改 POST）")
		mAlias := fs.String("method", "GET", "HTTP 方法（同 -m）")
		data := fs.String("data", "", "请求体（原样发送，不做表单编码）")
		var hdrs stringListFlag
		fs.Var(&hdrs, "header", "附加请求头，形如 'K: V'（可重复；键 Host 改写 req.Host）")
		timeoutSec := fs.Int("timeout", replay.DefaultTimeout, "整次请求超时（秒）")
		noRedirect := fs.Bool("no-redirect", false, "不跟随重定向（返回 3xx 响应本身）")
		o := fs.String("o", "", "输出目录（默认 out/<host>/）")
		oAlias := fs.String("out", "", "输出目录（同 -o）")
		const usage = "replay -u <url> [-m GET] [--data ...] [--header 'K: V'] [--timeout 10] [--no-redirect] [-o <dir>]"
		if c := parseOrUsage(fs, rest, cmd, usage); c != -1 {
			return c
		}
		url := pickAliasLastWins(rest, map[string]*string{"-u": u, "--url": uAlias})
		if strings.TrimSpace(url) == "" {
			return missingArgs(cmd, usage)
		}
		method := pickAliasLastWins(rest, map[string]*string{"-m": m, "--method": mAlias})
		if strings.TrimSpace(method) == "" {
			method = "GET" // 两别名都没出现时 pickAliasLastWins 回空串，落回默认
		}
		outDir := strings.TrimSpace(pickAliasLastWins(rest, map[string]*string{"-o": o, "--out": oAlias}))
		if outDir == "" {
			// 默认 out/<host>/：HostOf 保留端口，MakeOutdir 负责目录名清洗
			base, err := MakeOutdir(replay.HostOf(url))
			if err != nil {
				fmt.Printf("[!] 输出目录创建失败: %v\n", err)
				return 1
			}
			outDir = base
		}
		if err := replay.Run(url, method, *data, hdrs, *timeoutSec, !*noRedirect, outDir); err != nil {
			fmt.Printf("[!] replay: %v\n", err)
			if errors.Is(err, replay.ErrBadArgs) {
				return 2 // 参数错：URL 非法 / 头格式错 / timeout 非正
			}
			return 1 // 产物写不下去
		}
		// 传输层失败（status=0）也走这里：产物照写、exit 0，结论看 JSON
		fmt.Printf("[+] replay -> %s\n", replay.Path(outDir))
		return 0

	case "strike": // 深度验证：内建 litmus 内核，产物 out/<target>/strike/ 由 Kara 解析入账
		return runStrike(rest, cmd)

	case "brute": // 内网弱口令验证（断网可用；命中即停，有额度、识别锁定）
		fs := newFlagSet()
		target := fs.String("t", "", "")
		targetAlias := fs.String("target", "", "")
		ports := fs.String("p", "", "端口，如 22,3306,6379（空 = 按 --service 的默认端口）")
		service := fs.String("service", "", "ftp/mysql/postgres/redis/telnet/http-basic（空 = 自动识别）")
		usersFile := fs.String("users", "", "用户名文件（一行一个；空 = 内置表）")
		passesFile := fs.String("passes", "", "口令文件（一行一个；空 = 内置弱口令表）")
		maxAttempts := fs.Int("max", 20, "最大尝试次数（命中即停）")
		to := fs.Int("timeout", 4, "单次握手超时秒数")
		usage := "brute -t <host> [-p 22,3306] [--service redis] [--users u.txt] [--passes p.txt] [--max 20]"
		if c := parseOrUsage(fs, rest, cmd, usage); c != -1 {
			return c
		}
		hostT := pickAliasLastWins(rest, map[string]*string{"-t": target, "--target": targetAlias})
		if hostT == "" {
			return missingArgs(cmd, usage)
		}
		host, portList := hostAndPorts(hostT, *ports, *service)
		if len(portList) == 0 {
			fmt.Printf("[!] 没有可爆破的端口（用 -p 指定，或 --service 给默认端口）\n")
			return 2
		}
		opt := brute.Options{Service: *service, MaxAttempts: *maxAttempts,
			Timeout: time.Duration(*to) * time.Second,
			Log:     func(f string, a ...any) { fmt.Printf(f+"\n", a...) }}
		if p := strings.TrimSpace(*usersFile); p != "" {
			opt.Users = readListFile(p)
		}
		if p := strings.TrimSpace(*passesFile); p != "" {
			opt.Passes = readListFile(p)
		}
		out, err := MakeOutdir(hostT)
		if err != nil {
			fmt.Printf("[!] 输出目录创建失败: %v\n", err)
			return 1
		}
		var results []brute.Result
		for _, prt := range portList {
			r := brute.Run(nil, host, prt, opt)
			results = append(results, r)
			if len(r.Found) > 0 {
				for _, h := range r.Found {
					fmt.Printf("[+] 弱口令 %s://%s:%d %s/%s（%s）\n", h.Service, h.Host, h.Port, h.User, h.Pass, h.Note)
				}
			} else if r.Skipped != "" {
				fmt.Printf("[*] %s:%d 跳过：%s\n", host, prt, r.Skipped)
			}
		}
		if err := writeJSON(filepath.Join(out, "brute.json"), results); err != nil {
			fmt.Printf("[!] 写 brute.json 失败: %v\n", err)
			return 1
		}
		fmt.Printf("[+] 爆破完成 -> %s\n", filepath.Join(out, "brute.json"))
		return 0

	case "cve": // 离线 CVE 匹配：版本指纹 → 内置规则库（L1：只说明可能受影响）
		fs := newFlagSet()
		u := fs.String("u", "", "")
		uAlias := fs.String("url", "", "")
		usage := "cve -u <url>"
		if c := parseOrUsage(fs, rest, cmd, usage); c != -1 {
			return c
		}
		base := pickAliasLastWins(rest, map[string]*string{"-u": u, "--url": uAlias})
		if base == "" {
			return missingArgs(cmd, usage)
		}
		out, err := MakeOutdir(base)
		if err != nil {
			fmt.Printf("[!] 输出目录创建失败: %v\n", err)
			return 1
		}
		res, err := cve.Run(base)
		if err != nil {
			fmt.Printf("[!] cve: %v\n", err)
			return 1
		}
		p, err := cve.Write(out, res)
		if err != nil {
			fmt.Printf("[!] 写 cve.json 失败: %v\n", err)
			return 1
		}
		fmt.Printf("[*] 识别产品 %d 个，版本区间命中 %d 条（L1：可能受影响，需验证）\n",
			len(res.Products), len(res.Matches))
		for _, m := range res.Matches {
			fmt.Printf("    [%s] %s  %s %s  ← %s\n", m.Severity, m.ID, m.Product, m.Version, m.Evidence)
		}
		fmt.Printf("[+] 结果 -> %s\n", p)
		return 0

	case "poc": // yata.py:198-199：poc -t/--target -p/--poc
		fs := newFlagSet()
		target := fs.String("t", "", "")
		pocFile := fs.String("p", "", "")
		if c := parseOrUsage(fs, rest, cmd, "poc -t <target> -p <poc>"); c != -1 {
			return c
		}
		if *target == "" || *pocFile == "" {
			return missingArgs(cmd, "poc -t <target> -p <poc>")
		}
		poc.RunPOC(*target, *pocFile) // yata.py 不以命中与否改变退出码
		return 0

	case "patchdiff": // yata.py:208-213 / 266-270：-r/--repo 必填，--commit/--range/--limit/--emit-rule
		fs := newFlagSet()
		repo := fs.String("r", "", "")
		repoAlias := fs.String("repo", "", "")
		commit := fs.String("commit", "", "只看某个提交")
		rng := fs.String("range", "", "提交区间，如 v1.2..v1.3")
		limit := fs.Int("limit", patchdiff.DefaultLimit, "最多分析多少个安全相关提交")
		emitRule := fs.String("emit-rule", "", "生成 semgrep 规则文件名（写入输出目录）")
		usage := "patchdiff -r <repo> [--commit <sha>] [--range <a..b>] [--limit N] [--emit-rule <file>]"
		if c := parseOrUsage(fs, rest, cmd, usage); c != -1 {
			return c
		}
		r := pickAliasLastWins(rest, map[string]*string{"-r": repo, "--repo": repoAlias})
		if r == "" {
			return missingArgs(cmd, usage)
		}
		// 产物目录与 Python 一致：out/patchdiff（yata.py:268 make_outdir("patchdiff")）
		out, err := MakeOutdir("patchdiff")
		if err != nil {
			fmt.Printf("[!] 输出目录创建失败: %v\n", err)
			return 1
		}
		if _, err := patchdiff.Run(patchdiff.Options{
			Repo: r, Commit: *commit, Range: *rng, Limit: *limit,
			Emit: *emitRule, Outdir: out,
			Logf: func(f string, a ...any) { fmt.Printf(f, a...) },
		}); err != nil {
			// 与 Python 的偏差（有意）：Python 侧 run_patchdiff 返回 ok=False 但
			// CLI 不看返回值仍 exit 0；Go 按 fix3 口径 fail 事件 + exit 1，
			// 免得脚本把「不是 git 仓库」当成功继续往下跑。
			fmt.Printf("[!] patchdiff: %v\n", err)
			return 1
		}
		return 0

	case "report": // yata.py:204-206：report -t/--target -d/--domain（dest=target）
		fs := newFlagSet()
		target := fs.String("t", "", "")
		targetAlias := fs.String("target", "", "")
		domainAlias := fs.String("d", "", "")
		if c := parseOrUsage(fs, rest, cmd, "report -t <target>"); c != -1 {
			return c
		}
		t := pickAliasLastWins(rest, map[string]*string{"-t": target, "--target": targetAlias, "-d": domainAlias})
		if t == "" {
			return missingArgs(cmd, "report -t <target>")
		}
		out, err := MakeOutdir(t)
		if err != nil {
			fmt.Printf("[!] 输出目录创建失败: %v\n", err)
			return 1
		}
		if report.RunReport(out, t) == "" {
			return 1 // fix3：report.md 写盘失败（RunReport 以 "" 标记）→ fail 事件 + exit 1
		}
		return 0

	case "baseline": // report §5.9：域名暴露面基线 8 检查聚合（-d 必填 + 形状校验 + --checks 过滤）
		fs := newFlagSet()
		domain := fs.String("d", "", "")
		domainAlias := fs.String("domain", "", "")
		u := fs.String("u", "", "")
		uAlias := fs.String("url", "", "")
		checks := fs.String("checks", "", "逗号分隔检查名过滤（默认全跑 8 项）")
		if c := parseOrUsage(fs, rest, cmd, "baseline -d <domain> [-u <url>] [--checks secheaders,webfiles]"); c != -1 {
			return c
		}
		d := pickAliasLastWins(rest, map[string]*string{"-d": domain, "--domain": domainAlias})
		if d == "" {
			return missingArgs(cmd, "baseline -d <domain> [-u <url>] [--checks secheaders,webfiles]")
		}
		// 域名形状校验（与 icp 同闸，注入/路径形态入口拒绝）
		if bad, why := invalidDomainShape(d); bad {
			fmt.Printf("[!] 非法域名（%s）: %q\n", why, d)
			return 2
		}
		// --checks 归一化在 MakeOutdir/PickBase 之前（未知检查名 exit 2，零网络副作用）
		checkNames := []string(nil)
		if strings.TrimSpace(*checks) != "" {
			var err error
			checkNames, err = baseline.NormalizeChecks(strings.Split(*checks, ","))
			if err != nil {
				fmt.Printf("[!] %v\n", err)
				return 2
			}
		}
		out, err := MakeOutdir(d)
		if err != nil {
			fmt.Printf("[!] 输出目录创建失败: %v\n", err)
			return 1
		}
		// -u 缺省：HTTP 类检查入口从域名推导（PickBase 探测 https/http，
		// 全失败回退 https://<d>；桌面首版只传 -d 时走此分支）
		url := pickAliasLastWins(rest, map[string]*string{"-u": u, "--url": uAlias})
		if url == "" {
			url = PickBase(d)
		}
		if err := baseline.Run(baseline.Options{
			Domain: d, URL: url, Out: out, Checks: checkNames,
			AllowPrivate: true, // 桌面契约：授权内网目标放行（白名单由桌面线守）
			Emit:         emit,
			Logf:         func(f string, a ...any) { fmt.Printf(f, a...) },
		}); err != nil {
			fmt.Printf("[!] baseline: %v\n", err)
			return 1 // 聚合器自身错误（未知检查名兜底/outdir）→ fail + exit 1
		}
		return 0

	case "all": // yata.py:120-178：一键全流程（目标自动识别 IP/域名，两条分支）
		fs := newFlagSet()
		target := fs.String("t", "", "")
		targetAlias := fs.String("target", "", "")
		domainAlias := fs.String("d", "", "")
		domainAlias2 := fs.String("domain", "", "")
		if c := parseOrUsage(fs, rest, cmd, "all -t <target>"); c != -1 {
			return c
		}
		t := pickAliasLastWins(rest, map[string]*string{
			"-t": target, "--target": targetAlias, "-d": domainAlias, "--domain": domainAlias2,
		})
		if t == "" {
			return missingArgs(cmd, "all -t <target>")
		}
		return runAll(t)

	case "jsintel", "portscan":
		// 第三轮升级：jsintel 门面在 cli/recon_cmds.go，portscan 门面
		// （dispatchPortscan）同文件，端口步骤接线在 cli/port_step.go。
		return dispatchRecon(cmd, rest)

	case "identifier":
		// 结构化标识符检测：纯本地、零网络，只读文件/stdin，不写产物。
		// 注意 dispatch 收到的 rest 已经是子命令之后的参数，不能再切一刀。
		return cmdIdentifier(rest)

	case "help", "-h", "--help":
		fmt.Print(helpText)
		return 0

	case "version":
		// 只读自省：不创建输出目录、不发网络请求、不写任何产物。
		printVersion()
		return 0

	default:
		fmt.Printf("[*] 未知子命令: %q\n\n", cmd)
		fmt.Print(helpText)
		return 2
	}
}

// ── 与 yata.py:30-63 对齐的公共小工具 ──

// IsIP 等价 yata.py:65-70 is_ip（ipaddress.ip_address 可解析即真）。
// fix1（审计 low#9）：不做 TrimSpace——Python ip_address(" 1.2.3.4 ") 判假，
// 此前 Go 侧 trim 后判真，属潜伏契约差异（c2 轮 all 实现时会生效）。
func IsIP(s string) bool { return net.ParseIP(s) != nil }

// outdirNameReplacer 目标 → 目录名清洗（fix1 P1，与 Python yata.py make_outdir
// 同步改，两引擎必须产出同名目录）：在原 :// 、/ 、: 基础上补齐
// 反斜杠（Windows 路径分隔符，防 ..\.. 逃逸出 out/）与 Windows 非法字符
// ? & = " < > | *（此前 query 原样进目录名：Windows 直接 mkdir 语法错误，
// Linux 则把含潜在 api_key 的完整 query 持久化进文件系统路径）。
var outdirNameReplacer = strings.NewReplacer(
	"://", "_", "/", "_", "\\", "_", ":", "_",
	"?", "_", "&", "_", "=", "_", `"`, "_",
	"<", "_", ">", "_", "|", "_", "*", "_",
)

// OutdirName 目标 → 产物目录名的纯清洗函数（第一步 C 项拆出，不含 mkdir）：
// 供桌面直调拼绝对产物目录，维持 Python yata.py make_outdir / engine-go
// MakeOutdir / desktop evidence.go outDirFor 三方同名契约。清洗规则与
// MakeOutdir 逐字一致（同一实现，不得漂移）。
func OutdirName(target string) string {
	name := outdirNameReplacer.Replace(target)
	name = strings.Trim(name, ". ")
	if name == "" || name == ".." {
		name = "unknown"
	}
	// fix2 P3：Windows 保留设备名主干（con/nul/aux/com1-9/lpt1-9）与
	// SafeFilename 同规则补 _——实测 `report -t CON` 会在本机建出 out\CON，
	// 与文件层加固不一致。Python make_outdir / desktop outDirFor 同步。
	return netutil.DefuseWindowsReservedStem(name)
}

// MakeOutdir 等价 yata.py:73-76：out/<target 清洗>。
// fix1（审计 medium#2 / low#6）：
//   - 清洗后剔首尾点号与空格；结果为空或 ".."（纯穿越锚）回 "unknown"——
//     此前 "..\..\x" 换 \ 后仍可能残留 ".." 组件，os.MkdirAll 在 out/ 之外
//     创建目录（实测逃逸两级）；
//   - MkdirAll 失败上抛给调用方（CLI 打印后 exit 1），对齐 Python os.makedirs
//     抛 OSError 未捕获 → exit 1 的退出码契约；不再吞错继续走完流程。
//
// 第一步 C 项：目录名清洗拆为导出纯函数 OutdirName（见上），本函数只管落盘。
func MakeOutdir(target string) (string, error) {
	out := "out" + string(os.PathSeparator) + OutdirName(target)
	if err := os.MkdirAll(out, 0o755); err != nil {
		return out, err
	}
	return out, nil
}

// PickBase 等价 yata.py:44-63：优先 https，status<500 即用，失败退 http。
// 授权测试允许内网目标，故显式 allowPrivate=true 放行私网（c2 轮 all 命令使用）。
// fix1 P1：Follow 模式逐跳复验重定向落点（与入口同策略），与 RunFingerprint 一致。
func PickBase(host string) string {
	for _, scheme := range []string{"https", "http"} {
		url := scheme + "://" + host
		checked, err := netutil.CheckHTTPURL(url, true)
		if err != nil {
			continue
		}
		r := netutil.Fetch(checked, netutil.FetchOpt{Timeout: 10 * time.Second, Follow: true,
			HopCheck: netutil.HopPolicy(checked)})
		if r.OK && r.Status > 0 && r.Status < 500 {
			return checked
		}
	}
	return "https://" + host
}

// ── flag 辅助 ──

func newFlagSet() *flag.FlagSet {
	fs := flag.NewFlagSet("", flag.ContinueOnError)
	fs.SetOutput(discard{})
	return fs
}

type discard struct{}

func (discard) Write(p []byte) (int, error) { return len(p), nil }

// stringListFlag 可重复的字符串旗标（--header 'K: V' --header 'K2: V2'）。
// flag 包对同一 Var 的多次出现按命令行顺序回调 Set，正好对上「多值按序发送」
// 的语义；String() 只用于 PrintDefaults，不影响发送顺序。
type stringListFlag []string

func (s *stringListFlag) String() string { return strings.Join(*s, ", ") }

func (s *stringListFlag) Set(v string) error {
	*s = append(*s, v)
	return nil
}

func parseOrUsage(fs *flag.FlagSet, args []string, cmd, usage string) int {
	err := fs.Parse(args)
	if err == nil {
		return -1
	}
	if errors.Is(err, flag.ErrHelp) {
		// fix3（audit low#6）：子命令内 -h/--help 对齐 argparse——打印本命令
		// 用法后 exit 0（此前 flag 包报参数错误 exit 2）
		fmt.Printf("用法: sweep %s\n", usage)
		fs.PrintDefaults()
		return 0
	}
	fmt.Printf("[!] 参数错误: %v\n  用法: sweep %s\n", err, usage)
	return 2
}

func missingArgs(cmd, usage string) int {
	fmt.Printf("[!] 缺少必填参数（subcommand=%s）\n  用法: sweep %s\n", cmd, usage)
	return 2
}

// pickAliasLastWins 重复旗标取「命令行中最后出现」者的值（argparse last-wins
// 语义，fix2 audit low#7：此前 pickNonEmpty 取第一个非空，与 Python 相反——
// `verify -w 16 --workers 8` Go 得 16、Python 得 8）。fs.Visit 是字典序而非
// 命令行序，故按原始 args 里各别名的最后出现位置判定。
// 未显式设置任何别名时返回零值""（由调用方走 missingArgs）。
func pickAliasLastWins(args []string, vals map[string]*string) string {
	norm := map[string]*string{}
	for k, v := range vals {
		norm[strings.TrimLeft(k, "-")] = v // vals 键带横线；args token 无横线
	}
	lastPos := map[string]int{}
	for i, tk := range args {
		name := strings.TrimLeft(tk, "-")
		if j := strings.IndexByte(name, '='); j >= 0 {
			name = name[:j]
		}
		if _, isAlias := norm[name]; isAlias {
			lastPos[name] = i
		}
	}
	best, picked := -1, ""
	for name, p := range norm {
		if o, ok := lastPos[name]; ok && o > best {
			best, picked = o, *p
		}
	}
	return picked
}

// pickIntAliasLastWins 同 pickAliasLastWins 的 int 版；全部未设置回 def。
func pickIntAliasLastWins(args []string, def int, vals map[string]*int) int {
	norm := map[string]*int{}
	for k, v := range vals {
		norm[strings.TrimLeft(k, "-")] = v
	}
	lastPos := map[string]int{}
	for i, tk := range args {
		name := strings.TrimLeft(tk, "-")
		if j := strings.IndexByte(name, '='); j >= 0 {
			name = name[:j]
		}
		if _, isAlias := norm[name]; isAlias {
			lastPos[name] = i
		}
	}
	best, picked, any := -1, def, false
	for name, p := range norm {
		if o, ok := lastPos[name]; ok && o > best {
			best, picked, any = o, *p, true
		}
	}
	if !any {
		return def
	}
	return picked
}

// invalidDomainShape 域名形状白名单（与 subdomain.Run 入口污点闸同规则）：
// 非空、≤253、无路径分隔符/悬浮点组件/控制字符。bad=true 时 why 给出原因。
func invalidDomainShape(d string) (bool, string) {
	v := strings.TrimSpace(d)
	switch {
	case v == "":
		return true, "空"
	case len(v) > 253:
		return true, "超长"
	case strings.ContainsAny(v, `/\`):
		return true, "含路径分隔符"
	case strings.Contains(v, ".."):
		return true, "含悬浮点组件"
	case strings.ContainsFunc(v, func(r rune) bool { return r <= 0x20 || r == 0x7f }):
		return true, "含控制字符/空白"
	case strings.ContainsFunc(v, func(r rune) bool {
		return !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' ||
			r >= '0' && r <= '9' || r == '.' || r == '-')
	}):
		return true, "含域名合法字符集之外的字符（&=?# 等）"
	}
	return false, ""
}

func pickNonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

// pickNonEmpty3 三个候选里取第一个非空值。
func pickNonEmpty3(a, b, c string) string {
	if a != "" {
		return a
	}
	return pickNonEmpty(b, c)
}

// pickInt 取非默认值者优先，两个都等于默认则回默认。
func pickInt(a, b, def int) int {
	if a != def {
		return a
	}
	return b
}
