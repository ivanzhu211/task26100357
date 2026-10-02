# vulnmatch

开源依赖漏洞匹配库（Go）。由上层的依赖扫描平台在进程内调用，漏洞记录、
项目依赖和各包已发布版本列表全部由调用方在内存中传入，不做持久化，
不监听端口，无外部依赖（仅标准库）。

## 能力

- 双生态：**PyPI**（PEP 440 版本 + PEP 440 版本说明符，PEP 503 包名归一化）
  与 **npm**（node-semver 严格模式范围，判定行为等价于
  `includePrerelease: true`）。
- 版本与范围判定与参考实现逐条一致：
  - PyPI 侧对照 `pypa/packaging` 26.2（含 epoch、预发布、后发布、开发版、
    本地版本、`~=`、`==1.4.*` 前缀匹配、`<`/`>` 的同版本预发布/后发布排除）。
  - npm 侧对照 `node-semver` 7.7.4（`^`、`~`、`x`/`*`、不完整版本、
    连字符范围 `1.2 - 2.3`、`||` 并集、预发布边界 `-0` 上界）。
- 预发布版本照常参与匹配，不会被跳过。
- 命中后给出推荐升级版本：已发布版本中比已安装版本新、非预发布、
  且不落在该包任何一条漏洞记录范围里的最旧版本；没有则明确标出。
- 表达式解析失败或已安装版本不合规范时，该依赖标为“无法判定”并附原因，
  不会当作未命中。

## 用法

```go
records := []vulnmatch.VulnRecord{
    {ID: "CVE-2024-0001", Ecosystem: vulnmatch.EcosystemPyPI,
     Package: "requests", Ranges: []string{">=2.0,<2.31.1"}},
    {ID: "CVE-2024-0002", Ecosystem: vulnmatch.EcosystemNPM,
     Package: "@scope/lib", Ranges: []string{"^0.2.3 || >=2.0.0-beta.1 <2.0.3"}},
}

// 构建一次索引，反复用于扫描。解析失败的表达式会收进 errs，
// 受影响依赖在扫描时会被标为 StatusUnknown。
m, errs := vulnmatch.NewMatcher(records)
_ = errs

deps := []vulnmatch.Dependency{
    {Ecosystem: vulnmatch.EcosystemPyPI, Package: "Requests", Version: "2.30.0"},
    {Ecosystem: vulnmatch.EcosystemNPM, Package: "@scope/lib", Version: "0.2.9"},
}

// 各包已发布版本（用于升级推荐），PyPI 的键会按 PEP 503 归一化。
published := map[vulnmatch.Ecosystem]map[string][]string{
    vulnmatch.EcosystemPyPI: {"requests": {"2.30.0", "2.31.0", "2.31.1", "2.32.0rc1"}},
    vulnmatch.EcosystemNPM:  {"@scope/lib": {"0.2.9", "0.3.0"}},
}

results := m.Scan(deps, published)
for _, r := range results {
    switch r.Status {
    case vulnmatch.StatusVulnerable:
        // r.Matches 为命中的记录；r.Upgrade 为推荐升级版本；
        // r.NoSafeVer 为 true 表示没有安全版本可升。
    case vulnmatch.StatusClean:
    case vulnmatch.StatusUnknown:
        // r.Reason 说明无法判定的具体原因。
    }
}
```

## 性能

按 20 万条记录 / 3 万个包建索引（约 1 秒，一次性），单次扫描
2.5 万个依赖在普通笔记本上约 0.1 秒完成（预算 5 秒），
见 `TestScanPerformance`。

## 测试

```sh
go test ./...          # 全部测试
go test -short ./...   # 跳过性能测试
```

- `testdata/` 中的 ground truth 由参考实现生成，可用脚本重新生成：
  - `node scripts/gen_npm_groundtruth.cjs` / `node scripts/gen_npm_fuzz.cjs`
    （使用本机 npm 自带的 node-semver 7.7.4）
  - `python3 scripts/gen_pypi_groundtruth.py` / `python3 scripts/gen_pypi_fuzz.py`
    （需要 `packaging` 26.x）
- 覆盖：两个生态的版本比较、范围/说明符写法、非法输入判定，
  重点是预发布边界与不完整版本号；另有约 8000 条随机差分用例。
