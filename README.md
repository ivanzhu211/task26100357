# vulnmatch

开源依赖漏洞匹配库，供上层依赖扫描平台以库的形式调用（无接口层、无持久化）。
漏洞记录、项目依赖和各包的已发布版本列表都由调用方在内存里传入。

## 能力

- 支持 PyPI（PEP 440 版本说明符、PEP 503 包名归一化）和 npm（node-semver
  非 loose 范围语法、includePrerelease 语义）两个生态。
- 预发布版本照常参与判断，遵循各生态规范的边界规则：
  PyPI 的 `<1.4.2` 不包含 `1.4.2rc1`；npm 的 `<2.0.0` 包含 `2.0.0-beta.1`，
  而 `^1.2.3`、`<2` 不包含它。
- 命中的依赖给出推荐升级版本：比已安装版本新、非预发布、不落在该包任何
  一条漏洞记录范围里的最旧版本；没有则标记 `NoSafeVersion`。
- 表达式解析失败或已安装版本号不合规范时，该依赖标为 `StatusUndetermined`
  并附原因，不会当作未命中。

## 用法

```go
m := vulnmatch.NewMatcher(records)   // 加载一次，可反复扫描
results := m.Scan(deps, published)   // published: map[vulnmatch.Package][]string
```

## 结构

- `pep440/`：PEP 440 版本解析、比较与说明符匹配
- `semver/`：node-semver 严格模式版本与范围匹配（includePrerelease）
- `matcher.go`：索引、扫描与推荐升级版本

## 测试

```sh
go test ./...
```

含版本比较、范围写法、推荐升级与性能测试（20 万条记录 / 3 万个包 /
2.5 万条依赖，要求 5 秒内完成）。
