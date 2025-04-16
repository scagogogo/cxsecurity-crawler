# CXSecurity Crawler

[![Go Tests](https://github.com/scagogogo/cxsecurity-crawler/actions/workflows/go-test.yml/badge.svg)](https://github.com/scagogogo/cxsecurity-crawler/actions/workflows/go-test.yml)
[![codecov](https://codecov.io/gh/scagogogo/cxsecurity-crawler/branch/main/graph/badge.svg)](https://codecov.io/gh/scagogogo/cxsecurity-crawler)

一个用于爬取 CXSecurity 网站漏洞数据的工具。可以作为命令行工具使用，也可以作为Go库集成到其他项目中。

## 功能特性

- 爬取 CXSecurity 网站的漏洞列表数据
- 爬取 CXSecurity 网站的CVE详情页面数据
- 解析漏洞标题、URL、风险级别、发布日期等信息
- 支持筛选输出特定字段
- 将结果保存为 JSON 格式
- 提供可复用的Go API，支持集成到其他项目

## 使用方法

### 作为命令行工具

#### 编译

```bash
# 编译整个项目为单个二进制文件
go build -o cxsecurity
```

#### 运行漏洞列表爬虫

```bash
# 基本用法
./cxsecurity exploit

# 指定漏洞ID和输出文件
./cxsecurity exploit -i 85 -o "result.json"

# 只输出标题和URL字段
./cxsecurity exploit -i 85 -o "result.json" -f "title,url"

# 输出所有字段
./cxsecurity exploit -i 85 -o "result.json" -f "all"
```

#### 运行CVE详情爬虫

```bash
# 基本用法
./cxsecurity cve

# 指定CVE编号和输出文件
./cxsecurity cve --cve="CVE-2007-1411" -o "cve_result.json"

# 只输出描述和参考链接字段
./cxsecurity cve --cve="CVE-2007-1411" -o "cve_result.json" -f "description,references"

# 输出所有字段
./cxsecurity cve --cve="CVE-2007-1411" -o "cve_result.json" -f "all"
```

#### 运行漏洞详情爬虫

```bash
# 基本用法
./cxsecurity vuln-detail

# 指定漏洞ID和输出文件
./cxsecurity vuln-detail --id="WLB-2023010123" -o "vuln_detail.json"

# 只输出特定字段
./cxsecurity vuln-detail --id="WLB-2023010123" -o "vuln_detail.json" -f "title,risk_level,author"
```

### 漏洞列表爬虫命令行参数

- `-i, --id`: 要爬取的漏洞ID，例如 `85`
- `-o, --output`: 结果输出的文件路径，默认为 `exploit_result.json`
- `-f, --fields`: 要输出的字段，多个字段用逗号分隔，例如 `title,url,date`。可选值包括：
  - `title`: 漏洞标题
  - `url`: 漏洞详情页URL
  - `date`: 发布日期
  - `risk_level`: 风险级别
  - `tags`: 标签列表
  - `author`: 作者名称
  - `author_url`: 作者页面URL
  - `all`: 输出所有字段（默认）

### CVE详情爬虫命令行参数

- `-cve`: 要爬取的CVE编号，默认为 `CVE-2007-1411`
- `-output`: 结果输出的文件路径，默认为 `cve_output.json`
- `-fields`: 要输出的字段，多个字段用逗号分隔，例如 `cve_id,description,references`。可选值包括：
  - `cve_id`: CVE编号
  - `published`: 发布日期
  - `modified`: 最后修改日期
  - `description`: 漏洞描述
  - `type`: 漏洞类型
  - `cvss_base_score`: CVSS基础评分
  - `cvss_impact_score`: CVSS影响评分
  - `cvss_exploit_score`: CVSS可利用性评分
  - `exploit_range`: 利用范围
  - `attack_complexity`: 攻击复杂度
  - `authentication`: 认证需求
  - `confidentiality_impact`: 机密性影响
  - `integrity_impact`: 完整性影响
  - `availability_impact`: 可用性影响
  - `affected_software`: 受影响的软件列表
  - `references`: 参考链接
  - `related_vulnerabilities`: 相关漏洞
  - `all`: 输出所有字段

## API 文档

本项目可以作为Go库集成到其他项目中使用。以下是主要API的使用方法和示例。

### 安装

```bash
go get github.com/scagogogo/cxsecurity-crawler
```

### 使用HTTP客户端

HTTP客户端负责处理与CXSecurity网站的网络通信，包括自动重试、处理重定向等功能。

```go
import "github.com/scagogogo/cxsecurity-crawler/pkg/crawler"

// 创建一个默认配置的客户端
client := crawler.NewClient()

// 使用自定义选项创建客户端
client := crawler.NewClient(
    crawler.WithTimeout(10 * time.Second),         // 设置超时时间
    crawler.WithRetry(3, 500 * time.Millisecond),  // 设置重试次数和延迟
    crawler.WithHeader("User-Agent", "Custom-UA"), // 设置自定义请求头
)

// 获取页面内容
content, err := client.GetPage("/exploit/85")
if err != nil {
    // 处理错误
}
fmt.Println(content)
```

### 爬取漏洞列表

```go
import (
    "github.com/scagogogo/cxsecurity-crawler/pkg/crawler"
    "github.com/scagogogo/cxsecurity-crawler/pkg/model"
)

// 创建列表解析器
listParser := crawler.NewListParser()

// 创建客户端
client := crawler.NewClient()

// 爬取漏洞列表页面
content, err := client.GetPage("/exploit/85")
if err != nil {
    // 处理错误
}

// 解析页面内容
vulnList, err := listParser.Parse(content)
if err != nil {
    // 处理错误
}

// 使用解析后的结果
for _, vuln := range vulnList.Items {
    fmt.Printf("漏洞标题: %s\n", vuln.Title)
    fmt.Printf("发布日期: %s\n", vuln.Date.Format("2006-01-02"))
    fmt.Printf("风险级别: %s\n", vuln.RiskLevel)
    fmt.Printf("标签: %v\n", vuln.Tags)
}

fmt.Printf("当前页: %d, 总页数: %d\n", vulnList.CurrentPage, vulnList.TotalPages)
```

### 爬取CVE详情

```go
import (
    "github.com/scagogogo/cxsecurity-crawler/pkg/crawler"
    "github.com/scagogogo/cxsecurity-crawler/pkg/model"
)

// 创建CVE详情解析器
cveParser := crawler.NewCveParser()

// 创建客户端
client := crawler.NewClient()

// 爬取CVE详情页面
content, err := client.GetPage("/cve/CVE-2007-1411")
if err != nil {
    // 处理错误
}

// 解析页面内容
cveDetail, err := cveParser.Parse(content)
if err != nil {
    // 处理错误
}

// 使用解析后的结果
fmt.Printf("CVE编号: %s\n", cveDetail.CveID)
fmt.Printf("发布日期: %s\n", cveDetail.Published.Format("2006-01-02"))
fmt.Printf("漏洞描述: %s\n", cveDetail.Description)
fmt.Printf("CVSS基础评分: %.1f\n", cveDetail.CvssBaseScore)

// 输出受影响的软件
for _, software := range cveDetail.AffectedSoftware {
    fmt.Printf("受影响的软件: %s %s\n", software.VendorName, software.ProductName)
}
```

### 完整的爬虫实现

```go
package main

import (
    "encoding/json"
    "fmt"
    "os"

    "github.com/scagogogo/cxsecurity-crawler/pkg/crawler"
)

func main() {
    // 创建客户端和解析器
    client := crawler.NewClient()
    listParser := crawler.NewListParser()
    
    // 爬取漏洞列表
    content, err := client.GetPage("/exploit/85")
    if err != nil {
        fmt.Printf("获取页面失败: %v\n", err)
        return
    }
    
    // 解析页面内容
    vulnList, err := listParser.Parse(content)
    if err != nil {
        fmt.Printf("解析页面失败: %v\n", err)
        return
    }
    
    // 将结果保存为JSON文件
    jsonData, err := json.MarshalIndent(vulnList, "", "  ")
    if err != nil {
        fmt.Printf("JSON序列化失败: %v\n", err)
        return
    }
    
    err = os.WriteFile("vulnerabilities.json", jsonData, 0644)
    if err != nil {
        fmt.Printf("写入文件失败: %v\n", err)
        return
    }
    
    fmt.Println("成功爬取并保存漏洞列表!")
}
```

### 模型结构

#### 漏洞列表模型

```go
type Vulnerability struct {
    // 漏洞基本信息
    Date      time.Time `json:"date,omitempty"`       // 发布日期
    Title     string    `json:"title,omitempty"`      // 漏洞标题
    URL       string    `json:"url,omitempty"`        // 漏洞详情页URL
    RiskLevel string    `json:"risk_level,omitempty"` // 风险级别(High, Med., Low)

    // 漏洞标签
    Tags []string `json:"tags,omitempty"` // 标签列表(CVE, CWE, Remote, Local等)

    // 作者信息
    Author    string `json:"author,omitempty"`     // 作者名称
    AuthorURL string `json:"author_url,omitempty"` // 作者页面URL
}

type VulnerabilityList struct {
    Items       []Vulnerability `json:"items"`        // 漏洞条目列表
    CurrentPage int             `json:"current_page"` // 当前页码
    TotalPages  int             `json:"total_pages"`  // 总页数
}
```

#### CVE详情模型

```go
type CveDetail struct {
    // 基本信息
    CveID       string    `json:"cve_id,omitempty"`      // CVE编号
    Published   time.Time `json:"published,omitempty"`   // 发布日期
    Modified    time.Time `json:"modified,omitempty"`    // 最后修改日期
    Description string    `json:"description,omitempty"` // 漏洞描述

    // 类型信息
    Type string `json:"type,omitempty"` // 漏洞类型

    // CVSS评分
    CvssBaseScore    float64 `json:"cvss_base_score,omitempty"`    // CVSS基础评分
    CvssImpactScore  float64 `json:"cvss_impact_score,omitempty"`  // CVSS影响评分
    CvssExploitScore float64 `json:"cvss_exploit_score,omitempty"` // CVSS可利用性评分

    // 漏洞属性
    ExploitRange          string `json:"exploit_range,omitempty"`          // 利用范围
    AttackComplexity      string `json:"attack_complexity,omitempty"`      // 攻击复杂度
    Authentication        string `json:"authentication,omitempty"`         // 认证需求
    ConfidentialityImpact string `json:"confidentiality_impact,omitempty"` // 机密性影响
    IntegrityImpact       string `json:"integrity_impact,omitempty"`       // 完整性影响
    AvailabilityImpact    string `json:"availability_impact,omitempty"`    // 可用性影响

    // 受影响的软件
    AffectedSoftware []AffectedSoftware `json:"affected_software,omitempty"` // 受影响的软件列表

    // 相关链接
    References []string `json:"references,omitempty"` // 相关参考链接

    // 相关漏洞
    RelatedVulnerabilities []Vulnerability `json:"related_vulnerabilities,omitempty"` // 相关漏洞列表
}

type AffectedSoftware struct {
    VendorName  string `json:"vendor_name,omitempty"`  // 厂商名称
    VendorURL   string `json:"vendor_url,omitempty"`   // 厂商URL
    ProductName string `json:"product_name,omitempty"` // 产品名称
    ProductURL  string `json:"product_url,omitempty"`  // 产品URL
}
```

## 数据格式示例

### 漏洞列表输出格式

程序将爬取的漏洞列表数据保存为 JSON 格式，结构如下：

```json
{
  "items": [
    {
      "date": "2007-03-21T00:00:00Z",
      "title": "PHP <= 4.4.6 ibase_connect() local buffer overflow",
      "url": "https://cxsecurity.com/issue/WLB-2007030137",
      "risk_level": "High",
      "tags": ["CVE", "CWE", "Local"],
      "author": "rgod",
      "author_url": "https://cxsecurity.com/author/rgod/1/"
    },
    {
      "date": "2007-03-20T00:00:00Z",
      "title": "Another vulnerability example",
      "url": "https://cxsecurity.com/issue/WLB-2007030136",
      "risk_level": "Medium",
      "tags": ["Remote", "XSS"],
      "author": "security_researcher",
      "author_url": "https://cxsecurity.com/author/security_researcher/1/"
    }
  ],
  "current_page": 1,
  "total_pages": 85
}
```

### CVE详情输出格式

程序将爬取的CVE详情数据保存为 JSON 格式，结构如下：

```json
{
  "cve_id": "CVE-2007-1411",
  "published": "2007-03-10T00:00:00Z",
  "modified": "2012-02-12T00:00:00Z",
  "description": "Buffer overflow in PHP 4.4.6 and earlier...",
  "type": "CWE-Other",
  "cvss_base_score": 6.8,
  "cvss_impact_score": 6.4,
  "cvss_exploit_score": 8.6,
  "exploit_range": "Remote",
  "attack_complexity": "Medium",
  "authentication": "No required",
  "confidentiality_impact": "Partial",
  "integrity_impact": "Partial",
  "availability_impact": "Partial",
  "affected_software": [
    {
      "vendor_name": "PHP",
      "vendor_url": "https://cxsecurity.com//cvevendor/42/php/",
      "product_name": "PHP",
      "product_url": "https://cxsecurity.com/cveproduct/42/81/php/"
    }
  ],
  "references": [
    "http://retrogod.altervista.org/php_446_mssql_connect_bof.html",
    "http://www.securityfocus.com/bid/22987"
  ],
  "related_vulnerabilities": [
    {
      "date": "2007-03-14T00:00:00Z",
      "title": "PHP <= 4.4.6 mssql_connect() & mssql_pconnect() local buffer overflow and safe_mode bypass",
      "url": "https://cxsecurity.com/issue/WLB-2007030105",
      "risk_level": "High",
      "author": "rgod"
    }
  ]
}
```

## 开发与贡献

欢迎提交问题或贡献代码。提交PR前请确保通过所有测试并且代码已格式化。

```bash
# 运行测试
go test ./...

# 格式化代码
go fmt ./...
```

## 许可证

本项目使用 MIT 许可证。详见 [LICENSE](LICENSE) 文件。

https://cxsecurity.com/exploit/#google_vignette







