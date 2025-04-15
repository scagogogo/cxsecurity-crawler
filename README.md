# CXSecurity Crawler

一个用于爬取 CXSecurity 网站漏洞数据的工具。

## 功能特性

- 爬取 CXSecurity 网站的漏洞列表数据
- 爬取 CXSecurity 网站的CVE详情页面数据
- 解析漏洞标题、URL、风险级别、发布日期等信息
- 支持筛选输出特定字段
- 将结果保存为 JSON 格式

## 使用方法

### 编译

```bash
# 编译漏洞列表爬虫
go build -o crawler cmd/crawler/main.go

# 编译CVE详情爬虫
go build -o cve_crawler cmd/cve_crawler/main.go
```

### 运行漏洞列表爬虫

```bash
# 基本用法
./crawler

# 指定URL和输出文件
./crawler -url="/exploit/85" -output="result.json"

# 只输出标题和URL字段
./crawler -url="/exploit/85" -output="result.json" -fields="title,url"

# 输出所有字段
./crawler -url="/exploit/85" -output="result.json" -fields="all"
```

### 运行CVE详情爬虫

```bash
# 基本用法
./cve_crawler

# 指定CVE编号和输出文件
./cve_crawler -cve="CVE-2007-1411" -output="cve_result.json"

# 只输出描述和参考链接字段
./cve_crawler -cve="CVE-2007-1411" -output="cve_result.json" -fields="description,references"

# 输出所有字段
./cve_crawler -cve="CVE-2007-1411" -output="cve_result.json" -fields="all"
```

### 漏洞列表爬虫命令行参数

- `-url`: 要爬取的页面路径，默认为 `/exploit/85`
- `-output`: 结果输出的文件路径，默认为 `output.json`
- `-fields`: 要输出的字段，多个字段用逗号分隔，例如 `title,url,date`。可选值包括：
  - `title`: 漏洞标题
  - `url`: 漏洞详情页URL
  - `date`: 发布日期
  - `risk_level`: 风险级别
  - `tags`: 标签列表
  - `author`: 作者名称
  - `author_url`: 作者页面URL
  - `all`: 输出所有字段

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

## 漏洞列表输出格式

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
    // 更多漏洞条目...
  ],
  "current_page": 1,
  "total_pages": 1
}
```

## CVE详情输出格式

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
    // 更多参考链接...
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

https://cxsecurity.com/exploit/#google_vignette







