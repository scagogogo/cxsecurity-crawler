package crawler

import (
	"github.com/scagogogo/cxsecurity-crawler/pkg/model"
)

// HTMLParser 定义HTML解析器接口，用于解析不同类型的页面内容。
// 这个接口的设计目的是将页面解析逻辑与爬虫逻辑分离，便于测试和扩展。
//
// 接口包含三个主要方法：
// 1. ParseListPage: 解析漏洞列表页面，支持标准列表和搜索结果两种格式
// 2. ParseVulnerabilityDetailPage: 解析单个漏洞的详情页面
// 3. ParseCveDetailPage: 解析CVE漏洞的详情页面
//
// 实现这个接口时需要注意：
// - 每个方法都应该能够处理空内容和格式错误的情况
// - 解析失败时应返回明确的错误信息
// - 应该尽可能多地提取页面中的有用信息
type HTMLParser interface {
	// ParseListPage 解析漏洞列表页面，支持标准列表和搜索结果格式。
	// 参数 htmlContent 是页面的HTML内容字符串。
	// 返回解析后的漏洞列表对象，如果解析失败则返回错误。
	ParseListPage(htmlContent string) (*model.VulnerabilityList, error)

	// ParseVulnerabilityDetailPage 解析单个漏洞的详情页面。
	// 参数 htmlContent 是页面的HTML内容字符串。
	// 返回解析后的漏洞详情对象，如果解析失败则返回错误。
	ParseVulnerabilityDetailPage(htmlContent string) (*model.Vulnerability, error)

	// ParseCveDetailPage 解析CVE漏洞的详情页面。
	// 参数 htmlContent 是页面的HTML内容字符串。
	// 返回解析后的CVE详情对象，如果解析失败则返回错误。
	ParseCveDetailPage(htmlContent string) (*model.CveDetail, error)
}

// Parser 是HTMLParser接口的默认实现，提供了对CXSecurity网站各类页面的解析功能。
// 它使用goquery库进行HTML解析，支持以下功能：
// - 解析漏洞列表页面（标准列表和搜索结果）
// - 解析漏洞详情页面
// - 解析CVE详情页面
//
// Parser的设计遵循以下原则：
// 1. 容错性：能够处理HTML结构变化和异常情况
// 2. 可扩展性：易于添加新的解析功能
// 3. 可测试性：支持单元测试和集成测试
//
// 使用示例：
//
//	parser := &Parser{}
//	list, err := parser.ParseListPage(htmlContent)
//	if err != nil {
//	    log.Fatal(err)
//	}
//	fmt.Printf("Found %d vulnerabilities\n", len(list.Items))
type Parser struct{}

// NewParser 创建一个新的Parser实例
func NewParser() *Parser {
	return &Parser{}
}
