package crawler

import (
	"github.com/scagogogo/cxsecurity-crawler/pkg/model"
)

// HTMLParser 定义HTML解析器接口，便于测试
type HTMLParser interface {
	// 解析漏洞列表页面
	ParseListPage(htmlContent string) (*model.VulnerabilityList, error)

	// 解析漏洞详情页面
	ParseVulnerabilityDetailPage(htmlContent string) (*model.Vulnerability, error)

	// 解析CVE详情页面
	ParseCveDetailPage(htmlContent string) (*model.CveDetail, error)
}

// Parser 是一个HTML解析器，用于从页面中提取漏洞数据
type Parser struct{}

// NewParser 创建一个新的Parser实例
func NewParser() *Parser {
	return &Parser{}
}
