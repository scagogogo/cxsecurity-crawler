package crawler

import (
	"github.com/scagogogo/cxsecurity-crawler/pkg/model"
)

// HTMLParser 定义HTML解析器接口，便于测试
type HTMLParser interface {
	ParseListPage(htmlContent string) (*model.VulnerabilityList, error)
	ParseCveDetailPage(htmlContent string) (*model.CveDetail, error)
	ParseVulnerabilityDetailPage(htmlContent string) (*model.Vulnerability, error)
}

// Parser 是一个HTML解析器，用于从页面中提取漏洞数据
type Parser struct{}

// NewParser 创建一个新的Parser实例
func NewParser() *Parser {
	return &Parser{}
}
