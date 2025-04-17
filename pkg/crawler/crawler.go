package crawler

import (
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/scagogogo/cxsecurity-crawler/pkg/model"
)

// Crawler 是爬虫主类，用于协调整个爬取过程
type Crawler struct {
	client HTTPClient
	parser HTMLParser
}

// CrawlerOption 是设置Crawler选项的函数类型
type CrawlerOption func(*Crawler)

// WithClientOptions 传递HTTP客户端的选项
func WithClientOptions(options ...ClientOption) CrawlerOption {
	return func(c *Crawler) {
		c.client = NewClient(options...)
	}
}

// WithCustomParser 设置自定义解析器
func WithCustomParser(parser HTMLParser) CrawlerOption {
	return func(c *Crawler) {
		c.parser = parser
	}
}

// NewCrawler 创建一个新的Crawler实例
func NewCrawler(options ...CrawlerOption) *Crawler {
	// 创建默认配置的爬虫
	crawler := &Crawler{
		client: NewClient(),
		parser: NewParser(),
	}

	// 应用选项
	for _, option := range options {
		option(crawler)
	}

	return crawler
}

// SearchResult 表示搜索结果
type SearchResult struct {
	Keyword         string                // 搜索关键词
	CurrentPage     int                   // 当前页码
	TotalPages      int                   // 总页数
	SortOrder       string                // 排序顺序(ASC或DESC)
	PerPage         int                   // 每页记录数
	Vulnerabilities []SearchVulnerability // 漏洞列表
}

// SearchVulnerability 表示搜索结果中的单个漏洞项
type SearchVulnerability struct {
	ID        string // 漏洞ID
	Title     string // 标题
	URL       string // URL
	Date      string // 日期
	RiskLevel string // 风险级别
	Author    string // 作者
	AuthorURL string // 作者URL
}

// SearchVulnerabilities 根据关键词搜索漏洞
func (c *Crawler) SearchVulnerabilities(keyword string, page int, outputPath string) (*SearchResult, error) {
	// 使用默认值调用高级搜索方法
	return c.SearchVulnerabilitiesAdvanced(keyword, page, 10, "DESC", outputPath)
}

// SearchVulnerabilitiesAdvanced 高级搜索功能
func (c *Crawler) SearchVulnerabilitiesAdvanced(keyword string, page int, perPage int, sortOrder string, outputPath string) (*SearchResult, error) {
	// 构建搜索URL，格式为: /search/wlb/DESC/AND/结束日期.开始日期/页码/每页数量/关键词/
	// 结束日期使用当前日期，开始日期使用一个固定的早期日期
	currentTime := time.Now()
	endDate := fmt.Sprintf("%d.%d.%d", currentTime.Year(), currentTime.Month(), currentTime.Day())
	startDate := "1999.1.1" // 一个固定的早期日期

	// 默认值和验证
	if perPage != 10 && perPage != 30 {
		perPage = 10 // 默认每页10条，仅支持10或30
	}

	if sortOrder != "ASC" && sortOrder != "DESC" {
		sortOrder = "DESC" // 默认为DESC，仅支持ASC或DESC
	}

	path := fmt.Sprintf("/search/wlb/%s/AND/%s.%s/%d/%d/%s/",
		sortOrder, endDate, startDate, page, perPage, url.QueryEscape(keyword))

	// 获取页面内容
	htmlContent, err := c.client.GetPage(path)
	if err != nil {
		return nil, fmt.Errorf("获取搜索结果页面内容失败: %w", err)
	}

	// 解析搜索结果页面
	vulnList, err := c.parser.ParseListPage(htmlContent)
	if err != nil {
		return nil, fmt.Errorf("解析搜索结果页面内容失败: %w", err)
	}

	// 转换为SearchResult格式
	result := &SearchResult{
		Keyword:         keyword,
		CurrentPage:     vulnList.CurrentPage,
		TotalPages:      vulnList.TotalPages,
		SortOrder:       sortOrder,
		PerPage:         perPage,
		Vulnerabilities: make([]SearchVulnerability, 0, len(vulnList.Items)),
	}

	// 提取搜索结果项
	for _, item := range vulnList.Items {
		// 提取ID
		id := "未知"
		if item.ID != "" {
			id = item.ID
		} else if item.URL != "" && strings.Contains(item.URL, "WLB-") {
			idx := strings.Index(item.URL, "WLB-")
			id = item.URL[idx:]
		}

		// 格式化日期
		date := "未知"
		if !item.Date.IsZero() {
			date = item.Date.Format("2006-01-02")
		}

		searchVuln := SearchVulnerability{
			ID:        id,
			Title:     item.Title,
			URL:       item.URL,
			Date:      date,
			RiskLevel: item.RiskLevel,
			Author:    item.Author,
			AuthorURL: item.AuthorURL,
		}

		result.Vulnerabilities = append(result.Vulnerabilities, searchVuln)
	}

	// 保存结果
	if outputPath != "" {
		if err := c.saveSearchResult(result, outputPath); err != nil {
			return nil, fmt.Errorf("保存搜索结果失败: %w", err)
		}
	}

	return result, nil
}

// saveSearchResult 保存搜索结果
func (c *Crawler) saveSearchResult(result *SearchResult, outputPath string) error {
	// 创建目录
	dir := filepath.Dir(outputPath)
	if dir != "." && dir != "" {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return fmt.Errorf("创建输出目录失败: %w", err)
		}
	}

	// 将结果编码为JSON
	jsonData, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return fmt.Errorf("编码JSON失败: %w", err)
	}

	// 写入文件
	if err := os.WriteFile(outputPath, jsonData, 0644); err != nil {
		return fmt.Errorf("写入文件失败: %w", err)
	}

	return nil
}

// CrawlPage 爬取指定页面并保存结果
func (c *Crawler) CrawlPage(path string, outputPath string) (*model.VulnerabilityList, error) {
	// 获取页面内容
	htmlContent, err := c.client.GetPage(path)
	if err != nil {
		return nil, fmt.Errorf("获取页面内容失败: %w", err)
	}

	// 解析页面内容
	result, err := c.parser.ParseListPage(htmlContent)
	if err != nil {
		return nil, fmt.Errorf("解析页面内容失败: %w", err)
	}

	// 保存结果
	if outputPath != "" {
		if err := c.saveResult(result, outputPath); err != nil {
			return nil, fmt.Errorf("保存结果失败: %w", err)
		}
	}

	return result, nil
}

// CrawlVulnerabilityDetail 爬取漏洞详情页面并保存结果
func (c *Crawler) CrawlVulnerabilityDetail(path string, outputPath string) (*model.Vulnerability, error) {
	// 构建完整URL路径
	if path != "" && !strings.HasPrefix(path, "/") {
		path = "/" + path
	}

	// 获取页面内容
	htmlContent, err := c.client.GetPage(path)
	if err != nil {
		return nil, fmt.Errorf("获取漏洞详情页面内容失败: %w", err)
	}

	// 解析页面内容
	result, err := c.parser.ParseVulnerabilityDetailPage(htmlContent)
	if err != nil {
		return nil, fmt.Errorf("解析漏洞详情页面内容失败: %w", err)
	}

	// 设置URL (由于HTML内容中不含完整URL)
	// 修复URL重复问题，避免前缀重复
	if result.URL == "" {
		// 清理可能存在的重复WLB-前缀
		cleanPath := path
		if strings.Contains(path, "/issue/WLB-WLB-") {
			cleanPath = strings.Replace(path, "/issue/WLB-WLB-", "/issue/WLB-", 1)
		}
		result.URL = c.client.GetBaseURL() + cleanPath
	}

	// 保存结果
	if outputPath != "" {
		if err := c.saveVulnerabilityDetailResult(result, outputPath); err != nil {
			return nil, fmt.Errorf("保存漏洞详情结果失败: %w", err)
		}
	}

	return result, nil
}

// CrawlCveDetail 爬取CVE详情页面并保存结果
func (c *Crawler) CrawlCveDetail(cveID string, outputPath string) (*model.CveDetail, error) {
	// 构建URL路径
	path := fmt.Sprintf("/cveshow/%s/", cveID)

	// 获取页面内容
	htmlContent, err := c.client.GetPage(path)
	if err != nil {
		return nil, fmt.Errorf("获取CVE详情页面内容失败: %w", err)
	}

	// 解析页面内容
	result, err := c.parser.ParseCveDetailPage(htmlContent)
	if err != nil {
		return nil, fmt.Errorf("解析CVE详情页面内容失败: %w", err)
	}

	// 保存结果
	if outputPath != "" {
		if err := c.saveCveDetailResult(result, outputPath); err != nil {
			return nil, fmt.Errorf("保存CVE详情结果失败: %w", err)
		}
	}

	return result, nil
}

// CrawlExploit 爬取漏洞列表或漏洞详情
func (c *Crawler) CrawlExploit(id string, outputPath string, fields string) (interface{}, error) {
	// 确定路径
	var path string
	if id == "" {
		// 默认爬取漏洞列表页面
		path = "/exploit/1"
	} else {
		// 检查ID是否已包含WLB-前缀
		if strings.HasPrefix(id, "WLB-") {
			path = "/issue/" + id
		} else {
			path = "/issue/WLB-" + id
		}
	}

	// 根据路径判断是爬取详情页还是列表页
	if strings.Contains(path, "/issue/WLB-") {
		// 如果是详情页面，调用详情页面爬取
		result, err := c.CrawlVulnerabilityDetail(path, outputPath)
		if err != nil {
			return nil, err
		}

		// 提取漏洞ID，并添加到结果中
		if result.URL != "" && strings.Contains(result.URL, "WLB-") {
			idx := strings.Index(result.URL, "WLB-")
			result.ID = result.URL[idx:]
		}

		return result, nil
	} else {
		// 如果是列表页面，调用列表页面爬取
		result, err := c.CrawlPage(path, outputPath)
		if err != nil {
			return nil, err
		}

		// 处理每个漏洞项目，确保ID字段有值
		for i := range result.Items {
			if result.Items[i].URL != "" {
				if idx := strings.Index(result.Items[i].URL, "WLB-"); idx != -1 {
					// 提取URL中的ID
					urlPart := result.Items[i].URL[idx:]
					endIdx := len(urlPart)
					if slashIdx := strings.IndexByte(urlPart, '/'); slashIdx != -1 {
						endIdx = slashIdx
					}
					result.Items[i].ID = urlPart[:endIdx]
				}
			}
		}

		return result, nil
	}
}

// CrawlAuthor 爬取作者信息页面并保存结果
func (c *Crawler) CrawlAuthor(authorID string, outputPath string) (*model.AuthorProfile, error) {
	// 构建URL路径
	path := fmt.Sprintf("/author/%s/1/", authorID)

	// 获取页面内容
	htmlContent, err := c.client.GetPage(path)
	if err != nil {
		return nil, fmt.Errorf("获取作者页面内容失败: %w", err)
	}

	// 解析页面内容
	authorParser := NewAuthorParser()
	resultInterface, err := authorParser.Parse(htmlContent)
	if err != nil {
		return nil, fmt.Errorf("解析作者页面内容失败: %w", err)
	}

	result, ok := resultInterface.(*model.AuthorProfile)
	if !ok {
		return nil, fmt.Errorf("解析结果类型错误")
	}

	// 如果未成功解析到ID，使用输入的作者ID
	if result.ID == "" {
		result.ID = authorID
	}

	// 保存结果
	if outputPath != "" {
		if err := c.saveAuthorResult(result, outputPath); err != nil {
			return nil, fmt.Errorf("保存作者信息结果失败: %w", err)
		}
	}

	return result, nil
}

// saveResult 将爬取结果保存到文件中
func (c *Crawler) saveResult(result *model.VulnerabilityList, outputPath string) error {
	// 创建目录
	dir := filepath.Dir(outputPath)
	if dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return err
		}
	}

	// 将结果序列化为JSON
	data, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return err
	}

	// 写入文件
	if err := os.WriteFile(outputPath, data, 0644); err != nil {
		return err
	}

	return nil
}

// saveVulnerabilityDetailResult 将漏洞详情结果保存到文件中
func (c *Crawler) saveVulnerabilityDetailResult(result *model.Vulnerability, outputPath string) error {
	// 创建目录
	dir := filepath.Dir(outputPath)
	if dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return err
		}
	}

	// 将结果序列化为JSON
	data, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return err
	}

	// 写入文件
	if err := os.WriteFile(outputPath, data, 0644); err != nil {
		return err
	}

	return nil
}

// saveCveDetailResult 将CVE详情结果保存到文件中
func (c *Crawler) saveCveDetailResult(result *model.CveDetail, outputPath string) error {
	// 创建目录
	dir := filepath.Dir(outputPath)
	if dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return err
		}
	}

	// 将结果序列化为JSON
	data, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return err
	}

	// 写入文件
	if err := os.WriteFile(outputPath, data, 0644); err != nil {
		return err
	}

	return nil
}

// saveAuthorResult 将作者信息结果保存到文件中
func (c *Crawler) saveAuthorResult(result *model.AuthorProfile, outputPath string) error {
	// 创建目录
	dir := filepath.Dir(outputPath)
	if dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return err
		}
	}

	// 将结果序列化为JSON
	data, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return err
	}

	// 写入文件
	if err := os.WriteFile(outputPath, data, 0644); err != nil {
		return err
	}

	return nil
}
