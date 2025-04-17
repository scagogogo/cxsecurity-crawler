package crawler

import (
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// SearchResult 表示搜索结果
type SearchResult struct {
	Keyword         string                `json:"keyword"`         // 搜索关键词
	CurrentPage     int                   `json:"current_page"`    // 当前页码
	TotalPages      int                   `json:"total_pages"`     // 总页数
	SortOrder       string                `json:"sort_order"`      // 排序顺序(ASC或DESC)
	PerPage         int                   `json:"per_page"`        // 每页记录数
	Vulnerabilities []SearchVulnerability `json:"vulnerabilities"` // 漏洞列表
}

// SearchVulnerability 表示搜索结果中的单个漏洞项
type SearchVulnerability struct {
	ID        string `json:"id"`         // 漏洞ID
	Title     string `json:"title"`      // 标题
	URL       string `json:"url"`        // URL
	Date      string `json:"date"`       // 日期
	RiskLevel string `json:"risk_level"` // 风险级别
	Author    string `json:"author"`     // 作者
	AuthorURL string `json:"author_url"` // 作者URL
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
		if err := saveSearchResult(result, outputPath); err != nil {
			return nil, fmt.Errorf("保存搜索结果失败: %w", err)
		}
	}

	return result, nil
}

// saveSearchResult 保存搜索结果
func saveSearchResult(result *SearchResult, outputPath string) error {
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
