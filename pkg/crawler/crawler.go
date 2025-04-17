package crawler

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/jedib0t/go-pretty/v6/table"
	"github.com/jedib0t/go-pretty/v6/text"
	"golang.org/x/term"

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

// CrawlExploit 爬取漏洞列表或指定ID的漏洞
func (c *Crawler) CrawlExploit(id string, outputPath string, fields string) error {
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

	if strings.Contains(path, "/issue/WLB-") {
		// 如果是详情页面，调用详情页面爬取
		result, err := c.CrawlVulnerabilityDetail(path, outputPath)
		if err != nil {
			return err
		}
		fmt.Printf("爬取成功，漏洞标题: %s\n", result.Title)
		fmt.Printf("风险级别: %s\n", result.RiskLevel)
		fmt.Printf("发布日期: %s\n", result.Date.Format("2006-01-02"))
		fmt.Printf("标签数量: %d\n", len(result.Tags))
		fmt.Printf("作者: %s\n", result.Author)
	} else {
		// 如果是列表页面，调用列表页面爬取
		result, err := c.CrawlPage(path, outputPath)
		if err != nil {
			return err
		}

		// 使用go-pretty创建美观的表格
		t := table.NewWriter()
		t.SetOutputMirror(os.Stdout)

		// 设置表格样式
		t.SetStyle(table.StyleRounded)

		// 获取终端宽度
		width, _, err := term.GetSize(int(os.Stdout.Fd()))
		if err != nil {
			// 如果获取失败，使用默认宽度
			width = 120
		}

		// 动态计算各列宽度
		// 终端宽度减去表格边框和列分隔符所占用的空间（大约是每列2个字符和表边框4个字符）
		availableWidth := width - (4 + 2*5)

		// 根据内容特点分配各列宽度占比
		dateRatio := 0.10   // 日期列 - 约10%
		riskRatio := 0.07   // 风险列 - 约7%
		titleRatio := 0.45  // 标题列 - 约45%
		tagsRatio := 0.18   // 标签列 - 约18%
		authorRatio := 0.20 // 作者列 - 约20%

		// 计算各列实际宽度（最小保证有10个字符）
		dateWidth := max(12, int(float64(availableWidth)*dateRatio))
		riskWidth := max(8, int(float64(availableWidth)*riskRatio))
		titleWidth := max(20, int(float64(availableWidth)*titleRatio))
		tagsWidth := max(15, int(float64(availableWidth)*tagsRatio))
		authorWidth := max(15, int(float64(availableWidth)*authorRatio))

		// 设置表头
		t.AppendHeader(table.Row{"日期", "风险", "标题", "标签", "作者"})

		// 设置表头颜色和样式
		t.SetColumnConfigs([]table.ColumnConfig{
			{Number: 1, Align: text.AlignCenter, AlignHeader: text.AlignCenter, Colors: text.Colors{text.FgHiCyan, text.Bold}, WidthMax: dateWidth},
			{Number: 2, Align: text.AlignCenter, AlignHeader: text.AlignCenter, Colors: text.Colors{text.FgHiYellow}, WidthMax: riskWidth},
			{Number: 3, AlignHeader: text.AlignCenter, Colors: text.Colors{text.FgHiWhite}, WidthMax: titleWidth},
			{Number: 4, Align: text.AlignCenter, AlignHeader: text.AlignCenter, Colors: text.Colors{text.FgHiGreen}, WidthMax: tagsWidth},
			{Number: 5, AlignHeader: text.AlignCenter, Colors: text.Colors{text.FgHiMagenta}, WidthMax: authorWidth},
		})

		// 添加数据行
		for _, item := range result.Items {
			// 日期格式化
			date := "未知"
			if !item.Date.IsZero() {
				date = item.Date.Format("2006-01-02")
			}

			// 标题可能很长，需要截断
			title := item.Title
			if len(title) > titleWidth-3 {
				title = title[:titleWidth-6] + "..."
			}

			// 标签格式化
			tags := "无"
			if len(item.Tags) > 0 {
				tagsStr := strings.Join(item.Tags, ", ")
				if len(tagsStr) > tagsWidth-3 {
					tagsStr = tagsStr[:tagsWidth-6] + "..."
				}
				tags = tagsStr
			}

			// 作者名可能很长，需要截断
			author := item.Author
			if len(author) > authorWidth-3 {
				author = author[:authorWidth-6] + "..."
			}

			// 根据风险级别设置不同颜色
			riskLevel := item.RiskLevel
			var riskRow table.Row

			// 添加数据行，根据风险等级着色
			switch strings.ToLower(riskLevel) {
			case "high":
				riskRow = table.Row{date, text.Colors{text.FgRed, text.Bold}.Sprint(riskLevel), title, tags, author}
			case "med.", "medium":
				riskRow = table.Row{date, text.Colors{text.FgYellow, text.Bold}.Sprint(riskLevel), title, tags, author}
			case "low":
				riskRow = table.Row{date, text.Colors{text.FgGreen, text.Bold}.Sprint(riskLevel), title, tags, author}
			default:
				riskRow = table.Row{date, riskLevel, title, tags, author}
			}
			t.AppendRow(riskRow)
		}

		// 添加页码信息到表格底部
		t.AppendFooter(table.Row{"", "",
			fmt.Sprintf("总计: %d 条记录", len(result.Items)),
			fmt.Sprintf("页码: %d/%d", result.CurrentPage, result.TotalPages),
			""})

		// 渲染表格
		fmt.Printf("\n爬取成功！\n")
		t.Render()
		fmt.Println()
	}

	if outputPath != "" {
		fmt.Printf("结果已保存到 %s\n", outputPath)
	}
	return nil
}

// 辅助函数：返回两个整数中的较大值
func max(a, b int) int {
	if a > b {
		return a
	}
	return b
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
