package crawler

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/PuerkitoBio/goquery"

	"github.com/scagogogo/cxsecurity-crawler/pkg/model"
)

// Crawler 是爬虫主类，用于协调整个爬取过程
// 它负责管理HTTP客户端和HTML解析器，提供高级的爬取功能
// 支持爬取漏洞列表、漏洞详情、CVE详情和作者信息等
type Crawler struct {
	client HTTPClient // HTTP客户端，用于发送请求和获取页面内容
	parser HTMLParser // HTML解析器，用于解析页面内容并提取数据
}

// CrawlerOption 是设置Crawler选项的函数类型
// 使用函数选项模式来配置Crawler实例
type CrawlerOption func(*Crawler)

// WithClientOptions 传递HTTP客户端的选项
// 可以通过这个选项来自定义HTTP客户端的行为，比如设置超时、代理等
// 参数:
//   - options: HTTP客户端的配置选项列表
//
// 返回值:
//   - CrawlerOption: 返回一个配置函数
func WithClientOptions(options ...ClientOption) CrawlerOption {
	return func(c *Crawler) {
		c.client = NewClient(options...)
	}
}

// WithCustomParser 设置自定义解析器
// 允许用户提供自己的HTML解析器实现
// 参数:
//   - parser: 自定义的HTML解析器实现
//
// 返回值:
//   - CrawlerOption: 返回一个配置函数
func WithCustomParser(parser HTMLParser) CrawlerOption {
	return func(c *Crawler) {
		c.parser = parser
	}
}

// NewCrawler 创建一个新的Crawler实例
// 可以通过选项函数来自定义爬虫的行为
// 参数:
//   - options: 配置选项列表
//
// 返回值:
//   - *Crawler: 返回配置好的爬虫实例
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
// 用于爬取漏洞列表页面，支持将结果保存到文件
// 参数:
//   - path: 要爬取的页面路径，例如 "/exploit/1"
//   - outputPath: 结果保存路径，为空则不保存
//
// 返回值:
//   - *model.VulnerabilityList: 解析后的漏洞列表
//   - error: 如果发生错误则返回错误信息
//
// 示例:
//
//	result, err := crawler.CrawlPage("/exploit/1", "output.json")
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
// 用于获取单个漏洞的详细信息
// 参数:
//   - path: 漏洞详情页面的路径，例如 "/issue/WLB-2024-0001"
//   - outputPath: 结果保存路径，为空则不保存
//
// 返回值:
//   - *model.Vulnerability: 解析后的漏洞详情
//   - error: 如果发生错误则返回错误信息
//
// 示例:
//
//	result, err := crawler.CrawlVulnerabilityDetail("/issue/WLB-2024-0001", "vuln.json")
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
// 用于获取CVE漏洞的详细信息
// 参数:
//   - cveID: CVE编号，例如 "CVE-2024-21413"
//   - outputPath: 结果保存路径，为空则不保存
//
// 返回值:
//   - *model.CveDetail: 解析后的CVE详情
//   - error: 如果发生错误则返回错误信息
//
// 示例:
//
//	result, err := crawler.CrawlCveDetail("CVE-2024-21413", "cve.json")
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
// 这是一个智能方法，可以根据输入参数决定爬取列表还是详情
//
// 功能：
// 1. 当id为空时，爬取漏洞列表页面
// 2. 当id不为空时，爬取指定ID的漏洞详情页面
// 3. 支持将结果保存到指定文件
// 4. 支持指定返回字段，可以只返回需要的信息
//
// 参数:
//   - id: 漏洞ID，例如 "2024-0001"。为空则爬取列表页
//   - outputPath: 结果保存路径，为空则不保存
//   - fields: 指定要返回的字段，支持以下值：
//   - "all": 返回所有字段
//   - "basic": 仅返回基本信息（ID、标题、日期、风险等级）
//   - "detail": 返回详细信息（包括描述、CVE、CWE等）
//
// 返回值:
//   - interface{}: 根据爬取类型返回不同的结果：
//   - 列表页：返回 *model.VulnerabilityList
//   - 详情页：返回 *model.Vulnerability
//   - error: 如果发生错误则返回错误信息
//
// 示例:
//
//	// 爬取漏洞列表
//	list, err := crawler.CrawlExploit("", "list.json", "all")
//	if err != nil {
//	    log.Fatal(err)
//	}
//	fmt.Printf("Found %d vulnerabilities\n", len(list.Items))
//
//	// 爬取漏洞详情
//	detail, err := crawler.CrawlExploit("2024-0001", "detail.json", "all")
//	if err != nil {
//	    log.Fatal(err)
//	}
//	fmt.Printf("Title: %s\n", detail.Title)
//
// 注意事项：
// 1. 爬取详情页时，会自动处理ID格式，支持以下格式：
//   - 完整格式：WLB-2024-0001
//   - 简短格式：2024-0001
//
// 2. 保存文件时会自动创建必要的目录
// 3. 返回的接口类型需要根据实际情况转换为具体类型
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

// CrawlAuthor 爬取作者信息页面并解析作者的详细资料
//
// 功能：
// 1. 获取作者的基本信息（姓名、国家、简介等）
// 2. 获取作者发布的漏洞列表
// 3. 支持将结果保存到文件
//
// 参数:
//   - authorID: 作者ID，例如 "researcher"
//   - outputPath: 结果保存路径，为空则不保存
//
// 返回值:
//   - *model.AuthorProfile: 作者信息对象，包含以下内容：
//   - 基本信息（ID、姓名、国家等）
//   - 社交媒体链接（Twitter、个人网站等）
//   - 漏洞统计（已发布的漏洞数量）
//   - 漏洞列表（作者发布的所有漏洞）
//   - error: 如果发生错误则返回错误信息
//
// 示例:
//
//	profile, err := crawler.CrawlAuthor("researcher", "author.json")
//	if err != nil {
//	    log.Fatal(err)
//	}
//	fmt.Printf("Author: %s, Country: %s\n", profile.Name, profile.Country)
//	fmt.Printf("Published %d vulnerabilities\n", profile.ReportedCount)
//
// 注意事项：
// 1. 作者页面可能包含分页，目前只获取第一页内容
// 2. 如果作者ID不存在，会返回错误
// 3. 保存的JSON文件会包含完整的作者信息和漏洞列表
func (c *Crawler) CrawlAuthor(authorID string, outputPath string) (*model.AuthorProfile, error) {
	// 构建URL路径
	path := fmt.Sprintf("/author/%s/1/", authorID)

	// 获取页面内容
	htmlContent, err := c.client.GetPage(path)
	if err != nil {
		return nil, fmt.Errorf("获取作者页面内容失败: %w", err)
	}

	// 解析HTML内容为Document
	doc, err := goquery.NewDocumentFromReader(strings.NewReader(htmlContent))
	if err != nil {
		return nil, fmt.Errorf("解析HTML内容失败: %w", err)
	}

	// 解析页面内容
	authorParser := NewAuthorParser()
	result, err := authorParser.Parse(doc)
	if err != nil {
		return nil, fmt.Errorf("解析作者页面内容失败: %w", err)
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

// saveResult 将漏洞列表保存到JSON文件中
// 这个方法会自动创建必要的目录，并将结果格式化为易读的JSON格式。
//
// 功能：
// 1. 自动创建目录
// 2. 格式化JSON（带缩进）
// 3. 设置适当的文件权限
//
// 参数:
//   - result: 要保存的漏洞列表对象
//   - outputPath: 输出文件路径
//
// 返回值:
//   - error: 保存过程中的错误，包括：
//   - 目录创建失败
//   - JSON序列化失败
//   - 文件写入失败
//
// 示例:
//
//	err := crawler.saveResult(vulnList, "output/vulns.json")
//	if err != nil {
//	    log.Fatal(err)
//	}
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

// saveVulnerabilityDetailResult 将漏洞详情保存到JSON文件中
// 这个方法会自动创建必要的目录，并将结果格式化为易读的JSON格式。
//
// 功能：
// 1. 自动创建目录
// 2. 格式化JSON（带缩进）
// 3. 设置适当的文件权限
//
// 参数:
//   - result: 要保存的漏洞详情对象
//   - outputPath: 输出文件路径
//
// 返回值:
//   - error: 保存过程中的错误，包括：
//   - 目录创建失败
//   - JSON序列化失败
//   - 文件写入失败
//
// 示例:
//
//	err := crawler.saveVulnerabilityDetailResult(vuln, "output/vuln_detail.json")
//	if err != nil {
//	    log.Fatal(err)
//	}
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

// saveCveDetailResult 将CVE详情保存到JSON文件中
// 这个方法会自动创建必要的目录，并将结果格式化为易读的JSON格式。
//
// 功能：
// 1. 自动创建目录
// 2. 格式化JSON（带缩进）
// 3. 设置适当的文件权限
//
// 参数:
//   - result: 要保存的CVE详情对象
//   - outputPath: 输出文件路径
//
// 返回值:
//   - error: 保存过程中的错误，包括：
//   - 目录创建失败
//   - JSON序列化失败
//   - 文件写入失败
//
// 示例:
//
//	err := crawler.saveCveDetailResult(cve, "output/cve_detail.json")
//	if err != nil {
//	    log.Fatal(err)
//	}
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

// saveAuthorResult 将作者信息保存到JSON文件中
// 这个方法会自动创建必要的目录，并将结果格式化为易读的JSON格式。
//
// 功能：
// 1. 自动创建目录
// 2. 格式化JSON（带缩进）
// 3. 设置适当的文件权限
//
// 参数:
//   - result: 要保存的作者信息对象
//   - outputPath: 输出文件路径
//
// 返回值:
//   - error: 保存过程中的错误，包括：
//   - 目录创建失败
//   - JSON序列化失败
//   - 文件写入失败
//
// 示例:
//
//	err := crawler.saveAuthorResult(author, "output/author_info.json")
//	if err != nil {
//	    log.Fatal(err)
//	}
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
