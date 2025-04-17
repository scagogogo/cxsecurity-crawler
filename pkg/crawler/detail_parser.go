package crawler

import (
	"fmt"
	"strings"
	"time"

	"github.com/PuerkitoBio/goquery"

	"github.com/scagogogo/cxsecurity-crawler/pkg/model"
)

// ParseVulnerabilityDetailPage 解析漏洞详情页面
func (p *Parser) ParseVulnerabilityDetailPage(htmlContent string) (*model.Vulnerability, error) {
	if strings.TrimSpace(htmlContent) == "" {
		return nil, fmt.Errorf("HTML content is empty")
	}

	doc, err := goquery.NewDocumentFromReader(strings.NewReader(htmlContent))
	if err != nil {
		return nil, fmt.Errorf("failed to parse HTML: %w", err)
	}

	vulnerability := &model.Vulnerability{}

	// 提取标题 - 更精确的选择器
	vulnerability.Title = strings.TrimSpace(doc.Find("h4 > B").First().Text())
	if vulnerability.Title == "" {
		// 增加更多备选方案或日志记录
		// log.Println("Could not find title with primary selector, trying alternatives...")
		vulnerability.Title = strings.TrimSpace(doc.Find(".panel-body h4 b").First().Text()) // 尝试另一个常见的结构
	}

	// 提取风险级别 - 定位包含 "Risk:" 的 well 内部的 label
	riskLevelLabel := doc.Find(".well-sm:contains('Risk:')").Find("span.label")
	vulnerability.RiskLevel = strings.TrimSpace(riskLevelLabel.Text())

	// 提取标签 - 逐个精确查找
	vulnerability.Tags = []string{} // 初始化为空切片

	// CVE
	cveLink := doc.Find(".well-sm:contains('CVE:')").Find("a[href*='cveshow']")
	cveText := strings.TrimSpace(cveLink.Text())
	if cveText != "" {
		vulnerability.Tags = append(vulnerability.Tags, cveText)
	}

	// CWE
	cweLink := doc.Find(".well-sm:contains('CWE:')").Find("a[href*='cwe']")
	cweText := strings.TrimSpace(cweLink.Text())
	if cweText != "" {
		vulnerability.Tags = append(vulnerability.Tags, cweText)
	}

	// Local - HTML: <U>Local:</U> <b><B>Yes</B></span></b> or similar
	doc.Find(".well-sm:contains('Local:')").Each(func(_ int, s *goquery.Selection) {
		// 查找此 well 内部的 <b> 或 <B> 标签，并检查文本
		s.Find("b, B").Each(func(_ int, b *goquery.Selection) {
			if strings.TrimSpace(b.Text()) == "Yes" {
				// 只有当找到文本为 Yes 的 b 标签时才添加
				vulnerability.Tags = append(vulnerability.Tags, "Local")
				return // 假设每个 well 最多一个 Yes
			}
		})
	})

	// Remote - HTML: <U>Remote:</U> <b>No</b> or similar
	doc.Find(".well-sm:contains('Remote:')").Each(func(_ int, s *goquery.Selection) {
		// 查找此 well 内部的 <b> 或 <B> 标签，并检查文本
		s.Find("b, B").Each(func(_ int, b *goquery.Selection) {
			if strings.TrimSpace(b.Text()) == "Yes" {
				vulnerability.Tags = append(vulnerability.Tags, "Remote")
				return
			}
		})
	})

	// 提取日期 - 定位包含日期的 well (通常是第一个)
	dateText := ""
	doc.Find(".panel-body .row .col-xs-12.col-md-3 .well-sm b").Each(func(i int, s *goquery.Selection) {
		// 假设日期格式总是 YYYY.MM.DD
		potentialDate := strings.TrimSpace(s.Text())
		_, err := time.Parse("2006.01.02", potentialDate)
		if err == nil {
			dateText = potentialDate
			return // 找到即停止
		}
	})

	if dateText != "" {
		// 优先使用最可能的格式
		formats := []string{"2006.01.02", "2006-01-02", "02.01.2006", "Jan 2, 2006", "January 2, 2006"}
		for _, format := range formats {
			if t, err := time.Parse(format, dateText); err == nil {
				vulnerability.Date = t
				break
			}
		}
	}

	// 提取作者信息 - 定位包含 "Credit:" 的 well 内部的链接
	authorSelection := doc.Find(".well-sm:contains('Credit:')").Find("a[href*='author']")
	if authorSelection.Length() > 0 {
		vulnerability.Author = strings.TrimSpace(authorSelection.Text())
		vulnerability.AuthorURL, _ = authorSelection.Attr("href")
		// 确保 AuthorURL 是相对路径或绝对路径
		if vulnerability.AuthorURL != "" && !strings.HasPrefix(vulnerability.AuthorURL, "/") && !strings.HasPrefix(vulnerability.AuthorURL, "http") {
			// 如果需要，添加基础 URL 或 "/"
			// vulnerability.AuthorURL = "/" + vulnerability.AuthorURL // 示例
		}
	}

	// --- 去重 Tags ---
	if len(vulnerability.Tags) > 0 {
		uniqueTags := make(map[string]struct{})
		var result []string
		for _, tag := range vulnerability.Tags {
			if _, exists := uniqueTags[tag]; !exists {
				uniqueTags[tag] = struct{}{}
				result = append(result, tag)
			}
		}
		vulnerability.Tags = result
	}
	// --- End 去重 Tags ---

	return vulnerability, nil
}
