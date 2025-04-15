package crawler

import (
	"strings"
	"time"

	"github.com/PuerkitoBio/goquery"

	"github.com/scagogogo/cxsecurity-crawler/pkg/model"
)

// ParseVulnerabilityDetailPage 解析漏洞详情页面
func (p *Parser) ParseVulnerabilityDetailPage(htmlContent string) (*model.Vulnerability, error) {
	doc, err := goquery.NewDocumentFromReader(strings.NewReader(htmlContent))
	if err != nil {
		return nil, err
	}

	vulnerability := &model.Vulnerability{}

	// 提取标题
	vulnerability.Title = strings.TrimSpace(doc.Find("h1").Text())

	// 提取风险级别
	riskLevelText := doc.Find("h5 span.label").First().Text()
	vulnerability.RiskLevel = strings.TrimSpace(riskLevelText)

	// 提取标签
	doc.Find("h5 span.label").Each(func(i int, s *goquery.Selection) {
		tag := strings.TrimSpace(s.Text())
		// 排除风险级别标签，它通常是第一个标签且已单独提取
		if i > 0 && tag != "" {
			vulnerability.Tags = append(vulnerability.Tags, tag)
		}
	})

	// 提取日期
	dateText := doc.Find("small").Text()
	if dateText != "" {
		// 尝试不同的日期格式
		formats := []string{"2006-01-02", "02.01.2006", "2.1.2006", "January 2, 2006"}
		for _, format := range formats {
			if t, err := time.Parse(format, strings.TrimSpace(dateText)); err == nil {
				vulnerability.Date = t
				break
			}
		}
	}

	// 提取作者信息
	authorSelection := doc.Find("span.label-default a").First()
	if authorSelection.Length() > 0 {
		vulnerability.Author = strings.TrimSpace(authorSelection.Text())
		vulnerability.AuthorURL, _ = authorSelection.Attr("href")
	}

	// 提取URL（当前页面URL）
	// 注意：这部分可能需要从外部传入，因为HTML内容本身不包含当前URL

	return vulnerability, nil
}
