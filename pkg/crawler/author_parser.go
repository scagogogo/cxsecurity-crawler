package crawler

import (
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/PuerkitoBio/goquery"

	"github.com/scagogogo/cxsecurity-crawler/pkg/model"
)

// AuthorParser 是解析作者资料页面的解析器
type AuthorParser struct{}

// NewAuthorParser 创建一个新的作者解析器
func NewAuthorParser() *AuthorParser {
	return &AuthorParser{}
}

// Parse 实现Parser接口，解析作者资料页面HTML内容
func (p *AuthorParser) Parse(content string) (interface{}, error) {
	if content == "" {
		return nil, errors.New("内容为空，无法解析")
	}

	// 创建goquery文档
	doc, err := goquery.NewDocumentFromReader(strings.NewReader(content))
	if err != nil {
		return nil, err
	}

	// 初始化结果
	result := &model.AuthorProfile{
		Vulnerabilities: make([]model.Vulnerability, 0),
		CurrentPage:     1,
		TotalPages:      1,
	}

	// 提取作者名称
	authorNameText := doc.Find("h1:contains('Author:')").Text()
	if authorNameText != "" {
		authorName := strings.TrimSpace(strings.Replace(authorNameText, "Author:", "", 1))
		result.Name = authorName
		result.ID = authorName // 作者ID通常与名称相同
	}

	// 提取国家信息
	countryLink := doc.Find("a[href*='/best/']").First()
	if countryLink.Length() > 0 {
		href, exists := countryLink.Attr("href")
		if exists {
			// 从URL中提取国家代码
			re := regexp.MustCompile(`/best/([^/]+)/`)
			matches := re.FindStringSubmatch(href)
			if len(matches) > 1 {
				result.CountryCode = strings.ToUpper(matches[1])
				if result.CountryCode == "XX" {
					result.Country = "Unknown"
				} else {
					result.Country = result.CountryCode
				}
			}
		}
	}

	// 提取报告数量
	reportCountText := doc.Find("h4:contains('Reported research:')").Text()
	if reportCountText != "" {
		re := regexp.MustCompile(`Reported research:\s*<U>(\d+)</U>`)
		matches := re.FindStringSubmatch(reportCountText)
		if len(matches) > 1 {
			count, err := strconv.Atoi(matches[1])
			if err == nil {
				result.ReportedCount = count
			}
		} else {
			// 尝试另一种提取方式
			reportText := strings.TrimSpace(strings.Replace(reportCountText, "Reported research:", "", 1))
			reportText = strings.TrimSpace(strings.Replace(reportText, "U", "", -1))
			count, err := strconv.Atoi(reportText)
			if err == nil {
				result.ReportedCount = count
			}
		}
	}

	// 使用map去重，避免解析到重复的漏洞
	uniqueVulns := make(map[string]model.Vulnerability)

	// 解析漏洞列表
	doc.Find("tbody tr").Each(func(i int, s *goquery.Selection) {
		vuln := model.Vulnerability{}

		// 提取风险级别
		riskLabel := s.Find("span.label").First()
		if riskLabel.Length() > 0 {
			riskText := strings.TrimSpace(riskLabel.Text())
			vuln.RiskLevel = riskText
		}

		// 提取标题和URL
		titleLink := s.Find("a[href*='/issue/']").First()
		if titleLink.Length() > 0 {
			vuln.Title = strings.TrimSpace(titleLink.Text())
			if href, exists := titleLink.Attr("href"); exists {
				vuln.URL = href
				// 提取ID
				if strings.Contains(href, "WLB-") {
					idx := strings.Index(href, "WLB-")
					vuln.ID = href[idx:]
				}
			}
		}

		// 如果没有ID或标题，则跳过
		if vuln.ID == "" || vuln.Title == "" {
			return
		}

		// 检查是否有CVE标记
		cveText := s.Find("font[color='#FF8C00']").Text()
		if strings.Contains(cveText, "CVE assigned") {
			vuln.Tags = append(vuln.Tags, "CVE")
		}

		// 提取Remote/Local标记和日期
		detailsText := s.Find("div.col-md-3").Text()
		if strings.Contains(detailsText, "Remote") {
			vuln.IsRemote = true
			vuln.Tags = append(vuln.Tags, "Remote")
		}
		if strings.Contains(detailsText, "Local") {
			vuln.IsLocal = true
			vuln.Tags = append(vuln.Tags, "Local")
		}

		// 提取日期
		dateRegex := regexp.MustCompile(`(\d{4}-\d{2}-\d{2})`)
		dateMatches := dateRegex.FindStringSubmatch(detailsText)
		if len(dateMatches) > 1 {
			date, err := time.Parse("2006-01-02", dateMatches[1])
			if err == nil {
				vuln.Date = date
			}
		}

		// 设置作者信息
		vuln.Author = result.Name
		vuln.AuthorURL = fmt.Sprintf("https://cxsecurity.com/author/%s/1/", result.ID)

		// 使用ID作为Key去重
		uniqueVulns[vuln.ID] = vuln
	})

	// 将唯一漏洞转换为列表
	for _, vuln := range uniqueVulns {
		result.Vulnerabilities = append(result.Vulnerabilities, vuln)
	}

	return result, nil
}
