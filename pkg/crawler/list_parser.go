package crawler

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/PuerkitoBio/goquery"

	"github.com/scagogogo/cxsecurity-crawler/pkg/model"
)

// ParseListPage 解析漏洞列表页面
func (p *Parser) ParseListPage(htmlContent string) (*model.VulnerabilityList, error) {
	if strings.TrimSpace(htmlContent) == "" {
		return nil, fmt.Errorf("HTML content is empty")
	}

	doc, err := goquery.NewDocumentFromReader(strings.NewReader(htmlContent))
	if err != nil {
		return nil, fmt.Errorf("failed to parse HTML: %w", err)
	}

	result := &model.VulnerabilityList{
		Items: []model.Vulnerability{},
	}

	var currentDate time.Time // 用于存储最近解析到的日期

	// 编译正则表达式用于匹配CVE和CWE
	cvePattern := regexp.MustCompile(`CVE-\d{4}-\d+`)
	cwePattern := regexp.MustCompile(`CWE-\d+`)

	// 查找表格
	table := doc.Find("table.table-striped")

	// 遍历表格内的所有 thead 和 tbody > tr 元素
	table.Find("thead, tbody > tr").Each(func(i int, element *goquery.Selection) {

		// 检查当前元素是否是日期标题行 (thead)
		if element.Is("thead") {
			dateHeader := element.Find("tr > th font").Text()
			formats := []string{"2006-01-02", "02.01.2006", "Jan 2, 2006"} // 尝试的日期格式
			for _, format := range formats {
				if parsedDate, err := time.Parse(format, strings.TrimSpace(dateHeader)); err == nil {
					currentDate = parsedDate // 更新最近解析到的日期
					break
				}
			}
			return // 处理完 thead 后继续下一个元素
		}

		// 如果执行到这里，说明元素是 <tr> (因为选择器是 thead, tbody > tr)
		// 处理漏洞信息行 (tr)
		cells := element.Find("td")
		if cells.Length() < 2 {
			return
		}

		// 风险级别 (第一列)
		riskLevelCell := cells.Eq(0).Find("span.label")
		riskLevel := strings.TrimSpace(riskLevelCell.Text())

		// 标题和URL (第二列)
		titleCell := cells.Eq(1).Find("div.row div.col-md-7 a")
		title := strings.TrimSpace(titleCell.Text())
		url, _ := titleCell.Attr("href")
		// 修正URL，确保是完整的
		if url != "" && !strings.HasPrefix(url, "http") {
			if strings.HasPrefix(url, "/") {
				url = "https://cxsecurity.com" + url
			} else {
				url = "https://cxsecurity.com/" + url
			}
		}

		// 初始化漏洞对象，设置基本信息
		vulnerability := model.Vulnerability{
			Date:      currentDate,
			Title:     title,
			URL:       url,
			RiskLevel: riskLevel,
			Tags:      []string{}, // 用于保存其他标签
			Author:    "",         // 默认为空，后面会设置
			AuthorURL: "",         // 默认为空，后面会设置
		}

		// 标签 (第二列，右侧)
		cells.Eq(1).Find("div.row div.col-md-5 span.label").Each(func(j int, tagSelection *goquery.Selection) {
			// 跳过作者标签
			if tagSelection.Find("a[href*='/author/']").Length() == 0 {
				tag := strings.TrimSpace(tagSelection.Text())
				if tag == "" {
					return
				}

				// 检查是否是CVE编号
				if cveMatches := cvePattern.FindStringSubmatch(tag); len(cveMatches) > 0 {
					vulnerability.CVE = cveMatches[0]
					return
				}

				// 检查是否是CWE编号
				if cweMatches := cwePattern.FindStringSubmatch(tag); len(cweMatches) > 0 {
					vulnerability.CWE = cweMatches[0]
					return
				}

				// 检查是否是Remote/Local标记
				if tag == "Remote" {
					vulnerability.IsRemote = true
					return
				}
				if tag == "Local" {
					vulnerability.IsLocal = true
					return
				}

				// 添加到其他标签列表
				vulnerability.Tags = append(vulnerability.Tags, tag)
			}
		})

		// 作者信息 (第二列，右侧的作者链接)
		authorSelection := cells.Eq(1).Find("div.row div.col-md-5 a[href*='/author/']")
		vulnerability.Author = strings.TrimSpace(authorSelection.Text())
		vulnerability.AuthorURL, _ = authorSelection.Attr("href")
		// 修正作者URL
		if vulnerability.AuthorURL != "" && !strings.HasPrefix(vulnerability.AuthorURL, "http") {
			if strings.HasPrefix(vulnerability.AuthorURL, "/") {
				vulnerability.AuthorURL = "https://cxsecurity.com" + vulnerability.AuthorURL
			} else {
				vulnerability.AuthorURL = "https://cxsecurity.com/" + vulnerability.AuthorURL
			}
		}

		// 只有标题不为空才添加该漏洞
		if vulnerability.Title != "" {
			result.Items = append(result.Items, vulnerability)
		}
	})

	// 获取分页信息 - 静态解析困难
	pagiNation := doc.Find("pagination[ng-model='currentPage']")
	// 下面的变量尝试读取 Angular 控件属性，但通常只包含变量名，因此注释掉
	// currentPageStr, _ := pagiNation.Attr("ng-model")
	// totalItemsStr, _ := pagiNation.Attr("total-items")
	// maxSizeStr, _ := pagiNation.Attr("max-size")

	_ = pagiNation // 避免 'declared and not used'，尽管 pagiNation 本身可能没用

	// 从嵌入的JS或特定元素中提取可能的值（更复杂且脆弱）
	currentPage := 1
	totalPages := 1
	doc.Find("script").Each(func(i int, s *goquery.Selection) {
		scriptContent := s.Text()
		if strings.Contains(scriptContent, "$scope.currentPage") {
			reCurrent := regexp.MustCompile(`\$scope\.currentPage\s*=\s*(\d+)`)
			reTotal := regexp.MustCompile(`\$scope\.totalItems\s*=\s*(\d+)`)
			rePerPage := regexp.MustCompile(`\$scope\.perPage\s*=\s*(\d+)`)

			if matches := reCurrent.FindStringSubmatch(scriptContent); len(matches) > 1 {
				currentPage, _ = strconv.Atoi(matches[1])
			}
			if matches := reTotal.FindStringSubmatch(scriptContent); len(matches) > 1 {
				totalItems, _ := strconv.Atoi(matches[1])
				if matchesPerPage := rePerPage.FindStringSubmatch(scriptContent); len(matchesPerPage) > 1 {
					perPage, _ := strconv.Atoi(matchesPerPage[1])
					if perPage > 0 {
						totalPages = (totalItems + perPage - 1) / perPage
					}
				}
			}
		}
	})

	result.CurrentPage = currentPage
	result.TotalPages = totalPages

	return result, nil
}
