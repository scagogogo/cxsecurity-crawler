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

// ParseListPage 解析漏洞列表页面和搜索结果页面
// 支持两种页面格式：
// 1. 标准漏洞列表页面（按日期分组的漏洞列表）
// 2. 搜索结果页面（带分页的漏洞列表）
//
// 解析内容包括：
// - 漏洞标题和URL
// - 发布日期
// - 风险等级
// - 作者信息
// - CVE/CWE编号（如果存在）
// - 标签信息
//
// 参数:
//   - htmlContent: 页面的HTML内容
//
// 返回值:
//   - *model.VulnerabilityList: 解析出的漏洞列表，包含漏洞条目和分页信息
//   - error: 解析过程中的错误
//
// 示例HTML结构（标准列表页）:
//
//	<table class="table-striped">
//	  <thead>
//	    <tr><th><font>2024-04-15</font></th></tr>
//	  </thead>
//	  <tbody>
//	    <tr>
//	      <td><span class="label">High</span></td>
//	      <td>
//	        <div class="row">
//	          <div class="col-md-7">
//	            <a href="/issue/WLB-2024040015">漏洞标题</a>
//	          </div>
//	        </div>
//	      </td>
//	    </tr>
//	  </tbody>
//	</table>
//
// 示例HTML结构（搜索结果页）:
//
//	<table width="100%" border="0" cellpadding="0" cellspacing="0">
//	  <tr>
//	    <td><span class="label">High</span></td>
//	    <td><h6><a href="/issue/WLB-2024040015">漏洞标题</a></h6></td>
//	    <td><span class="label">24.03.2024</span></td>
//	    <td><a href="/author/researcher">作者</a></td>
//	  </tr>
//	</table>
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

	// 尝试找标准的漏洞列表表格
	table := doc.Find("table.table-striped")

	// 如果没有找到标准表格，尝试查找搜索结果页面的表格
	if table.Length() == 0 {
		table = doc.Find("table[width='100%'][border='0'][cellpadding='0'][cellspacing='0']")
	}

	// 确保找到了表格
	if table.Length() == 0 {
		// 返回空结果而不是错误，因为可能是合法的空结果页
		return result, nil
	}

	// 检查是否是搜索结果页面
	isSearchPage := doc.Find("div[ng-controller='PagIt']").Length() > 0

	// 根据页面类型决定如何解析
	if isSearchPage {
		// 解析搜索结果页面
		rows := table.Find("tr")
		var headerRow bool = true

		rows.Each(func(i int, row *goquery.Selection) {
			// 跳过表头行
			if headerRow {
				headerRow = false
				return
			}

			cells := row.Find("td")
			if cells.Length() < 3 {
				return
			}

			// 风险级别 (第一列)
			riskLevelCell := cells.Eq(0).Find("span.label")
			riskLevel := strings.TrimSpace(riskLevelCell.Text())

			// 标题和URL (第二列)
			titleCell := cells.Eq(1).Find("h6 a")
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

			// 日期 (第三列)
			dateCell := cells.Eq(2).Find("span.label")
			dateStr := strings.TrimSpace(dateCell.Text())

			// 尝试解析日期
			var date time.Time
			formats := []string{
				"02.01.2006", // 例如: 24.03.2024
				"2006-01-02", // 例如: 2024-03-24
				"01/02/2006", // 例如: 03/24/2024
			}

			for _, format := range formats {
				if parsedDate, err := time.Parse(format, dateStr); err == nil {
					date = parsedDate
					break
				}
			}

			// 作者 (第四列)
			authorCell := cells.Eq(3).Find("a")
			author := strings.TrimSpace(authorCell.Text())
			authorURL, _ := authorCell.Attr("href")

			// 修正作者URL
			if authorURL != "" && !strings.HasPrefix(authorURL, "http") {
				if strings.HasPrefix(authorURL, "/") {
					authorURL = "https://cxsecurity.com" + authorURL
				} else {
					authorURL = "https://cxsecurity.com/" + authorURL
				}
			}

			// 提取CVE和CWE编号（如果存在于标题中）
			var cve, cwe string
			if cveMatches := cvePattern.FindStringSubmatch(title); len(cveMatches) > 0 {
				cve = cveMatches[0]
			}
			if cweMatches := cwePattern.FindStringSubmatch(title); len(cweMatches) > 0 {
				cwe = cweMatches[0]
			}

			// 初始化漏洞对象
			vulnerability := model.Vulnerability{
				Date:      date,
				Title:     title,
				URL:       url,
				RiskLevel: riskLevel,
				CVE:       cve,
				CWE:       cwe,
				Author:    author,
				AuthorURL: authorURL,
				Tags:      []string{}, // 搜索页面中可能没有标签
			}

			// 只有标题不为空才添加该漏洞
			if vulnerability.Title != "" {
				result.Items = append(result.Items, vulnerability)
			}
		})
	} else {
		// 这是原来的漏洞列表解析逻辑
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
	}

	// 获取分页信息
	// 尝试从Angular控制器中提取
	var totalItems, currentPage, perPage int = 0, 1, 10

	// 查找Angular分页控制器脚本
	doc.Find("script").Each(func(i int, s *goquery.Selection) {
		scriptContent := s.Text()

		// 尝试从Angular控制器中提取分页信息
		if strings.Contains(scriptContent, "$scope.totalItems") {
			reTotalItems := regexp.MustCompile(`\$scope\.totalItems\s*=\s*(\d+)`)
			reCurrentPage := regexp.MustCompile(`\$scope\.currentPage\s*=\s*(\d+)`)
			rePerPage := regexp.MustCompile(`\$scope\.perPage\s*=\s*(\d+)`)

			if matches := reTotalItems.FindStringSubmatch(scriptContent); len(matches) > 1 {
				totalItems, _ = strconv.Atoi(matches[1])
			}

			if matches := reCurrentPage.FindStringSubmatch(scriptContent); len(matches) > 1 {
				currentPage, _ = strconv.Atoi(matches[1])
			}

			if matches := rePerPage.FindStringSubmatch(scriptContent); len(matches) > 1 {
				perPage, _ = strconv.Atoi(matches[1])
			}
		}
	})

	// 计算总页数
	totalPages := 1
	if perPage > 0 && totalItems > 0 {
		totalPages = (totalItems + perPage - 1) / perPage
	}

	// 确保当前页码至少为1
	if currentPage < 1 {
		currentPage = 1
	}

	result.CurrentPage = currentPage
	result.TotalPages = totalPages

	return result, nil
}
