package crawler

import (
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/PuerkitoBio/goquery"

	"github.com/scagogogo/cxsecurity-crawler/pkg/model"
)

// 国家代码映射
var countryCodeMap = map[string]string{
	"XX": "未知",
	"US": "美国",
	"CN": "中国",
	"UK": "英国",
	"RU": "俄罗斯",
	"FR": "法国",
	"DE": "德国",
	"JP": "日本",
	"CA": "加拿大",
	"AU": "澳大利亚",
	"BR": "巴西",
	"IN": "印度",
	"IT": "意大利",
	"ES": "西班牙",
	"NL": "荷兰",
	"SE": "瑞典",
	"KR": "韩国",
	"CH": "瑞士",
}

// AuthorParser 用于解析作者信息页面的专用解析器
// 负责从HTML页面中提取作者的详细信息和发布的漏洞列表
//
// 主要功能：
// 1. 解析作者基本信息（姓名、国家、简介等）
// 2. 提取社交媒体链接（Twitter、个人网站等）
// 3. 解析作者发布的漏洞列表
// 4. 处理分页信息
//
// 使用示例：
//
//	parser := NewAuthorParser()
//	profile, err := parser.Parse(doc)
//	if err != nil {
//	    log.Fatal(err)
//	}
//	fmt.Printf("Author: %s\n", profile.Name)
//
// 注意事项：
// 1. 解析器会自动处理不同的页面布局
// 2. 支持多种日期格式
// 3. 自动补全URL（如作者头像、漏洞链接等）
type AuthorParser struct {
}

// NewAuthorParser 创建一个新的作者页面解析器
func NewAuthorParser() *AuthorParser {
	return &AuthorParser{}
}

// Parse 解析作者信息页面，提取作者详细信息和漏洞列表
//
// 解析内容包括：
// - 基本信息：
//   - 作者ID和姓名
//   - 国家和地区
//   - 个人简介
//   - 头像URL
//
// - 社交媒体：
//   - Twitter账号
//   - 个人网站
//   - Zone-H档案
//
// - 漏洞统计：
//   - 已发布的漏洞数量
//   - 漏洞类型分布
//
// - 漏洞列表：
//   - 标题和链接
//   - 发布日期
//   - 风险等级
//   - 漏洞类型标签
//
// 参数:
//   - doc: goquery.Document对象，包含作者页面的HTML内容
//
// 返回值:
//   - *model.AuthorProfile: 解析后的作者信息对象
//   - error: 解析过程中的错误
//
// 示例HTML结构:
//
//	<div class="author-info">
//	  <h2>作者名称</h2>
//	  <img src="/avatar.jpg" alt="头像">
//	  <div class="country">
//	    <img src="/flags/us.png"> United States
//	  </div>
//	  <div class="social">
//	    <a href="https://twitter.com/researcher">Twitter</a>
//	    <a href="https://example.com">Website</a>
//	  </div>
//	</div>
//	<table class="table-striped">
//	  <tr>
//	    <td><span class="label">High</span></td>
//	    <td><h6><a href="/vuln/123">漏洞标题</a></h6></td>
//	    <td><h6>2024-03-24</h6></td>
//	  </tr>
//	</table>
//
// 注意事项：
// 1. 所有URL都会被处理为完整的绝对路径
// 2. 日期解析支持多种格式
// 3. 漏洞列表会自动去重
func (p *AuthorParser) Parse(doc *goquery.Document) (*model.AuthorProfile, error) {
	profile := &model.AuthorProfile{}

	// 解析作者名称
	profile.Name = strings.TrimSpace(doc.Find("h1").First().Text())

	// 解析作者国家
	countryImg := doc.Find("img[src*='flags/']").First()
	countryCode := ""
	if src, exists := countryImg.Attr("src"); exists {
		// 从图片URL中提取国家代码
		re := regexp.MustCompile(`flags/(\w+)\.png`)
		if matches := re.FindStringSubmatch(src); len(matches) > 1 {
			countryCode = strings.ToUpper(matches[1])
		}
	}
	profile.CountryCode = countryCode
	if countryName, exists := countryCodeMap[countryCode]; exists {
		profile.Country = countryName
	} else {
		profile.Country = "未知"
	}

	// 解析研究报告数量
	researchCountText := doc.Find("h4:contains('Reported research:')").Text()
	re := regexp.MustCompile(`\d+`)
	if matches := re.FindString(researchCountText); matches != "" {
		if count, err := strconv.Atoi(matches); err == nil {
			profile.ReportedCount = count
		}
	}

	// 解析联系信息
	doc.Find(".jumbotron h4 small.text-muted").Each(func(i int, s *goquery.Selection) {
		text := s.Text()
		switch {
		case strings.Contains(text, "Twitter"):
			profile.Twitter = strings.TrimSpace(strings.TrimPrefix(text, "- Twitter Link"))
		case strings.Contains(text, "Website"):
			profile.Website = strings.TrimSpace(strings.TrimPrefix(text, "- Website Link"))
		case strings.Contains(text, "Zone-H"):
			profile.ZoneH = strings.TrimSpace(strings.TrimPrefix(text, "- Zone-H Link"))
		case strings.Contains(text, "Description"):
			profile.Description = strings.TrimSpace(strings.TrimPrefix(text, "- Description of profile"))
		}
	})

	// 解析漏洞列表
	vulnerabilities := make([]model.Vulnerability, 0)
	doc.Find("table.table-striped tr").Each(func(i int, s *goquery.Selection) {
		// 跳过表头
		if i == 0 {
			return
		}

		cells := s.Find("td")
		if cells.Length() < 3 {
			return
		}

		vuln := model.Vulnerability{}

		// 解析日期
		dateStr := strings.TrimSpace(cells.Eq(2).Find("h6").Text())
		if dateStr != "" {
			formats := []string{"2006-01-02", "02.01.2006", "2006.01.02"}
			for _, format := range formats {
				if t, err := time.Parse(format, dateStr); err == nil {
					vuln.Date = t
					break
				}
			}
		}

		// 解析标题和URL
		titleLink := cells.Eq(1).Find("h6 a")
		vuln.Title = strings.TrimSpace(titleLink.Text())
		vuln.URL, _ = titleLink.Attr("href")
		if vuln.URL != "" && !strings.HasPrefix(vuln.URL, "http") {
			vuln.URL = "https://cxsecurity.com" + vuln.URL
		}

		// 从URL中提取漏洞ID
		if vuln.URL != "" {
			if idx := strings.Index(vuln.URL, "WLB-"); idx != -1 {
				urlPart := vuln.URL[idx:]
				endIdx := len(urlPart)
				if slashIdx := strings.IndexByte(urlPart, '/'); slashIdx != -1 {
					endIdx = slashIdx
				}
				vuln.ID = urlPart[:endIdx]
			}
		}

		// 解析风险等级
		riskLevelSpan := cells.Eq(0).Find("span.label")
		vuln.RiskLevel = strings.TrimSpace(riskLevelSpan.Text())

		// 解析漏洞类型标签
		cells.Eq(1).Find("font[color='#FF8C00']").Each(func(j int, tag *goquery.Selection) {
			tagText := strings.TrimSpace(tag.Text())
			if tagText != "" {
				vuln.Tags = append(vuln.Tags, strings.Trim(tagText, "()"))
			}
		})

		// 检查Remote/Local标记
		if remoteText := cells.Eq(1).Find("div.col-md-3 h6 u").Text(); remoteText != "" {
			if remoteText == "Remote" {
				vuln.IsRemote = true
			} else if remoteText == "Local" {
				vuln.IsLocal = true
			}
		}

		// 只有标题不为空才添加该漏洞
		if vuln.Title != "" {
			vulnerabilities = append(vulnerabilities, vuln)
		}
	})

	// 设置漏洞列表
	profile.Vulnerabilities = vulnerabilities

	// 解析分页信息
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

	profile.CurrentPage = currentPage
	profile.TotalPages = totalPages

	return profile, nil
}
