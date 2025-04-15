package crawler

import (
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/PuerkitoBio/goquery"

	"github.com/scagogogo/cxsecurity-crawler/pkg/model"
)

// ParseCveDetailPage 解析CVE详情页面
func (p *Parser) ParseCveDetailPage(htmlContent string) (*model.CveDetail, error) {
	doc, err := goquery.NewDocumentFromReader(strings.NewReader(htmlContent))
	if err != nil {
		return nil, err
	}

	cveDetail := &model.CveDetail{}

	// 提取CVE编号
	cveDetail.CveID = strings.TrimSpace(doc.Find("h1 strong").Text())

	// 提取发布日期和修改日期
	dateText := doc.Find("center").First().Text()
	publishedPattern := regexp.MustCompile(`Published:\s+(\d{4}-\d{2}-\d{2})`)
	modifiedPattern := regexp.MustCompile(`Modified:\s+(\d{4}-\d{2}-\d{2})`)

	if matches := publishedPattern.FindStringSubmatch(dateText); len(matches) >= 2 {
		if published, err := time.Parse("2006-01-02", matches[1]); err == nil {
			cveDetail.Published = published
		}
	}

	if matches := modifiedPattern.FindStringSubmatch(dateText); len(matches) >= 2 {
		if modified, err := time.Parse("2006-01-02", matches[1]); err == nil {
			cveDetail.Modified = modified
		}
	}

	// 提取漏洞描述
	cveDetail.Description = strings.TrimSpace(doc.Find("table tr td[bgcolor='#202020'] h6").First().Text())

	// 提取漏洞类型
	cveDetail.Type = strings.TrimSpace(doc.Find("a[href*='/cwe/'] h4").Text())

	// 提取CVSS评分
	cvssScores := make(map[string]float64)
	doc.Find("td[bgcolor] h6 span.label").Each(func(i int, s *goquery.Selection) {
		scoreText := strings.TrimSpace(s.Text())
		if matches := regexp.MustCompile(`([\d.]+)/10`).FindStringSubmatch(scoreText); len(matches) >= 2 {
			score, _ := strconv.ParseFloat(matches[1], 64)

			// 根据标签类和位置区分不同类型的评分
			class, _ := s.Attr("class")
			if strings.Contains(class, "label-warning") {
				parent := s.ParentsFiltered("td")
				bgcolor, _ := parent.Attr("bgcolor")
				if bgcolor == "#202020" {
					cvssScores["base"] = score
				} else if bgcolor == "#1B1B1B" {
					cvssScores["impact"] = score
				}
			} else if strings.Contains(class, "label-danger") {
				cvssScores["exploit"] = score
			}
		}
	})

	cveDetail.CvssBaseScore = cvssScores["base"]
	cveDetail.CvssImpactScore = cvssScores["impact"]
	cveDetail.CvssExploitScore = cvssScores["exploit"]

	// 提取漏洞属性
	// 直接查找表格中的具体文本内容
	tdPairs := [][2]string{
		{"Remote", "ExploitRange"},
		{"Medium", "AttackComplexity"},
		{"No required", "Authentication"},
		{"Partial", "ConfidentialityImpact"},
		{"Partial", "IntegrityImpact"},
		{"Partial", "AvailabilityImpact"},
	}

	for _, pair := range tdPairs {
		doc.Find("td[bgcolor] h6").Each(func(i int, s *goquery.Selection) {
			if strings.TrimSpace(s.Text()) == pair[0] {
				switch pair[1] {
				case "ExploitRange":
					cveDetail.ExploitRange = pair[0]
				case "AttackComplexity":
					cveDetail.AttackComplexity = pair[0]
				case "Authentication":
					cveDetail.Authentication = pair[0]
				case "ConfidentialityImpact":
					cveDetail.ConfidentialityImpact = pair[0]
				case "IntegrityImpact":
					cveDetail.IntegrityImpact = pair[0]
				case "AvailabilityImpact":
					cveDetail.AvailabilityImpact = pair[0]
				}
			}
		})
	}

	// 提取受影响的软件 - 通过找到特定的表格
	doc.Find("table").Each(func(i int, table *goquery.Selection) {
		caption := table.Find("thead tr th").Text()
		if strings.Contains(caption, "Affected software") {
			table.Find("tbody tr").Each(func(j int, tr *goquery.Selection) {
				td := tr.Find("td")

				links := td.Find("a")
				if links.Length() >= 2 {
					vendorA := links.First()
					productA := links.Last()

					vendorName := strings.TrimSpace(vendorA.Text())
					vendorURL, _ := vendorA.Attr("href")
					productName := strings.TrimSpace(productA.Text())
					productURL, _ := productA.Attr("href")

					if vendorName != "" && productName != "" {
						cveDetail.AffectedSoftware = append(cveDetail.AffectedSoftware, model.AffectedSoftware{
							VendorName:  vendorName,
							VendorURL:   vendorURL,
							ProductName: productName,
							ProductURL:  productURL,
						})
					}
				}
			})
		}
	})

	// 提取参考链接
	doc.Find("td[bgcolor='#202020'] div").Each(func(i int, s *goquery.Selection) {
		link := strings.TrimSpace(s.Text())
		if link != "" && strings.HasPrefix(link, "http") {
			cveDetail.References = append(cveDetail.References, link)
		}
	})

	// 提取相关漏洞 - 只处理第一个匹配的表格，避免重复
	var relatedVulnerabilities []model.Vulnerability
	var processed bool

	doc.Find("table").Each(func(i int, table *goquery.Selection) {
		if !processed && strings.Contains(table.Text(), "See advisories in our WLB2 database") {
			processed = true

			// 找到表格标题行的下一个tr
			advisoryRows := table.Find("tr")

			// 跳过标题行
			if advisoryRows.Length() > 1 {
				advisoryRows.Slice(1, advisoryRows.Length()).Each(func(j int, tr *goquery.Selection) {
					// 风险级别
					riskLevelCell := tr.Find("td[bgcolor='#1B1B1B'] h5 span.label").Text()
					if riskLevelCell == "" {
						return
					}
					riskLevel := strings.TrimSpace(riskLevelCell)

					// 标题和URL
					titleA := tr.Find("td[bgcolor='#1B1B1B'] h6 a")
					title := strings.TrimSpace(titleA.Text())
					url, _ := titleA.Attr("href")

					// 作者
					author := strings.TrimSpace(tr.Find("td[bgcolor='#1B1B1B']").Eq(2).Text())

					// 日期
					dateStr := strings.TrimSpace(tr.Find("td[bgcolor='#1B1B1B']").Eq(3).Text())
					var date time.Time

					// 尝试解析日期
					if parsedDate, err := time.Parse("02.01.2006", dateStr); err == nil {
						date = parsedDate
					} else if parsedDate, err := time.Parse("2.1.2006", dateStr); err == nil {
						date = parsedDate
					}

					// 创建漏洞对象
					if title != "" {
						vulnerability := model.Vulnerability{
							Date:      date,
							Title:     title,
							URL:       url,
							RiskLevel: riskLevel,
							Author:    author,
						}
						relatedVulnerabilities = append(relatedVulnerabilities, vulnerability)
					}
				})
			}
		}
	})

	cveDetail.RelatedVulnerabilities = relatedVulnerabilities

	return cveDetail, nil
}
