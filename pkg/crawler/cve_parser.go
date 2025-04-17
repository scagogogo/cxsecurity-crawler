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

// ParseCveDetailPage 解析CVE详情页面
func (p *Parser) ParseCveDetailPage(htmlContent string) (*model.CveDetail, error) {
	if strings.TrimSpace(htmlContent) == "" {
		return nil, fmt.Errorf("HTML content is empty")
	}

	doc, err := goquery.NewDocumentFromReader(strings.NewReader(htmlContent))
	if err != nil {
		return nil, fmt.Errorf("failed to parse HTML: %w", err)
	}

	cveDetail := &model.CveDetail{}

	// 提取CVE编号
	cveDetail.CveID = strings.TrimSpace(doc.Find("h1 strong").First().Text())

	// 提取发布日期和修改日期
	doc.Find("center > b").Each(func(i int, s *goquery.Selection) {
		text := s.Text()
		parentText := s.Parent().Text()
		if strings.Contains(text, "Published:") {
			re := regexp.MustCompile(`Published:\s*(\d{4}-\d{2}-\d{2})`)
			matches := re.FindStringSubmatch(parentText)
			if len(matches) > 1 {
				if published, err := time.Parse("2006-01-02", matches[1]); err == nil {
					cveDetail.Published = published
				}
			}
		} else if strings.Contains(text, "Modified:") {
			re := regexp.MustCompile(`Modified:\s*(\d{4}-\d{2}-\d{2})`)
			matches := re.FindStringSubmatch(parentText)
			if len(matches) > 1 {
				if modified, err := time.Parse("2006-01-02", matches[1]); err == nil {
					cveDetail.Modified = modified
				}
			}
		}
	})

	// 提取漏洞描述
	descriptionCell := doc.Find("td:contains('Description:')").Closest("tr").Next().Find("td h6")
	cveDetail.Description = strings.TrimSpace(descriptionCell.Text())

	// 提取漏洞类型 (CWE)
	typeLink := doc.Find("b:contains('Type:')").Parent().Find("a[href*='/cwe/']")
	cveDetail.Type = strings.TrimSpace(typeLink.Text())

	// --- 提取CVSS评分 ---
	cvssTable := doc.Find("b:contains('CVSS Base Score')").Closest("table")
	cvssDataRow := cvssTable.Find("tr").Eq(1) // 数据在第二行 (索引1)
	if cvssDataRow.Length() > 0 {
		cells := cvssDataRow.Find("td")
		if cells.Length() >= 3 {
			scoreText1 := cells.Eq(0).Find("span.label").Text()
			scoreText2 := cells.Eq(1).Find("span.label").Text()
			scoreText3 := cells.Eq(2).Find("span.label").Text()

			if matches := regexp.MustCompile(`([\d.]+)/10`).FindStringSubmatch(scoreText1); len(matches) >= 2 {
				cveDetail.CvssBaseScore, _ = strconv.ParseFloat(matches[1], 64)
			}
			if matches := regexp.MustCompile(`([\d.]+)/10`).FindStringSubmatch(scoreText2); len(matches) >= 2 {
				cveDetail.CvssImpactScore, _ = strconv.ParseFloat(matches[1], 64)
			}
			if matches := regexp.MustCompile(`([\d.]+)/10`).FindStringSubmatch(scoreText3); len(matches) >= 2 {
				cveDetail.CvssExploitScore, _ = strconv.ParseFloat(matches[1], 64)
			}
		}
	}

	// --- 提取漏洞属性 ---
	attrTable := doc.Find("b:contains('Exploit range')").Closest("table")
	attrValues := make(map[string]string)
	var headers1, headers2 []string

	// 获取第一行标题
	attrTable.Find("tr").Eq(0).Find("td b").Each(func(i int, headerCell *goquery.Selection) {
		headers1 = append(headers1, strings.TrimSpace(headerCell.Text()))
	})
	// 获取第一行数据
	attrTable.Find("tr").Eq(1).Find("td h6").Each(func(j int, valueCell *goquery.Selection) {
		if j < len(headers1) {
			attrValues[headers1[j]] = strings.TrimSpace(valueCell.Text())
		}
	})

	// 获取第三行标题 (如果存在)
	if attrTable.Find("tr").Length() >= 3 {
		attrTable.Find("tr").Eq(2).Find("td b").Each(func(i int, headerCell *goquery.Selection) {
			headers2 = append(headers2, strings.TrimSpace(headerCell.Text()))
		})
		// 获取第四行数据 (如果存在)
		if attrTable.Find("tr").Length() >= 4 {
			attrTable.Find("tr").Eq(3).Find("td h6").Each(func(j int, valueCell *goquery.Selection) {
				if j < len(headers2) {
					attrValues[headers2[j]] = strings.TrimSpace(valueCell.Text())
				}
			})
		}
	}

	cveDetail.ExploitRange = attrValues["Exploit range"]
	cveDetail.AttackComplexity = attrValues["Attack complexity"]
	cveDetail.Authentication = attrValues["Authentication"]
	cveDetail.ConfidentialityImpact = attrValues["Confidentiality impact"]
	cveDetail.IntegrityImpact = attrValues["Integrity impact"]
	cveDetail.AvailabilityImpact = attrValues["Availability impact"]

	// 提取受影响的软件
	affectedTable := doc.Find("table.table-striped:has(th:contains('Affected software'))")
	affectedTable.Find("tbody tr").Each(func(j int, tr *goquery.Selection) {
		links := tr.Find("td a")
		if links.Length() >= 2 {
			vendorA := links.Eq(0)
			productA := links.Eq(1)
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

	// 提取参考链接
	referencesCell := doc.Find("td:contains('References:')").Closest("tr").Next().Find("td div[onclick]")
	referencesCell.Each(func(i int, s *goquery.Selection) {
		onclickAttr, exists := s.Attr("onclick")
		if exists {
			matches := regexp.MustCompile(`window\.open\('([^']*)'`).FindStringSubmatch(onclickAttr)
			if len(matches) > 1 {
				link := strings.TrimSpace(matches[1])
				if link != "" && strings.HasPrefix(link, "http") {
					cveDetail.References = append(cveDetail.References, link)
				}
			}
		}
	})

	// 提取相关漏洞
	relatedVulnTable := doc.Find("td > center:contains('See advisories in our WLB2 database')").Closest("td").Find("table")
	relatedRows := relatedVulnTable.Find("tr")
	if relatedRows.Length() > 1 {
		relatedRows.Slice(1, goquery.ToEnd).Each(func(j int, tr *goquery.Selection) {
			cells := tr.Find("td")
			if cells.Length() >= 4 {
				riskLevel := strings.TrimSpace(cells.Eq(0).Find("span.label").Text())
				titleA := cells.Eq(1).Find("a")
				title := strings.TrimSpace(titleA.Text())
				url, _ := titleA.Attr("href")
				author := strings.TrimSpace(cells.Eq(2).Text())
				dateStr := strings.TrimSpace(cells.Eq(3).Text())
				var date time.Time
				formats := []string{"02.01.2006", "2.1.2006", "2006-01-02"}
				for _, format := range formats {
					if parsedDate, err := time.Parse(format, dateStr); err == nil {
						date = parsedDate
						break
					}
				}
				if title != "" {
					cveDetail.RelatedVulnerabilities = append(cveDetail.RelatedVulnerabilities, model.Vulnerability{
						Date:      date,
						Title:     title,
						URL:       url,
						RiskLevel: riskLevel,
						Author:    author,
					})
				}
			}
		})
	}

	return cveDetail, nil
}
