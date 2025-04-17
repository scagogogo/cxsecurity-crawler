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

// ParseCveDetailPage 解析CVE详情页面的HTML内容，提取CVE漏洞的详细信息。
//
// 参数:
//   - htmlContent: CVE详情页面的HTML内容字符串
//
// 返回值:
//   - *model.CveDetail: 解析后的CVE详情对象，包含以下信息：
//   - CVE编号 (如 CVE-2024-21413)
//   - 发布日期和修改日期
//   - 漏洞描述
//   - 漏洞类型 (CWE)
//   - CVSS评分 (基础分、影响分、利用分)
//   - 漏洞属性 (攻击范围、复杂度、认证要求等)
//   - 受影响的软件列表
//   - 参考链接
//   - 相关漏洞
//   - error: 解析过程中遇到的错误
//
// HTML结构示例:
// <html>
//
//	<h1><strong>CVE-2024-21413</strong></h1>
//	<center>
//	  <b>Published:</b> 2024-03-24
//	  <b>Modified:</b> 2024-03-25
//	</center>
//	<tr>
//	  <td>Description:</td>
//	  <td><h6>漏洞描述内容...</h6></td>
//	</tr>
//	<table>
//	  <!-- CVSS评分表格 -->
//	  <tr>
//	    <td><span class="label">7.5/10</span></td>
//	    <td><span class="label">6.4/10</span></td>
//	    <td><span class="label">8.6/10</span></td>
//	  </tr>
//	</table>
//	<table>
//	  <!-- 漏洞属性表格 -->
//	  <tr>
//	    <td><b>Exploit range</b></td>
//	    <td><b>Attack complexity</b></td>
//	    <!-- ... -->
//	  </tr>
//	</table>
//	<table class="table-striped">
//	  <!-- 受影响软件表格 -->
//	  <tr>
//	    <td><a href="/vendor/microsoft">Microsoft</a></td>
//	    <td><a href="/product/outlook">Outlook</a></td>
//	  </tr>
//	</table>
//
// </html>
//
// 注意事项:
//  1. 日期解析支持多种格式: "2006-01-02", "02.01.2006", "2.1.2006"
//  2. CVSS评分从标签文本中提取数值，格式为 "X.Y/10"
//  3. 相关漏洞的风险等级会被转换为标准格式 (High/Medium/Low)
//  4. 参考链接从onclick属性中提取，确保是有效的HTTP(S)链接
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
	// 从页面的h1标签中提取CVE编号，格式如 "CVE-2024-21413"
	cveDetail.CveID = strings.TrimSpace(doc.Find("h1 strong").First().Text())

	// 提取发布日期和修改日期
	// 在center标签中查找Published和Modified日期
	// 使用正则表达式匹配日期格式 "YYYY-MM-DD"
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
	// 在Description标签后的h6标签中提取完整的漏洞描述文本
	descriptionCell := doc.Find("td:contains('Description:')").Closest("tr").Next().Find("td h6")
	cveDetail.Description = strings.TrimSpace(descriptionCell.Text())

	// 提取漏洞类型 (CWE)
	// 在Type字段后查找指向CWE的链接，提取CWE类型名称
	typeLink := doc.Find("b:contains('Type:')").Parent().Find("a[href*='/cwe/']")
	cveDetail.Type = strings.TrimSpace(typeLink.Text())

	// --- 提取CVSS评分 ---
	// 从CVSS评分表格中提取三个评分：
	// 1. 基础评分 (Base Score)
	// 2. 影响评分 (Impact Score)
	// 3. 利用评分 (Exploit Score)
	// 评分格式为 "X.Y/10"，使用正则表达式提取数值部分
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
	// 从属性表格中提取多个安全相关属性：
	// - 攻击范围 (Exploit range)
	// - 攻击复杂度 (Attack complexity)
	// - 认证要求 (Authentication)
	// - 机密性影响 (Confidentiality impact)
	// - 完整性影响 (Integrity impact)
	// - 可用性影响 (Availability impact)
	// 表格包含两行标题和两行数据，需要分别处理
	attrTable := doc.Find("b:contains('Exploit range')").Closest("table")
	attrValues := make(map[string]string)
	var headers1, headers2 []string

	// 获取第一行标题和对应的数据
	attrTable.Find("tr").Eq(0).Find("td b").Each(func(i int, headerCell *goquery.Selection) {
		headers1 = append(headers1, strings.TrimSpace(headerCell.Text()))
	})
	attrTable.Find("tr").Eq(1).Find("td h6").Each(func(j int, valueCell *goquery.Selection) {
		if j < len(headers1) {
			attrValues[headers1[j]] = strings.TrimSpace(valueCell.Text())
		}
	})

	// 获取第三行标题和第四行数据（如果存在）
	if attrTable.Find("tr").Length() >= 3 {
		attrTable.Find("tr").Eq(2).Find("td b").Each(func(i int, headerCell *goquery.Selection) {
			headers2 = append(headers2, strings.TrimSpace(headerCell.Text()))
		})
		if attrTable.Find("tr").Length() >= 4 {
			attrTable.Find("tr").Eq(3).Find("td h6").Each(func(j int, valueCell *goquery.Selection) {
				if j < len(headers2) {
					attrValues[headers2[j]] = strings.TrimSpace(valueCell.Text())
				}
			})
		}
	}

	// 将提取的属性值赋给结构体字段
	cveDetail.ExploitRange = attrValues["Exploit range"]
	cveDetail.AttackComplexity = attrValues["Attack complexity"]
	cveDetail.Authentication = attrValues["Authentication"]
	cveDetail.ConfidentialityImpact = attrValues["Confidentiality impact"]
	cveDetail.IntegrityImpact = attrValues["Integrity impact"]
	cveDetail.AvailabilityImpact = attrValues["Availability impact"]

	// 提取受影响的软件
	// 从表格中提取每个受影响的软件条目：
	// - 厂商名称和链接
	// - 产品名称和链接
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
	// 从onclick属性中提取参考链接URL
	// 只保留以http开头的有效链接
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
	// 从WLB2数据库表格中提取相关漏洞信息：
	// - 风险等级
	// - 标题和链接
	// - 作者
	// - 日期（支持多种格式）
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
				// 尝试多种日期格式解析
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
