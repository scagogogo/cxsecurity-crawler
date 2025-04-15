package crawler

import (
	"strings"
	"time"

	"github.com/PuerkitoBio/goquery"

	"github.com/scagogogo/cxsecurity-crawler/pkg/model"
)

// ParseListPage 解析漏洞列表页面
func (p *Parser) ParseListPage(htmlContent string) (*model.VulnerabilityList, error) {
	doc, err := goquery.NewDocumentFromReader(strings.NewReader(htmlContent))
	if err != nil {
		return nil, err
	}

	result := &model.VulnerabilityList{
		Items: []model.Vulnerability{},
	}

	// 查找表格行
	var currentDate time.Time

	// 遍历表格行
	doc.Find("table tr").Each(func(i int, rowSelection *goquery.Selection) {
		// 检查是否是日期行
		dateHeader := rowSelection.Find("th u h6 b font").Text()
		if dateHeader != "" {
			// 解析日期
			parsedDate, err := time.Parse("2006-01-02", dateHeader)
			if err == nil {
				currentDate = parsedDate
			}
			return
		}

		// 提取漏洞信息行
		riskLevelCell := rowSelection.Find("td:first-child h6 span.label").Text()
		if riskLevelCell == "" {
			return
		}

		// 风险级别
		riskLevel := strings.TrimSpace(riskLevelCell)

		// 标题和URL
		titleCell := rowSelection.Find("td:nth-child(2) div.row div.col-md-7 h6 a")
		title := strings.TrimSpace(titleCell.Text())
		url, _ := titleCell.Attr("href")

		// 标签
		var tags []string
		rowSelection.Find("td:nth-child(2) div.row div.col-md-5 h6 span.label").Each(func(j int, tagSelection *goquery.Selection) {
			tag := strings.TrimSpace(tagSelection.Text())
			// 过滤掉作者标签
			if tag != "" && !strings.Contains(tagSelection.AttrOr("class", ""), "label-default") {
				tags = append(tags, tag)
			}
		})

		// 作者信息
		authorSelection := rowSelection.Find("td:nth-child(2) div.row div.col-md-5 h6 span.label-default a")
		author := strings.TrimSpace(authorSelection.Text())
		authorURL, _ := authorSelection.Attr("href")

		// 创建漏洞对象
		vulnerability := model.Vulnerability{
			Date:      currentDate,
			Title:     title,
			URL:       url,
			RiskLevel: riskLevel,
			Tags:      tags,
			Author:    author,
			AuthorURL: authorURL,
		}

		// 添加到结果中
		if title != "" {
			result.Items = append(result.Items, vulnerability)
		}
	})

	// 获取分页信息
	// 由于页面使用Angular，直接解析可能不准确
	// 后续可能需要调整为通过JavaScript执行或分析实际页面行为来获取

	// 设置默认值
	result.CurrentPage = 1 // 默认第一页
	result.TotalPages = 1  // 默认总页数为1

	return result, nil
}
