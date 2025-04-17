package crawler

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestSearchVulnerabilities(t *testing.T) {
	// 创建临时目录用于存放测试结果
	tempDir, err := os.MkdirTemp("", "search_test_*")
	if err != nil {
		t.Fatalf("创建临时目录失败: %v", err)
	}
	defer os.RemoveAll(tempDir)

	// 创建爬虫实例
	crawler := NewCrawler()

	// 测试基本搜索功能
	t.Run("基本搜索功能", func(t *testing.T) {
		outputPath := filepath.Join(tempDir, "search_result.json")
		result, err := crawler.SearchVulnerabilities("XSS", 1, outputPath)
		if err != nil {
			t.Fatalf("搜索失败: %v", err)
		}

		// 验证搜索结果不为空
		if result == nil {
			t.Fatal("搜索结果为空")
		}

		// 验证关键字
		if result.Keyword != "XSS" {
			t.Errorf("关键字不匹配, 期望: XSS, 实际: %s", result.Keyword)
		}

		// 验证分页信息
		if result.CurrentPage != 1 {
			t.Errorf("当前页码不匹配, 期望: 1, 实际: %d", result.CurrentPage)
		}
		if result.TotalPages <= 0 {
			t.Errorf("总页数异常, 实际: %d", result.TotalPages)
		}
		if result.PerPage != 10 {
			t.Errorf("每页记录数不匹配, 期望: 10, 实际: %d", result.PerPage)
		}

		// 验证排序顺序
		if result.SortOrder != "DESC" {
			t.Errorf("排序顺序不匹配, 期望: DESC, 实际: %s", result.SortOrder)
		}

		// 验证漏洞列表
		if len(result.Vulnerabilities) == 0 {
			t.Fatal("漏洞列表为空")
		}
		if len(result.Vulnerabilities) > result.PerPage {
			t.Errorf("漏洞列表超出每页限制, 期望最大: %d, 实际: %d", result.PerPage, len(result.Vulnerabilities))
		}

		// 验证每个漏洞项的字段
		for i, vuln := range result.Vulnerabilities {
			t.Run(vuln.ID, func(t *testing.T) {
				// 验证ID格式
				if !strings.HasPrefix(vuln.ID, "WLB-") {
					t.Errorf("漏洞ID格式错误 [%d]: %s", i, vuln.ID)
				}

				// 验证标题
				if vuln.Title == "" {
					t.Errorf("漏洞标题为空 [%d]", i)
				}
				if !strings.Contains(strings.ToLower(vuln.Title), "xss") {
					t.Errorf("漏洞标题不包含搜索关键词 [%d]: %s", i, vuln.Title)
				}

				// 验证URL
				if vuln.URL == "" {
					t.Errorf("漏洞URL为空 [%d]", i)
				}
				if !strings.HasPrefix(vuln.URL, "https://cxsecurity.com/issue/") {
					t.Errorf("漏洞URL格式错误 [%d]: %s", i, vuln.URL)
				}

				// 验证日期格式
				if vuln.Date == "未知" {
					t.Errorf("漏洞日期未知 [%d]", i)
				} else {
					_, err := time.Parse("2006-01-02", vuln.Date)
					if err != nil {
						t.Errorf("漏洞日期格式错误 [%d]: %s", i, vuln.Date)
					}
				}

				// 验证风险级别
				validRiskLevels := map[string]bool{
					"High": true,
					"Med.": true,
					"Low":  true,
				}
				if !validRiskLevels[vuln.RiskLevel] {
					t.Errorf("风险级别无效 [%d]: %s", i, vuln.RiskLevel)
				}

				// 验证作者信息
				if vuln.Author == "" {
					t.Errorf("作者为空 [%d]", i)
				}
				if vuln.AuthorURL == "" {
					t.Errorf("作者URL为空 [%d]", i)
				}
				if !strings.HasPrefix(vuln.AuthorURL, "https://cxsecurity.com/author/") {
					t.Errorf("作者URL格式错误 [%d]: %s", i, vuln.AuthorURL)
				}
			})
		}

		// 验证结果文件是否已保存
		if _, err := os.Stat(outputPath); os.IsNotExist(err) {
			t.Error("结果文件未创建")
		}
	})

	// 测试高级搜索功能
	t.Run("高级搜索功能", func(t *testing.T) {
		testCases := []struct {
			name      string
			keyword   string
			page      int
			perPage   int
			sortOrder string
		}{
			{"每页30条记录", "SQL", 1, 30, "DESC"},
			{"升序排序", "RCE", 1, 10, "ASC"},
			{"无效的每页记录数", "XSS", 1, 20, "DESC"},   // 应该自动调整为10
			{"无效的排序顺序", "LFI", 1, 10, "INVALID"}, // 应该自动调整为DESC
		}

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				outputPath := filepath.Join(tempDir, tc.name+".json")
				result, err := crawler.SearchVulnerabilitiesAdvanced(
					tc.keyword,
					tc.page,
					tc.perPage,
					tc.sortOrder,
					outputPath,
				)
				if err != nil {
					t.Fatalf("高级搜索失败: %v", err)
				}

				// 验证每页记录数的自动调整
				expectedPerPage := tc.perPage
				if expectedPerPage != 10 && expectedPerPage != 30 {
					expectedPerPage = 10
				}
				if result.PerPage != expectedPerPage {
					t.Errorf("每页记录数未正确调整, 期望: %d, 实际: %d", expectedPerPage, result.PerPage)
				}

				// 验证排序顺序的自动调整
				expectedSortOrder := tc.sortOrder
				if expectedSortOrder != "ASC" && expectedSortOrder != "DESC" {
					expectedSortOrder = "DESC"
				}
				if result.SortOrder != expectedSortOrder {
					t.Errorf("排序顺序未正确调整, 期望: %s, 实际: %s", expectedSortOrder, result.SortOrder)
				}

				// 验证结果数量
				if len(result.Vulnerabilities) > result.PerPage {
					t.Errorf("结果数量超出每页限制, 期望最大: %d, 实际: %d", result.PerPage, len(result.Vulnerabilities))
				}

				// 验证日期排序
				if len(result.Vulnerabilities) > 1 {
					isCorrectOrder := true
					for i := 1; i < len(result.Vulnerabilities); i++ {
						date1, _ := time.Parse("2006-01-02", result.Vulnerabilities[i-1].Date)
						date2, _ := time.Parse("2006-01-02", result.Vulnerabilities[i].Date)

						if result.SortOrder == "DESC" {
							if date1.Before(date2) {
								isCorrectOrder = false
								break
							}
						} else {
							if date1.After(date2) {
								isCorrectOrder = false
								break
							}
						}
					}
					if !isCorrectOrder {
						t.Error("搜索结果未按指定顺序排序")
					}
				}
			})
		}
	})
}
