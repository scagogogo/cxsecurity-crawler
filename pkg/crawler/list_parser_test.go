package crawler

import (
	"os"
	"testing"
	"time"
)

func TestParseListPage(t *testing.T) {
	// 创建测试实例
	parser := NewParser()

	// 尝试加载测试HTML文件
	htmlContent, err := os.ReadFile("../../docs/list-response.html")
	if err != nil {
		t.Skip("跳过测试，测试文件不存在：../../docs/list-response.html")
		return
	}

	// 解析内容
	result, err := parser.ParseListPage(string(htmlContent))
	if err != nil {
		t.Fatalf("解析失败: %v", err)
	}

	// 验证结果不为nil
	if result == nil {
		t.Fatal("解析结果不应为nil")
	}

	// 验证结果包含漏洞条目
	if len(result.Items) == 0 {
		t.Error("解析结果中应包含漏洞条目")
	}

	// 验证分页信息
	if result.CurrentPage <= 0 {
		t.Errorf("当前页码无效: %d", result.CurrentPage)
	}

	if result.TotalPages <= 0 {
		t.Errorf("总页数无效: %d", result.TotalPages)
	}

	// 验证第一个漏洞条目的基本信息
	if len(result.Items) > 0 {
		firstItem := result.Items[0]
		if firstItem.Title == "" {
			t.Error("漏洞标题不应为空")
		}

		if firstItem.URL == "" {
			t.Error("漏洞URL不应为空")
		}

		if firstItem.RiskLevel == "" {
			t.Error("漏洞风险级别不应为空")
		}
	}
}

func TestParseListPageWithEmptyContent(t *testing.T) {
	parser := NewParser()

	// 测试空内容
	result, err := parser.ParseListPage("")
	if err == nil {
		t.Error("解析空内容应该返回错误")
	}
	if result != nil {
		t.Error("解析空内容应该返回nil结果")
	}
}

func TestParseListPageWithInvalidContent(t *testing.T) {
	parser := NewParser()

	// 测试无效HTML内容
	result, err := parser.ParseListPage("<invalid>html</content>")
	if err != nil {
		t.Fatalf("解析无效内容返回错误: %v", err)
	}

	// 应该返回空结果，但不报错
	if result == nil {
		t.Fatal("解析无效内容应该返回非nil结果")
	}

	// 验证返回了空条目列表
	if len(result.Items) != 0 {
		t.Errorf("解析无效内容应该返回空条目列表，实际长度: %d", len(result.Items))
	}
}

func TestParseListPageMock(t *testing.T) {
	parser := NewParser()

	// 创建一个精简的测试HTML
	mockHTML := `
	<html>
		<body>
			<table>
				<tr>
					<th><u><h6><b><font>2023-06-15</font></b></h6></u></th>
				</tr>
				<tr>
					<td><h6><span class="label">High</span></h6></td>
					<td>
						<div class="row">
							<div class="col-md-7">
								<h6><a href="/vuln/123">测试漏洞标题</a></h6>
							</div>
							<div class="col-md-5">
								<h6>
									<span class="label">CVE</span>
									<span class="label">Remote</span>
									<span class="label-default"><a href="/author/test">测试作者</a></span>
								</h6>
							</div>
						</div>
					</td>
				</tr>
			</table>
		</body>
	</html>`

	// 解析内容
	result, err := parser.ParseListPage(mockHTML)
	if err != nil {
		t.Fatalf("解析模拟HTML失败: %v", err)
	}

	// 验证结果
	if len(result.Items) != 1 {
		t.Fatalf("应解析出1个漏洞条目，实际: %d", len(result.Items))
	}

	item := result.Items[0]

	// 验证日期
	expectedDate, _ := time.Parse("2006-01-02", "2023-06-15")
	if !item.Date.Equal(expectedDate) {
		t.Errorf("日期不匹配: 期望 %s, 实际 %s", expectedDate.Format("2006-01-02"), item.Date.Format("2006-01-02"))
	}

	// 验证标题和URL
	if item.Title != "测试漏洞标题" {
		t.Errorf("标题不匹配: 期望 '测试漏洞标题', 实际 '%s'", item.Title)
	}

	if item.URL != "/vuln/123" {
		t.Errorf("URL不匹配: 期望 '/vuln/123', 实际 '%s'", item.URL)
	}

	// 验证风险级别
	if item.RiskLevel != "High" {
		t.Errorf("风险级别不匹配: 期望 'High', 实际 '%s'", item.RiskLevel)
	}

	// 验证标签
	expectedTags := []string{"CVE", "Remote"}
	if len(item.Tags) != len(expectedTags) {
		t.Errorf("标签数量不匹配: 期望 %d, 实际 %d", len(expectedTags), len(item.Tags))
	} else {
		for i, tag := range expectedTags {
			if i < len(item.Tags) && item.Tags[i] != tag {
				t.Errorf("标签[%d]不匹配: 期望 '%s', 实际 '%s'", i, tag, item.Tags[i])
			}
		}
	}

	// 验证作者
	if item.Author != "测试作者" {
		t.Errorf("作者不匹配: 期望 '测试作者', 实际 '%s'", item.Author)
	}

	if item.AuthorURL != "/author/test" {
		t.Errorf("作者URL不匹配: 期望 '/author/test', 实际 '%s'", item.AuthorURL)
	}
}
