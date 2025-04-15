package crawler

import (
	"os"
	"testing"
	"time"
)

func TestParseVulnerabilityDetailPage(t *testing.T) {
	// 创建测试实例
	parser := NewParser()

	// 尝试加载测试HTML文件
	htmlContent, err := os.ReadFile("../../docs/vul-detail-response.html")
	if err != nil {
		t.Skip("跳过测试，测试文件不存在：../../docs/vul-detail-response.html")
		return
	}

	// 解析内容
	result, err := parser.ParseVulnerabilityDetailPage(string(htmlContent))
	if err != nil {
		t.Fatalf("解析失败: %v", err)
	}

	// 验证结果不为nil
	if result == nil {
		t.Fatal("解析结果不应为nil")
	}

	// 验证基本字段
	if result.Title == "" {
		t.Error("漏洞标题不应为空")
	}

	if result.RiskLevel == "" {
		t.Error("风险级别不应为空")
	}

	// 验证标签字段 (如果存在)
	if len(result.Tags) == 0 {
		t.Log("警告：未解析到标签，但这可能是正常的，取决于测试HTML内容")
	}

	// 验证作者信息 (如果存在)
	if result.Author == "" {
		t.Log("警告：未解析到作者名称，但这可能是正常的，取决于测试HTML内容")
	}
}

func TestParseVulnerabilityDetailPageWithEmptyContent(t *testing.T) {
	parser := NewParser()

	// 测试空内容
	result, err := parser.ParseVulnerabilityDetailPage("")
	if err == nil {
		t.Error("解析空内容应该返回错误")
	}
	if result != nil {
		t.Error("解析空内容应该返回nil结果")
	}
}

func TestParseVulnerabilityDetailPageWithInvalidContent(t *testing.T) {
	parser := NewParser()

	// 测试无效HTML内容
	result, err := parser.ParseVulnerabilityDetailPage("<invalid>html</content>")
	if err != nil {
		t.Fatalf("解析无效内容返回错误: %v", err)
	}

	// 应该返回空结果对象，但不报错
	if result == nil {
		t.Fatal("解析无效内容应该返回非nil结果")
	}

	// 验证标题为空
	if result.Title != "" {
		t.Errorf("解析无效内容应该返回空漏洞标题，实际: %s", result.Title)
	}
}

func TestParseVulnerabilityDetailPageMock(t *testing.T) {
	parser := NewParser()

	// 创建一个精简的测试HTML
	mockHTML := `
	<html>
		<body>
			<h1>测试漏洞标题</h1>
			<h5><span class="label">High</span></h5>
			<h5>
				<span class="label">CVE</span>
				<span class="label">Remote</span>
				<span class="label">XSS</span>
			</h5>
			<small>2023-07-15</small>
			<span class="label-default"><a href="/author/test">测试作者</a></span>
		</body>
	</html>`

	// 解析内容
	result, err := parser.ParseVulnerabilityDetailPage(mockHTML)
	if err != nil {
		t.Fatalf("解析模拟HTML失败: %v", err)
	}

	// 验证标题
	if result.Title != "测试漏洞标题" {
		t.Errorf("标题不匹配: 期望 '测试漏洞标题', 实际 '%s'", result.Title)
	}

	// 验证风险级别
	if result.RiskLevel != "High" {
		t.Errorf("风险级别不匹配: 期望 'High', 实际 '%s'", result.RiskLevel)
	}

	// 验证标签
	expectedTags := []string{"CVE", "Remote", "XSS"}
	if len(result.Tags) != len(expectedTags) {
		t.Errorf("标签数量不匹配: 期望 %d, 实际 %d", len(expectedTags), len(result.Tags))
	} else {
		for i, tag := range expectedTags {
			if i < len(result.Tags) && result.Tags[i] != tag {
				t.Errorf("标签[%d]不匹配: 期望 '%s', 实际 '%s'", i, tag, result.Tags[i])
			}
		}
	}

	// 验证日期
	expectedDate, _ := time.Parse("2006-01-02", "2023-07-15")
	if !result.Date.Equal(expectedDate) {
		t.Errorf("日期不匹配: 期望 %s, 实际 %s",
			expectedDate.Format("2006-01-02"),
			result.Date.Format("2006-01-02"))
	}

	// 验证作者
	if result.Author != "测试作者" {
		t.Errorf("作者不匹配: 期望 '测试作者', 实际 '%s'", result.Author)
	}

	if result.AuthorURL != "/author/test" {
		t.Errorf("作者URL不匹配: 期望 '/author/test', 实际 '%s'", result.AuthorURL)
	}
}
