package crawler

import (
	"os"
	"testing"
	"time"
)

func TestParseCveDetailPage(t *testing.T) {
	// 创建测试实例
	parser := NewParser()

	// 尝试加载测试HTML文件
	htmlContent, err := os.ReadFile("../../docs/cve-show-detail-response.html")
	if err != nil {
		t.Skip("跳过测试，测试文件不存在：../../docs/cve-show-detail-response.html")
		return
	}

	// 解析内容
	result, err := parser.ParseCveDetailPage(string(htmlContent))
	if err != nil {
		t.Fatalf("解析失败: %v", err)
	}

	// 验证结果不为nil
	if result == nil {
		t.Fatal("解析结果不应为nil")
	}

	// 验证基本字段
	if result.CveID == "" {
		t.Error("CVE ID不应为空")
	}

	if result.Description == "" {
		t.Error("描述不应为空")
	}

	// 验证时间字段
	if result.Published.IsZero() {
		t.Error("发布日期不应为零值")
	}

	// 验证CVSS评分
	if result.CvssBaseScore <= 0 {
		t.Error("CVSS基础评分应大于0")
	}

	// 验证受影响软件
	if len(result.AffectedSoftware) == 0 {
		t.Error("受影响软件列表不应为空")
	} else {
		firstSoftware := result.AffectedSoftware[0]
		if firstSoftware.VendorName == "" {
			t.Error("厂商名称不应为空")
		}
		if firstSoftware.ProductName == "" {
			t.Error("产品名称不应为空")
		}
	}

	// 验证参考链接
	if len(result.References) == 0 {
		t.Error("参考链接列表不应为空")
	}

	// 验证相关漏洞
	if len(result.RelatedVulnerabilities) == 0 {
		t.Error("相关漏洞列表不应为空")
	}
}

func TestParseCveDetailPageWithEmptyContent(t *testing.T) {
	parser := NewParser()

	// 测试空内容
	result, err := parser.ParseCveDetailPage("")
	if err == nil {
		t.Error("解析空内容应该返回错误")
	}
	if result != nil {
		t.Error("解析空内容应该返回nil结果")
	}
}

func TestParseCveDetailPageWithInvalidContent(t *testing.T) {
	parser := NewParser()

	// 测试无效HTML内容
	result, err := parser.ParseCveDetailPage("<invalid>html</content>")
	if err != nil {
		t.Fatalf("解析无效内容返回错误: %v", err)
	}

	// 应该返回空结果对象，但不报错
	if result == nil {
		t.Fatal("解析无效内容应该返回非nil结果")
	}

	// 验证ID为空
	if result.CveID != "" {
		t.Errorf("解析无效内容应该返回空CVE ID，实际: %s", result.CveID)
	}
}

func TestParseCveDetailPageMock(t *testing.T) {
	parser := NewParser()

	// 创建一个精简的测试HTML，包含必要的结构
	mockHTML := `
	<html>
		<body>
			<h1><strong>CVE-2023-12345</strong></h1>
			<center>Published: 2023-05-20 Modified: 2023-06-01</center>
			<table>
				<tr>
					<td bgcolor="#202020"><h6>这是一个测试CVE的描述</h6></td>
				</tr>
				<tr>
					<td bgcolor="#202020">
						<h6><span class="label label-warning">7.5/10</span></h6>
					</td>
				</tr>
				<tr>
					<td bgcolor="#1B1B1B">
						<h6><span class="label label-warning">8.0/10</span></h6>
					</td>
				</tr>
				<tr>
					<td>
						<h6><span class="label label-danger">6.5/10</span></h6>
					</td>
				</tr>
				<tr>
					<td bgcolor="#202020"><h6>Remote</h6></td>
				</tr>
				<tr>
					<td bgcolor="#202020"><h6>Medium</h6></td>
				</tr>
				<tr>
					<td bgcolor="#202020"><h6>No required</h6></td>
				</tr>
				<tr>
					<td bgcolor="#202020"><h6>Partial</h6></td>
				</tr>
				<tr>
					<td bgcolor="#202020"><h6>Partial</h6></td>
				</tr>
				<tr>
					<td bgcolor="#202020"><h6>Partial</h6></td>
				</tr>
			</table>
			<a href="/cwe/123"><h4>CWE-79</h4></a>
			<table>
				<thead>
					<tr><th>Affected software</th></tr>
				</thead>
				<tbody>
					<tr>
						<td>
							<a href="/vendor/1">测试厂商</a> -> <a href="/product/1">测试产品</a>
						</td>
					</tr>
				</tbody>
			</table>
			<td bgcolor="#202020">
				<div>https://example.com/ref1</div>
				<div>https://example.com/ref2</div>
			</td>
			<table>
				<tr><td>See advisories in our WLB2 database</td></tr>
				<tr>
					<td bgcolor="#1B1B1B"><h5><span class="label">High</span></h5></td>
					<td bgcolor="#1B1B1B"><h6><a href="/vuln/1">相关漏洞标题</a></h6></td>
					<td bgcolor="#1B1B1B">测试作者</td>
					<td bgcolor="#1B1B1B">15.06.2023</td>
				</tr>
			</table>
		</body>
	</html>`

	// 解析内容
	result, err := parser.ParseCveDetailPage(mockHTML)
	if err != nil {
		t.Fatalf("解析模拟HTML失败: %v", err)
	}

	// 验证CVE ID
	if result.CveID != "CVE-2023-12345" {
		t.Errorf("CVE ID不匹配: 期望 'CVE-2023-12345', 实际 '%s'", result.CveID)
	}

	// 验证发布日期
	expectedPublished, _ := time.Parse("2006-01-02", "2023-05-20")
	if !result.Published.Equal(expectedPublished) {
		t.Errorf("发布日期不匹配: 期望 %s, 实际 %s",
			expectedPublished.Format("2006-01-02"),
			result.Published.Format("2006-01-02"))
	}

	// 验证修改日期
	expectedModified, _ := time.Parse("2006-01-02", "2023-06-01")
	if !result.Modified.Equal(expectedModified) {
		t.Errorf("修改日期不匹配: 期望 %s, 实际 %s",
			expectedModified.Format("2006-01-02"),
			result.Modified.Format("2006-01-02"))
	}

	// 验证描述
	if result.Description != "这是一个测试CVE的描述" {
		t.Errorf("描述不匹配: 期望 '这是一个测试CVE的描述', 实际 '%s'", result.Description)
	}

	// 验证CVSS评分
	if result.CvssBaseScore != 7.5 {
		t.Errorf("CVSS基础评分不匹配: 期望 7.5, 实际 %f", result.CvssBaseScore)
	}

	if result.CvssImpactScore != 8.0 {
		t.Errorf("CVSS影响评分不匹配: 期望 8.0, 实际 %f", result.CvssImpactScore)
	}

	if result.CvssExploitScore != 6.5 {
		t.Errorf("CVSS利用评分不匹配: 期望 6.5, 实际 %f", result.CvssExploitScore)
	}

	// 验证漏洞类型
	if result.Type != "CWE-79" {
		t.Errorf("漏洞类型不匹配: 期望 'CWE-79', 实际 '%s'", result.Type)
	}

	// 验证漏洞属性
	if result.ExploitRange != "Remote" {
		t.Errorf("利用范围不匹配: 期望 'Remote', 实际 '%s'", result.ExploitRange)
	}

	// 验证受影响软件
	if len(result.AffectedSoftware) != 1 {
		t.Errorf("受影响软件数量不匹配: 期望 1, 实际 %d", len(result.AffectedSoftware))
	} else {
		software := result.AffectedSoftware[0]
		if software.VendorName != "测试厂商" {
			t.Errorf("厂商名称不匹配: 期望 '测试厂商', 实际 '%s'", software.VendorName)
		}
		if software.ProductName != "测试产品" {
			t.Errorf("产品名称不匹配: 期望 '测试产品', 实际 '%s'", software.ProductName)
		}
	}

	// 验证参考链接
	if len(result.References) != 2 {
		t.Errorf("参考链接数量不匹配: 期望 2, 实际 %d", len(result.References))
	} else {
		if result.References[0] != "https://example.com/ref1" {
			t.Errorf("第一个参考链接不匹配: 期望 'https://example.com/ref1', 实际 '%s'", result.References[0])
		}
		if result.References[1] != "https://example.com/ref2" {
			t.Errorf("第二个参考链接不匹配: 期望 'https://example.com/ref2', 实际 '%s'", result.References[1])
		}
	}

	// 验证相关漏洞
	if len(result.RelatedVulnerabilities) != 1 {
		t.Errorf("相关漏洞数量不匹配: 期望 1, 实际 %d", len(result.RelatedVulnerabilities))
	} else {
		vuln := result.RelatedVulnerabilities[0]
		if vuln.Title != "相关漏洞标题" {
			t.Errorf("相关漏洞标题不匹配: 期望 '相关漏洞标题', 实际 '%s'", vuln.Title)
		}
		if vuln.RiskLevel != "High" {
			t.Errorf("相关漏洞风险级别不匹配: 期望 'High', 实际 '%s'", vuln.RiskLevel)
		}
		if vuln.Author != "测试作者" {
			t.Errorf("相关漏洞作者不匹配: 期望 '测试作者', 实际 '%s'", vuln.Author)
		}

		// 验证日期 - 注意日期格式可能会有差异
		expectedVulnDate, _ := time.Parse("02.01.2006", "15.06.2023")
		if !vuln.Date.Equal(expectedVulnDate) {
			t.Errorf("相关漏洞日期不匹配: 期望 %s, 实际 %s",
				expectedVulnDate.Format("2006-01-02"),
				vuln.Date.Format("2006-01-02"))
		}
	}
}
