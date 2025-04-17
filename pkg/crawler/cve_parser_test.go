package crawler

import (
	"os"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestParseCveDetailPage(t *testing.T) {
	// 创建测试实例
	parser := NewParser()

	// 加载测试HTML文件
	htmlContent, err := os.ReadFile("../../docs/cve-show-detail-response.html")
	if err != nil {
		t.Skip("跳过测试，测试文件不存在：../../docs/cve-show-detail-response.html")
		return
	}

	// 解析内容
	result, err := parser.ParseCveDetailPage(string(htmlContent))
	assert.NoError(t, err, "解析失败")
	assert.NotNil(t, result, "解析结果不应为nil")

	// --- 验证字段值是否与 docs/cve-show-detail-response.html 完全对应 ---

	// 基本字段
	assert.Equal(t, "CVE-2007-1411", result.CveID, "CVE ID 不匹配")
	assert.True(t, strings.HasPrefix(result.Description, "Buffer overflow in PHP 4.4.6 and earlier"), "描述开头不匹配")

	// 时间字段
	expectedPublished, _ := time.Parse("2006-01-02", "2007-03-10")
	assert.Equal(t, expectedPublished, result.Published, "发布日期不匹配")
	expectedModified, _ := time.Parse("2006-01-02", "2012-02-12")
	assert.Equal(t, expectedModified, result.Modified, "修改日期不匹配")

	// CVSS评分
	assert.Equal(t, 6.8, result.CvssBaseScore, "CVSS基础评分不匹配")
	assert.Equal(t, 6.4, result.CvssImpactScore, "CVSS影响评分不匹配")
	assert.Equal(t, 8.6, result.CvssExploitScore, "CVSS利用评分不匹配")

	// 漏洞类型
	assert.Equal(t, "CWE-Other", result.Type, "漏洞类型(CWE)不匹配")

	// 漏洞属性
	assert.Equal(t, "Remote", result.ExploitRange, "利用范围不匹配")
	assert.Equal(t, "Medium", result.AttackComplexity, "攻击复杂度不匹配")
	assert.Equal(t, "No required", result.Authentication, "认证要求不匹配")
	assert.Equal(t, "Partial", result.ConfidentialityImpact, "机密性影响不匹配")
	assert.Equal(t, "Partial", result.IntegrityImpact, "完整性影响不匹配")
	assert.Equal(t, "Partial", result.AvailabilityImpact, "可用性影响不匹配")

	// 受影响软件 (验证第一条)
	assert.NotEmpty(t, result.AffectedSoftware, "受影响软件列表不应为空")
	if len(result.AffectedSoftware) > 0 {
		software := result.AffectedSoftware[0]
		assert.Equal(t, "PHP", software.VendorName, "厂商名称不匹配")
		assert.Equal(t, "PHP", software.ProductName, "产品名称不匹配")
		assert.Equal(t, "https://cxsecurity.com//cvevendor/42/php/", software.VendorURL, "厂商URL不匹配")
		assert.Equal(t, "https://cxsecurity.com/cveproduct/42/81/php/", software.ProductURL, "产品URL不匹配")
	}

	// 参考链接 (验证第一条)
	assert.NotEmpty(t, result.References, "参考链接列表不应为空")
	if len(result.References) > 0 {
		assert.Equal(t, "http://retrogod.altervista.org/php_446_mssql_connect_bof.html", result.References[0], "第一个参考链接不匹配")
	}

	// 相关漏洞 (验证第一条)
	assert.NotEmpty(t, result.RelatedVulnerabilities, "相关漏洞列表不应为空")
	if len(result.RelatedVulnerabilities) > 0 {
		vuln := result.RelatedVulnerabilities[0]
		expectedVulnDate, _ := time.Parse("02.01.2006", "14.03.2007") // 注意HTML中的日期格式
		assert.Equal(t, "PHP <= 4.4.6 mssql_connect() & mssql_pconnect() local buffer overflow and safe_mode bypass", vuln.Title, "相关漏洞标题不匹配")
		assert.Equal(t, "https://cxsecurity.com/issue/WLB-2007030105", vuln.URL, "相关漏洞URL不匹配")
		assert.Equal(t, "High", vuln.RiskLevel, "相关漏洞风险级别不匹配")
		assert.Equal(t, "rgod", vuln.Author, "相关漏洞作者不匹配")
		assert.Equal(t, expectedVulnDate.Format("2006-01-02"), vuln.Date.Format("2006-01-02"), "相关漏洞日期不匹配") // 比较格式化后的日期字符串
	}
}
