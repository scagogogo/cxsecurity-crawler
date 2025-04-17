package crawler

import (
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestParseVulnerabilityDetailPage(t *testing.T) {
	parser := NewParser()

	// 加载测试HTML文件
	htmlContent, err := os.ReadFile("../../docs/vul-detail-response.html")
	if err != nil {
		t.Skip("跳过测试，测试文件不存在：../../docs/vul-detail-response.html")
		return
	}

	// 解析内容
	result, err := parser.ParseVulnerabilityDetailPage(string(htmlContent))
	assert.NoError(t, err, "解析失败")
	assert.NotNil(t, result, "解析结果不应为nil")

	// --- 验证字段值是否与 docs/vul-detail-response.html 完全对应 ---

	// 标题
	assert.Equal(t, "PHP <= 4.4.6 ibase_connect() local buffer overflow", result.Title, "标题不匹配")

	// 风险级别
	assert.Equal(t, "High", result.RiskLevel, "风险级别不匹配")

	// 日期
	expectedDate, _ := time.Parse("2006.01.02", "2007.03.21") // 注意HTML中的日期格式
	assert.Equal(t, expectedDate.Format("2006-01-02"), result.Date.Format("2006-01-02"), "日期不匹配")

	// 作者信息
	assert.Equal(t, "rgod", result.Author, "作者不匹配")
	assert.Equal(t, "https://cxsecurity.com/author/rgod/1/", result.AuthorURL, "作者URL不匹配")

	// 标签 (验证存在的标签)
	assert.Contains(t, result.Tags, "CVE-2007-1475", "标签应包含CVE")
	assert.Contains(t, result.Tags, "CWE-119", "标签应包含CWE")
	assert.Contains(t, result.Tags, "Local", "标签应包含Local")
	// Remote 标签在此HTML中不存在，所以不检查
	// assert.Contains(t, result.Tags, "Remote", "标签应包含Remote")
}
