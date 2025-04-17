package crawler

import (
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestParseListPage(t *testing.T) {
	parser := NewParser()

	// 加载测试HTML文件
	htmlContent, err := os.ReadFile("../../docs/list-response.html")
	if err != nil {
		t.Skip("跳过测试，测试文件不存在：../../docs/list-response.html")
		return
	}

	// 解析内容
	result, err := parser.ParseListPage(string(htmlContent))
	assert.NoError(t, err, "解析失败")
	assert.NotNil(t, result, "解析结果不应为nil")

	// --- 验证字段值是否与 docs/list-response.html 完全对应 ---

	// 验证列表非空
	assert.NotEmpty(t, result.Items, "解析结果中应包含漏洞条目")

	// 验证分页信息 (基于HTML中的JS变量)
	assert.Equal(t, 85, result.CurrentPage, "当前页码不匹配")
	// totalItems = 860, perPage = 60 => totalPages = ceil(860/60) = 15
	assert.Equal(t, 15, result.TotalPages, "总页数不匹配")

	// 验证第一条记录的基本信息
	if len(result.Items) > 0 {
		item := result.Items[0]

		// 预期日期 (从第一个 thead 获取)
		expectedDate, _ := time.Parse("2006-01-02", "2007-03-21")
		assert.Equal(t, expectedDate.Format("2006-01-02"), item.Date.Format("2006-01-02"), "第一条记录的日期不匹配")

		// 预期其他字段
		assert.Equal(t, "PHP <= 4.4.6 ibase_connect() local buffer overflow", item.Title, "第一条记录的标题不匹配")
		assert.Equal(t, "https://cxsecurity.com/issue/WLB-2007030137", item.URL, "第一条记录的URL不匹配")
		assert.Equal(t, "High", item.RiskLevel, "第一条记录的风险级别不匹配")
		assert.Equal(t, "rgod", item.Author, "第一条记录的作者不匹配")
		assert.Equal(t, "https://cxsecurity.com/author/rgod/1/", item.AuthorURL, "第一条记录的作者URL不匹配")

		// 预期标签
		assert.Contains(t, item.Tags, "CVE", "第一条记录的标签应包含CVE")
		assert.Contains(t, item.Tags, "CWE", "第一条记录的标签应包含CWE")
		assert.Contains(t, item.Tags, "Local", "第一条记录的标签应包含Local")
	}
}
