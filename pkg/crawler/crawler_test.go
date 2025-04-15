package crawler

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/scagogogo/cxsecurity-crawler/pkg/model"
)

// 创建一个模拟的client，用于单元测试
type mockClient struct {
	getPageFunc func(path string) (string, error)
	baseURL     string
}

func (m *mockClient) GetPage(path string) (string, error) {
	return m.getPageFunc(path)
}

func (m *mockClient) GetBaseURL() string {
	return m.baseURL
}

// 创建一个模拟的parser，用于单元测试
type mockParser struct {
	parseListPageFunc                func(htmlContent string) (*model.VulnerabilityList, error)
	parseCveDetailPageFunc           func(htmlContent string) (*model.CveDetail, error)
	parseVulnerabilityDetailPageFunc func(htmlContent string) (*model.Vulnerability, error)
}

func (m *mockParser) ParseListPage(htmlContent string) (*model.VulnerabilityList, error) {
	return m.parseListPageFunc(htmlContent)
}

func (m *mockParser) ParseCveDetailPage(htmlContent string) (*model.CveDetail, error) {
	return m.parseCveDetailPageFunc(htmlContent)
}

func (m *mockParser) ParseVulnerabilityDetailPage(htmlContent string) (*model.Vulnerability, error) {
	return m.parseVulnerabilityDetailPageFunc(htmlContent)
}

func TestNewCrawler(t *testing.T) {
	crawler := NewCrawler()
	if crawler == nil {
		t.Fatal("NewCrawler()应该返回非nil的爬虫实例")
	}

	if crawler.client == nil {
		t.Error("爬虫实例的client不应为nil")
	}

	if crawler.parser == nil {
		t.Error("爬虫实例的parser不应为nil")
	}
}

func TestCrawlPage(t *testing.T) {
	// 创建临时文件用于测试输出
	tempDir, err := os.MkdirTemp("", "crawler_test")
	if err != nil {
		t.Fatalf("创建临时目录失败: %v", err)
	}
	defer os.RemoveAll(tempDir)

	outputPath := filepath.Join(tempDir, "output.json")

	// 创建模拟数据
	currentTime := time.Now()
	mockList := &model.VulnerabilityList{
		Items: []model.Vulnerability{
			{
				Title:     "测试漏洞1",
				URL:       "https://example.com/1",
				Date:      currentTime,
				RiskLevel: "High",
				Tags:      []string{"CVE", "XSS"},
				Author:    "作者1",
			},
		},
		CurrentPage: 1,
		TotalPages:  5,
	}

	// 创建模拟客户端
	mockClient := &mockClient{
		getPageFunc: func(path string) (string, error) {
			return "<html>mock html content</html>", nil
		},
		baseURL: "https://example.com",
	}

	// 创建模拟解析器
	mockParser := &mockParser{
		parseListPageFunc: func(htmlContent string) (*model.VulnerabilityList, error) {
			return mockList, nil
		},
	}

	// 创建爬虫实例并注入模拟依赖
	crawler := &Crawler{
		client: mockClient,
		parser: mockParser,
	}

	// 测试不带输出路径的情况
	result, err := crawler.CrawlPage("/test-path", "")
	if err != nil {
		t.Fatalf("CrawlPage()返回错误: %v", err)
	}

	if result != mockList {
		t.Error("CrawlPage()返回的结果不是期望的模拟列表")
	}

	// 测试带输出路径的情况
	result, err = crawler.CrawlPage("/test-path", outputPath)
	if err != nil {
		t.Fatalf("CrawlPage()带输出路径返回错误: %v", err)
	}

	// 验证文件已创建
	if _, err := os.Stat(outputPath); os.IsNotExist(err) {
		t.Error("输出文件未创建")
	}

	// 验证文件内容
	fileContent, err := os.ReadFile(outputPath)
	if err != nil {
		t.Fatalf("读取输出文件失败: %v", err)
	}

	var savedList model.VulnerabilityList
	if err := json.Unmarshal(fileContent, &savedList); err != nil {
		t.Fatalf("解析输出文件JSON失败: %v", err)
	}

	if len(savedList.Items) != 1 {
		t.Errorf("保存的条目数量不匹配: 期望 1, 实际 %d", len(savedList.Items))
	}

	if savedList.Items[0].Title != "测试漏洞1" {
		t.Errorf("保存的漏洞标题不匹配: 期望 '测试漏洞1', 实际 '%s'", savedList.Items[0].Title)
	}
}

func TestCrawlCveDetail(t *testing.T) {
	// 创建临时文件用于测试输出
	tempDir, err := os.MkdirTemp("", "crawler_test")
	if err != nil {
		t.Fatalf("创建临时目录失败: %v", err)
	}
	defer os.RemoveAll(tempDir)

	outputPath := filepath.Join(tempDir, "cve_output.json")

	// 创建模拟数据
	currentTime := time.Now()
	mockCveDetail := &model.CveDetail{
		CveID:         "CVE-2023-1234",
		Published:     currentTime,
		Description:   "测试CVE描述",
		Type:          "CWE-79",
		CvssBaseScore: 7.5,
		AffectedSoftware: []model.AffectedSoftware{
			{
				VendorName:  "测试厂商",
				ProductName: "测试产品",
			},
		},
	}

	// 创建模拟客户端
	mockClient := &mockClient{
		getPageFunc: func(path string) (string, error) {
			if path == "/cveshow/CVE-2023-1234/" {
				return "<html>mock cve html</html>", nil
			}
			return "", nil
		},
		baseURL: "https://example.com",
	}

	// 创建模拟解析器
	mockParser := &mockParser{
		parseCveDetailPageFunc: func(htmlContent string) (*model.CveDetail, error) {
			return mockCveDetail, nil
		},
	}

	// 创建爬虫实例并注入模拟依赖
	crawler := &Crawler{
		client: mockClient,
		parser: mockParser,
	}

	// 测试不带输出路径的情况
	result, err := crawler.CrawlCveDetail("CVE-2023-1234", "")
	if err != nil {
		t.Fatalf("CrawlCveDetail()返回错误: %v", err)
	}

	if result != mockCveDetail {
		t.Error("CrawlCveDetail()返回的结果不是期望的模拟CVE详情")
	}

	// 测试带输出路径的情况
	result, err = crawler.CrawlCveDetail("CVE-2023-1234", outputPath)
	if err != nil {
		t.Fatalf("CrawlCveDetail()带输出路径返回错误: %v", err)
	}

	// 验证文件已创建
	if _, err := os.Stat(outputPath); os.IsNotExist(err) {
		t.Error("输出文件未创建")
	}

	// 验证文件内容
	fileContent, err := os.ReadFile(outputPath)
	if err != nil {
		t.Fatalf("读取输出文件失败: %v", err)
	}

	var savedCve model.CveDetail
	if err := json.Unmarshal(fileContent, &savedCve); err != nil {
		t.Fatalf("解析输出文件JSON失败: %v", err)
	}

	if savedCve.CveID != "CVE-2023-1234" {
		t.Errorf("保存的CVE ID不匹配: 期望 'CVE-2023-1234', 实际 '%s'", savedCve.CveID)
	}
}

func TestCrawlVulnerabilityDetail(t *testing.T) {
	// 创建临时文件用于测试输出
	tempDir, err := os.MkdirTemp("", "crawler_test")
	if err != nil {
		t.Fatalf("创建临时目录失败: %v", err)
	}
	defer os.RemoveAll(tempDir)

	outputPath := filepath.Join(tempDir, "vuln_output.json")

	// 创建模拟数据
	mockVuln := &model.Vulnerability{
		Title:     "测试漏洞详情",
		RiskLevel: "High",
		Tags:      []string{"CVE", "XSS"},
		Author:    "测试作者",
		Date:      time.Now(),
	}

	// 创建模拟客户端
	mockClient := &mockClient{
		getPageFunc: func(path string) (string, error) {
			if path == "/vuln/123" {
				return "<html>mock vuln html</html>", nil
			}
			return "", nil
		},
		baseURL: "https://example.com",
	}

	// 创建模拟解析器
	mockParser := &mockParser{
		parseVulnerabilityDetailPageFunc: func(htmlContent string) (*model.Vulnerability, error) {
			return mockVuln, nil
		},
	}

	// 创建爬虫实例并注入模拟依赖
	crawler := &Crawler{
		client: mockClient,
		parser: mockParser,
	}

	// 测试相对路径自动添加斜杠
	result, err := crawler.CrawlVulnerabilityDetail("vuln/123", "")
	if err != nil {
		t.Fatalf("CrawlVulnerabilityDetail()返回错误: %v", err)
	}

	if result != mockVuln {
		t.Error("CrawlVulnerabilityDetail()返回的结果不是期望的模拟漏洞详情")
	}

	// 验证URL被设置
	if result.URL != "https://example.com/vuln/123" {
		t.Errorf("URL设置不正确: 期望 'https://example.com/vuln/123', 实际 '%s'", result.URL)
	}

	// 测试带输出路径的情况
	result, err = crawler.CrawlVulnerabilityDetail("/vuln/123", outputPath)
	if err != nil {
		t.Fatalf("CrawlVulnerabilityDetail()带输出路径返回错误: %v", err)
	}

	// 验证文件已创建
	if _, err := os.Stat(outputPath); os.IsNotExist(err) {
		t.Error("输出文件未创建")
	}

	// 验证文件内容
	fileContent, err := os.ReadFile(outputPath)
	if err != nil {
		t.Fatalf("读取输出文件失败: %v", err)
	}

	var savedVuln model.Vulnerability
	if err := json.Unmarshal(fileContent, &savedVuln); err != nil {
		t.Fatalf("解析输出文件JSON失败: %v", err)
	}

	if savedVuln.Title != "测试漏洞详情" {
		t.Errorf("保存的漏洞标题不匹配: 期望 '测试漏洞详情', 实际 '%s'", savedVuln.Title)
	}
}

func TestCrawlExploit(t *testing.T) {
	// 创建临时文件用于测试输出
	tempDir, err := os.MkdirTemp("", "crawler_test")
	if err != nil {
		t.Fatalf("创建临时目录失败: %v", err)
	}
	defer os.RemoveAll(tempDir)

	outputPath := filepath.Join(tempDir, "exploit_output.json")

	// 创建模拟数据 - 漏洞列表
	mockList := &model.VulnerabilityList{
		Items: []model.Vulnerability{
			{
				Title:     "测试漏洞1",
				URL:       "https://example.com/1",
				RiskLevel: "High",
			},
		},
		CurrentPage: 1,
		TotalPages:  5,
	}

	// 创建模拟数据 - 漏洞详情
	mockVuln := &model.Vulnerability{
		Title:     "测试漏洞详情",
		RiskLevel: "High",
		Date:      time.Now(),
	}

	// 记录哪个路径被请求了
	requestedPath := ""

	// 创建模拟客户端
	mockClient := &mockClient{
		getPageFunc: func(path string) (string, error) {
			requestedPath = path
			return "<html>mock html</html>", nil
		},
		baseURL: "https://example.com",
	}

	// 创建模拟解析器
	mockParser := &mockParser{
		parseListPageFunc: func(htmlContent string) (*model.VulnerabilityList, error) {
			return mockList, nil
		},
		parseVulnerabilityDetailPageFunc: func(htmlContent string) (*model.Vulnerability, error) {
			return mockVuln, nil
		},
	}

	// 创建爬虫实例并注入模拟依赖
	crawler := &Crawler{
		client: mockClient,
		parser: mockParser,
	}

	// 测试空ID (应该爬取列表)
	err = crawler.CrawlExploit("", outputPath, "")
	if err != nil {
		t.Fatalf("CrawlExploit()返回错误: %v", err)
	}

	if requestedPath != "/exploit/1" {
		t.Errorf("空ID应该请求列表页: 期望 '/exploit/1', 实际 '%s'", requestedPath)
	}

	// 验证文件已创建 (列表模式)
	if _, err := os.Stat(outputPath); os.IsNotExist(err) {
		t.Error("列表模式下的输出文件未创建")
	}

	// 测试带ID (应该爬取详情)
	err = crawler.CrawlExploit("12345", outputPath, "")
	if err != nil {
		t.Fatalf("CrawlExploit()带ID返回错误: %v", err)
	}

	if requestedPath != "/issue/WLB-12345" {
		t.Errorf("带ID应该请求详情页: 期望 '/issue/WLB-12345', 实际 '%s'", requestedPath)
	}

	// 验证文件已创建 (详情模式)
	if _, err := os.Stat(outputPath); os.IsNotExist(err) {
		t.Error("详情模式下的输出文件未创建")
	}
}

func TestNewCrawlerWithOptions(t *testing.T) {
	// 测试带选项的爬虫创建
	timeout := 10 * time.Second

	// 创建测试服务器模拟重试
	requestCount := 0
	testServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCount++
		if requestCount <= 2 {
			// 模拟服务器错误，强制客户端重试
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("测试成功"))
	}))
	defer testServer.Close()

	// 创建爬虫
	crawler := NewCrawler(
		WithClientOptions(
			WithTimeout(timeout),
			WithRetry(2, 10*time.Millisecond), // 设置为2次重试，总共最多3次请求
		),
	)

	// 修改baseURL指向测试服务器
	client, ok := crawler.client.(*Client)
	if !ok {
		t.Fatal("无法将接口转换为具体类型")
	}
	client.baseURL = testServer.URL

	// 验证功能
	_, err := crawler.client.GetPage("/test")
	if err != nil {
		t.Errorf("重试机制失败: %v", err)
	}

	// 验证重试次数
	expectedRequests := 3 // 初始请求 + 2次重试
	if requestCount != expectedRequests {
		t.Errorf("重试次数不匹配: 期望 %d, 实际 %d", expectedRequests, requestCount)
	}
}
