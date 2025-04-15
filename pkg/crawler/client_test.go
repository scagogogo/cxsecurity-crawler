package crawler

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestNewClient(t *testing.T) {
	// 测试默认参数
	client := NewClient()

	// 验证client不为nil
	if client == nil {
		t.Fatal("NewClient()应该返回非nil的客户端实例")
	}

	// 验证baseURL已设置
	if client.GetBaseURL() != "https://cxsecurity.com" {
		t.Errorf("baseURL不匹配: 期望 https://cxsecurity.com, 实际 %s", client.GetBaseURL())
	}

	// 验证http客户端已设置且超时正确
	if client.client == nil {
		t.Fatal("client.client不应该为nil")
	}

	if client.client.Timeout != 30*time.Second {
		t.Errorf("client超时设置不匹配: 期望 30s, 实际 %v", client.client.Timeout)
	}

	// 测试自定义选项
	customTimeout := 10 * time.Second
	client = NewClient(WithTimeout(customTimeout))

	if client.client.Timeout != customTimeout {
		t.Errorf("自定义超时设置不匹配: 期望 %v, 实际 %v", customTimeout, client.client.Timeout)
	}

	// 测试重试参数
	maxRetries := 5
	retryDelay := 1 * time.Second
	client = NewClient(WithRetry(maxRetries, retryDelay))

	if client.maxRetries != maxRetries {
		t.Errorf("最大重试次数设置不匹配: 期望 %d, 实际 %d", maxRetries, client.maxRetries)
	}

	if client.retryDelay != retryDelay {
		t.Errorf("重试延迟设置不匹配: 期望 %v, 实际 %v", retryDelay, client.retryDelay)
	}

	// 测试自定义请求头
	customKey := "X-Custom-Header"
	customValue := "CustomValue"
	client = NewClient(WithHeader(customKey, customValue))

	if client.customHeaders[customKey] != customValue {
		t.Errorf("自定义请求头设置不匹配: 期望 %s, 实际 %s", customValue, client.customHeaders[customKey])
	}
}

func TestGetBaseURL(t *testing.T) {
	client := NewClient()
	baseURL := client.GetBaseURL()

	// 验证返回的baseURL正确
	if baseURL != "https://cxsecurity.com" {
		t.Errorf("GetBaseURL()返回错误: 期望 https://cxsecurity.com, 实际 %s", baseURL)
	}
}

func TestGetPage(t *testing.T) {
	// 创建一个测试服务器
	testServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// 验证请求头
		userAgent := r.Header.Get("User-Agent")
		if userAgent == "" {
			t.Error("未设置User-Agent")
		}

		accept := r.Header.Get("Accept")
		if accept == "" {
			t.Error("未设置Accept")
		}

		// 根据请求路径返回不同的响应
		switch r.URL.Path {
		case "/test-path":
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("测试页面内容"))
		case "/error-path":
			w.WriteHeader(http.StatusNotFound)
			w.Write([]byte("页面不存在"))
		default:
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("默认响应"))
		}
	}))
	defer testServer.Close()

	// 创建一个带有测试服务器URL的客户端
	client := NewClient(
		WithTimeout(5*time.Second),
		WithHeader("X-Test", "Test Value"),
	)
	client.baseURL = testServer.URL

	// 测试成功的请求
	content, err := client.GetPage("/test-path")
	if err != nil {
		t.Fatalf("GetPage()返回错误: %v", err)
	}
	if content != "测试页面内容" {
		t.Errorf("GetPage()返回内容不匹配: 期望 '测试页面内容', 实际 '%s'", content)
	}

	// 测试404响应 - 应该返回404的响应内容，但不会返回错误
	content, err = client.GetPage("/error-path")
	if err != nil {
		t.Fatalf("对于404响应，GetPage()不应该返回错误: %v", err)
	}
	if content != "页面不存在" {
		t.Errorf("GetPage()对于404响应返回内容不匹配: 期望 '页面不存在', 实际 '%s'", content)
	}

	// 测试无效URL的情况
	invalidClient := NewClient()
	invalidClient.baseURL = "http://invalid-url-that-should-not-exist.example"
	_, err = invalidClient.GetPage("/test")
	if err == nil {
		t.Error("对于无效URL，GetPage()应该返回错误")
	}
}

func TestClientWithTimeout(t *testing.T) {
	// 创建一个带自定义超时的客户端
	customTimeout := 10 * time.Second
	client := NewClient(WithTimeout(customTimeout))

	// 验证超时设置正确
	if client.client.Timeout != customTimeout {
		t.Errorf("自定义超时设置不匹配: 期望 %v, 实际 %v", customTimeout, client.client.Timeout)
	}
}

func TestGetPageWithRedirect(t *testing.T) {
	// 创建测试服务器，模拟重定向
	redirectCount := 0
	testServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/redirect" {
			redirectCount++
			if redirectCount < 3 {
				// 重定向到自身，最多重定向2次
				http.Redirect(w, r, "/redirect", http.StatusFound)
				return
			}
			// 第3次返回实际内容
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("重定向后的内容"))
			return
		}

		// 默认响应
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("默认响应"))
	}))
	defer testServer.Close()

	// 创建客户端
	client := NewClient(WithTimeout(5 * time.Second))
	client.baseURL = testServer.URL

	// 测试重定向请求
	content, err := client.GetPage("/redirect")
	if err != nil {
		t.Fatalf("GetPage()处理重定向失败: %v", err)
	}
	if content != "重定向后的内容" {
		t.Errorf("GetPage()返回内容不匹配: 期望 '重定向后的内容', 实际 '%s'", content)
	}

	// 验证重定向计数
	if redirectCount != 3 {
		t.Errorf("重定向次数不匹配: 期望 3, 实际 %d", redirectCount)
	}
}

func TestGetPageWithDifferentStatusCodes(t *testing.T) {
	// 创建测试服务器，返回不同的状态码
	testServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/status-200":
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("状态码200"))
		case "/status-404":
			w.WriteHeader(http.StatusNotFound)
			w.Write([]byte("状态码404"))
		case "/status-500":
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte("状态码500"))
		case "/status-403":
			w.WriteHeader(http.StatusForbidden)
			w.Write([]byte("状态码403"))
		case "/empty-response":
			w.WriteHeader(http.StatusOK)
			// 不写入任何内容
		default:
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("默认响应"))
		}
	}))
	defer testServer.Close()

	// 创建客户端，禁用重试功能
	client := NewClient(
		WithTimeout(5*time.Second),
		WithRetry(0, 0), // 禁用重试，以便测试不同状态码
	)
	client.baseURL = testServer.URL

	// 测试状态码200
	content, err := client.GetPage("/status-200")
	if err != nil {
		t.Errorf("GetPage()对状态码200返回错误: %v", err)
	}
	if content != "状态码200" {
		t.Errorf("GetPage()对状态码200返回内容不匹配: 期望 '状态码200', 实际 '%s'", content)
	}

	// 测试状态码404
	content, err = client.GetPage("/status-404")
	if err != nil {
		t.Errorf("GetPage()对状态码404返回错误: %v", err)
	}
	if content != "状态码404" {
		t.Errorf("GetPage()对状态码404返回内容不匹配: 期望 '状态码404', 实际 '%s'", content)
	}

	// 测试状态码500 - 现在应该返回错误
	content, err = client.GetPage("/status-500")
	if err == nil {
		t.Error("GetPage()对状态码500应该返回错误")
	} else if !strings.Contains(err.Error(), "服务器错误") {
		t.Errorf("GetPage()对状态码500返回的错误不包含'服务器错误': %v", err)
	}

	// 测试状态码403
	content, err = client.GetPage("/status-403")
	if err != nil {
		t.Errorf("GetPage()对状态码403返回错误: %v", err)
	}
	if content != "状态码403" {
		t.Errorf("GetPage()对状态码403返回内容不匹配: 期望 '状态码403', 实际 '%s'", content)
	}

	// 测试空响应
	content, err = client.GetPage("/empty-response")
	if err != nil {
		t.Errorf("GetPage()对空响应返回错误: %v", err)
	}
	if content != "" {
		t.Errorf("GetPage()对空响应返回内容不为空: '%s'", content)
	}
}

func TestGetPageWithLargeContent(t *testing.T) {
	// 创建一个大字符串，大约1MB大小
	largeContent := strings.Repeat("测试大内容数据", 100000) // 约1MB的中文字符

	// 创建测试服务器
	testServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/large-content" {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(largeContent))
			return
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("默认响应"))
	}))
	defer testServer.Close()

	// 创建客户端
	client := NewClient(WithTimeout(10 * time.Second)) // 增加超时时间，处理大内容需要更多时间
	client.baseURL = testServer.URL

	// 测试大内容响应
	content, err := client.GetPage("/large-content")
	if err != nil {
		t.Fatalf("GetPage()对大内容返回错误: %v", err)
	}
	if len(content) != len(largeContent) {
		t.Errorf("GetPage()返回的大内容长度不匹配: 期望 %d, 实际 %d", len(largeContent), len(content))
	}
	if content != largeContent {
		t.Error("GetPage()返回的大内容与原始内容不一致")
	}
}

func TestGetPageWithDelay(t *testing.T) {
	// 创建测试服务器，带延迟
	testServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/delay" {
			// 延迟1秒
			time.Sleep(1 * time.Second)
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("延迟响应"))
			return
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("默认响应"))
	}))
	defer testServer.Close()

	// 创建正常超时的客户端（超时时间大于延迟）
	clientNormal := NewClient(WithTimeout(2 * time.Second))
	clientNormal.baseURL = testServer.URL

	// 测试延迟响应（应该成功）
	startTime := time.Now()
	content, err := clientNormal.GetPage("/delay")
	elapsed := time.Since(startTime)

	if err != nil {
		t.Fatalf("GetPage()对延迟响应返回错误: %v", err)
	}
	if content != "延迟响应" {
		t.Errorf("GetPage()对延迟响应返回内容不匹配: 期望 '延迟响应', 实际 '%s'", content)
	}
	if elapsed < 1*time.Second {
		t.Errorf("GetPage()对延迟响应时间过短: %v", elapsed)
	}

	// 创建短超时的客户端（超时时间小于延迟）
	clientShort := NewClient(WithTimeout(500 * time.Millisecond))
	clientShort.baseURL = testServer.URL

	// 测试延迟响应（应该超时）
	_, err = clientShort.GetPage("/delay")
	if err == nil {
		t.Fatal("GetPage()对延迟响应应该返回超时错误，但未返回")
	}
	// 检查错误是否与超时有关
	if !strings.Contains(err.Error(), "timeout") && !strings.Contains(err.Error(), "deadline") {
		t.Errorf("GetPage()对延迟响应返回的错误不是超时错误: %v", err)
	}
}

func TestGetPageWithCustomHeaders(t *testing.T) {
	// 创建测试服务器，验证请求头
	testServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// 记录请求头
		headers := make(map[string]string)

		// 检查关键请求头
		userAgent := r.Header.Get("User-Agent")
		headers["User-Agent"] = userAgent

		accept := r.Header.Get("Accept")
		headers["Accept"] = accept

		acceptLanguage := r.Header.Get("Accept-Language")
		headers["Accept-Language"] = acceptLanguage

		// 检查自定义头
		customHeader := r.Header.Get("X-Custom-Header")
		headers["X-Custom-Header"] = customHeader

		// 将请求头信息返回为JSON
		headerJSON, _ := json.Marshal(headers)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write(headerJSON)
	}))
	defer testServer.Close()

	// 创建客户端并设置自定义头
	client := NewClient(
		WithTimeout(5*time.Second),
		WithHeader("X-Custom-Header", "TestValue"),
	)
	client.baseURL = testServer.URL

	// 获取响应
	content, err := client.GetPage("/check-headers")
	if err != nil {
		t.Fatalf("GetPage()获取请求头信息失败: %v", err)
	}

	// 解析响应中的请求头信息
	var headers map[string]string
	if err := json.Unmarshal([]byte(content), &headers); err != nil {
		t.Fatalf("解析请求头JSON失败: %v", err)
	}

	// 验证User-Agent
	if userAgent := headers["User-Agent"]; userAgent == "" {
		t.Error("请求中未设置User-Agent")
	} else if !strings.Contains(userAgent, "Mozilla") {
		t.Errorf("User-Agent格式不正确: %s", userAgent)
	}

	// 验证Accept
	if accept := headers["Accept"]; accept == "" {
		t.Error("请求中未设置Accept")
	} else if !strings.Contains(accept, "text/html") {
		t.Errorf("Accept格式不正确: %s", accept)
	}

	// 验证Accept-Language
	if acceptLanguage := headers["Accept-Language"]; acceptLanguage == "" {
		t.Error("请求中未设置Accept-Language")
	} else if !strings.Contains(acceptLanguage, "en-US") {
		t.Errorf("Accept-Language格式不正确: %s", acceptLanguage)
	}

	// 验证自定义头
	if customHeader := headers["X-Custom-Header"]; customHeader != "TestValue" {
		t.Errorf("自定义请求头不匹配: 期望 'TestValue', 实际 '%s'", customHeader)
	}
}

func TestGetPageWithChineseContent(t *testing.T) {
	// 创建带中文内容的测试服务器
	testServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/chinese" {
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("中文内容测试，包含特殊字符：！@#￥%……&*（）"))
			return
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("默认响应"))
	}))
	defer testServer.Close()

	// 创建客户端
	client := NewClient(WithTimeout(5 * time.Second))
	client.baseURL = testServer.URL

	// 测试中文内容
	content, err := client.GetPage("/chinese")
	if err != nil {
		t.Fatalf("GetPage()获取中文内容失败: %v", err)
	}

	expectedContent := "中文内容测试，包含特殊字符：！@#￥%……&*（）"
	if content != expectedContent {
		t.Errorf("GetPage()返回的中文内容不匹配:\n期望: '%s'\n实际: '%s'", expectedContent, content)
	}

	// 验证字符长度
	if len([]rune(content)) != len([]rune(expectedContent)) {
		t.Errorf("GetPage()返回的中文字符长度不匹配: 期望 %d, 实际 %d",
			len([]rune(expectedContent)), len([]rune(content)))
	}
}

func TestGetPageWithMalformedURL(t *testing.T) {
	// 创建客户端
	client := NewClient(WithTimeout(5 * time.Second))
	client.baseURL = "https://example.com"

	// 测试各种畸形URL情况
	testCases := []struct {
		name      string
		path      string
		shouldErr bool
	}{
		{"空路径", "", false},
		{"只有斜杠", "/", false},
		{"重复斜杠", "//test//path", false},
		{"URL编码字符", "/test%20path", false},
		{"包含查询参数", "/test?param=value", false},
		{"包含锚点", "/test#section", false},
		{"包含特殊字符", "/test!@#$%^&*()", false},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := client.GetPage(tc.path)
			// 注意：这些URL实际上是有效的，但会连接到真实服务器并失败
			// 我们只需验证URL构造部分不会出错
			if tc.shouldErr && err == nil {
				t.Errorf("GetPage(%q)应该返回错误，但未返回", tc.path)
			}
		})
	}
}

func TestGetPageWithNoBaseURL(t *testing.T) {
	// 创建一个没有baseURL的客户端
	client := NewClient()
	client.baseURL = ""

	// 尝试获取页面
	_, err := client.GetPage("/test")
	if err == nil {
		t.Error("GetPage()在没有baseURL的情况下应该返回错误，但未返回")
	}

	if !strings.Contains(err.Error(), "baseURL未设置") {
		t.Errorf("错误消息不匹配: 期望包含 'baseURL未设置', 实际 '%s'", err.Error())
	}
}

func TestRetryMechanism(t *testing.T) {
	// 创建一个测试服务器，前两次请求返回错误，第三次返回成功
	requestCount := 0
	testServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/retry-test" {
			requestCount++
			if requestCount <= 2 {
				// 前两次请求返回服务器错误
				w.WriteHeader(http.StatusServiceUnavailable)
				w.Write([]byte("服务暂时不可用"))
				return
			}
			// 第三次请求返回成功
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("重试成功"))
			return
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("默认响应"))
	}))
	defer testServer.Close()

	// 创建客户端，设置重试参数
	client := NewClient(
		WithRetry(2, 10*time.Millisecond), // 设置为2次重试，总共最多3次请求
	)
	client.baseURL = testServer.URL

	// 测试重试机制
	content, err := client.GetPage("/retry-test")
	if err != nil {
		t.Fatalf("重试后GetPage()仍然返回错误: %v", err)
	}

	if content != "重试成功" {
		t.Errorf("重试后返回内容不匹配: 期望 '重试成功', 实际 '%s'", content)
	}

	// 验证请求次数
	if requestCount != 3 {
		t.Errorf("请求次数不匹配: 期望 3, 实际 %d", requestCount)
	}
}
