package crawler

import (
	"errors"
	"io"
	"net/http"
	"net/url"
	"time"
)

// HTTPClient 定义HTTP客户端接口，用于发送HTTP请求和获取页面内容。
// 这个接口的设计目的是将HTTP请求逻辑与爬虫逻辑分离，便于测试和扩展。
//
// 接口包含两个主要方法：
// 1. GetPage: 获取指定路径的页面内容
// 2. GetBaseURL: 获取基础URL
//
// 实现这个接口时需要注意：
// - 处理HTTP错误和重试逻辑
// - 设置适当的请求头和超时
// - 处理不同的响应状态码
type HTTPClient interface {
	// GetPage 获取指定路径的页面内容
	// 参数:
	//   - path: 相对于baseURL的路径
	// 返回值:
	//   - string: 页面的HTML内容
	//   - error: 请求过程中的错误
	GetPage(path string) (string, error)

	// GetBaseURL 获取基础URL
	// 返回值:
	//   - string: 网站的基础URL
	GetBaseURL() string
}

// ClientOption 是设置Client选项的函数类型
// 使用函数选项模式来配置Client实例，支持链式调用
// 例如：
//
//	client := NewClient(
//	    WithTimeout(30*time.Second),
//	    WithProxy("http://proxy.example.com"),
//	    WithRetry(3, 500*time.Millisecond),
//	)
type ClientOption func(*Client)

// Client 是一个功能强大的HTTP客户端，专门用于爬取网页内容。
// 它提供了丰富的配置选项和容错机制，确保稳定可靠的网页获取。
//
// 主要特性：
// 1. 超时控制：可配置请求超时时间，防止请求阻塞
// 2. 代理支持：支持HTTP/HTTPS代理，便于绕过访问限制
// 3. 自动重试：遇到临时错误时自动重试，提高成功率
// 4. 自定义请求头：支持添加自定义HTTP头，模拟浏览器行为
//
// 使用示例：
//
//	client := NewClient(
//	    WithTimeout(30*time.Second),
//	    WithRetry(3, 500*time.Millisecond),
//	)
//	content, err := client.GetPage("/path")
//	if err != nil {
//	    log.Fatal(err)
//	}
//	fmt.Println(content)
//
// 注意事项：
// 1. 请求失败时会自动重试，直到达到最大重试次数
// 2. 每次重试之间有可配置的延迟时间
// 3. 支持处理各种HTTP状态码，包括重定向
// 4. 自动处理响应编码，确保正确解析页面内容
type Client struct {
	client        *http.Client      // 标准HTTP客户端
	baseURL       string            // 网站基础URL
	maxRetries    int               // 最大重试次数
	retryDelay    time.Duration     // 重试间隔时间
	customHeaders map[string]string // 自定义HTTP头
}

// WithTimeout 设置客户端超时时间
// 超时时间包括连接建立、请求发送和响应接收的总时间。
// 如果请求超过设定时间，将返回超时错误。
//
// 参数:
//   - timeout: 超时时间，例如 30 * time.Second
//
// 返回值:
//   - ClientOption: 返回一个配置函数
//
// 示例:
//
//	client := NewClient(WithTimeout(30 * time.Second))
func WithTimeout(timeout time.Duration) ClientOption {
	return func(c *Client) {
		c.client.Timeout = timeout
	}
}

// WithProxy 设置HTTP代理
// 支持HTTP和HTTPS代理，用于访问需要代理的网站。
// 如果代理URL无效，将忽略该设置。
//
// 参数:
//   - proxyURL: 代理服务器URL，例如 "http://proxy.example.com:8080"
//
// 返回值:
//   - ClientOption: 返回一个配置函数
//
// 示例:
//
//	client := NewClient(WithProxy("http://proxy.example.com:8080"))
func WithProxy(proxyURL string) ClientOption {
	return func(c *Client) {
		if proxyURL != "" {
			proxy, err := url.Parse(proxyURL)
			if err == nil {
				c.client.Transport = &http.Transport{
					Proxy: http.ProxyURL(proxy),
				}
			}
		}
	}
}

// WithRetry 设置重试参数
// 当请求失败时（如服务器错误、网络超时等），将自动重试。
// 每次重试之间会等待指定的延迟时间。
//
// 参数:
//   - maxRetries: 最大重试次数，建议设置为3-5
//   - retryDelay: 重试间隔时间，建议设置为500ms-1s
//
// 返回值:
//   - ClientOption: 返回一个配置函数
//
// 示例:
//
//	client := NewClient(WithRetry(3, 500 * time.Millisecond))
func WithRetry(maxRetries int, retryDelay time.Duration) ClientOption {
	return func(c *Client) {
		if maxRetries > 0 {
			c.maxRetries = maxRetries
		}
		if retryDelay > 0 {
			c.retryDelay = retryDelay
		}
	}
}

// WithHeader 添加自定义HTTP头
// 可以添加多个自定义头，用于模拟浏览器行为或满足特定的请求要求。
// 如果key已存在，value将被覆盖。
//
// 参数:
//   - key: HTTP头名称，例如 "User-Agent"
//   - value: HTTP头值，例如 "Mozilla/5.0 ..."
//
// 返回值:
//   - ClientOption: 返回一个配置函数
//
// 示例:
//
//	client := NewClient(
//	    WithHeader("User-Agent", "Custom Agent"),
//	    WithHeader("Accept-Language", "zh-CN,zh;q=0.9"),
//	)
func WithHeader(key, value string) ClientOption {
	return func(c *Client) {
		if c.customHeaders == nil {
			c.customHeaders = make(map[string]string)
		}
		c.customHeaders[key] = value
	}
}

// NewClient 创建一个新的Client实例
// 默认配置:
//   - 超时时间: 30秒
//   - 基础URL: https://cxsecurity.com
//   - 最大重试次数: 3
//   - 重试间隔: 500毫秒
//   - 基本请求头: User-Agent, Accept, Accept-Language
//
// 参数:
//   - options: 配置选项列表，可以组合多个选项
//
// 返回值:
//   - *Client: 新创建的客户端实例
//
// 示例:
//
//	// 创建默认配置的客户端
//	client := NewClient()
//
//	// 创建自定义配置的客户端
//	client := NewClient(
//	    WithTimeout(30 * time.Second),
//	    WithProxy("http://proxy.example.com:8080"),
//	    WithRetry(3, 500 * time.Millisecond),
//	    WithHeader("User-Agent", "Custom Agent"),
//	)
func NewClient(options ...ClientOption) *Client {
	client := &Client{
		client: &http.Client{
			Timeout: 30 * time.Second,
		},
		baseURL:    "https://cxsecurity.com",
		maxRetries: 3,
		retryDelay: 500 * time.Millisecond,
	}

	// 应用选项
	for _, option := range options {
		option(client)
	}

	return client
}

// GetBaseURL 返回客户端配置的基础URL
// 这个URL用于构建完整的请求URL。
//
// 返回值:
//   - string: 网站的基础URL，例如 "https://cxsecurity.com"
func (c *Client) GetBaseURL() string {
	return c.baseURL
}

// GetPage 获取指定URL的页面内容
// 这个方法会自动处理重试、超时和错误。
//
// 功能：
// 1. 自动重试失败的请求
// 2. 处理HTTP状态码
// 3. 设置必要的请求头
// 4. 支持自定义请求头
//
// 参数:
//   - path: 相对于baseURL的路径，例如 "/exploit/1"
//
// 返回值:
//   - string: 页面的HTML内容
//   - error: 请求过程中的错误，包括：
//   - 网络错误
//   - 超时错误
//   - 服务器错误（5xx）
//   - URL错误
//
// 示例:
//
//	content, err := client.GetPage("/exploit/1")
//	if err != nil {
//	    log.Fatal(err)
//	}
//	fmt.Println(content)
func (c *Client) GetPage(path string) (string, error) {
	// 检查baseURL是否为空
	if c.baseURL == "" {
		return "", errors.New("baseURL未设置")
	}

	// 添加重试机制
	var lastErr error
	for attempt := 0; attempt <= c.maxRetries; attempt++ {
		if attempt > 0 {
			// 如果不是第一次尝试，则等待一段时间
			time.Sleep(c.retryDelay)
		}

		content, err := c.doRequest(path)
		if err == nil {
			return content, nil
		}
		lastErr = err
	}

	return "", lastErr
}

// doRequest 执行HTTP请求
// 内部方法，处理单次HTTP请求的具体逻辑。
//
// 功能：
// 1. 设置标准请求头
//   - User-Agent: 模拟浏览器
//   - Accept: 支持的内容类型
//   - Accept-Language: 语言偏好
//
// 2. 添加自定义请求头
// 3. 处理响应状态码
//   - 2xx: 成功
//   - 3xx: 重定向（自动处理）
//   - 4xx: 客户端错误
//   - 5xx: 服务器错误（需要重试）
//
// 参数:
//   - path: 相对于baseURL的路径
//
// 返回值:
//   - string: 页面的HTML内容
//   - error: 请求过程中的错误
//
// 注意事项：
// 1. 5xx错误会触发重试机制
// 2. 4xx错误会返回错误页面内容
// 3. 重定向会自动处理
func (c *Client) doRequest(path string) (string, error) {
	url := c.baseURL + path

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return "", err
	}

	// 设置基本的请求头，模拟浏览器行为
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36")
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8")
	req.Header.Set("Accept-Language", "en-US,en;q=0.5")

	// 设置自定义请求头
	for key, value := range c.customHeaders {
		req.Header.Set(key, value)
	}

	resp, err := c.client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	// 读取响应内容
	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	// 检查状态码，某些状态码需要重试
	if resp.StatusCode >= 500 && resp.StatusCode < 600 {
		return "", errors.New("服务器错误: " + resp.Status)
	}

	return string(bodyBytes), nil
}
