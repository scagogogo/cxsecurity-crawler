package crawler

import (
	"errors"
	"io"
	"net/http"
	"net/url"
	"time"
)

// HTTPClient 定义HTTP客户端接口，便于测试
type HTTPClient interface {
	GetPage(path string) (string, error)
	GetBaseURL() string
}

// ClientOption 是设置Client选项的函数类型
type ClientOption func(*Client)

// Client 是一个包装了http.Client的客户端，用于请求页面内容
type Client struct {
	client        *http.Client
	baseURL       string
	maxRetries    int
	retryDelay    time.Duration
	customHeaders map[string]string
}

// WithTimeout 设置客户端超时时间
func WithTimeout(timeout time.Duration) ClientOption {
	return func(c *Client) {
		c.client.Timeout = timeout
	}
}

// WithProxy 设置HTTP代理
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
func WithHeader(key, value string) ClientOption {
	return func(c *Client) {
		if c.customHeaders == nil {
			c.customHeaders = make(map[string]string)
		}
		c.customHeaders[key] = value
	}
}

// NewClient 创建一个新的Client实例
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

// GetBaseURL 返回基础URL
func (c *Client) GetBaseURL() string {
	return c.baseURL
}

// GetPage 获取指定URL的页面内容
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
