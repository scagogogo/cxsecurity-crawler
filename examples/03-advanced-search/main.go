package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

// SearchResult 定义了搜索结果的数据结构
type SearchResult struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	Data    struct {
		Items []struct {
			ID          string   `json:"id"`
			Title       string   `json:"title"`
			Date        string   `json:"date"`
			Risk        string   `json:"risk"`
			Tags        []string `json:"tags"`
			Author      string   `json:"author"`
			AuthorID    string   `json:"author_id"`
			DetailURL   string   `json:"detail_url"`
			AuthorURL   string   `json:"author_url"`
			Description string   `json:"description"`
		} `json:"items"`
		Total     int `json:"total"`
		Page      int `json:"page"`
		TotalPage int `json:"total_page"`
	} `json:"data"`
}

// SearchOptions 定义搜索选项
type SearchOptions struct {
	Keyword   string   // 搜索关键词
	Page      int      // 页码
	PerPage   int      // 每页结果数
	SortOrder string   // 排序方式：ASC或DESC
	Tags      []string // 标签过滤
	Risk      string   // 风险等级过滤
}

// 执行高级搜索
func advancedSearch(baseURL, token string, options SearchOptions) (*SearchResult, error) {
	// 构建查询参数
	params := url.Values{}
	params.Add("keyword", options.Keyword)
	params.Add("page", fmt.Sprintf("%d", options.Page))
	params.Add("per_page", fmt.Sprintf("%d", options.PerPage))
	params.Add("sort_order", options.SortOrder)

	// 如果指定了标签，添加标签过滤
	if len(options.Tags) > 0 {
		params.Add("tags", strings.Join(options.Tags, ","))
	}

	// 如果指定了风险等级，添加风险等级过滤
	if options.Risk != "" {
		params.Add("risk", options.Risk)
	}

	// 构建完整URL
	searchURL := fmt.Sprintf("%s/api/search?%s", baseURL, params.Encode())

	// 创建请求
	req, err := http.NewRequest("GET", searchURL, nil)
	if err != nil {
		return nil, fmt.Errorf("创建请求失败: %v", err)
	}

	// 添加认证Token
	req.Header.Add("X-API-Token", token)

	// 发送请求
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("发送请求失败: %v", err)
	}
	defer resp.Body.Close()

	// 读取响应
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("读取响应失败: %v", err)
	}

	// 解析JSON
	var result SearchResult
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("解析JSON失败: %v", err)
	}

	return &result, nil
}

func main() {
	// 设置API参数
	baseURL := "http://localhost:8080"
	token := "your-api-token-here"

	// 创建高级搜索选项
	options := SearchOptions{
		Keyword:   "WordPress",            // 搜索WordPress相关漏洞
		Page:      1,                      // 第一页
		PerPage:   10,                     // 每页10条结果
		SortOrder: "DESC",                 // 按时间降序排序
		Tags:      []string{"RCE", "XSS"}, // 只显示包含RCE或XSS标签的结果
		Risk:      "High",                 // 只显示高风险漏洞
	}

	// 执行高级搜索
	result, err := advancedSearch(baseURL, token, options)
	if err != nil {
		fmt.Printf("搜索失败: %v\n", err)
		return
	}

	// 打印搜索条件
	fmt.Println("=== 搜索条件 ===")
	fmt.Printf("关键词: %s\n", options.Keyword)
	fmt.Printf("标签过滤: %v\n", options.Tags)
	fmt.Printf("风险等级: %s\n", options.Risk)
	fmt.Printf("排序方式: %s\n\n", options.SortOrder)

	// 打印搜索结果
	fmt.Printf("总共找到 %d 条结果\n", result.Data.Total)
	fmt.Printf("当前页码: %d, 总页数: %d\n\n", result.Data.Page, result.Data.TotalPage)

	// 打印每条结果的详细信息
	for _, item := range result.Data.Items {
		fmt.Printf("标题: %s\n", item.Title)
		fmt.Printf("日期: %s\n", item.Date)
		fmt.Printf("风险等级: %s\n", item.Risk)
		fmt.Printf("标签: %v\n", item.Tags)
		fmt.Printf("作者: %s\n", item.Author)
		fmt.Printf("详情链接: %s\n", item.DetailURL)
		fmt.Printf("描述: %s\n", item.Description)
		fmt.Println("----------------------------------------")
	}
}

/*
示例输出：

=== 搜索条件 ===
关键词: WordPress
标签过滤: [RCE XSS]
风险等级: High
排序方式: DESC

总共找到 8 条结果
当前页码: 1, 总页数: 1

标题: WordPress Plugin Advanced Custom Fields 6.2.3 - Remote Code Execution
日期: 2024-03-18
风险等级: High
标签: [WordPress Plugin RCE CVE-2024-25832]
作者: Security Research Team
详情链接: https://cxsecurity.com/issue/WLB-2024030xxx
描述: A critical vulnerability was discovered in WordPress Plugin Advanced Custom Fields...
----------------------------------------
标题: WordPress Plugin Contact Form 7 - Stored Cross-Site Scripting
日期: 2024-03-17
风险等级: High
标签: [WordPress Plugin XSS CVE-2024-25834]
作者: Web Security Team
详情链接: https://cxsecurity.com/issue/WLB-2024030xxx
描述: A high-risk stored XSS vulnerability was found in the popular Contact Form 7 plugin...
----------------------------------------
... (更多结果)
*/
