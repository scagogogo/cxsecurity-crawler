package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"
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

// 执行搜索请求并返回结果
func search(baseURL, token, keyword string, page int, perPage int) (*SearchResult, error) {
	// 构建查询参数
	params := url.Values{}
	params.Add("keyword", keyword)
	params.Add("page", fmt.Sprintf("%d", page))
	params.Add("per_page", fmt.Sprintf("%d", perPage))

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
	keyword := "RCE"
	perPage := 30 // 每页显示30条结果

	// 获取第一页结果
	result, err := search(baseURL, token, keyword, 1, perPage)
	if err != nil {
		fmt.Printf("搜索失败: %v\n", err)
		return
	}

	// 打印总体信息
	fmt.Printf("搜索关键词: %s\n", keyword)
	fmt.Printf("总共找到: %d 条结果\n", result.Data.Total)
	fmt.Printf("总页数: %d\n\n", result.Data.TotalPage)

	// 遍历所有页面
	for page := 1; page <= result.Data.TotalPage; page++ {
		if page > 1 {
			// 获取下一页结果
			result, err = search(baseURL, token, keyword, page, perPage)
			if err != nil {
				fmt.Printf("获取第 %d 页失败: %v\n", page, err)
				continue
			}
			// 在请求之间添加短暂延时，避免请求过于频繁
			time.Sleep(time.Second)
		}

		fmt.Printf("=== 第 %d 页结果 ===\n", page)
		// 打印当前页的结果
		for _, item := range result.Data.Items {
			fmt.Printf("标题: %s\n", item.Title)
			fmt.Printf("日期: %s\n", item.Date)
			fmt.Printf("风险等级: %s\n", item.Risk)
			fmt.Printf("作者: %s\n", item.Author)
			fmt.Println("----------------------------------------")
		}
	}
}

/*
示例输出：

搜索关键词: RCE
总共找到: 45 条结果
总页数: 2

=== 第 1 页结果 ===
标题: Apache OFBiz 18.12.09 Remote Code Execution
日期: 2024-03-20
风险等级: High
作者: John Smith
----------------------------------------
标题: Fortinet FortiOS - Remote Code Execution
日期: 2024-03-19
风险等级: Critical
作者: Security Team
----------------------------------------
... (更多结果)

=== 第 2 页结果 ===
标题: Jenkins Pipeline Remote Code Execution
日期: 2024-03-10
风险等级: High
作者: Security Researcher
----------------------------------------
... (更多结果)
*/
