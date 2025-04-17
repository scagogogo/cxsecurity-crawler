package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
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

func main() {
	// 设置API基础URL和认证Token
	baseURL := "http://localhost:8080"
	token := "your-api-token-here"

	// 创建搜索请求
	// 这里我们搜索包含"XSS"关键词的漏洞
	params := url.Values{}
	params.Add("keyword", "XSS")

	// 构建完整的URL
	searchURL := fmt.Sprintf("%s/api/search?%s", baseURL, params.Encode())

	// 创建HTTP请求
	req, err := http.NewRequest("GET", searchURL, nil)
	if err != nil {
		fmt.Printf("创建请求失败: %v\n", err)
		return
	}

	// 添加认证Token
	req.Header.Add("X-API-Token", token)

	// 发送请求
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		fmt.Printf("发送请求失败: %v\n", err)
		return
	}
	defer resp.Body.Close()

	// 读取响应内容
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		fmt.Printf("读取响应失败: %v\n", err)
		return
	}

	// 解析JSON响应
	var result SearchResult
	if err := json.Unmarshal(body, &result); err != nil {
		fmt.Printf("解析JSON失败: %v\n", err)
		return
	}

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

总共找到 15 条结果
当前页码: 1, 总页数: 2

标题: WordPress Plugin Simple File List 4.2.2 - Stored Cross-Site Scripting
日期: 2024-03-15
风险等级: Medium
标签: [XSS WordPress Plugin CVE-2024-25833]
作者: Vulnerability Lab
详情链接: https://cxsecurity.com/issue/WLB-2024030xxx
描述: A vulnerability was discovered in WordPress Plugin Simple File List and classified as problematic...
----------------------------------------
标题: WordPress Plugin Pipe - Stored Cross-Site Scripting
日期: 2024-03-14
风险等级: Medium
标签: [XSS WordPress Plugin]
作者: WPScan
详情链接: https://cxsecurity.com/issue/WLB-2024030xxx
描述: A vulnerability classified as critical was found in WordPress Plugin Pipe...
----------------------------------------
... (更多结果)
*/
