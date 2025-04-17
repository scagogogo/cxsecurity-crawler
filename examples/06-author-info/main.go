package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
)

// AuthorProfile 定义了作者信息的数据结构
type AuthorProfile struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	Data    struct {
		ID              string `json:"id"`             // 作者ID
		Name            string `json:"name"`           // 作者名称
		Country         string `json:"country"`        // 国家
		CountryCode     string `json:"country_code"`   // 国家代码
		ReportedCount   int    `json:"reported_count"` // 报告漏洞数量
		Twitter         string `json:"twitter"`        // Twitter账号
		Website         string `json:"website"`        // 个人网站
		ZoneH           string `json:"zone_h"`         // Zone-H档案
		Description     string `json:"description"`    // 作者描述
		Vulnerabilities []struct {
			ID        string   `json:"id"`         // 漏洞ID
			Title     string   `json:"title"`      // 漏洞标题
			Date      string   `json:"date"`       // 发布日期
			Risk      string   `json:"risk"`       // 风险等级
			Tags      []string `json:"tags"`       // 标签
			DetailURL string   `json:"detail_url"` // 详情链接
		} `json:"vulnerabilities"` // 作者报告的漏洞列表
		CurrentPage int `json:"current_page"` // 当前页码
		TotalPages  int `json:"total_pages"`  // 总页数
	} `json:"data"`
}

func main() {
	// 设置API参数
	baseURL := "http://localhost:8080"
	token := "your-api-token-here"
	authorID := "SRT-2024" // 示例作者ID

	// 构建请求URL
	authorURL := fmt.Sprintf("%s/api/author/%s", baseURL, authorID)

	// 创建HTTP请求
	req, err := http.NewRequest("GET", authorURL, nil)
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
	var profile AuthorProfile
	if err := json.Unmarshal(body, &profile); err != nil {
		fmt.Printf("解析JSON失败: %v\n", err)
		return
	}

	// 打印作者基本信息
	fmt.Println("=== 作者信息 ===")
	fmt.Printf("ID: %s\n", profile.Data.ID)
	fmt.Printf("名称: %s\n", profile.Data.Name)
	fmt.Printf("国家: %s (%s)\n", profile.Data.Country, profile.Data.CountryCode)
	fmt.Printf("报告漏洞数量: %d\n", profile.Data.ReportedCount)

	if profile.Data.Twitter != "" {
		fmt.Printf("Twitter: %s\n", profile.Data.Twitter)
	}
	if profile.Data.Website != "" {
		fmt.Printf("个人网站: %s\n", profile.Data.Website)
	}
	if profile.Data.ZoneH != "" {
		fmt.Printf("Zone-H档案: %s\n", profile.Data.ZoneH)
	}

	if profile.Data.Description != "" {
		fmt.Println("\n=== 作者描述 ===")
		fmt.Println(profile.Data.Description)
	}

	// 打印作者报告的漏洞
	fmt.Printf("\n=== 报告的漏洞 (第 %d 页，共 %d 页) ===\n",
		profile.Data.CurrentPage, profile.Data.TotalPages)

	for _, vuln := range profile.Data.Vulnerabilities {
		fmt.Printf("\n标题: %s\n", vuln.Title)
		fmt.Printf("ID: %s\n", vuln.ID)
		fmt.Printf("日期: %s\n", vuln.Date)
		fmt.Printf("风险等级: %s\n", vuln.Risk)
		fmt.Printf("标签: %v\n", vuln.Tags)
		fmt.Printf("详情链接: %s\n", vuln.DetailURL)
		fmt.Println("----------------------------------------")
	}
}

/*
示例输出：

=== 作者信息 ===
ID: SRT-2024
名称: Security Research Team
国家: United States (US)
报告漏洞数量: 156
Twitter: @SecurityResearchTeam
个人网站: https://security-research.team
Zone-H档案: http://zone-h.org/archive/notifier=SRT

=== 作者描述 ===
专注于Web应用安全研究的独立安全团队。我们致力于发现和报告各类Web应用程序中的安全漏洞，
帮助开发者构建更安全的应用。

=== 报告的漏洞 (第 1 页，共 8 页) ===

标题: Apache OFBiz 18.12.09 Remote Code Execution
ID: WLB-2024030123
日期: 2024-03-20
风险等级: High
标签: [RCE Apache CVE-2024-12345]
详情链接: https://cxsecurity.com/issue/WLB-2024030123
----------------------------------------
标题: WordPress Plugin Advanced Custom Fields 6.2.3 - Remote Code Execution
ID: WLB-2024030124
日期: 2024-03-18
风险等级: High
标签: [WordPress Plugin RCE CVE-2024-25832]
详情链接: https://cxsecurity.com/issue/WLB-2024030124
----------------------------------------
... (更多结果)
*/
