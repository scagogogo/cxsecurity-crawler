package model

import (
	"encoding/json"
)

// AuthorProfile 表示作者的个人资料信息
type AuthorProfile struct {
	// 基本信息
	ID            string `json:"id,omitempty"`             // 作者ID
	Name          string `json:"name,omitempty"`           // 作者名称
	Country       string `json:"country,omitempty"`        // 国家
	CountryCode   string `json:"country_code,omitempty"`   // 国家代码
	ReportedCount int    `json:"reported_count,omitempty"` // 报告数量

	// 联系信息
	Twitter     string `json:"twitter,omitempty"`     // Twitter链接
	Website     string `json:"website,omitempty"`     // 个人网站
	ZoneH       string `json:"zone_h,omitempty"`      // Zone-H链接
	Description string `json:"description,omitempty"` // 个人描述

	// 漏洞列表
	Vulnerabilities []Vulnerability `json:"vulnerabilities,omitempty"` // 漏洞列表
	CurrentPage     int             `json:"current_page,omitempty"`    // 当前页码
	TotalPages      int             `json:"total_pages,omitempty"`     // 总页数
}

// MarshalJSON 自定义JSON序列化方法
func (a AuthorProfile) MarshalJSON() ([]byte, error) {
	type Alias AuthorProfile
	aux := &struct {
		*Alias
	}{
		Alias: (*Alias)(&a),
	}

	return json.Marshal(aux)
}

// Author 表示一个作者的信息
type Author struct {
	// 作者名称
	Name string `json:"name"`

	// 作者所在国家
	Country string `json:"country"`

	// 作者报告的研究数量
	ReportedResearchCount int `json:"reported_research_count"`

	// 作者发布的漏洞列表
	Vulnerabilities []AuthorVulnerability `json:"vulnerabilities"`
}

// AuthorVulnerability 表示作者发布的一个漏洞
type AuthorVulnerability struct {
	// 漏洞发布日期
	Date string `json:"date"`

	// 漏洞标题
	Title string `json:"title"`

	// 漏洞详情页URL
	URL string `json:"url"`

	// 漏洞风险等级
	RiskLevel string `json:"risk_level"`

	// 漏洞标签
	Tags []string `json:"tags"`
}
