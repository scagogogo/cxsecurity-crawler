package model

import (
	"time"
)

// CveDetail 表示一个CVE详情页面的数据结构
type CveDetail struct {
	// 基本信息
	CveID       string    `json:"cve_id,omitempty"`      // CVE编号
	Published   time.Time `json:"published,omitempty"`   // 发布日期
	Modified    time.Time `json:"modified,omitempty"`    // 最后修改日期
	Description string    `json:"description,omitempty"` // 漏洞描述

	// 类型信息
	Type string `json:"type,omitempty"` // 漏洞类型

	// CVSS评分
	CvssBaseScore    float64 `json:"cvss_base_score,omitempty"`    // CVSS基础评分
	CvssImpactScore  float64 `json:"cvss_impact_score,omitempty"`  // CVSS影响评分
	CvssExploitScore float64 `json:"cvss_exploit_score,omitempty"` // CVSS可利用性评分

	// 漏洞属性
	ExploitRange          string `json:"exploit_range,omitempty"`          // 利用范围
	AttackComplexity      string `json:"attack_complexity,omitempty"`      // 攻击复杂度
	Authentication        string `json:"authentication,omitempty"`         // 认证需求
	ConfidentialityImpact string `json:"confidentiality_impact,omitempty"` // 机密性影响
	IntegrityImpact       string `json:"integrity_impact,omitempty"`       // 完整性影响
	AvailabilityImpact    string `json:"availability_impact,omitempty"`    // 可用性影响

	// 受影响的软件
	AffectedSoftware []AffectedSoftware `json:"affected_software,omitempty"` // 受影响的软件列表

	// 相关链接
	References []string `json:"references,omitempty"` // 相关参考链接

	// 相关漏洞
	RelatedVulnerabilities []Vulnerability `json:"related_vulnerabilities,omitempty"` // 相关漏洞列表
}

// AffectedSoftware 表示受影响的软件
type AffectedSoftware struct {
	VendorName  string `json:"vendor_name,omitempty"`  // 厂商名称
	VendorURL   string `json:"vendor_url,omitempty"`   // 厂商URL
	ProductName string `json:"product_name,omitempty"` // 产品名称
	ProductURL  string `json:"product_url,omitempty"`  // 产品URL
}
