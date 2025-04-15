package model

import (
	"encoding/json"
	"testing"
	"time"
)

func TestCveDetailJSON(t *testing.T) {
	// 创建测试用的时间
	publishedTime, _ := time.Parse("2006-01-02", "2023-01-15")
	modifiedTime, _ := time.Parse("2006-01-02", "2023-02-20")

	// 创建一个完整的CveDetail对象
	cveDetail := CveDetail{
		CveID:       "CVE-2023-1234",
		Published:   publishedTime,
		Modified:    modifiedTime,
		Description: "这是一个测试用的CVE描述",
		Type:        "CWE-79",

		CvssBaseScore:    7.5,
		CvssImpactScore:  8.0,
		CvssExploitScore: 6.8,

		ExploitRange:          "Remote",
		AttackComplexity:      "Low",
		Authentication:        "None",
		ConfidentialityImpact: "Partial",
		IntegrityImpact:       "Complete",
		AvailabilityImpact:    "Partial",

		AffectedSoftware: []AffectedSoftware{
			{
				VendorName:  "测试厂商",
				VendorURL:   "https://example.com/vendor/1",
				ProductName: "测试产品",
				ProductURL:  "https://example.com/product/1",
			},
			{
				VendorName:  "测试厂商2",
				VendorURL:   "https://example.com/vendor/2",
				ProductName: "测试产品2",
				ProductURL:  "https://example.com/product/2",
			},
		},

		References: []string{
			"https://example.com/ref/1",
			"https://example.com/ref/2",
		},

		RelatedVulnerabilities: []Vulnerability{
			{
				Title:     "相关漏洞1",
				RiskLevel: "High",
				Date:      publishedTime,
			},
		},
	}

	// 1. 测试序列化
	bytes, err := json.Marshal(cveDetail)
	if err != nil {
		t.Fatalf("序列化CVE详情失败: %v", err)
	}

	// 2. 测试反序列化
	var decodedCve CveDetail
	if err := json.Unmarshal(bytes, &decodedCve); err != nil {
		t.Fatalf("反序列化CVE详情失败: %v", err)
	}

	// 3. 验证基本字段
	if decodedCve.CveID != "CVE-2023-1234" {
		t.Errorf("CVE ID不匹配: 期望 CVE-2023-1234, 实际 %s", decodedCve.CveID)
	}

	if decodedCve.Published.Format("2006-01-02") != "2023-01-15" {
		t.Errorf("发布日期不匹配: 期望 2023-01-15, 实际 %s", decodedCve.Published.Format("2006-01-02"))
	}

	if decodedCve.CvssBaseScore != 7.5 {
		t.Errorf("CVSS基础评分不匹配: 期望 7.5, 实际 %f", decodedCve.CvssBaseScore)
	}

	// 4. 验证数组字段
	if len(decodedCve.AffectedSoftware) != 2 {
		t.Errorf("受影响软件数量不匹配: 期望 2, 实际 %d", len(decodedCve.AffectedSoftware))
	} else {
		if decodedCve.AffectedSoftware[0].VendorName != "测试厂商" {
			t.Errorf("厂商名称不匹配: 期望 测试厂商, 实际 %s", decodedCve.AffectedSoftware[0].VendorName)
		}
		if decodedCve.AffectedSoftware[1].ProductName != "测试产品2" {
			t.Errorf("产品名称不匹配: 期望 测试产品2, 实际 %s", decodedCve.AffectedSoftware[1].ProductName)
		}
	}

	if len(decodedCve.References) != 2 {
		t.Errorf("参考链接数量不匹配: 期望 2, 实际 %d", len(decodedCve.References))
	}

	if len(decodedCve.RelatedVulnerabilities) != 1 {
		t.Errorf("相关漏洞数量不匹配: 期望 1, 实际 %d", len(decodedCve.RelatedVulnerabilities))
	} else {
		if decodedCve.RelatedVulnerabilities[0].Title != "相关漏洞1" {
			t.Errorf("相关漏洞标题不匹配: 期望 相关漏洞1, 实际 %s", decodedCve.RelatedVulnerabilities[0].Title)
		}
	}
}

func TestAffectedSoftwareJSON(t *testing.T) {
	software := AffectedSoftware{
		VendorName:  "测试厂商",
		VendorURL:   "https://example.com/vendor",
		ProductName: "测试产品",
		ProductURL:  "https://example.com/product",
	}

	// 序列化
	bytes, err := json.Marshal(software)
	if err != nil {
		t.Fatalf("序列化受影响软件失败: %v", err)
	}

	// 检查序列化结果
	expectedJSON := `{"vendor_name":"测试厂商","vendor_url":"https://example.com/vendor","product_name":"测试产品","product_url":"https://example.com/product"}`
	actualJSON := string(bytes)

	if actualJSON != expectedJSON {
		t.Errorf("序列化结果不匹配:\n期望: %s\n实际: %s", expectedJSON, actualJSON)
	}

	// 反序列化
	var decodedSoftware AffectedSoftware
	if err := json.Unmarshal(bytes, &decodedSoftware); err != nil {
		t.Fatalf("反序列化受影响软件失败: %v", err)
	}

	// 验证字段
	if decodedSoftware.VendorName != "测试厂商" {
		t.Errorf("厂商名称不匹配: 期望 测试厂商, 实际 %s", decodedSoftware.VendorName)
	}
	if decodedSoftware.ProductName != "测试产品" {
		t.Errorf("产品名称不匹配: 期望 测试产品, 实际 %s", decodedSoftware.ProductName)
	}
}
