package cmd

import (
	"fmt"
	"os"
	"strings"

	"github.com/jedib0t/go-pretty/v6/text"
	"github.com/spf13/cobra"
	"golang.org/x/term"

	"github.com/scagogogo/cxsecurity-crawler/pkg/crawler"
	"github.com/scagogogo/cxsecurity-crawler/pkg/model"
)

var (
	cveOutputFile string
	cveFields     string
	cveID         string
)

var cveCmd = &cobra.Command{
	Use:   "cve",
	Short: "爬取CVE详情",
	Long:  `爬取CXSecurity网站的CVE详情页面，并将结果保存为JSON格式`,
	Run: func(cmd *cobra.Command, args []string) {
		// 创建爬虫实例
		c := crawler.NewCrawler()

		// 执行爬取
		if cveID != "" {
			result, err := c.CrawlCveDetail(cveID, cveOutputFile)
			if err != nil {
				cmd.PrintErr("爬取失败: ", err)
				return
			}

			// 打印详细信息
			printCveResult(result, cveOutputFile)
		} else {
			cmd.PrintErr("请指定CVE编号")
		}
	},
}

// printCveResult 美化输出CVE详情
func printCveResult(result *model.CveDetail, outputPath string) {
	// 获取终端宽度
	width, _, err := term.GetSize(int(os.Stdout.Fd()))
	if err != nil {
		// 如果获取失败，使用默认宽度
		width = 80
	}

	// 计算边框和内容宽度
	borderWidth := width - 2               // 两侧各减1个字符给边框
	titlePadding := (borderWidth - 12) / 2 // "CVE详情信息"是6个汉字(12个字符宽度)，两侧填充

	// 构建顶部边框
	topBorder := "┏" + strings.Repeat("━", borderWidth) + "┓"
	titleLine := "┃" + strings.Repeat(" ", titlePadding) + "CVE详情信息" + strings.Repeat(" ", borderWidth-titlePadding-12) + "┃"
	middleBorder := "┣" + strings.Repeat("━", borderWidth) + "┫"
	bottomBorder := "┗" + strings.Repeat("━", borderWidth) + "┛"

	// 显示表头
	fmt.Println()
	fmt.Println(topBorder)
	fmt.Println(titleLine)
	fmt.Println(middleBorder)

	// 计算内容区域宽度
	contentWidth := borderWidth - 2 // 左右各减1个字符的padding

	// 构建输出行的函数
	printLine := func(label string, value string, color ...text.Color) {
		// 先处理标签
		labelText := text.Colors{text.Bold}.Sprint(label)
		labelDisplayWidth := stringDisplayWidth(label)

		// 先获取原始文本的显示宽度（在应用颜色之前）
		valueDisplayWidth := stringDisplayWidth(value)

		// 如果有指定颜色，应用到value
		valueText := value
		if len(color) > 0 {
			valueText = text.Colors(color).Sprint(value)
		}

		// 计算所需填充宽度 (2是": "的宽度)
		padding := contentWidth - labelDisplayWidth - 2 - valueDisplayWidth
		if padding < 0 {
			padding = 0
		}

		// 输出行，确保右边框对齐
		fmt.Printf("┃ %s: %s%s ┃\n", labelText, valueText, strings.Repeat(" ", padding))
	}

	// 输出CVE基本信息
	printLine("CVE编号", result.CveID, text.FgHiYellow)
	printLine("发布日期", result.Published.Format("2006-01-02"))
	if !result.Modified.IsZero() {
		printLine("修改日期", result.Modified.Format("2006-01-02"))
	}

	// 输出描述信息（可能很长，需要进行分行处理）
	if result.Description != "" {
		// 截断字符串，超出部分用省略号代替
		description := result.Description
		if len(description) > contentWidth-10 { // 10是"漏洞描述: "的宽度
			description = description[:contentWidth-13] + "..."
		}
		printLine("漏洞描述", description)
	}

	// 输出CVE类型
	if result.Type != "" {
		printLine("漏洞类型", result.Type, text.FgHiGreen)
	}

	// 输出CVSS评分
	if result.CvssBaseScore > 0 {
		// 根据评分高低使用不同颜色
		scoreColor := text.FgGreen
		if result.CvssBaseScore >= 7.0 {
			scoreColor = text.FgRed
		} else if result.CvssBaseScore >= 4.0 {
			scoreColor = text.FgYellow
		}
		printLine("CVSS评分", fmt.Sprintf("%.1f/10", result.CvssBaseScore), scoreColor, text.Bold)
	}

	if result.CvssImpactScore > 0 {
		printLine("影响评分", fmt.Sprintf("%.1f", result.CvssImpactScore))
	}

	if result.CvssExploitScore > 0 {
		printLine("利用评分", fmt.Sprintf("%.1f", result.CvssExploitScore))
	}

	// 输出漏洞特性信息
	if result.ExploitRange != "" {
		printLine("利用范围", result.ExploitRange, text.FgHiCyan)
	}

	if result.AttackComplexity != "" {
		printLine("攻击复杂度", result.AttackComplexity)
	}

	if result.Authentication != "" {
		printLine("认证需求", result.Authentication)
	}

	if result.ConfidentialityImpact != "" {
		printLine("机密性影响", result.ConfidentialityImpact)
	}

	if result.IntegrityImpact != "" {
		printLine("完整性影响", result.IntegrityImpact)
	}

	if result.AvailabilityImpact != "" {
		printLine("可用性影响", result.AvailabilityImpact)
	}

	// 输出受影响软件数量
	if len(result.AffectedSoftware) > 0 {
		printLine("受影响软件", fmt.Sprintf("%d个", len(result.AffectedSoftware)), text.FgHiMagenta)
		// 最多显示前3个
		showCount := len(result.AffectedSoftware)
		if showCount > 3 {
			showCount = 3
		}

		for i := 0; i < showCount; i++ {
			software := result.AffectedSoftware[i]
			softwareInfo := fmt.Sprintf("%s %s", software.VendorName, software.ProductName)
			printLine(fmt.Sprintf("  软件%d", i+1), softwareInfo, text.FgHiMagenta)
		}

		if len(result.AffectedSoftware) > 3 {
			printLine("  更多软件", fmt.Sprintf("... 共%d个", len(result.AffectedSoftware)-3))
		}
	}

	// 输出参考链接数量
	if len(result.References) > 0 {
		printLine("参考链接", fmt.Sprintf("%d个", len(result.References)), text.FgBlue)
		// 最多显示前2个
		showCount := len(result.References)
		if showCount > 2 {
			showCount = 2
		}

		for i := 0; i < showCount; i++ {
			reference := result.References[i]
			// 截断长URL
			if len(reference) > contentWidth-15 {
				reference = reference[:contentWidth-18] + "..."
			}
			printLine(fmt.Sprintf("  链接%d", i+1), reference, text.FgBlue)
		}

		if len(result.References) > 2 {
			printLine("  更多链接", fmt.Sprintf("... 共%d个", len(result.References)-2))
		}
	}

	// 输出相关漏洞数量
	if len(result.RelatedVulnerabilities) > 0 {
		printLine("相关漏洞", fmt.Sprintf("%d个", len(result.RelatedVulnerabilities)), text.FgHiWhite)
	}

	// 输出底部边框
	fmt.Println(bottomBorder)

	// 显示结果保存信息
	if outputPath != "" {
		fmt.Printf("结果已保存到 %s\n", outputPath)
	}
}

func init() {
	rootCmd.AddCommand(cveCmd)

	// 添加标志
	cveCmd.Flags().StringVarP(&cveOutputFile, "output", "o", "cve_output.json", "输出文件路径")
	cveCmd.Flags().StringVarP(&cveID, "id", "i", "", "要爬取的CVE编号，例如：CVE-2007-1411")
	cveCmd.Flags().StringVarP(&cveFields, "fields", "f", "all", "要输出的字段，用逗号分隔，或使用'all'获取所有字段")
}
