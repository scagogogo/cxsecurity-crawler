package cmd

import (
	"github.com/spf13/cobra"

	"github.com/scagogogo/cxsecurity-crawler/pkg/crawler"
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

			// 截断字符串，超出部分用省略号代替
			truncate := func(s string, maxLen int) string {
				if len(s) <= maxLen {
					return s
				}
				return s[:maxLen] + "..."
			}

			// 打印一些基本信息
			cmd.Printf("爬取成功，CVE编号: %s\n", result.CveID)
			cmd.Printf("漏洞描述: %s\n", truncate(result.Description, 100))
			cmd.Printf("发布日期: %s\n", result.Published.Format("2006-01-02"))
			cmd.Printf("CVSS评分: %.1f/10\n", result.CvssBaseScore)
			cmd.Printf("受影响的软件数量: %d\n", len(result.AffectedSoftware))
			cmd.Printf("相关漏洞数量: %d\n", len(result.RelatedVulnerabilities))
			cmd.Printf("结果已保存到 %s\n", cveOutputFile)
		} else {
			cmd.PrintErr("请指定CVE编号")
		}
	},
}

func init() {
	rootCmd.AddCommand(cveCmd)

	// 添加标志
	cveCmd.Flags().StringVarP(&cveOutputFile, "output", "o", "cve_output.json", "输出文件路径")
	cveCmd.Flags().StringVarP(&cveID, "id", "i", "", "要爬取的CVE编号，例如：CVE-2007-1411")
	cveCmd.Flags().StringVarP(&cveFields, "fields", "f", "all", "要输出的字段，用逗号分隔，或使用'all'获取所有字段")
}
