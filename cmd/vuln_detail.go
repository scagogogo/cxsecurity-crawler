package cmd

import (
	"github.com/spf13/cobra"

	"github.com/scagogogo/cxsecurity-crawler/pkg/crawler"
)

var (
	vulnDetailOutputFile string
	vulnDetailFields     string
	vulnDetailID         string
)

var vulnDetailCmd = &cobra.Command{
	Use:   "vuln-detail",
	Short: "爬取漏洞详情",
	Long:  `爬取CXSecurity网站的漏洞详情页面，并将结果保存为JSON格式`,
	Run: func(cmd *cobra.Command, args []string) {
		// 创建爬虫实例
		c := crawler.NewCrawler()

		// 执行爬取
		if vulnDetailID != "" {
			path := "/issue/WLB-" + vulnDetailID
			result, err := c.CrawlVulnerabilityDetail(path, vulnDetailOutputFile)
			if err != nil {
				cmd.PrintErr("爬取失败: ", err)
				return
			}

			// 打印一些基本信息
			cmd.Printf("爬取成功，漏洞标题: %s\n", result.Title)
			cmd.Printf("风险级别: %s\n", result.RiskLevel)
			cmd.Printf("发布日期: %s\n", result.Date.Format("2006-01-02"))
			cmd.Printf("标签数量: %d\n", len(result.Tags))
			cmd.Printf("作者: %s\n", result.Author)
			cmd.Printf("结果已保存到 %s\n", vulnDetailOutputFile)
		} else {
			cmd.PrintErr("请指定漏洞ID")
		}
	},
}

func init() {
	rootCmd.AddCommand(vulnDetailCmd)

	// 添加标志
	vulnDetailCmd.Flags().StringVarP(&vulnDetailOutputFile, "output", "o", "vuln_detail.json", "输出文件路径")
	vulnDetailCmd.Flags().StringVarP(&vulnDetailID, "id", "i", "", "要爬取的漏洞ID，例如：2007030137")
}
