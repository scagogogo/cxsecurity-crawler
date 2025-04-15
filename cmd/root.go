package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "cxcrawler",
	Short: "CXSecurity爬虫工具",
	Long: `CXSecurity爬虫工具是一个用于爬取CXSecurity网站数据的命令行工具，
可以爬取漏洞列表页面和CVE详情页面，并将结果保存为JSON格式。`,
}

// Execute 执行rootCmd
func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

func init() {
	// 这里可以添加全局标志
}
