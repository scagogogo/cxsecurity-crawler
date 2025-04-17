package cmd

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/scagogogo/cxsecurity-crawler/pkg/crawler"
)

var (
	testInputFile  string
	testOutputFile string
)

var testParserCmd = &cobra.Command{
	Use:   "test-parser",
	Short: "测试HTML解析器",
	Long:  `使用本地HTML文件测试漏洞详情解析器`,
	Run: func(cmd *cobra.Command, args []string) {
		// 读取HTML文件
		htmlContent, err := os.ReadFile(testInputFile)
		if err != nil {
			fmt.Printf("读取文件失败: %v\n", err)
			return
		}

		// 创建解析器
		parser := crawler.NewParser()

		// 解析HTML内容
		result, err := parser.ParseVulnerabilityDetailPage(string(htmlContent))
		if err != nil {
			fmt.Printf("解析HTML失败: %v\n", err)
			return
		}

		// 打印解析结果
		fmt.Printf("解析成功:\n")
		fmt.Printf("标题: %s\n", result.Title)
		fmt.Printf("风险级别: %s\n", result.RiskLevel)
		fmt.Printf("发布日期: %s\n", result.Date.Format("2006-01-02"))
		fmt.Printf("标签数量: %d\n", len(result.Tags))
		fmt.Printf("标签: %v\n", result.Tags)
		fmt.Printf("作者: %s\n", result.Author)
		fmt.Printf("作者URL: %s\n", result.AuthorURL)

		// 保存结果到文件
		if testOutputFile != "" {
			data, err := json.MarshalIndent(result, "", "  ")
			if err != nil {
				fmt.Printf("序列化JSON失败: %v\n", err)
				return
			}

			err = os.WriteFile(testOutputFile, data, 0644)
			if err != nil {
				fmt.Printf("写入文件失败: %v\n", err)
				return
			}

			fmt.Printf("结果已保存到 %s\n", testOutputFile)
		}
	},
}

func init() {
	rootCmd.AddCommand(testParserCmd)

	// 添加标志
	testParserCmd.Flags().StringVarP(&testInputFile, "input", "i", "docs/vul-detail-response.html", "输入HTML文件路径")
	testParserCmd.Flags().StringVarP(&testOutputFile, "output", "o", "test_parser_result.json", "输出文件路径")
}
