package cmd

import (
	"fmt"
	"os"
	"strings"

	"github.com/jedib0t/go-pretty/v6/table"
	"github.com/jedib0t/go-pretty/v6/text"
	"github.com/spf13/cobra"
	"golang.org/x/term"

	"github.com/scagogogo/cxsecurity-crawler/pkg/crawler"
	"github.com/scagogogo/cxsecurity-crawler/pkg/model"
)

var (
	authorID         string
	authorOutputFile string
	authorSilent     bool
)

var authorCmd = &cobra.Command{
	Use:   "author",
	Short: "爬取作者信息",
	Long:  `爬取CXSecurity网站的作者信息，并将结果保存为JSON格式`,
	Run: func(cmd *cobra.Command, args []string) {
		// 如果没有提供作者ID，显示使用帮助
		if authorID == "" {
			fmt.Println("请使用 -i 或 --id 参数指定作者ID")
			cmd.Help()
			return
		}

		// 创建爬虫实例
		c := crawler.NewCrawler()

		// 显示加载提示
		if !authorSilent {
			fmt.Printf("\n%s %s\n",
				text.Colors{text.FgHiBlue, text.Bold}.Sprint("👤 正在获取作者信息:"),
				text.Colors{text.FgHiWhite, text.Bold}.Sprint(authorID))
		}

		// 执行爬取
		result, err := c.CrawlAuthor(authorID, authorOutputFile)
		if err != nil {
			fmt.Printf("\n%s %v\n",
				text.Colors{text.FgRed, text.Bold}.Sprint("❌ 获取失败:"),
				err)
			return
		}

		// 只有在非静默模式下才输出结果
		if !authorSilent {
			printAuthorResult(result, authorOutputFile)
		}
	},
}

// printAuthorResult 格式化输出作者信息结果
func printAuthorResult(result *model.AuthorProfile, outputPath string) {
	// 获取终端宽度
	width, _, err := term.GetSize(int(os.Stdout.Fd()))
	if err != nil {
		// 如果获取失败，使用默认宽度
		width = 80
	}

	// 计算边框和内容宽度
	borderWidth := width - 2              // 两侧各减1个字符给边框
	titlePadding := (borderWidth - 8) / 2 // "作者信息"是4个汉字(8个字符宽度)，两侧填充

	// 构建顶部边框
	topBorder := "┏" + strings.Repeat("━", borderWidth) + "┓"
	titleLine := "┃" + strings.Repeat(" ", titlePadding) + text.Colors{text.FgHiCyan, text.Bold}.Sprint("作者信息") + strings.Repeat(" ", borderWidth-titlePadding-8) + "┃"
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
		labelDisplayWidth := calculateDisplayWidth(label)

		// 先获取原始文本的显示宽度（在应用颜色之前）
		valueDisplayWidth := calculateDisplayWidth(value)

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

	// 输出基本信息
	printLine("作者ID", result.ID, text.FgHiCyan)
	printLine("作者名称", result.Name, text.FgHiWhite, text.Bold)
	printLine("国家", fmt.Sprintf("%s (%s)", result.Country, result.CountryCode), text.FgYellow)
	printLine("报告数量", fmt.Sprintf("%d", result.ReportedCount), text.FgHiGreen, text.Bold)

	// 如果有联系方式，输出联系信息
	if result.Twitter != "" || result.Website != "" || result.ZoneH != "" {
		fmt.Println("┣" + strings.Repeat("━", borderWidth) + "┫")
		fmt.Printf("┃ %s%s ┃\n", text.Colors{text.Bold, text.BgBlack, text.FgHiWhite}.Sprint("联系方式"), strings.Repeat(" ", contentWidth-8))

		if result.Twitter != "" {
			printLine("Twitter", result.Twitter, text.FgBlue, text.Underline)
		}
		if result.Website != "" {
			printLine("网站", result.Website, text.FgBlue, text.Underline)
		}
		if result.ZoneH != "" {
			printLine("Zone-H", result.ZoneH, text.FgBlue, text.Underline)
		}
	}

	// 如果有描述，输出描述信息
	if result.Description != "" {
		fmt.Println("┣" + strings.Repeat("━", borderWidth) + "┫")
		fmt.Printf("┃ %s%s ┃\n", text.Colors{text.Bold, text.BgBlack, text.FgHiWhite}.Sprint("个人描述"), strings.Repeat(" ", contentWidth-8))

		// 处理可能的多行描述
		descLines := strings.Split(result.Description, "\n")
		for _, line := range descLines {
			lineDisplayWidth := calculateDisplayWidth(line)
			padding := contentWidth - lineDisplayWidth
			if padding < 0 {
				padding = 0
			}
			fmt.Printf("┃ %s%s ┃\n", text.Colors{text.FgHiWhite}.Sprint(line), strings.Repeat(" ", padding))
		}
	}

	// 输出漏洞列表
	if len(result.Vulnerabilities) > 0 {
		fmt.Println("┣" + strings.Repeat("━", borderWidth) + "┫")
		fmt.Printf("┃ %s%s ┃\n", text.Colors{text.Bold, text.BgBlack, text.FgHiWhite}.Sprint("发布的漏洞"), strings.Repeat(" ", contentWidth-8))
		fmt.Println("┣" + strings.Repeat("━", borderWidth) + "┫")

		// 创建并配置表格
		t := table.NewWriter()
		t.SetOutputMirror(os.Stdout)
		t.SetStyle(table.StyleLight)

		// 设置表头
		t.AppendHeader(table.Row{"#", "日期", "风险", "漏洞标题", "类型"})

		// 设置表头样式
		t.SetColumnConfigs([]table.ColumnConfig{
			{Number: 1, Align: text.AlignCenter, AlignHeader: text.AlignCenter, ColorsHeader: text.Colors{text.BgBlack, text.FgHiWhite, text.Bold}},
			{Number: 2, Align: text.AlignCenter, AlignHeader: text.AlignCenter, ColorsHeader: text.Colors{text.BgBlack, text.FgHiWhite, text.Bold}},
			{Number: 3, Align: text.AlignCenter, AlignHeader: text.AlignCenter, ColorsHeader: text.Colors{text.BgBlack, text.FgHiWhite, text.Bold}},
			{Number: 4, AlignHeader: text.AlignCenter, ColorsHeader: text.Colors{text.BgBlack, text.FgHiWhite, text.Bold}},
			{Number: 5, Align: text.AlignCenter, AlignHeader: text.AlignCenter, ColorsHeader: text.Colors{text.BgBlack, text.FgHiWhite, text.Bold}},
		})

		// 添加数据行
		for i, vuln := range result.Vulnerabilities {
			// 格式化日期
			date := "未知"
			if !vuln.Date.IsZero() {
				date = vuln.Date.Format("2006-01-02")
			}

			// 格式化风险级别
			risk := vuln.RiskLevel
			switch strings.ToLower(risk) {
			case "high":
				risk = text.Colors{text.FgRed, text.Bold}.Sprint(risk)
			case "med.", "medium":
				risk = text.Colors{text.FgYellow, text.Bold}.Sprint(risk)
			case "low":
				risk = text.Colors{text.FgGreen, text.Bold}.Sprint(risk)
			}

			// 格式化漏洞类型
			vulnType := ""
			if vuln.IsRemote {
				vulnType = text.Colors{text.FgRed}.Sprint("Remote")
			} else if vuln.IsLocal {
				vulnType = text.Colors{text.FgBlue}.Sprint("Local")
			}

			// 高亮显示漏洞ID和标题
			title := vuln.Title
			if vuln.ID != "" {
				idPart := text.Colors{text.FgHiCyan}.Sprint(vuln.ID)
				title = fmt.Sprintf("%s: %s", idPart, title)
			}

			t.AppendRow([]interface{}{
				i + 1,
				date,
				risk,
				title,
				vulnType,
			})
		}

		// 渲染表格
		t.Render()
	}

	// 输出底部边框
	fmt.Println(bottomBorder)
	fmt.Println()

	// 输出保存路径信息
	if outputPath != "" {
		fmt.Printf("%s %s\n",
			text.Colors{text.FgHiGreen}.Sprint("✅ 已保存:"),
			text.Colors{text.FgHiCyan, text.Underline}.Sprint(outputPath))
	}
}

// calculateDisplayWidth 计算字符串在终端中的显示宽度
func calculateDisplayWidth(s string) int {
	width := 0
	for _, r := range s {
		if r > 127 {
			width += 2 // 假设所有非ASCII字符宽度为2
		} else {
			width += 1
		}
	}
	return width
}

func init() {
	rootCmd.AddCommand(authorCmd)

	// 添加命令行参数
	authorCmd.Flags().StringVarP(&authorID, "id", "i", "", "要爬取的作者ID (必须)")
	authorCmd.Flags().StringVarP(&authorOutputFile, "output", "o", "author_result.json", "结果输出的文件路径")
	authorCmd.Flags().BoolVarP(&authorSilent, "silent", "s", false, "静默模式，不输出到标准输出")
}
