package cmd

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/jedib0t/go-pretty/v6/table"
	"github.com/jedib0t/go-pretty/v6/text"
	"github.com/spf13/cobra"
	"golang.org/x/term"

	"github.com/scagogogo/cxsecurity-crawler/pkg/crawler"
)

var (
	searchOutputFile string
	searchKeyword    string
	searchPage       int
	searchPerPage    int
	searchSortOrder  string
	searchSilent     bool
	searchNoPaging   bool
)

var searchCmd = &cobra.Command{
	Use:   "search",
	Short: "搜索漏洞信息",
	Long:  `使用关键词在CXSecurity网站上搜索漏洞，并将结果保存为JSON格式`,
	Run: func(cmd *cobra.Command, args []string) {
		// 创建爬虫实例
		c := crawler.NewCrawler()

		// 检查每页数量和排序顺序的有效性
		if searchPerPage != 10 && searchPerPage != 30 {
			fmt.Println("警告: 每页数量只能为10或30，已自动设置为10")
			searchPerPage = 10
		}

		sortOrder := "DESC"
		if searchSortOrder != "" {
			upperSortOrder := strings.ToUpper(searchSortOrder)
			if upperSortOrder == "ASC" || upperSortOrder == "DESC" {
				sortOrder = upperSortOrder
			} else {
				fmt.Println("警告: 排序顺序只能为ASC或DESC，已自动设置为DESC")
			}
		}

		// 循环查询多页结果
		currentPage := searchPage
		for {
			// 构建输出文件名，如果指定了多页，则添加页码后缀
			outputPath := searchOutputFile
			if currentPage > searchPage {
				ext := filepath.Ext(searchOutputFile)
				base := strings.TrimSuffix(searchOutputFile, ext)
				outputPath = fmt.Sprintf("%s_page%d%s", base, currentPage, ext)
			}

			result, err := c.SearchVulnerabilitiesAdvanced(searchKeyword, currentPage, searchPerPage, sortOrder, outputPath)
			if err != nil {
				fmt.Printf("搜索失败: %v\n", err)
				return
			}

			// 只有在非静默模式下才输出结果
			if !searchSilent {
				printSearchResult(result, outputPath)
			}

			// 如果启用了分页并且还有更多页，询问用户是否继续
			if !searchNoPaging && currentPage < result.TotalPages {
				if !askForNextPage() {
					break
				}
				currentPage++
			} else {
				break
			}
		}
	},
}

// askForNextPage 询问用户是否继续查看下一页
func askForNextPage() bool {
	reader := bufio.NewReader(os.Stdin)
	fmt.Print("是否查看下一页？(y/n): ")
	text, _ := reader.ReadString('\n')
	text = strings.TrimSpace(strings.ToLower(text))
	return text == "y" || text == "yes"
}

// printSearchResult 打印搜索结果
func printSearchResult(result *crawler.SearchResult, outputPath string) {
	// 使用go-pretty创建美观的表格
	t := table.NewWriter()
	t.SetOutputMirror(os.Stdout)

	// 设置表格样式
	t.SetStyle(table.StyleRounded)

	// 获取终端宽度
	width, _, err := term.GetSize(int(os.Stdout.Fd()))
	if err != nil {
		// 如果获取失败，使用默认宽度
		width = 120
	}

	// 动态计算各列宽度
	// 终端宽度减去表格边框和列分隔符所占用的空间
	availableWidth := width - (4 + 2*4) // 4列: ID、标题、日期、作者

	// 根据内容特点分配各列宽度占比
	idRatio := 0.15     // ID列 - 约15%
	titleRatio := 0.50  // 标题列 - 约50%
	dateRatio := 0.10   // 日期列 - 约10%
	riskRatio := 0.10   // 风险级别 - 约10%
	authorRatio := 0.15 // 作者列 - 约15%

	// 计算各列实际宽度（最小保证有合理的字符数）
	idWidth := max(15, int(float64(availableWidth)*idRatio))
	titleWidth := max(35, int(float64(availableWidth)*titleRatio))
	dateWidth := max(10, int(float64(availableWidth)*dateRatio))
	riskWidth := max(10, int(float64(availableWidth)*riskRatio))
	authorWidth := max(12, int(float64(availableWidth)*authorRatio))

	// 设置表头
	t.AppendHeader(table.Row{"ID", "标题", "日期", "风险级别", "作者"})

	// 设置表头样式 - 深色背景
	t.SetColumnConfigs([]table.ColumnConfig{
		{Number: 1, Align: text.AlignCenter, AlignHeader: text.AlignCenter, Colors: text.Colors{text.FgHiCyan}, ColorsHeader: text.Colors{text.BgBlack, text.FgHiWhite, text.Bold}, WidthMax: idWidth},
		{Number: 2, AlignHeader: text.AlignCenter, Colors: text.Colors{text.FgHiWhite}, ColorsHeader: text.Colors{text.BgBlack, text.FgHiWhite, text.Bold}, WidthMax: titleWidth},
		{Number: 3, Align: text.AlignCenter, AlignHeader: text.AlignCenter, ColorsHeader: text.Colors{text.BgBlack, text.FgHiWhite, text.Bold}, WidthMax: dateWidth},
		{Number: 4, Align: text.AlignCenter, AlignHeader: text.AlignCenter, ColorsHeader: text.Colors{text.BgBlack, text.FgHiWhite, text.Bold}, WidthMax: riskWidth},
		{Number: 5, AlignHeader: text.AlignCenter, Colors: text.Colors{text.FgHiMagenta}, ColorsHeader: text.Colors{text.BgBlack, text.FgHiWhite, text.Bold}, WidthMax: authorWidth},
	})

	// 添加数据行
	for _, item := range result.Vulnerabilities {
		// 标题可能很长，需要截断
		title := item.Title
		if len(title) > titleWidth-3 {
			// 截断标题部分，为省略号留出空间
			maxTitleLen := titleWidth - 6
			if maxTitleLen > 0 && maxTitleLen < len(title) {
				title = title[:maxTitleLen] + "..."
			}
		}

		// 作者名可能很长，需要截断
		author := item.Author
		if len(author) > authorWidth-3 {
			// 安全截断，确保不会越界
			maxAuthorLen := authorWidth - 6
			if maxAuthorLen > 0 && maxAuthorLen < len(author) {
				author = author[:maxAuthorLen] + "..."
			}
		}

		// 根据风险级别设置不同颜色
		var riskColor text.Colors
		switch item.RiskLevel {
		case "High":
			riskColor = text.Colors{text.FgRed, text.Bold}
		case "Med.":
			riskColor = text.Colors{text.FgYellow, text.Bold}
		case "Low":
			riskColor = text.Colors{text.FgGreen, text.Bold}
		default:
			riskColor = text.Colors{}
		}

		// 添加数据行
		t.AppendRow(table.Row{
			text.Colors{text.FgHiCyan}.Sprint(item.ID),
			title,
			item.Date,
			riskColor.Sprint(item.RiskLevel),
			text.Colors{text.FgHiMagenta}.Sprint(author),
		})
	}

	// 添加页码信息到表格底部
	t.AppendFooter(table.Row{
		fmt.Sprintf("总计: %d 条记录", len(result.Vulnerabilities)),
		"",
		"",
		fmt.Sprintf("页码: %d/%d", result.CurrentPage, result.TotalPages),
		""})

	// 渲染表格
	fmt.Printf("\n搜索关键词: %s\n", text.Colors{text.Bold, text.FgHiGreen}.Sprint(result.Keyword))
	fmt.Printf("排序方式: %s | 每页记录数: %d\n",
		result.SortOrder,
		result.PerPage)
	t.Render()
	fmt.Println()

	if outputPath != "" {
		fmt.Printf("结果已保存到 %s\n", outputPath)
	}
}

func init() {
	rootCmd.AddCommand(searchCmd)

	// 添加标志
	searchCmd.Flags().StringVarP(&searchOutputFile, "output", "o", "search_result.json", "输出文件路径")
	searchCmd.Flags().StringVarP(&searchKeyword, "keyword", "k", "", "搜索关键词")
	searchCmd.Flags().IntVarP(&searchPage, "page", "p", 1, "搜索结果页码")
	searchCmd.Flags().IntVarP(&searchPerPage, "perpage", "n", 10, "每页记录数(10或30)")
	searchCmd.Flags().StringVarP(&searchSortOrder, "sort", "s", "DESC", "排序顺序(ASC或DESC)")
	searchCmd.Flags().BoolVarP(&searchSilent, "silent", "", false, "静默模式，不输出到标准输出，适用于API调用")
	searchCmd.Flags().BoolVarP(&searchNoPaging, "no-paging", "", false, "禁用交互式分页，只显示指定页")

	// 设置必需标志
	searchCmd.MarkFlagRequired("keyword")
}
