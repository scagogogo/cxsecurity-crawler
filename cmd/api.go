package cmd

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"strings"

	"github.com/gorilla/mux"
	"github.com/spf13/cobra"

	"github.com/scagogogo/cxsecurity-crawler/pkg/crawler"
)

var (
	apiPort    int
	apiToken   string
	enableCORS bool
)

// APIResponse 定义了API的标准响应格式
// 所有的API响应都会被包装在这个结构体中返回
// success: 表示请求是否成功
// data: 成功时返回的数据
// error: 失败时的错误信息
type APIResponse struct {
	Success bool        `json:"success"`
	Data    interface{} `json:"data,omitempty"`
	Error   string      `json:"error,omitempty"`
}

// generateRandomToken 生成一个随机的API Token
// 使用crypto/rand生成32字节的随机数据，并转换为16进制字符串
// 返回值:
//   - string: 生成的随机token，如果生成失败则返回"default-token-error"
func generateRandomToken() string {
	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		return "default-token-error"
	}
	return hex.EncodeToString(bytes)
}

// authMiddleware 实现API的认证中间件
// 支持两种方式传递token:
//  1. 通过X-API-Token请求头
//  2. 通过URL参数token
//
// 参数:
//   - next: 下一个要执行的处理函数
//
// 返回值:
//   - http.HandlerFunc: 包装后的处理函数
func authMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		token := r.Header.Get("X-API-Token")
		if token == "" {
			token = r.URL.Query().Get("token")
		}

		if token != apiToken {
			w.WriteHeader(http.StatusUnauthorized)
			json.NewEncoder(w).Encode(APIResponse{
				Success: false,
				Error:   "无效的API Token",
			})
			return
		}

		next.ServeHTTP(w, r)
	}
}

// corsMiddleware 实现跨域资源共享(CORS)中间件
// 当enableCORS为true时，添加必要的CORS响应头
// 支持OPTIONS预检请求
// 参数:
//   - next: 下一个要执行的处理函数
//
// 返回值:
//   - http.HandlerFunc: 包装后的处理函数
func corsMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if enableCORS {
			w.Header().Set("Access-Control-Allow-Origin", "*")
			w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
			w.Header().Set("Access-Control-Allow-Headers", "Content-Type, X-API-Token")
		}

		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}

		next.ServeHTTP(w, r)
	}
}

/**
 * @api {get} /api/exploit 获取漏洞列表
 * @apiName GetExploitList
 * @apiGroup Exploit
 * @apiVersion 1.0.0
 *
 * @apiHeader {String} X-API-Token API认证Token
 * @apiHeaderExample {json} Header示例:
 *     {
 *       "X-API-Token": "your-api-token"
 *     }
 *
 * @apiParam {String} [token] API认证Token(URL参数方式)
 *
 * @apiSuccess {Boolean} success 是否成功
 * @apiSuccess {Object} data 返回数据
 * @apiSuccess {Object[]} data.vulnerabilities 漏洞列表
 * @apiSuccess {String} data.vulnerabilities.id 漏洞ID
 * @apiSuccess {String} data.vulnerabilities.title 漏洞标题
 * @apiSuccess {String} data.vulnerabilities.url 漏洞详情URL
 * @apiSuccess {String} data.vulnerabilities.date 发布日期
 * @apiSuccess {String} data.vulnerabilities.risk_level 风险等级
 * @apiSuccess {String} data.vulnerabilities.author 作者
 * @apiSuccess {String} data.vulnerabilities.author_url 作者主页URL
 *
 * @apiSuccessExample {json} 成功响应:
 *     HTTP/1.1 200 OK
 *     {
 *       "success": true,
 *       "data": {
 *         "vulnerabilities": [
 *           {
 *             "id": "WLB-2024040015",
 *             "title": "WordPress Plugin Vulnerability",
 *             "url": "https://cxsecurity.com/issue/WLB-2024040015",
 *             "date": "2024-04-09",
 *             "risk_level": "High",
 *             "author": "Security Researcher",
 *             "author_url": "https://cxsecurity.com/author/researcher"
 *           }
 *         ]
 *       }
 *     }
 *
 * @apiError {Boolean} success 始终为false
 * @apiError {String} error 错误信息
 *
 * @apiErrorExample {json} 认证错误:
 *     HTTP/1.1 401 Unauthorized
 *     {
 *       "success": false,
 *       "error": "无效的API Token"
 *     }
 *
 * @apiExample {curl} 示例:
 *     curl -H "X-API-Token: your-token" http://localhost:8080/api/exploit
 *     curl "http://localhost:8080/api/exploit?token=your-token"
 */
// handleExploitList 处理漏洞列表请求
// 获取最新的漏洞列表，不需要额外的参数
// 参数:
//   - c: Crawler实例，用于执行爬虫操作
// 返回值:
//   - http.HandlerFunc: HTTP处理函数
// 响应示例:
//   {
//     "success": true,
//     "data": {
//       "vulnerabilities": [
//         {
//           "id": "WLB-2024040015",
//           "title": "WordPress Plugin Vulnerability",
//           "url": "https://cxsecurity.com/issue/WLB-2024040015",
//           "date": "2024-04-09",
//           "risk_level": "High",
//           "author": "Security Researcher",
//           "author_url": "https://cxsecurity.com/author/researcher"
//         }
//       ]
//     }
//   }
func handleExploitList(c *crawler.Crawler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		result, err := c.CrawlExploit("", "", "all")
		if err != nil {
			json.NewEncoder(w).Encode(APIResponse{
				Success: false,
				Error:   err.Error(),
			})
			return
		}

		json.NewEncoder(w).Encode(APIResponse{
			Success: true,
			Data:    result,
		})
	}
}

/**
 * @api {get} /api/exploit/:id 获取漏洞详情
 * @apiName GetExploitDetail
 * @apiGroup Exploit
 * @apiVersion 1.0.0
 *
 * @apiHeader {String} X-API-Token API认证Token
 *
 * @apiParam {String} id 漏洞ID(WLB-XXXXXXXX格式,不带WLB-前缀也可以)
 * @apiParam {String} [token] API认证Token(URL参数方式)
 *
 * @apiSuccess {Boolean} success 是否成功
 * @apiSuccess {Object} data 漏洞详情数据
 * @apiSuccess {String} data.id 漏洞ID
 * @apiSuccess {String} data.title 漏洞标题
 * @apiSuccess {String} data.url 漏洞URL
 * @apiSuccess {String} data.date 发布日期
 * @apiSuccess {String} data.risk_level 风险等级
 * @apiSuccess {String} data.author 作者
 * @apiSuccess {String} data.author_url 作者主页
 * @apiSuccess {String} data.description 漏洞描述
 * @apiSuccess {String[]} data.tags 标签列表
 *
 * @apiSuccessExample {json} 成功响应:
 *     HTTP/1.1 200 OK
 *     {
 *       "success": true,
 *       "data": {
 *         "id": "WLB-2024040015",
 *         "title": "WordPress Plugin Vulnerability",
 *         "url": "https://cxsecurity.com/issue/WLB-2024040015",
 *         "date": "2024-04-09",
 *         "risk_level": "High",
 *         "author": "Security Researcher",
 *         "author_url": "https://cxsecurity.com/author/researcher",
 *         "description": "详细的漏洞描述...",
 *         "tags": ["wordpress", "plugin", "xss"]
 *       }
 *     }
 *
 * @apiError {Boolean} success 始终为false
 * @apiError {String} error 错误信息
 *
 * @apiErrorExample {json} 漏洞不存在:
 *     HTTP/1.1 200 OK
 *     {
 *       "success": false,
 *       "error": "漏洞不存在"
 *     }
 *
 * @apiExample {curl} 示例:
 *     curl -H "X-API-Token: your-token" http://localhost:8080/api/exploit/2024-0001
 *     curl "http://localhost:8080/api/exploit/WLB-2024-0001?token=your-token"
 */
// handleExploitDetail 处理漏洞详情请求
// 根据漏洞ID获取详细信息
// 参数:
//   - c: Crawler实例，用于执行爬虫操作
// URL参数:
//   - id: 漏洞ID，格式为WLB-XXXXXXXX，不带WLB-前缀也可以
// 返回值:
//   - http.HandlerFunc: HTTP处理函数
// 响应示例:
//   {
//     "success": true,
//     "data": {
//       "id": "WLB-2024040015",
//       "title": "WordPress Plugin Vulnerability",
//       "url": "https://cxsecurity.com/issue/WLB-2024040015",
//       "date": "2024-04-09",
//       "risk_level": "High",
//       "author": "Security Researcher",
//       "author_url": "https://cxsecurity.com/author/researcher",
//       "description": "详细的漏洞描述...",
//       "tags": ["wordpress", "plugin", "xss"]
//     }
//   }
func handleExploitDetail(c *crawler.Crawler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		vars := mux.Vars(r)
		id := vars["id"]

		// 确保ID格式正确
		if !strings.HasPrefix(id, "WLB-") {
			id = "WLB-" + id
		}

		result, err := c.CrawlExploit(id, "", "all")
		if err != nil {
			json.NewEncoder(w).Encode(APIResponse{
				Success: false,
				Error:   err.Error(),
			})
			return
		}

		json.NewEncoder(w).Encode(APIResponse{
			Success: true,
			Data:    result,
		})
	}
}

/**
 * @api {get} /api/cve/:id 获取CVE详情
 * @apiName GetCveDetail
 * @apiGroup CVE
 * @apiVersion 1.0.0
 *
 * @apiHeader {String} X-API-Token API认证Token
 *
 * @apiParam {String} id CVE编号(CVE-YYYY-XXXXX格式)
 * @apiParam {String} [token] API认证Token(URL参数方式)
 *
 * @apiSuccess {Boolean} success 是否成功
 * @apiSuccess {Object} data CVE详情数据
 * @apiSuccess {String} data.id CVE编号
 * @apiSuccess {String} data.description 漏洞描述
 * @apiSuccess {String} data.published 发布时间
 * @apiSuccess {String} data.modified 最后修改时间
 * @apiSuccess {Number} data.cvss_score CVSS评分
 * @apiSuccess {String} data.cvss_vector CVSS向量
 * @apiSuccess {String[]} data.affected_software 受影响的软件
 * @apiSuccess {String[]} data.references 参考链接
 *
 * @apiSuccessExample {json} 成功响应:
 *     HTTP/1.1 200 OK
 *     {
 *       "success": true,
 *       "data": {
 *         "id": "CVE-2024-21413",
 *         "description": "Microsoft Outlook远程代码执行漏洞",
 *         "published": "2024-04-09T00:00:00Z",
 *         "modified": "2024-04-10T00:00:00Z",
 *         "cvss_score": 8.8,
 *         "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H",
 *         "affected_software": [
 *           "Microsoft Outlook 2016",
 *           "Microsoft Outlook 2019"
 *         ],
 *         "references": [
 *           "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-21413"
 *         ]
 *       }
 *     }
 *
 * @apiError {Boolean} success 始终为false
 * @apiError {String} error 错误信息
 *
 * @apiErrorExample {json} CVE不存在:
 *     HTTP/1.1 200 OK
 *     {
 *       "success": false,
 *       "error": "CVE不存在"
 *     }
 *
 * @apiExample {curl} 示例:
 *     curl -H "X-API-Token: your-token" http://localhost:8080/api/cve/2024-21413
 *     curl "http://localhost:8080/api/cve/CVE-2024-21413?token=your-token"
 */
// handleCveDetail 处理CVE详情请求
// 根据CVE编号获取详细信息
// 参数:
//   - c: Crawler实例，用于执行爬虫操作
// URL参数:
//   - id: CVE编号，格式为CVE-YYYY-XXXXX
// 返回值:
//   - http.HandlerFunc: HTTP处理函数
// 响应示例:
//   {
//     "success": true,
//     "data": {
//       "id": "CVE-2024-21413",
//       "description": "Microsoft Outlook远程代码执行漏洞",
//       "published": "2024-04-09T00:00:00Z",
//       "modified": "2024-04-10T00:00:00Z",
//       "cvss_score": 8.8,
//       "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H",
//       "affected_software": ["Microsoft Outlook 2016", "Microsoft Outlook 2019"],
//       "references": ["https://msrc.microsoft.com/..."]
//     }
//   }
func handleCveDetail(c *crawler.Crawler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		vars := mux.Vars(r)
		cveID := vars["id"]

		result, err := c.CrawlCveDetail(cveID, "")
		if err != nil {
			json.NewEncoder(w).Encode(APIResponse{
				Success: false,
				Error:   err.Error(),
			})
			return
		}

		json.NewEncoder(w).Encode(APIResponse{
			Success: true,
			Data:    result,
		})
	}
}

/**
 * @api {get} /api/author/:id 获取作者信息
 * @apiName GetAuthorProfile
 * @apiGroup Author
 * @apiVersion 1.0.0
 *
 * @apiHeader {String} X-API-Token API认证Token
 *
 * @apiParam {String} id 作者ID
 * @apiParam {String} [token] API认证Token(URL参数方式)
 *
 * @apiSuccess {Boolean} success 是否成功
 * @apiSuccess {Object} data 作者信息数据
 * @apiSuccess {String} data.id 作者ID
 * @apiSuccess {String} data.name 作者名称
 * @apiSuccess {String} data.country 国家
 * @apiSuccess {String} data.country_code 国家代码
 * @apiSuccess {Number} data.reported_count 报告漏洞数量
 * @apiSuccess {String} data.twitter Twitter账号
 * @apiSuccess {String} data.website 个人网站
 * @apiSuccess {String} data.zone_h Zone-H档案
 * @apiSuccess {String} data.description 个人描述
 * @apiSuccess {Number} data.current_page 当前页码
 * @apiSuccess {Number} data.total_pages 总页数
 * @apiSuccess {Object[]} data.vulnerabilities 报告的漏洞列表
 *
 * @apiSuccessExample {json} 成功响应:
 *     HTTP/1.1 200 OK
 *     {
 *       "success": true,
 *       "data": {
 *         "id": "researcher",
 *         "name": "Security Researcher",
 *         "country": "United States",
 *         "country_code": "US",
 *         "reported_count": 234,
 *         "twitter": "@researcher",
 *         "website": "https://researcher.com",
 *         "zone_h": "https://zone-h.org/archive/notifier=researcher",
 *         "description": "Security researcher focused on web vulnerabilities",
 *         "current_page": 1,
 *         "total_pages": 24,
 *         "vulnerabilities": [
 *           {
 *             "id": "WLB-2024040015",
 *             "title": "WordPress Plugin Vulnerability",
 *             "date": "2024-04-09"
 *           }
 *         ]
 *       }
 *     }
 *
 * @apiError {Boolean} success 始终为false
 * @apiError {String} error 错误信息
 *
 * @apiErrorExample {json} 作者不存在:
 *     HTTP/1.1 200 OK
 *     {
 *       "success": false,
 *       "error": "作者不存在"
 *     }
 *
 * @apiExample {curl} 示例:
 *     curl -H "X-API-Token: your-token" http://localhost:8080/api/author/researcher
 *     curl "http://localhost:8080/api/author/researcher?token=your-token"
 */
// handleAuthorProfile 处理作者信息请求
// 根据作者ID获取作者详细信息和发布的漏洞列表
// 参数:
//   - c: Crawler实例，用于执行爬虫操作
// URL参数:
//   - id: 作者ID
// 返回值:
//   - http.HandlerFunc: HTTP处理函数
// 响应示例:
//   {
//     "success": true,
//     "data": {
//       "id": "researcher",
//       "name": "Security Researcher",
//       "country": "United States",
//       "country_code": "US",
//       "reported_count": 234,
//       "twitter": "@researcher",
//       "website": "https://researcher.com",
//       "zone_h": "https://zone-h.org/archive/notifier=researcher",
//       "description": "Security researcher focused on web vulnerabilities",
//       "current_page": 1,
//       "total_pages": 24,
//       "vulnerabilities": [
//         {
//           "id": "WLB-2024040015",
//           "title": "WordPress Plugin Vulnerability",
//           "date": "2024-04-09"
//         }
//       ]
//     }
//   }
func handleAuthorProfile(c *crawler.Crawler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		vars := mux.Vars(r)
		authorID := vars["id"]

		result, err := c.CrawlAuthor(authorID, "")
		if err != nil {
			json.NewEncoder(w).Encode(APIResponse{
				Success: false,
				Error:   err.Error(),
			})
			return
		}

		json.NewEncoder(w).Encode(APIResponse{
			Success: true,
			Data:    result,
		})
	}
}

/**
 * @api {get} /api/search 搜索漏洞
 * @apiName SearchVulnerabilities
 * @apiGroup Search
 * @apiVersion 1.0.0
 *
 * @apiHeader {String} X-API-Token API认证Token
 *
 * @apiParam {String} keyword 搜索关键词
 * @apiParam {Number} [page=1] 页码
 * @apiParam {Number} [per_page=10] 每页记录数(10或30)
 * @apiParam {String} [sort_order=DESC] 排序顺序(ASC或DESC)
 * @apiParam {String} [token] API认证Token(URL参数方式)
 *
 * @apiSuccess {Boolean} success 是否成功
 * @apiSuccess {Object} data 搜索结果数据
 * @apiSuccess {String} data.keyword 搜索关键词
 * @apiSuccess {Number} data.current_page 当前页码
 * @apiSuccess {Number} data.total_pages 总页数
 * @apiSuccess {String} data.sort_order 排序顺序
 * @apiSuccess {Number} data.per_page 每页记录数
 * @apiSuccess {Object[]} data.vulnerabilities 漏洞列表
 * @apiSuccess {String} data.vulnerabilities.id 漏洞ID
 * @apiSuccess {String} data.vulnerabilities.title 漏洞标题
 * @apiSuccess {String} data.vulnerabilities.url 漏洞URL
 * @apiSuccess {String} data.vulnerabilities.date 发布日期
 * @apiSuccess {String} data.vulnerabilities.risk_level 风险等级
 * @apiSuccess {String} data.vulnerabilities.author 作者
 * @apiSuccess {String} data.vulnerabilities.author_url 作者主页URL
 *
 * @apiSuccessExample {json} 成功响应:
 *     HTTP/1.1 200 OK
 *     {
 *       "success": true,
 *       "data": {
 *         "keyword": "wordpress",
 *         "current_page": 1,
 *         "total_pages": 10,
 *         "sort_order": "DESC",
 *         "per_page": 10,
 *         "vulnerabilities": [
 *           {
 *             "id": "WLB-2024040015",
 *             "title": "WordPress Plugin Vulnerability",
 *             "url": "https://cxsecurity.com/issue/WLB-2024040015",
 *             "date": "2024-04-09",
 *             "risk_level": "High",
 *             "author": "Security Researcher",
 *             "author_url": "https://cxsecurity.com/author/researcher"
 *           }
 *         ]
 *       }
 *     }
 *
 * @apiError {Boolean} success 始终为false
 * @apiError {String} error 错误信息
 *
 * @apiErrorExample {json} 参数错误:
 *     HTTP/1.1 200 OK
 *     {
 *       "success": false,
 *       "error": "搜索关键词不能为空"
 *     }
 *
 * @apiExample {curl} 示例:
 *     curl -H "X-API-Token: your-token" "http://localhost:8080/api/search?keyword=wordpress&page=1&per_page=10&sort_order=DESC"
 */
// handleSearch 处理漏洞搜索请求
// 支持关键词搜索、分页和排序
// 参数:
//   - c: Crawler实例，用于执行爬虫操作
// URL参数:
//   - keyword: 搜索关键词（必填）
//   - page: 页码，默认1
//   - per_page: 每页数量，默认10
//   - sort_order: 排序方式，可选值：ASC/DESC，默认DESC
// 返回值:
//   - http.HandlerFunc: HTTP处理函数
// 响应示例:
//   {
//     "success": true,
//     "data": {
//       "keyword": "wordpress",
//       "current_page": 1,
//       "total_pages": 100,
//       "sort_order": "DESC",
//       "per_page": 10,
//       "vulnerabilities": [
//         {
//           "id": "WLB-2024040015",
//           "title": "WordPress Plugin Vulnerability",
//           "url": "https://cxsecurity.com/issue/WLB-2024040015",
//           "date": "2024-04-09",
//           "risk_level": "High",
//           "author": "Security Researcher",
//           "author_url": "https://cxsecurity.com/author/researcher"
//         }
//       ]
//     }
//   }
func handleSearch(c *crawler.Crawler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// 获取查询参数
		keyword := r.URL.Query().Get("keyword")
		if keyword == "" {
			json.NewEncoder(w).Encode(APIResponse{
				Success: false,
				Error:   "搜索关键词不能为空",
			})
			return
		}

		// 获取分页参数
		page := 1
		if pageStr := r.URL.Query().Get("page"); pageStr != "" {
			if p, err := strconv.Atoi(pageStr); err == nil && p > 0 {
				page = p
			}
		}

		// 获取每页记录数
		perPage := 10
		if perPageStr := r.URL.Query().Get("per_page"); perPageStr != "" {
			if pp, err := strconv.Atoi(perPageStr); err == nil && (pp == 10 || pp == 30) {
				perPage = pp
			}
		}

		// 获取排序顺序
		sortOrder := "DESC"
		if so := strings.ToUpper(r.URL.Query().Get("sort_order")); so == "ASC" || so == "DESC" {
			sortOrder = so
		}

		// 执行搜索
		result, err := c.SearchVulnerabilitiesAdvanced(keyword, page, perPage, sortOrder, "")
		if err != nil {
			json.NewEncoder(w).Encode(APIResponse{
				Success: false,
				Error:   err.Error(),
			})
			return
		}

		json.NewEncoder(w).Encode(APIResponse{
			Success: true,
			Data:    result,
		})
	}
}

var apiCmd = &cobra.Command{
	Use:   "api",
	Short: "启动HTTP API服务",
	Long:  `启动HTTP API服务，将爬虫功能以RESTful API的形式提供`,
	Run: func(cmd *cobra.Command, args []string) {
		// 如果未指定token，生成随机token
		if apiToken == "" {
			apiToken = generateRandomToken()
			fmt.Printf("已生成随机API Token: %s\n", apiToken)
		}

		// 创建爬虫实例
		c := crawler.NewCrawler()

		// 创建路由器
		r := mux.NewRouter()

		// 注册API路由
		r.HandleFunc("/api/exploit", corsMiddleware(authMiddleware(handleExploitList(c)))).Methods("GET", "OPTIONS")
		r.HandleFunc("/api/exploit/{id}", corsMiddleware(authMiddleware(handleExploitDetail(c)))).Methods("GET", "OPTIONS")
		r.HandleFunc("/api/cve/{id}", corsMiddleware(authMiddleware(handleCveDetail(c)))).Methods("GET", "OPTIONS")
		r.HandleFunc("/api/author/{id}", corsMiddleware(authMiddleware(handleAuthorProfile(c)))).Methods("GET", "OPTIONS")
		r.HandleFunc("/api/search", corsMiddleware(authMiddleware(handleSearch(c)))).Methods("GET", "OPTIONS")

		// 添加API文档路由
		r.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
			fmt.Fprintf(w, "CXSecurity Crawler API\n")
			fmt.Fprintf(w, "可用的API端点：\n")
			fmt.Fprintf(w, "GET /api/exploit - 获取漏洞列表\n")
			fmt.Fprintf(w, "GET /api/exploit/{id} - 获取漏洞详情\n")
			fmt.Fprintf(w, "GET /api/cve/{id} - 获取CVE详情\n")
			fmt.Fprintf(w, "GET /api/author/{id} - 获取作者信息\n")
			fmt.Fprintf(w, "GET /api/search - 搜索漏洞\n")
			fmt.Fprintf(w, "  参数：\n")
			fmt.Fprintf(w, "    - keyword: 搜索关键词（必填）\n")
			fmt.Fprintf(w, "    - page: 页码，默认1\n")
			fmt.Fprintf(w, "    - per_page: 每页数量，默认10\n")
			fmt.Fprintf(w, "    - sort_order: 排序方式，可选值：ASC/DESC，默认DESC\n")
		})

		// 启动服务器
		addr := fmt.Sprintf(":%d", apiPort)
		fmt.Printf("API服务器正在监听 http://localhost%s\n", addr)
		fmt.Printf("API Token: %s\n", apiToken)
		fmt.Printf("使用方式：在请求头中添加 X-API-Token: %s 或在URL中添加 ?token=%s\n", apiToken, apiToken)

		log.Fatal(http.ListenAndServe(addr, r))
	},
}

func init() {
	rootCmd.AddCommand(apiCmd)

	// 添加命令行参数
	apiCmd.Flags().IntVarP(&apiPort, "port", "p", 8080, "API服务器监听端口")
	apiCmd.Flags().StringVarP(&apiToken, "token", "t", "", "API认证Token（不指定则随机生成）")
	apiCmd.Flags().BoolVarP(&enableCORS, "cors", "c", false, "启用CORS支持")
}
