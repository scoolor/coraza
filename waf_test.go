// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package coraza

import (
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/corazawaf/coraza/v3/experimental/plugins/plugintypes"
	"github.com/corazawaf/coraza/v3/internal/corazawaf"
	"github.com/corazawaf/coraza/v3/types"
)

func TestRequestBodyLimit(t *testing.T) {
	testCases := map[string]struct {
		expectedErr   error
		limit         int
		inMemoryLimit int
	}{
		"empty limit": {
			limit:         0,
			inMemoryLimit: 2,
			expectedErr:   errors.New("request body limit should be bigger than 0"),
		},
		"empty memory limit": {
			limit:         2,
			inMemoryLimit: 0,
			expectedErr:   errors.New("request body memory limit should be bigger than 0"),
		},
		"memory limit bigger than limit": {
			limit:         5,
			inMemoryLimit: 9,
			expectedErr:   errors.New("request body limit should be at least the memory limit"),
		},
		"limit bigger than the hard limit": {
			limit:       1073741825,
			expectedErr: errors.New("request body limit should be at most 1GB"),
		},
		"right limits": {
			limit:         100,
			inMemoryLimit: 50,
		},
	}

	for name, tCase := range testCases {
		t.Run(name, func(t *testing.T) {
			cfg := NewWAFConfig().(*wafConfig)
			cfg.requestBodyLimit = &tCase.limit
			cfg.requestBodyInMemoryLimit = &tCase.inMemoryLimit

			_, err := NewWAF(cfg)
			if tCase.expectedErr == nil {
				if err != nil {
					t.Fatalf("unexpected error: %s", err.Error())
				}
			} else {
				if err == nil {
					t.Fatal("expected error")
				}

				if want, have := tCase.expectedErr, err; want.Error() != have.Error() {
					t.Fatalf("unexpected error: want %q, have %q", want, have)
				}
			}
		})
	}
}

func TestResponseBodyLimit(t *testing.T) {
	testCases := map[string]struct {
		expectedErr error
		limit       int
	}{
		"empty limit": {
			limit:       0,
			expectedErr: errors.New("response body limit should be bigger than 0"),
		},
		"limit bigger than the hard limit": {
			limit:       1073741825,
			expectedErr: errors.New("response body limit should be at most 1GB"),
		},
		"right limit": {
			limit: 100,
		},
	}

	for name, tCase := range testCases {
		t.Run(name, func(t *testing.T) {
			cfg := NewWAFConfig().(*wafConfig)
			cfg.responseBodyLimit = &tCase.limit

			_, err := NewWAF(cfg)
			if tCase.expectedErr == nil {
				if err != nil {
					t.Fatalf("unexpected error: %s", err.Error())
				}
			} else {
				if err == nil {
					t.Fatal("expected error")
				}

				if want, have := tCase.expectedErr, err; want.Error() != have.Error() {
					t.Fatalf("unexpected error: want %q, have %q", want, have)
				}
			}
		})
	}
}

type testAuditLogWriter struct {
	plugintypes.AuditLogWriter
}

func (*testAuditLogWriter) Init(plugintypes.AuditLogConfig) error {
	return nil
}

func TestPopulateAuditLog(t *testing.T) {
	writer := &testAuditLogWriter{}

	testCases := map[string]struct {
		config *wafConfig
		check  func(*testing.T, *corazawaf.WAF)
	}{
		"empty config": {
			config: &wafConfig{},
			check:  func(*testing.T, *corazawaf.WAF) {},
		},
		"with relevant only": {
			config: &wafConfig{
				auditLog: &auditLogConfig{
					relevantOnly: true,
				},
			},
			check: func(t *testing.T, waf *corazawaf.WAF) {
				if waf.AuditEngine != types.AuditEngineRelevantOnly {
					t.Fatal("expected AuditLogRelevantOnly to be true")
				}
			},
		},
		"with parts": {
			config: &wafConfig{
				auditLog: &auditLogConfig{
					parts: []types.AuditLogPart{
						types.AuditLogPartRequestHeaders,
						types.AuditLogPartResponseBody,
					},
				},
			},
			check: func(t *testing.T, waf *corazawaf.WAF) {
				if want, have := []types.AuditLogPart{
					types.AuditLogPartRequestHeaders,
					types.AuditLogPartResponseBody,
				}, waf.AuditLogParts; len(want) != len(have) {
					t.Fatalf("unexpected AuditLogParts: want %v, have %v", want, have)
				}
			},
		},
		"with audit log writer": {
			config: &wafConfig{
				auditLog: &auditLogConfig{writer: writer},
			},
			check: func(t *testing.T, waf *corazawaf.WAF) {
				if reflect.DeepEqual(waf.AuditLogWriter(), &writer) {
					t.Fatal("expected AuditLogWriter to be set")
				}
			},
		},
	}

	for name, tCase := range testCases {
		t.Run(name, func(t *testing.T) {
			waf := &corazawaf.WAF{}
			populateAuditLog(waf, tCase.config)
			tCase.check(t, waf)
		})
	}
}

// TestWAFAttackDetection 展示如何使用 Coraza WAF 检测常见的 Web 攻击
func TestWAFAttackDetection(t *testing.T) {
	// 创建一个新的 WAF 实例，并添加一些规则
	waf, err := NewWAF(NewWAFConfig().
		WithDirectives(`
			# 启用规则引擎
			SecRuleEngine On
			
			# 定义一些基本规则
			SecRule REQUEST_URI "@contains /admin" "id:1000,phase:1,deny,log,msg:'访问管理页面'"
			SecRule REQUEST_HEADERS:User-Agent "@contains sqlmap" "id:1001,phase:1,deny,log,msg:'检测到SQL注入工具'"
			# 使用更简单的 SQL 注入检测规则
			SecRule ARGS "@contains UNION SELECT" "id:1002,phase:2,deny,log,msg:'SQL注入攻击'"
			SecRule ARGS "@rx <script>" "id:1003,phase:2,deny,log,msg:'XSS攻击'"
		`))
	if err != nil {
		t.Fatalf("无法创建 WAF: %v", err)
	}

	// 定义测试用例
	testCases := map[string]struct {
		uri       string
		method    string
		userAgent string
		args      map[string]string
		expectBlock bool
		expectRuleIDs []int
	}{
		"正常请求": {
			uri:       "/",
			method:    "GET",
			userAgent: "Mozilla/5.0",
			args:      nil,
			expectBlock: false,
			expectRuleIDs: []int{},
		},
		"访问管理页面": {
			uri:       "/admin",
			method:    "GET",
			userAgent: "Mozilla/5.0",
			args:      nil,
			expectBlock: true,
			expectRuleIDs: []int{1000},
		},
		"使用SQL注入工具": {
			uri:       "/search",
			method:    "GET",
			userAgent: "sqlmap/1.0",
			args:      nil,
			expectBlock: true,
			expectRuleIDs: []int{1001},
		},
		"SQL注入攻击(GET)": {
			uri:       "/search",
			method:    "GET",
			userAgent: "Mozilla/5.0",
			args:      map[string]string{"q": "UNION SELECT username, password FROM users"},
			expectBlock: true,
			expectRuleIDs: []int{1002},
		},
		"SQL注入攻击(POST)": {
			uri:       "/search",
			method:    "POST",
			userAgent: "Mozilla/5.0",
			args:      map[string]string{"q": "UNION SELECT username, password FROM users"},
			expectBlock: true,
			expectRuleIDs: []int{1002},
		},
		"XSS攻击": {
			uri:       "/comment",
			method:    "POST",
			userAgent: "Mozilla/5.0",
			args:      map[string]string{"content": "<script>alert('XSS')</script>"},
			expectBlock: true,
			expectRuleIDs: []int{1003},
		},
	}

	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			// 创建一个新的事务
			tx := waf.NewTransaction()
			defer func() {
				// 确保事务被关闭
				err := tx.Close()
				if err != nil {
					t.Fatalf("关闭事务时出错: %v", err)
				}
			}()

			// 设置 URI
			tx.ProcessURI(tc.uri, tc.method, "HTTP/1.1")
			t.Logf("处理 URI: %s, 方法: %s", tc.uri, tc.method)
			
			// 添加请求头
			tx.AddRequestHeader("User-Agent", tc.userAgent)
			tx.AddRequestHeader("Content-Type", "application/x-www-form-urlencoded")
			t.Logf("添加请求头: User-Agent=%s", tc.userAgent)
			
			// 处理请求头
			interruption := tx.ProcessRequestHeaders()
			if interruption != nil {
				t.Logf("请求头处理阶段被中断: %s", interruption.Action)
			}

			// 添加参数
			if tc.method == "GET" {
				for name, value := range tc.args {
					tx.AddGetRequestArgument(name, value)
					t.Logf("添加 GET 参数: %s=%s", name, value)
				}
			} else if tc.method == "POST" {
				for name, value := range tc.args {
					tx.AddPostRequestArgument(name, value)
					t.Logf("添加 POST 参数: %s=%s", name, value)
				}
				
				// 对于 POST 请求，我们需要模拟请求体
				if len(tc.args) > 0 {
					var bodyParts []string
					for name, value := range tc.args {
						bodyParts = append(bodyParts, name+"="+value)
					}
					body := strings.Join(bodyParts, "&")
					t.Logf("添加请求体: %s", body)
					
					// 写入请求体
					_, _, err := tx.WriteRequestBody([]byte(body))
					if err != nil {
						t.Fatalf("写入请求体时出错: %v", err)
					}
				}
			}

			// 处理请求体
			interruption, err = tx.ProcessRequestBody()
			if err != nil {
				t.Fatalf("处理请求体时出错: %v", err)
			}
			if interruption != nil {
				t.Logf("请求体处理阶段被中断: %s", interruption.Action)
			}

			// 检查干预（是否需要阻止请求）
			isBlocked := tx.IsInterrupted()
			
			if tc.expectBlock != isBlocked {
				t.Errorf("期望请求%s，但实际%s", 
					expectBlockStr(tc.expectBlock), 
					expectBlockStr(isBlocked))
			}

			// 获取匹配的规则
			matchedRules := tx.MatchedRules()
			matchedIDs := make([]int, 0, len(matchedRules))
			
			for _, rule := range matchedRules {
				matchedIDs = append(matchedIDs, rule.Rule().ID())
				t.Logf("命中规则: ID=%d", rule.Rule().ID())
			}
			
			// 验证命中的规则 ID
			if !equalIntSlice(tc.expectRuleIDs, matchedIDs) {
				t.Errorf("期望命中规则 IDs %v，但实际命中 %v", tc.expectRuleIDs, matchedIDs)
			}

			// 处理日志
			tx.ProcessLogging()
		})
	}
}

// 辅助函数：将是否阻止转换为字符串
func expectBlockStr(blocked bool) string {
	if blocked {
		return "被阻止"
	}
	return "被允许"
}

// 辅助函数：比较两个整数切片是否相等
func equalIntSlice(a, b []int) bool {
	if len(a) != len(b) {
		return false
	}
	
	// 创建 a 的副本，避免修改原始切片
	aCopy := make([]int, len(a))
	copy(aCopy, a)
	
	// 对每个 b 中的元素，在 a 中查找并移除
	for _, val := range b {
		found := false
		for i, aVal := range aCopy {
			if aVal == val {
				// 从 aCopy 中移除这个元素
				aCopy = append(aCopy[:i], aCopy[i+1:]...)
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	
	return true
}
