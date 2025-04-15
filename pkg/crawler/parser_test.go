package crawler

import "testing"

func TestNewParser(t *testing.T) {
	parser := NewParser()

	// 确保创建的解析器不为nil
	if parser == nil {
		t.Error("NewParser()应该返回非nil的解析器实例")
	}

	// 由于Parser结构体是空的，我们只能验证它不是nil
	// 实际功能在其他专门的解析器测试文件中测试
}
