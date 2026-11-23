package golog

import "testing"

func TestSafeLocalTarget(t *testing.T) {
	for in, want := range map[string]string{
		"/demo/12":               "/demo/12",
		"/demo/?cmd=List&a=b":    "/demo/?cmd=List&a=b",
		"":                       "",
		"demo/12":                "",
		"//evil.example/x":       "",
		"/\\evil.example":        "",
		"https://evil.example/":  "",
		"javascript:alert(1)":    "",
		"/ok\r\nSet-Cookie: x=1": "",
		"/with\\backslash":       "",
		"  /padded":              "/padded",
	} {
		if got := safeLocalTarget(in); got != want {
			t.Errorf("safeLocalTarget(%q) = %q, want %q", in, got, want)
		}
	}
}
