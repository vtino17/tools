package proxy

import (
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestRoute(t *testing.T) {
	t.Setenv("DEVHIBERNATE_HOME", t.TempDir())
	b := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte("ok")) }))
	defer b.Close()
	if e := Register("x.localhost", b.URL, "o"); e != nil {
		t.Fatal(e)
	}
	q := httptest.NewRequest("GET", "http://x.localhost/", nil)
	q.Host = "x.localhost"
	w := httptest.NewRecorder()
	Handler().ServeHTTP(w, q)
	d, _ := io.ReadAll(w.Result().Body)
	if string(d) != "ok" {
		t.Fatal(string(d))
	}
}
func TestRemoveOwner(t *testing.T) {
	t.Setenv("DEVHIBERNATE_HOME", t.TempDir())
	_ = Register("a.localhost", "http://127.0.0.1:1", "x")
	_ = Register("b.localhost", "http://127.0.0.1:2", "y")
	_ = RemoveOwner("x")
	r, _ := LoadRegistry()
	if _, ok := r.Routes["a.localhost"]; ok {
		t.Fatal("not removed")
	}
	if _, ok := r.Routes["b.localhost"]; !ok {
		t.Fatal("removed wrong")
	}
}
