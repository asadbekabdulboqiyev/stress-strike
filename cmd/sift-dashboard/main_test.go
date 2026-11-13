package main

import (
	"strings"
	"sync"
	"testing"
)

func TestFlagStringsStringAndSet(t *testing.T) {
	var fs flagStrings
	if fs.String() != "" {
		t.Errorf("String() = %q, want empty", fs.String())
	}

	if err := fs.Set("a"); err != nil {
		t.Fatal(err)
	}
	if err := fs.Set("b"); err != nil {
		t.Fatal(err)
	}
	if err := fs.Set("c"); err != nil {
		t.Fatal(err)
	}

	got := fs.String()
	want := "a,b,c"
	if got != want {
		t.Errorf("String() = %q, want %q", got, want)
	}
	if len(fs) != 3 {
		t.Errorf("len(fs) = %d, want 3", len(fs))
	}
	if !strings.Contains(got, "b") {
		t.Errorf("String() = %q does not contain b", got)
	}
}

func TestGetString(t *testing.T) {
	m := map[string]interface{}{
		"name": "hello",
		"age":  30,
	}
	if getString(m, "name", "default") != "hello" {
		t.Error("getString string value wrong")
	}
	if getString(m, "missing", "default") != "default" {
		t.Error("getString missing key wrong")
	}
	if getString(m, "age", "default") != "default" {
		t.Error("getString non-string value wrong")
	}
}

func TestGetInt(t *testing.T) {
	m := map[string]interface{}{
		"count": float64(42),
		"name":  "hello",
	}
	if getInt(m, "count", 0) != 42 {
		t.Errorf("getInt float64 value wrong: %d", getInt(m, "count", 0))
	}
	if getInt(m, "missing", 7) != 7 {
		t.Errorf("getInt missing key wrong: %d", getInt(m, "missing", 7))
	}
	if getInt(m, "name", 99) != 99 {
		t.Errorf("getInt non-numeric value wrong: %d", getInt(m, "name", 99))
	}
}

func TestGetStringMap(t *testing.T) {
	m := map[string]interface{}{
		"headers": map[string]interface{}{
			"Content-Type": "application/json",
			"Count":        float64(5),
			"Active":       true,
			"Other":        []string{"a"},
		},
	}
	out := getStringMap(m, "headers")
	if out == nil {
		t.Fatal("getStringMap returned nil")
	}
	if out["Content-Type"] != "application/json" {
		t.Errorf("getStringMap string value wrong: %q", out["Content-Type"])
	}
	if out["Count"] != "5" {
		t.Errorf("getStringMap float64 value wrong: %q", out["Count"])
	}
	if out["Active"] != "true" {
		t.Errorf("getStringMap bool value wrong: %q", out["Active"])
	}
	if getStringMap(m, "missing") != nil {
		t.Error("getStringMap missing key should return nil")
	}
}

func TestMarkInactive(t *testing.T) {
	active := true
	markInactive(&sync.Mutex{}, &active)
	if active {
		t.Error("markInactive did not set active to false")
	}
}
