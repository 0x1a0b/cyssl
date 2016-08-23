package main

import "testing"

func TestLoad(t *testing.T) {
	config := NewConfig()
	if err := config.load(); err != nil {
		t.Error(err)
		t.Fail()
	}
}
