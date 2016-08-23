package main

import (
	"io/ioutil"

	"gopkg.in/yaml.v2"
)

// Config load and parse config.yml
type Config struct {
	Mongo   map[string]string `yaml:"mongo"`
	Plugins map[string]bool   `yaml:"plugins"`
}

// NewConfig create yaml Config
func NewConfig() *Config {
	return &Config{
		Mongo:   map[string]string{},
		Plugins: map[string]bool{},
	}
}
func (c *Config) load() error {
	data, err := ioutil.ReadFile("config.yml")
	if err != nil {
		return err
	}
	if err := yaml.Unmarshal(data, c); err != nil {
		return err
	}
	return nil
}
