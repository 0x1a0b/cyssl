package main

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"time"

	"github.com/fatih/color"

	"github.com/jetz/cyssl/db"
	"github.com/jetz/cyssl/plugins"
)

// SSLScanner scan SSL certificate/protocols/heartbleed etc.
type SSLScanner struct {
	Domains     []string
	Output      string
	Concurrency int

	DB        *db.Mongo
	Detectors []plugins.BaseDetector
}

// NewSSLScanner create a SSLScanner
func NewSSLScanner(domains []string, output string, concurrency int) *SSLScanner {
	return &SSLScanner{
		Domains:     domains,
		Output:      output,
		Concurrency: concurrency,
	}
}

func (s *SSLScanner) loadConfig() {
	// read the config file
	config := NewConfig()
	if err := config.load(); err != nil {
		log.Fatal(err)
	}

	// only apply enabled detectors
	for _, d := range plugins.PluginManager.Detectors {
		if config.Plugins[d.Name()] {
			s.Detectors = append(s.Detectors, d)
		}
	}

	// create mongo db
	mongoURI := fmt.Sprintf("mongodb://%s:%s@%s/%s",
		config.Mongo["username"],
		config.Mongo["password"],
		config.Mongo["address"],
		config.Mongo["db"],
	)
	if config.Mongo["username"] == "" {
		mongoURI = fmt.Sprintf("mongodb://%s/%s", config.Mongo["address"], config.Mongo["db"])
	}
	s.DB = db.NewMongo(mongoURI, config.Mongo["db"], config.Mongo["collection"])
}

// Run SSLScanner entrypoint
func (s *SSLScanner) Run() {
	s.loadConfig()

	r := make(chan map[string]interface{}, s.Concurrency)

	// Keep goroutine no more than s.Concurrency
	nTurns := len(s.Domains)/s.Concurrency + 1
	for i := 0; i < nTurns; i++ {
		start, end := i*s.Concurrency, (i+1)*s.Concurrency
		// when left items less than s.Concurrency in last turn
		if len(s.Domains[start:]) < s.Concurrency {
			end = len(s.Domains)
		}

		for _, domain := range s.Domains[start:end] {
			go s.scan(domain, r)
		}

		for j := 0; j < end-start; j++ {
			dr := <-r
			if domain, ok := dr["domain"].(string); ok {
				s.handOutput(dr, s.Output)
				log.Printf("Finish scanning %s", domain)
			}
		}
	}
	close(r)
}

func (s *SSLScanner) scan(domain string, ch chan map[string]interface{}) {
	r := map[string]interface{}{"domain": domain, "ssl": "enabled"}

	// Set timeout, check if domain has enabled SSL
	dialer := &net.Dialer{Timeout: 15 * time.Second}
	conn, err := tls.DialWithDialer(dialer, "tcp", domain+":443", &tls.Config{
		InsecureSkipVerify: true,
	})

	if err != nil {
		r["ssl"] = "disabled"
		fmt.Printf("%s => %s\n", domain, err.Error())
		ch <- r
		return
	}

	defer conn.Close()

	// call all plugin detectors, and merge result
	for _, detector := range s.Detectors {
		dResult := make(map[string]interface{})
		for k, v := range detector.Detect(domain, conn) {
			dResult[k] = v
		}
		r[detector.Name()] = dResult
	}

	ch <- r
}

func (s *SSLScanner) handOutput(result map[string]interface{}, format string) {
	switch format {
	case "json":
		jsonData, err := json.MarshalIndent(result, "", "    ")
		if err != nil {
			panic(err.Error())
		}
		color.Green(string(jsonData))
	case "mongo":
		s.DB.Output(result)
	default:
		color.Green("<%s> not support yet", format)
	}
}
