package main

import (
	"bufio"
	"flag"
	"log"
	"os"
	"strings"
)

func loadDomains(domain, filename string) []string {
	domains := []string{}

	if domain != "" {
		domains = append(domains, domain)
	} else if filename != "" {
		file, err := os.Open(filename)
		if err != nil {
			log.Fatal(err.Error())
		}
		defer file.Close()

		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			if d := strings.TrimSpace(scanner.Text()); d != "" {
				domains = append(domains, d)
			}
		}
	} else {
		flag.Usage()
		os.Exit(1)
	}
	return domains
}

func main() {

	log.SetFlags(log.LstdFlags | log.Lshortfile)
	log.SetOutput(os.Stdout)

	var concurrency int
	var domain, filename, output string

	flag.StringVar(&domain, "t", "", "Target domain to scan")
	flag.StringVar(&filename, "f", "", "File contains bulk domains")
	flag.StringVar(&output, "o", "json", "Output format")
	flag.IntVar(&concurrency, "c", 50, "Concurrency for scanning")
	flag.Parse()

	domains := loadDomains(domain, filename)

	NewSSLScanner(domains, output, concurrency).Run()
}
