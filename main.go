package main

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"time"
)

type Input struct {
	Domains []string `json:"domains"`
}

func loadInput() (*Input, error) {
	data, err := os.ReadFile("INPUT.json")
	if err != nil {
		return nil, fmt.Errorf("read INPUT.json: %w", err)
	}
	var input Input
	if err := json.Unmarshal(data, &input); err != nil {
		return nil, fmt.Errorf("parse INPUT.json: %w", err)
	}
	if len(input.Domains) == 0 {
		return nil, fmt.Errorf("no domains provided in INPUT.json")
	}
	return &input, nil
}

type DomainResult struct {
	Domain           string   `json:"domain"`
	Registrar        string   `json:"registrar"`
	RegistrationDate string   `json:"registration_date,omitempty"`
	ExpirationDate   string   `json:"expiration_date,omitempty"`
	LastChangedDate  string   `json:"last_changed_date,omitempty"`
	Status           []string `json:"status"`
	Nameservers      []string `json:"nameservers"`
	SSLCertExpiry    string   `json:"ssl_cert_expiry,omitempty"`
	SSLCertIssuer    string   `json:"ssl_cert_issuer,omitempty"`
	Error            string   `json:"error,omitempty"`
}

func main() {
	log.SetFlags(log.LstdFlags | log.Lshortfile)
	log.Println("Domain Expiry Watch Actor starting")

	input, err := loadInput()
	if err != nil {
		log.Fatalf("input: %v", err)
	}
	log.Printf("checking %d domains", len(input.Domains))

	client := &httpClient{client: &http.Client{Timeout: 20 * time.Second}}

	results := make([]DomainResult, 0, len(input.Domains))
	for _, domain := range input.Domains {
		domain = strings.TrimSpace(domain)
		if domain == "" {
			continue
		}
		log.Printf("checking: %s", domain)
		result := checkDomain(client, domain)
		results = append(results, result)
	}

	if err := pushResults(results); err != nil {
		log.Fatalf("push results: %v", err)
	}
	log.Printf("done: %d domains checked", len(results))
}

func checkDomain(c *httpClient, domain string) DomainResult {
	r := DomainResult{Domain: domain}

	rdap, err := c.rdapLookup(domain)
	if err != nil {
		r.Error = fmt.Sprintf("rdap: %v", err)
	} else {
		r.Registrar = rdap.Registrar
		r.RegistrationDate = rdap.RegistrationDate
		r.ExpirationDate = rdap.ExpirationDate
		r.LastChangedDate = rdap.LastChangedDate
		r.Status = rdap.Status
		for _, ns := range rdap.Nameservers {
			r.Nameservers = append(r.Nameservers, ns.Name)
		}
	}

	ssl, err := c.sslCheck(domain)
	if err != nil {
		if r.Error == "" {
			r.Error = fmt.Sprintf("ssl: %v", err)
		}
	} else {
		r.SSLCertExpiry = ssl.Expiry
		r.SSLCertIssuer = ssl.Issuer
	}

	return r
}

type httpClient struct {
	client *http.Client
}

type rdapRaw struct {
	LdName      string `json:"ldhName"`
	UnicodeName string `json:"unicodeName"`
	Status      []string
	Events      []rdapRawEvent
	Nameservers []struct {
		LdName string `json:"ldhName"`
	} `json:"nameservers"`
	Entities []rdapEntity `json:"entities"`
}

type rdapRawEvent struct {
	EventAction string `json:"eventAction"`
	EventDate   string `json:"eventDate"`
}

type rdapEntity struct {
	Roles  []string `json:"roles"`
	VCard []any    `json:"vcardArray"`
}

type rdapResult struct {
	Registrar        string
	RegistrationDate string
	ExpirationDate   string
	LastChangedDate  string
	Status           []string
	Nameservers      []struct{ Name string }
}

func (c *httpClient) rdapLookup(domain string) (*rdapResult, error) {
	url := "https://rdap.org/domain/" + domain
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/rdap+json")

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("rdap request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound || resp.StatusCode == http.StatusBadRequest {
		return nil, fmt.Errorf("domain not found in RDAP")
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("rdap returned %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read: %w", err)
	}

	var raw rdapRaw
	if err := json.Unmarshal(body, &raw); err != nil {
		return nil, fmt.Errorf("parse: %w", err)
	}

	out := &rdapResult{Status: raw.Status}
	if raw.UnicodeName != "" {
		// keep original domain for output
	}
	for _, e := range raw.Events {
		action := strings.ToLower(strings.TrimSpace(e.EventAction))
		switch action {
		case "registration":
			out.RegistrationDate = e.EventDate
		case "expiration":
			out.ExpirationDate = e.EventDate
		case "last changed":
			out.LastChangedDate = e.EventDate
		}
	}
	for _, ns := range raw.Nameservers {
		out.Nameservers = append(out.Nameservers, struct{ Name string }{ns.LdName})
	}
	for _, e := range raw.Entities {
		for _, role := range e.Roles {
			if role == "registrar" {
				out.Registrar = extractVCardName(e.VCard)
			}
		}
	}
	return out, nil
}

type sslResult struct {
	Expiry string
	Issuer string
}

func (c *httpClient) sslCheck(domain string) (*sslResult, error) {
	d := &net.Dialer{Timeout: 10 * time.Second}
	conn, err := tls.DialWithDialer(d, "tcp", domain+":443", &tls.Config{InsecureSkipVerify: true})
	if err != nil {
		return nil, fmt.Errorf("tls dial: %w", err)
	}
	defer conn.Close()

	certs := conn.ConnectionState().PeerCertificates
	if len(certs) == 0 {
		return nil, fmt.Errorf("no certificates")
	}

	cert := certs[0]
	return &sslResult{
		Expiry: cert.NotAfter.UTC().Format(time.RFC3339),
		Issuer: cert.Issuer.CommonName,
	}, nil
}

func extractVCardName(vcard []any) string {
	if len(vcard) < 2 {
		return ""
	}
	props, ok := vcard[1].([]any)
	if !ok {
		return ""
	}
	for _, p := range props {
		prop, ok := p.([]any)
		if !ok || len(prop) < 4 {
			continue
		}
		name, _ := prop[0].(string)
		if name == "fn" {
			val, _ := prop[3].(string)
			return val
		}
	}
	return ""
}

func pushResults(results []DomainResult) error {
	datasetID := os.Getenv("APIFY_DEFAULT_DATASET_ID")
	token := os.Getenv("APIFY_TOKEN")

	if datasetID == "" {
		log.Println("APIFY_DEFAULT_DATASET_ID not set, writing to stdout")
		for _, r := range results {
			b, _ := json.Marshal(r)
			fmt.Println(string(b))
		}
		return nil
	}

	baseURL := os.Getenv("APIFY_API_PUBLIC_BASE_URL")
	if baseURL == "" {
		baseURL = "https://api.apify.com"
	}

	url := fmt.Sprintf("%s/v2/datasets/%s/items", baseURL, datasetID)
	if token != "" {
		url += "?token=" + token
	}

	body, err := json.Marshal(results)
	if err != nil {
		return fmt.Errorf("marshal results: %w", err)
	}

	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := (&http.Client{Timeout: 30 * time.Second}).Do(req)
	if err != nil {
		return fmt.Errorf("push to dataset: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		respBody, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("dataset API returned %d: %s", resp.StatusCode, string(respBody))
	}
	log.Println("results pushed to dataset")
	return nil
}
