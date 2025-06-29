package recon

import (
	"context"
	"log"
	"strings"
	"time"

	"github.com/fatih/color"
	"github.com/gorilla/websocket"
	"github.com/tidwall/gjson"
)

const certStreamURL = "wss://certstream.calidog.io/"

// StartMonitoring connects to the Certificate Transparency Log stream and watches for new subdomains.
func (e *Engine) StartMonitoring(ctx context.Context) {
	color.Cyan("👂 Starting Real-Time Monitoring for *.%s...", e.Options.Domain)
	
	for {
		select {
		case <-ctx.Done():
			log.Println("Shutting down monitor.")
			return
		default:
			conn, _, err := websocket.DefaultDialer.Dial(certStreamURL, nil)
			if err != nil {
				log.Printf("⚠️ Could not connect to CertStream, retrying in 15 seconds: %v", err)
				time.Sleep(15 * time.Second)
				continue
			}
			
			color.Green("✅ Connected to CertStream real-time feed.")
			
			// Inner loop for reading messages
			for {
				_, message, err := conn.ReadMessage()
				if err != nil {
					log.Printf("⚠️ Error reading from CertStream, will attempt to reconnect: %v", err)
					conn.Close() // Close the connection on error
					break // Break inner loop to trigger reconnect
				}

				if gjson.Get(string(message), "message_type").String() != "certificate_update" {
					continue
				}

				for _, domain := range gjson.Get(string(message), "data.leaf_cert.all_domains").Array() {
					domainName := domain.String()
					if strings.HasSuffix(domainName, "."+e.Options.Domain) && !strings.HasPrefix(domainName, "*.") {
						e.processDiscoveredSubdomain(domainName)
					}
				}
			}
			conn.Close()
		}
	}
}

func (e *Engine) processDiscoveredSubdomain(subdomain string) {
	previousResult, _ := e.Store.GetPreviousResult(e.Options.Domain)
	if previousResult != nil {
		for _, knownSub := range previousResult.Subdomains {
			if knownSub == subdomain {
				return
			}
		}
	}
	color.Yellow("🚀 REAL-TIME DISCOVERY: Found new subdomain: %s", subdomain)
}
