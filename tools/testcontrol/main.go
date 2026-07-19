// Command testcontrol wraps Tailscale's tstest/integration/testcontrol.Server
// as a standalone HTTP server for wire-format interop testing against
// rustscale's tsnet client. It also runs an in-process HTTPS DERP+STUN server so
// that clients get a fully local DERPMap and can relay traffic without
// external dependencies.
//
// The first line of stdout is the control URL (e.g. http://127.0.0.1:PORT).
// A side-channel JSON API is served under /testapi/ on the same listener for
// test orchestration: add-fake-node, expire-all, nodes, raw-map-response.
package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"tailscale.com/derp/derpserver"
	"tailscale.com/net/stun"
	"tailscale.com/tailcfg"
	"tailscale.com/tstest/integration/testcontrol"
	"tailscale.com/types/key"
	"tailscale.com/types/logger"
)

func main() {
	log.SetFlags(log.Lmicroseconds | log.Lmsgprefix)
	log.SetPrefix("testcontrol: ")

	// 1. Generate a self-signed cert for the test-only DERP server.
	cert, err := generateSelfSignedCert()
	if err != nil {
		log.Fatalf("cert: %v", err)
	}

	// 2. Start in-process DERP + STUN servers on 127.0.0.1.
	derpMap := runDERPAndSTUN(logger.Discard, cert)
	log.Printf("DERP+STUN started: region 1, %d DERP nodes", len(derpMap.Regions))

	// 3. Create the fake control server.
	control := &testcontrol.Server{
		DERPMap: derpMap,
		Logf:    logger.WithPrefix(log.Printf, "control: "),
	}

	// 4. Build the HTTP mux: testcontrol at /, side-channel API at /testapi/.
	mux := http.NewServeMux()
	mux.Handle("/", control)
	mux.HandleFunc("/testapi/add-fake-node", handleAddFakeNode(control))
	mux.HandleFunc("/testapi/expire-all", handleExpireAll(control))
	mux.HandleFunc("/testapi/nodes", handleNodes(control))
	mux.HandleFunc("/testapi/raw-map-response", handleRawMapResponse(control))
	mux.HandleFunc("/testapi/health", handleHealth)
	mux.HandleFunc("/testapi/audit-log", handleAuditLogStats(control))

	// 5. Start the plain-HTTP test control server on 127.0.0.1:0.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		log.Fatalf("listen: %v", err)
	}

	srv := &http.Server{Handler: mux}

	// Set ExplicitBaseURL so control.BaseURL() works (needed for auth URLs).
	port := ln.Addr().(*net.TCPAddr).Port
	controlURL := fmt.Sprintf("http://127.0.0.1:%d", port)
	control.ExplicitBaseURL = controlURL

	go func() {
		if err := srv.Serve(ln); err != nil {
			log.Fatalf("Serve: %v", err)
		}
	}()

	// 5. Print the plain-HTTP control URL as the first stdout line consumed
	// by the Rust harness. Test servers must opt into HTTP rather than infer
	// insecure TLS merely because they listen on loopback.
	fmt.Println(controlURL)
	os.Stdout.Sync()

	// 6. Wait for SIGINT/SIGTERM.
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	<-sigCh
	log.Printf("shutting down")
	srv.Shutdown(context.Background())
}

// ---------------------------------------------------------------------------
// DERP + STUN server (replicated from tstest/integration.RunDERPAndSTUN
// without the testing.TB dependency)
// ---------------------------------------------------------------------------

func runDERPAndSTUN(logf logger.Logf, cert tls.Certificate) *tailcfg.DERPMap {
	d := derpserver.New(key.NewNode(), logf)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		log.Fatalf("DERP listen: %v", err)
	}

	handler := derpserver.AddWebSocketSupport(d, derpserver.Handler(d))
	// Use a custom TLS listener with the same self-signed cert as the
	// control server. httptest.StartTLS() generates its own cert which
	// can cause TLS HandshakeFailure with rustls due to cipher suite /
	// signature algorithm mismatches.
	tlsLn := tls.NewListener(ln, &tls.Config{
		Certificates: []tls.Certificate{cert},
	})
	httpsrv := &http.Server{
		Handler:  handler,
		ErrorLog: logger.StdLogger(logf),
	}
	go func() {
		if err := httpsrv.Serve(tlsLn); err != nil {
			log.Fatalf("DERP Serve: %v", err)
		}
	}()

	stunAddr := serveSTUN()
	derpPort := ln.Addr().(*net.TCPAddr).Port

	m := &tailcfg.DERPMap{
		Regions: map[int]*tailcfg.DERPRegion{
			1: {
				RegionID:   1,
				RegionCode: "test",
				Nodes: []*tailcfg.DERPNode{
					{
						Name:             "t1",
						RegionID:         1,
						HostName:         "127.0.0.1",
						IPv4:             "127.0.0.1",
						IPv6:             "none",
						STUNPort:         stunAddr.Port,
						DERPPort:         derpPort,
						InsecureForTests: true,
						STUNTestIP:       "127.0.0.1",
					},
				},
			},
		},
	}

	log.Printf("DERP server on 127.0.0.1:%d, STUN on 127.0.0.1:%d", derpPort, stunAddr.Port)
	return m
}

// serveSTUN starts a STUN binding server on 127.0.0.1:0 and returns the
// address it's listening on. The server runs until the process exits.
func serveSTUN() *net.UDPAddr {
	pc, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		log.Fatalf("STUN listen: %v", err)
	}
	addr := pc.LocalAddr().(*net.UDPAddr)
	go runSTUN(pc)
	return addr
}

func runSTUN(pc net.PacketConn) {
	var buf [65536]byte
	for {
		n, src, err := pc.ReadFrom(buf[:])
		if err != nil {
			return
		}
		pkt := buf[:n]
		if !stun.Is(pkt) {
			continue
		}
		txid, err := stun.ParseBindingRequest(pkt)
		if err != nil {
			continue
		}
		udpAddr, ok := src.(*net.UDPAddr)
		if !ok {
			continue
		}
		addrPort := netip.AddrPortFrom(netip.AddrFrom4([4]byte(udpAddr.IP.To4())), uint16(udpAddr.Port))
		res := stun.Response(txid, addrPort)
		if _, err := pc.WriteTo(res, src); err != nil {
			// Server shutting down.
			return
		}
	}
}

// ---------------------------------------------------------------------------
// Side-channel API handlers
// ---------------------------------------------------------------------------

func handleAddFakeNode(control *testcontrol.Server) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		existing := make(map[key.NodePublic]bool)
		for _, node := range control.AllNodes() {
			existing[node.Key] = true
		}

		control.AddFakeNode()
		for _, node := range control.AllNodes() {
			if !existing[node.Key] {
				// AddFakeNode updates the node map but intentionally does not notify
				// streaming clients. UpdateNode publishes the new peer immediately.
				control.UpdateNode(node)
				log.Printf("AddFakeNode called and update published")
				w.WriteHeader(http.StatusNoContent)
				return
			}
		}

		http.Error(w, "fake node was not created", http.StatusInternalServerError)
	}
}

type expireAllRequest struct {
	Expired bool `json:"expired"`
}

func handleExpireAll(control *testcontrol.Server) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		var req expireAllRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, fmt.Sprintf("bad JSON: %v", err), http.StatusBadRequest)
			return
		}
		control.SetExpireAllNodes(req.Expired)
		log.Printf("SetExpireAllNodes(%v)", req.Expired)
		w.WriteHeader(http.StatusNoContent)
	}
}

type nodeInfo struct {
	Key string `json:"key"`
	ID  int64  `json:"id"`
	IP  string `json:"ip"`
}

type nodesResponse struct {
	Count int        `json:"count"`
	Nodes []nodeInfo `json:"nodes"`
}

func handleNodes(control *testcontrol.Server) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		all := control.AllNodes()
		resp := nodesResponse{
			Count: len(all),
			Nodes: make([]nodeInfo, 0, len(all)),
		}
		for _, n := range all {
			ip := ""
			if len(n.Addresses) > 0 {
				ip = n.Addresses[0].String()
			}
			resp.Nodes = append(resp.Nodes, nodeInfo{
				Key: n.Key.String(),
				ID:  int64(n.ID),
				IP:  ip,
			})
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}
}

type rawMapResponseRequest struct {
	NodeKey         string          `json:"nodeKey"`
	MapResponseJSON json.RawMessage `json:"mapResponseJSON"`
}

func handleRawMapResponse(control *testcontrol.Server) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		var req rawMapResponseRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, fmt.Sprintf("bad JSON: %v", err), http.StatusBadRequest)
			return
		}
		nodeKeyStr := strings.TrimSpace(req.NodeKey)
		if nodeKeyStr == "" {
			http.Error(w, "nodeKey is required", http.StatusBadRequest)
			return
		}
		var nk key.NodePublic
		if err := nk.UnmarshalText([]byte(nodeKeyStr)); err != nil {
			http.Error(w, fmt.Sprintf("bad nodeKey: %v", err), http.StatusBadRequest)
			return
		}
		var mr tailcfg.MapResponse
		if err := json.Unmarshal(req.MapResponseJSON, &mr); err != nil {
			http.Error(w, fmt.Sprintf("bad MapResponse JSON: %v", err), http.StatusBadRequest)
			return
		}
		ok := control.AddRawMapResponse(nk, &mr)
		log.Printf("AddRawMapResponse(node=%s) -> %v", nodeKeyStr, ok)
		if !ok {
			http.Error(w, "node not currently in map poll", http.StatusConflict)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}
}

type auditLogStatsResponse struct {
	Accepted     uint64 `json:"accepted"`
	Rejected     uint64 `json:"rejected"`
	Action       string `json:"action"`
	DetailsLen   int    `json:"detailsLen"`
	TimestampSet bool   `json:"timestampSet"`
	BodySHA256   string `json:"bodySHA256"`
	LastError    string `json:"lastError"`
}

func handleAuditLogStats(control *testcontrol.Server) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		stats := control.AuditLogStats()
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(auditLogStatsResponse{
			Accepted: stats.Accepted, Rejected: stats.Rejected,
			Action: string(stats.Action), DetailsLen: stats.DetailsLen,
			TimestampSet: stats.TimestampSet, BodySHA256: stats.LastBodySHA256,
			LastError: stats.LastError,
		})
	}
}

func handleHealth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	fmt.Fprintf(w, `{"ok":true}`)
}

// ---------------------------------------------------------------------------
// Self-signed TLS certificate
// ---------------------------------------------------------------------------

func generateSelfSignedCert() (tls.Certificate, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("generate key: %w", err)
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "127.0.0.1",
		},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:              []string{"127.0.0.1", "localhost"},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
		BasicConstraintsValid: true,
	}

	der, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("create cert: %w", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyBytes, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("marshal key: %w", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyBytes})

	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("load key pair: %w", err)
	}
	return cert, nil
}

// Suppress unused import warnings for imports that may be needed in future
// extensions.
var _ = strings.TrimSpace
