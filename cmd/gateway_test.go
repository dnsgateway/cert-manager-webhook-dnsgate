/*
Copyright 2026 DNS Gateway Team.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"net/netip"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/resolver"
	"google.golang.org/grpc/resolver/manual"
	"google.golang.org/grpc/status"

	dnsgatev1 "github.com/dnsgateway/dnsgate-go/api/dnsgate/v1"
	"github.com/dnsgateway/dnsgate-go/client"
)

// retryingServiceConfig is a Gateway service config that asks the client
// to retry a call that ends Unavailable.
const retryingServiceConfig = `{
  "methodConfig": [{
    "name": [{"service": "dnsgate.v1.GatewayService"}],
    "retryPolicy": {
      "maxAttempts": 5,
      "initialBackoff": "0.01s",
      "maxBackoff": "0.01s",
      "backoffMultiplier": 1,
      "retryableStatusCodes": ["UNAVAILABLE"]
    }
  }]
}`

// unavailableGateway is a Gateway that counts the calls it gets and ends
// each one Unavailable.
type unavailableGateway struct {
	dnsgatev1.UnimplementedGatewayServiceServer

	calls atomic.Int32
}

func (g *unavailableGateway) Call(stream grpc.BidiStreamingServer[dnsgatev1.CallRequest, dnsgatev1.CallResponse]) error {
	g.calls.Add(1)

	if _, err := stream.Recv(); err != nil {
		return err
	}

	return status.Error(codes.Unavailable, "try again")
}

// localGatewayTLS returns the TLS config of a Gateway named serverName and the
// config of a client that trusts it.
func localGatewayTLS(t *testing.T, serverName string) (server, client *tls.Config) {
	t.Helper()

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: serverName},
		DNSNames:     []string{serverName},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, pub, priv)
	if err != nil {
		t.Fatal(err)
	}

	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}

	roots := x509.NewCertPool()
	roots.AddCert(cert)

	server = &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: priv}}, MinVersion: tls.VersionTLS13}
	client = &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS13}

	return server, client
}

// startGateway serves gw over TLS on a local port and returns an address
// that resolves to it with serviceConfig as the Gateway's service config.
func startGateway(t *testing.T, gw dnsgatev1.GatewayServiceServer, serverTLS *tls.Config, serviceConfig string) string {
	t.Helper()

	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}

	srv := grpc.NewServer(grpc.Creds(credentials.NewTLS(serverTLS)))
	dnsgatev1.RegisterGatewayServiceServer(srv, gw)

	go func() { _ = srv.Serve(lis) }()

	t.Cleanup(srv.Stop)

	r := manual.NewBuilderWithScheme("dnsgate-test")
	r.BuildCallback = func(_ resolver.Target, cc resolver.ClientConn, _ resolver.BuildOptions) {
		_ = cc.UpdateState(resolver.State{
			Addresses:     []resolver.Address{{Addr: lis.Addr().String()}},
			ServiceConfig: cc.ParseServiceConfig(serviceConfig),
		})
	}
	resolver.Register(r)

	return "dnsgate-test:///gateway"
}

// agentEgressGateway answers every Call by asking the client, as Egress
// Agent, to open a connection to providerHost on port 443, recording
// the client's answer, then sending a PatchRecord response.
type agentEgressGateway struct {
	dnsgatev1.UnimplementedGatewayServiceServer

	providerHost string

	mu     sync.Mutex
	opened *dnsgatev1.RelayOpened
}

func (g *agentEgressGateway) Call(stream grpc.BidiStreamingServer[dnsgatev1.CallRequest, dnsgatev1.CallResponse]) error {
	if _, err := stream.Recv(); err != nil {
		return err
	}

	open := &dnsgatev1.RelayOpen{Id: 1, Host: g.providerHost, Port: 443}
	if err := stream.Send(&dnsgatev1.CallResponse{Message: &dnsgatev1.CallResponse_Open{Open: open}}); err != nil {
		return err
	}

	msg, err := stream.Recv()
	if err != nil {
		return err
	}

	g.mu.Lock()
	g.opened = msg.GetOpened()
	g.mu.Unlock()

	return stream.Send(&dnsgatev1.CallResponse{Message: &dnsgatev1.CallResponse_Response{Response: &dnsgatev1.Response{
		Result: &dnsgatev1.Response_PatchRecord{PatchRecord: &dnsgatev1.PatchRecordResponse{}},
	}}})
}

// providerNet resolves every host to providerAddr and records the
// addresses dialed, answering each with a connection the Provider
// closes at once.
type providerNet struct {
	mu     sync.Mutex
	dialed []string
}

var providerAddr = netip.MustParseAddr("192.0.2.10")

func (n *providerNet) LookupNetIP(context.Context, string, string) ([]netip.Addr, error) {
	return []netip.Addr{providerAddr}, nil
}

func (n *providerNet) DialContext(_ context.Context, _, addr string) (net.Conn, error) {
	n.mu.Lock()
	n.dialed = append(n.dialed, addr)
	n.mu.Unlock()

	conn, peer := net.Pipe()
	_ = peer.Close()

	return conn, nil
}

func TestTheGatewayClientActsAsEgressAgent(t *testing.T) {
	serverTLS, clientTLS := localGatewayTLS(t, "gateway")
	gw := &agentEgressGateway{providerHost: "api.provider.example"}
	address := startGateway(t, gw, serverTLS, "{}")
	pn := &providerNet{}

	c, err := dialGateway(address, clientTLS, client.EgressAgent{Resolver: pn, Dialer: pn})
	if err != nil {
		t.Fatal(err)
	}

	req := &dnsgatev1.PatchRecordRequest{Token: "tok-a", Egress: dnsgatev1.Egress_EGRESS_AGENT, Zone: "example.com", Name: "_acme-challenge", Type: "TXT"}
	if _, err := c.PatchRecord(t.Context(), req); err != nil {
		t.Fatalf("PatchRecord: %v", err)
	}

	gw.mu.Lock()
	opened := gw.opened
	gw.mu.Unlock()

	if opened == nil || opened.GetId() != 1 || opened.GetError() != "" {
		t.Fatalf("the client answered RelayOpen with %v, want an opened connection", opened)
	}

	pn.mu.Lock()
	defer pn.mu.Unlock()

	if want := []string{"192.0.2.10:443"}; !slices.Equal(pn.dialed, want) {
		t.Errorf("the client dialed %v, want %v", pn.dialed, want)
	}
}

func TestTheGatewayClientNeverRetriesAFailedCall(t *testing.T) {
	serverTLS, clientTLS := localGatewayTLS(t, "gateway")
	gw := &unavailableGateway{}
	address := startGateway(t, gw, serverTLS, retryingServiceConfig)

	c, err := dialGateway(address, clientTLS, client.EgressAgent{})
	if err != nil {
		t.Fatal(err)
	}

	_, err = c.PatchRecord(t.Context(), &dnsgatev1.PatchRecordRequest{Token: "tok-a", Zone: "example.com", Name: "_acme-challenge", Type: "TXT"})
	if status.Code(err) != codes.Unavailable {
		t.Fatalf("PatchRecord error = %v, want Unavailable", err)
	}

	if n := gw.calls.Load(); n != 1 {
		t.Errorf("the Gateway got %d calls, want 1", n)
	}
}
