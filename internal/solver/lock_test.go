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

package solver_test

import (
	"context"
	"errors"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	whapi "github.com/cert-manager/cert-manager/pkg/acme/webhook/apis/acme/v1alpha1"
	"k8s.io/client-go/kubernetes/fake"
	corev1client "k8s.io/client-go/kubernetes/typed/core/v1"
	restclient "k8s.io/client-go/rest"

	dnsgatev1 "github.com/dnsgateway/dnsgate-go/api/dnsgate/v1"

	"github.com/dnsgateway/cert-manager-webhook-dnsgate/internal/solver"
)

// blockingGateway holds every PatchRecord until release is closed, and
// records how many it held at once. It ignores the context, so a call
// in it holds its Challenge Target for as long as the test wants.
type blockingGateway struct {
	entered chan struct{}
	release chan struct{}
	opened  sync.Once

	mu        sync.Mutex
	calls     int
	inFlight  int
	maxFlight int
	deadlines []time.Time
}

// newBlockingGateway returns a blockingGateway that t opens, at the
// latest, when it ends.
func newBlockingGateway(t *testing.T) *blockingGateway {
	t.Helper()

	g := &blockingGateway{entered: make(chan struct{}, 16), release: make(chan struct{})}
	t.Cleanup(g.open)

	return g
}

// open lets every call held in g, and every later one, through.
func (g *blockingGateway) open() { g.opened.Do(func() { close(g.release) }) }

func (g *blockingGateway) PatchRecord(ctx context.Context, _ *dnsgatev1.PatchRecordRequest) (*dnsgatev1.PatchRecordResponse, error) {
	deadline, _ := ctx.Deadline()

	g.mu.Lock()
	g.calls++
	g.deadlines = append(g.deadlines, deadline)
	g.inFlight++
	g.maxFlight = max(g.maxFlight, g.inFlight)
	g.mu.Unlock()

	g.entered <- struct{}{}
	<-g.release

	g.mu.Lock()
	g.inFlight--
	g.mu.Unlock()

	return &dnsgatev1.PatchRecordResponse{}, nil
}

// stats returns how many calls g got and the most it held at once.
func (g *blockingGateway) stats() (calls, maxFlight int) {
	g.mu.Lock()
	defer g.mu.Unlock()

	return g.calls, g.maxFlight
}

// deadline returns the context deadline of the i-th call g got.
func (g *blockingGateway) deadline(i int) time.Time {
	g.mu.Lock()
	defer g.mu.Unlock()

	return g.deadlines[i]
}

// waitEntered fails t unless a call enters g within d.
func (g *blockingGateway) waitEntered(t *testing.T, d time.Duration) {
	t.Helper()

	select {
	case <-g.entered:
	case <-time.After(d):
		t.Fatalf("no call reached the Gateway within %v", d)
	}
}

// noneEntered fails t if a call enters g within d.
func (g *blockingGateway) noneEntered(t *testing.T, d time.Duration) {
	t.Helper()

	select {
	case <-g.entered:
		t.Fatal("a second call reached the Gateway while the first held the Challenge Target")
	case <-time.After(d):
	}
}

// newInitializedSolver builds and initializes a solver with gw and timeout,
// over a clientset holding the dnsgate token Secret of team-a.
func newInitializedSolver(t *testing.T, gw solver.Gateway, timeout time.Duration) *solver.Solver {
	t.Helper()

	clientset := fake.NewClientset(tokenSecret("team-a", "dnsgate", map[string]string{"token": "tok-a"}))
	s := solver.New(solver.Options{
		NewSecrets: func(*restclient.Config) (corev1client.SecretsGetter, error) { return clientset.CoreV1(), nil },
		NewGateway: func() (solver.Gateway, error) { return gw, nil },
		Timeout:    timeout,
		Logger:     slog.New(slog.DiscardHandler),
	})
	if err := s.Initialize(&restclient.Config{}, nil); err != nil {
		t.Fatal(err)
	}

	return s
}

// withChallengeTarget returns ch with its Challenge Target and
// resolved zone set to fqdn and zone.
func withChallengeTarget(ch *whapi.ChallengeRequest, fqdn, zone string) *whapi.ChallengeRequest {
	ch.ResolvedFQDN, ch.ResolvedZone = fqdn, zone

	return ch
}

// tokenConfig is a solver config naming the dnsgate Secret.
const tokenConfig = `{"tokenSecretRef":{"name":"dnsgate"}}`

// goCall runs call in a goroutine and returns where its error arrives.
func goCall(call func() error) <-chan error {
	done := make(chan error, 1)

	go func() { done <- call() }()

	return done
}

func TestCallsAtOneChallengeTargetNeverOverlap(t *testing.T) {
	tests := map[string]func(*solver.Solver) error{
		"Present and Present": func(s *solver.Solver) error { return s.Present(challenge(tokenConfig)) },
		"Present and CleanUp": func(s *solver.Solver) error { return s.CleanUp(cleanUpChallenge(tokenConfig)) },
		"a target that differs only in case": func(s *solver.Solver) error {
			return s.Present(withChallengeTarget(challenge(tokenConfig), "_ACME-Challenge.Example.COM.", "EXAMPLE.com."))
		},
	}

	for name, second := range tests {
		t.Run(name, func(t *testing.T) {
			gw := newBlockingGateway(t)
			s := newInitializedSolver(t, gw, 5*time.Second)

			first := goCall(func() error { return s.Present(challenge(tokenConfig)) })
			gw.waitEntered(t, 5*time.Second)

			next := goCall(func() error { return second(s) })
			gw.noneEntered(t, 200*time.Millisecond)

			gw.open()

			for _, done := range []<-chan error{first, next} {
				if err := <-done; err != nil {
					t.Errorf("call: %v", err)
				}
			}

			if calls, maxFlight := gw.stats(); calls != 2 || maxFlight != 1 {
				t.Errorf("Gateway got %d calls, %d at once; want 2, one at a time", calls, maxFlight)
			}
		})
	}
}

func TestCallsAtDifferentChallengeTargetsOverlap(t *testing.T) {
	gw := newBlockingGateway(t)
	s := newInitializedSolver(t, gw, 5*time.Second)

	first := goCall(func() error { return s.Present(challenge(tokenConfig)) })
	next := goCall(func() error {
		return s.Present(withChallengeTarget(challenge(tokenConfig), "_acme-challenge.www.example.com.", "example.com."))
	})

	gw.waitEntered(t, 5*time.Second)
	gw.waitEntered(t, 5*time.Second)
	gw.open()

	for _, done := range []<-chan error{first, next} {
		if err := <-done; err != nil {
			t.Errorf("Present: %v", err)
		}
	}
}

func TestACallThatCannotTakeTheChallengeTargetInTimeFailsWithNoGatewayCall(t *testing.T) {
	gw := newBlockingGateway(t)
	s := newInitializedSolver(t, gw, 100*time.Millisecond)

	first := goCall(func() error { return s.Present(challenge(tokenConfig)) })
	gw.waitEntered(t, 5*time.Second)

	err := s.Present(challenge(tokenConfig))
	checkError(t, err, "timed out after 100ms waiting for another call at _acme-challenge.example.com")

	if calls, _ := gw.stats(); calls != 1 {
		t.Errorf("Gateway got %d calls, want only the first", calls)
	}

	gw.open()

	if err := <-first; err != nil {
		t.Errorf("first Present: %v", err)
	}
}

func TestTheGatewayCallGetsOnlyTheTimeLeftAfterWaitingForTheChallengeTarget(t *testing.T) {
	const timeout = 5 * time.Second

	gw := newBlockingGateway(t)
	s := newInitializedSolver(t, gw, timeout)

	first := goCall(func() error { return s.Present(challenge(tokenConfig)) })
	gw.waitEntered(t, 5*time.Second)

	// The second call waits for the first for wait. Had its timeout started
	// only once it took the Challenge Target, its deadline would be at
	// least wait + timeout after it started.
	const wait = 300 * time.Millisecond

	started := time.Now()
	next := goCall(func() error { return s.CleanUp(cleanUpChallenge(tokenConfig)) })

	time.Sleep(wait)
	gw.open()

	for _, done := range []<-chan error{first, next} {
		if err := <-done; err != nil {
			t.Fatalf("call: %v", err)
		}
	}

	if got := gw.deadline(1).Sub(started); got >= timeout+wait/2 {
		t.Errorf("Gateway deadline is %v after the call started, want about %v", got, timeout)
	}
}

func TestTheChallengeTargetIsFreeAgainAfterTheGatewayFails(t *testing.T) {
	gw := &fakeGateway{err: errors.New("unavailable: connection refused")}
	s := newInitializedSolver(t, gw, 200*time.Millisecond)

	for _, call := range []func() error{
		func() error { return s.Present(challenge(tokenConfig)) },
		func() error { return s.CleanUp(cleanUpChallenge(tokenConfig)) },
	} {
		if err := call(); err == nil || strings.Contains(err.Error(), "waiting for another call") {
			t.Errorf("error = %v, want the Gateway's failure", err)
		}
	}

	if reqs := gw.requests(); len(reqs) != 2 {
		t.Errorf("Gateway got %d PatchRecord requests, want 2", len(reqs))
	}
}
