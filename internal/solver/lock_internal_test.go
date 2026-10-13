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

package solver

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestLockFailsWhenItsContextIsDoneEvenIfTheTargetIsFree(t *testing.T) {
	var locks targetLocks

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	// select picks at random among ready cases, so try often enough
	// that a lock taken after the context ended would show.
	for range 100 {
		unlock, err := locks.lock(ctx, target{zone: "example.com", name: "_acme-challenge"})
		if err == nil {
			unlock()
			t.Fatal("lock succeeded with a done context")
		}

		if !errors.Is(err, context.Canceled) {
			t.Fatalf("error = %v, want context.Canceled", err)
		}
	}

	checkNoLocks(t, &locks)
}

func TestNoLockIsKeptOnceItsCallsAreDone(t *testing.T) {
	var locks targetLocks

	unlock, err := locks.lock(context.Background(), target{zone: "example.com", name: "_acme-challenge"})
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()

	// The same target, case aside, so this call waits until it times out.
	if _, err := locks.lock(ctx, target{zone: "EXAMPLE.com", name: "_ACME-challenge"}); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("waiting lock error = %v, want context.DeadlineExceeded", err)
	}

	unlock()

	unlock, err = locks.lock(context.Background(), target{zone: "example.com", name: "www"})
	if err != nil {
		t.Fatal(err)
	}

	unlock()

	checkNoLocks(t, &locks)
}

// checkNoLocks fails t unless locks keeps no entry.
func checkNoLocks(t *testing.T, locks *targetLocks) {
	t.Helper()

	locks.mu.Lock()
	defer locks.mu.Unlock()

	if n := len(locks.targets); n != 0 {
		t.Errorf("lock map holds %d entries, want none", n)
	}
}
