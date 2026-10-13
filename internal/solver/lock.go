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
	"sync"
)

// targetLocks is the lock per Challenge Target (ADR 0004): one holder
// at a time for each target, case-folded. A target's entry lives only
// while a call holds or waits for it.
type targetLocks struct {
	mu      sync.Mutex
	targets map[target]*targetLock
}

// targetLock is the lock of one target: a token in held means it is
// held, and users counts the calls holding or waiting for it.
type targetLock struct {
	held  chan struct{}
	users int
}

// lock takes the lock of t, waiting no longer than ctx allows, and
// returns what releases it, or ctx's error if the wait ran out.
func (l *targetLocks) lock(ctx context.Context, t target) (unlock func(), err error) {
	key := t.folded()

	l.mu.Lock()
	if l.targets == nil {
		l.targets = map[target]*targetLock{}
	}

	tl := l.targets[key]
	if tl == nil {
		tl = &targetLock{held: make(chan struct{}, 1)}
		l.targets[key] = tl
	}

	tl.users++
	l.mu.Unlock()

	select {
	case tl.held <- struct{}{}:
	case <-ctx.Done():
		l.leave(key, tl)

		return nil, ctx.Err()
	}

	unlock = func() {
		<-tl.held
		l.leave(key, tl)
	}

	// select picks at random when the token and ctx.Done() are both
	// ready, so the lock may have been taken after ctx ended.
	if err := ctx.Err(); err != nil {
		unlock()

		return nil, err
	}

	return unlock, nil
}

// leave drops one user of tl, the lock of key, and forgets it once no
// call holds or waits for it.
func (l *targetLocks) leave(key target, tl *targetLock) {
	l.mu.Lock()
	defer l.mu.Unlock()

	tl.users--
	if tl.users == 0 {
		delete(l.targets, key)
	}
}
