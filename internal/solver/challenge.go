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

import "errors"

// dns01 is the only challenge type the solver solves.
const dns01 = "dns-01"

// keyLength is the length of a challenge key: an unpadded base64url
// SHA-256 digest.
const keyLength = 43

var (
	errNotDNS01 = errors.New("the challenge is not dns-01")
	errBadKey   = errors.New("challenge key is not a 43-character base64url value")
)

// checkKey refuses key unless it has the shape of a challenge value, so
// that a crafted ChallengeRequest cannot write arbitrary TXT values. Its
// error never quotes key.
func checkKey(key string) error {
	if len(key) != keyLength {
		return errBadKey
	}

	for i := range len(key) {
		if !isBase64url(key[i]) {
			return errBadKey
		}
	}

	return nil
}

// isBase64url reports whether c is in the base64url alphabet, without
// the padding.
func isBase64url(c byte) bool {
	return 'A' <= c && c <= 'Z' || 'a' <= c && c <= 'z' || '0' <= c && c <= '9' || c == '-' || c == '_'
}
