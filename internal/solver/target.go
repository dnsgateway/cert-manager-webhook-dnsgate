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
	"fmt"
	"strings"
)

// apex is the relative name of a zone's own apex.
const apex = "@"

// target is where a challenge value is written: a zone, and a name
// relative to it.
type target struct {
	zone string
	name string
}

// challengeTarget makes fqdn, the Challenge Target, relative to zone.
// Both may end in a dot; neither the zone nor the name returned does.
func challengeTarget(fqdn, zone string) (target, error) {
	fqdn = strings.TrimSuffix(fqdn, ".")
	zone = strings.TrimSuffix(zone, ".")

	if zone == "" || fqdn == "" {
		return target{}, fmt.Errorf("no Challenge Target or zone in the request: %q in %q", fqdn, zone)
	}

	if strings.EqualFold(fqdn, zone) {
		return target{zone: zone, name: apex}, nil
	}

	suffix := "." + zone
	if len(fqdn) <= len(suffix) || !strings.EqualFold(fqdn[len(fqdn)-len(suffix):], suffix) {
		return target{}, fmt.Errorf("%s is not in zone %s", fqdn, zone)
	}

	return target{zone: zone, name: fqdn[:len(fqdn)-len(suffix)]}, nil
}
