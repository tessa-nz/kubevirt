/*
 * This file is part of the KubeVirt project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * Copyright The KubeVirt Authors.
 */

package protection

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
)

// RequireProtectedMemory is checked before generating or unsealing a key, and
// before creating plaintext state. A cgroup-v2 hard swap limit of zero is also
// sufficient on a host that permits swapping for unrelated workloads.
func RequireProtectedMemory() error {
	if err := checkNoSwap(os.ReadFile); err != nil {
		return err
	}
	if err := unix.Setrlimit(unix.RLIMIT_CORE, &unix.Rlimit{Cur: 0, Max: 0}); err != nil {
		return fmt.Errorf("disable hibernation process core dumps: %w", err)
	}
	if err := unix.Prctl(unix.PR_SET_DUMPABLE, 0, 0, 0, 0); err != nil {
		return fmt.Errorf("disable hibernation process dumping: %w", err)
	}
	return nil
}

func checkNoSwap(readFile func(string) ([]byte, error)) error {
	swaps, err := readFile("/proc/swaps")
	if err == nil {
		lines := strings.Split(strings.TrimSpace(string(swaps)), "\n")
		if len(lines) == 1 && strings.HasPrefix(lines[0], "Filename") {
			return nil
		}
	}
	cgroups, err := readFile("/proc/self/cgroup")
	if err != nil {
		return fmt.Errorf("cannot establish unswappable hibernation memory")
	}
	for _, line := range strings.Split(string(cgroups), "\n") {
		if !strings.HasPrefix(line, "0::/") {
			continue
		}
		// The cgroup mount may be namespace-relative. Check its root as well as
		// the process path and its ancestors; any zero limit is inherited.
		path := filepath.Join("/sys/fs/cgroup", strings.TrimPrefix(line, "0::/"))
		for {
			value, err := readFile(filepath.Join(path, "memory.swap.max"))
			if err == nil && strings.TrimSpace(string(value)) == "0" {
				return nil
			}
			if path == "/sys/fs/cgroup" {
				break
			}
			parent := filepath.Dir(path)
			if !strings.HasPrefix(parent+"/", "/sys/fs/cgroup/") {
				break
			}
			path = parent
		}
	}
	return fmt.Errorf("hibernation requires no host swap or a cgroup-v2 memory.swap.max limit of zero")
}

func RequireMemoryFilesystem(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("hibernation staging must be a real directory")
	}
	var stat unix.Statfs_t
	if err := unix.Statfs(path, &stat); err != nil {
		return err
	}
	if stat.Type != unix.TMPFS_MAGIC {
		return fmt.Errorf("hibernation plaintext staging requires tmpfs")
	}
	return nil
}
