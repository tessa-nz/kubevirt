// SPDX-License-Identifier: Apache-2.0
package keyservice

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	bolt "go.etcd.io/bbolt"
)

var metadataBucket = []byte("hibernation-v1")
var metadataKey = []byte("state")

func openDatabase(path string, initialize bool, providerID string) (*bolt.DB, error) {
	st, err := os.Lstat(path)
	if initialize && err == nil {
		return nil, fmt.Errorf("metadata already exists")
	}
	if !initialize && err != nil {
		return nil, fmt.Errorf("metadata absent; explicit initialization or recovery required")
	}
	if err == nil && (st.Mode()&os.ModeSymlink != 0 || !st.Mode().IsRegular() || st.Mode().Perm()&0077 != 0 || !ownedByProcess(st)) {
		return nil, fmt.Errorf("unsafe metadata file")
	}
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	db, err := bolt.Open(path, 0600, &bolt.Options{Timeout: time.Second})
	if err != nil {
		return nil, err
	}
	if initialize {
		state := State{Version: 1, ProviderID: providerID, Principals: map[string]*Principal{}, Attempts: map[string]*AttemptRecord{}}
		if err = saveState(db, &state); err == nil {
			err = syncDirectory(filepath.Dir(path))
		}
		if err != nil {
			db.Close()
			return nil, err
		}
	}
	return db, nil
}
func readState(db *bolt.DB) (*State, error) {
	state := &State{}
	err := db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket(metadataBucket)
		if b == nil {
			return fmt.Errorf("missing metadata bucket")
		}
		if err := json.Unmarshal(b.Get(metadataKey), state); err != nil {
			return fmt.Errorf("invalid metadata")
		}
		if state.Version != 1 || state.ProviderID == "" || state.Principals == nil || state.Attempts == nil {
			return fmt.Errorf("invalid metadata version or structure")
		}
		for id, p := range state.Principals {
			if p == nil || id != p.ID || !validID(p.ClusterID) || !validID(p.NodeUID) || !validID(p.RegistrationUID) || p.Fingerprint != fingerprint(p.PublicKey) || id != fingerprint([]byte(p.ClusterID+"/"+p.NodeUID+"/"+p.RegistrationUID+"/"+p.Fingerprint)) {
				return fmt.Errorf("inconsistent enrollment metadata; recovery required")
			}
			for _, g := range p.Grants {
				if g.ClusterID != p.ClusterID || !validID(g.VMUID) {
					return fmt.Errorf("inconsistent grant metadata; recovery required")
				}
			}
		}
		for id, a := range state.Attempts {
			if a == nil || id != a.Request.dbKey() || a.Request.ProviderID != state.ProviderID || state.Principals[a.PrincipalID] == nil || a.Request.ClusterID != state.Principals[a.PrincipalID].ClusterID {
				return fmt.Errorf("inconsistent attempt ownership; recovery required")
			}
		}
		return nil
	})
	return state, err
}
func saveState(db *bolt.DB, state *State) error {
	data, err := json.Marshal(state)
	if err != nil {
		return err
	}
	return db.Update(func(tx *bolt.Tx) error {
		b, err := tx.CreateBucketIfNotExists(metadataBucket)
		if err != nil {
			return err
		}
		return b.Put(metadataKey, data)
	})
}
func syncDirectory(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	return f.Sync()
}
func AtomicWrite(path string, data []byte, mode os.FileMode) error {
	f, err := os.CreateTemp(filepath.Dir(path), ".write-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	defer f.Close()
	if err = f.Chmod(mode); err != nil {
		return err
	}
	if _, err = f.Write(data); err != nil {
		return err
	}
	if err = f.Sync(); err != nil {
		return err
	}
	if err = f.Close(); err != nil {
		return err
	}
	if err = os.Rename(f.Name(), path); err != nil {
		return err
	}
	return syncDirectory(filepath.Dir(path))
}

// RecoveryMetadata reads only nonsecret ownership records. It acquires a shared
// database lock, so an operator must stop the service before offline inspection.
func RecoveryMetadata(dir string) (*State, error) {
	path := filepath.Join(dir, "metadata.db")
	st, e := os.Lstat(path)
	if e != nil {
		return nil, e
	}
	if !st.Mode().IsRegular() || st.Mode().Perm()&0077 != 0 || !ownedByProcess(st) {
		return nil, fmt.Errorf("unsafe metadata file")
	}
	db, e := bolt.Open(path, 0600, &bolt.Options{ReadOnly: true, Timeout: time.Second})
	if e != nil {
		return nil, e
	}
	defer db.Close()
	return readState(db)
}
