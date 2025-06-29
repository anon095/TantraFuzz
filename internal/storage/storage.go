package storage

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/anon095/TantraFuzz/internal/model"
	"github.com/dgraph-io/badger/v4"
)

type Store struct {
	db *badger.DB
}

func NewStore(path string) (*Store, error) {
	opts := badger.DefaultOptions(path).WithLogger(nil)
	db, err := badger.Open(opts)
	if err != nil {
		return nil, fmt.Errorf("failed to open badger database: %w", err)
	}
	return &Store{db: db}, nil
}

func (s *Store) Close() {
	s.db.Close()
}

func (s *Store) SaveResult(result *model.ReconResult) error {
	data, err := json.Marshal(result)
	if err != nil {
		return err
	}
	key := []byte(result.Domain)
	entry := badger.NewEntry(key, data)
	return s.db.Update(func(txn *badger.Txn) error {
		return txn.SetEntry(entry)
	})
}

func (s *Store) GetPreviousResult(domain string) (*model.ReconResult, error) {
	key := []byte(domain)
	var result model.ReconResult
	err := s.db.View(func(txn *badger.Txn) error {
		item, err := txn.Get(key)
		if err != nil {
			return err
		}
		return item.Value(func(val []byte) error {
			return json.Unmarshal(val, &result)
		})
	})
	if err != nil {
		if err == badger.ErrKeyNotFound {
			return nil, nil
		}
		return nil, err
	}
	return &result, nil
}
