package main

import (
	"context"

	shield "github.com/cipher-oss/cipher-shield/internal"
)

// noopStore satisfies db.Store with no-ops (used when DB can't be opened).
type noopStore struct{}

func (n *noopStore) GetCachedResult(_ context.Context, _ shield.Ecosystem, _, _ string) (*shield.ScanResult, error) {
	return nil, nil
}
func (n *noopStore) SaveResult(_ context.Context, _ shield.ScanResult) error { return nil }
func (n *noopStore) GetException(_ context.Context, _ shield.Ecosystem, _, _ string) (*shield.Exception, error) {
	return nil, nil
}
func (n *noopStore) ListExceptions(_ context.Context) ([]shield.Exception, error)              { return nil, nil }
func (n *noopStore) AddException(_ context.Context, _ shield.Exception) error                  { return nil }
func (n *noopStore) DeleteException(_ context.Context, _ string) error                         { return nil }
func (n *noopStore) ListHistory(_ context.Context, _ int) ([]shield.ScanResult, error)         { return nil, nil }
func (n *noopStore) PruneHistory(_ context.Context, _ int) (int64, error)                      { return 0, nil }
func (n *noopStore) CreateUser(_ context.Context, _, _, _ string) (*shield.User, error)        { return nil, nil }
func (n *noopStore) GetUserByEmail(_ context.Context, _ string) (*shield.User, error)          { return nil, nil }
func (n *noopStore) GetUserByID(_ context.Context, _ string) (*shield.User, error)             { return nil, nil }
func (n *noopStore) UpdatePassword(_ context.Context, _, _ string) error                       { return nil }
func (n *noopStore) CountUsers(_ context.Context) (int, error)                                 { return 0, nil }
func (n *noopStore) ListUsers(_ context.Context) ([]shield.User, error)                        { return nil, nil }
func (n *noopStore) ListViolations(_ context.Context, _ int) ([]shield.ViolationRow, error)       { return nil, nil }
func (n *noopStore) DismissResult(_ context.Context, _, _, _ string) error                        { return nil }
func (n *noopStore) SaveDownload(_ context.Context, _ shield.DownloadEvent) error                 { return nil }
func (n *noopStore) ListDownloads(_ context.Context, _ int) ([]shield.DownloadEvent, error)       { return nil, nil }
func (n *noopStore) Migrate() error                                                                { return nil }
func (n *noopStore) Close() error                                                                  { return nil }
