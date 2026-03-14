// Package certstore defines StoreScope constants for selecting which
// certificate store context to target (Local Machine vs Current User).
// This file is compiled on all platforms.
package certstore

import "github.com/GraceSolutions/StepCAAgent/internal/logging"

// StoreScope controls which certificate store is targeted on platforms
// that support per-user and per-machine stores (e.g., Windows).
// On Linux and macOS the system-wide trust store is always used regardless
// of the scope value.
type StoreScope string

const (
	// ScopeAuto automatically selects Local Machine if running elevated/root,
	// or Current User otherwise.
	ScopeAuto StoreScope = "auto"

	// ScopeLocalMachine targets the Local Machine certificate store (system-wide).
	// Requires elevated privileges.
	ScopeLocalMachine StoreScope = "localmachine"

	// ScopeCurrentUser targets the Current User certificate store.
	ScopeCurrentUser StoreScope = "currentuser"

	// ScopeBoth installs into both Local Machine and Current User stores.
	ScopeBoth StoreScope = "both"
)

// ValidScopes returns the list of valid scope values for CLI help text.
func ValidScopes() []string {
	return []string{string(ScopeAuto), string(ScopeLocalMachine), string(ScopeCurrentUser), string(ScopeBoth)}
}

// IsValid returns true if the scope is a recognized value.
func (s StoreScope) IsValid() bool {
	switch s {
	case ScopeAuto, ScopeLocalMachine, ScopeCurrentUser, ScopeBoth:
		return true
	}
	return false
}

// ResolveAutoScope returns the effective scope. If the scope is ScopeAuto,
// it detects whether the process is running elevated (admin/root) and returns
// ScopeLocalMachine if so, or ScopeCurrentUser otherwise.
func ResolveAutoScope(scope StoreScope) StoreScope {
	if scope != ScopeAuto {
		return scope
	}
	log := logging.Logger()
	if isElevated() {
		log.Info("auto store scope resolved to localmachine (running elevated)")
		return ScopeLocalMachine
	}
	log.Info("auto store scope resolved to currentuser (not elevated)")
	return ScopeCurrentUser
}

