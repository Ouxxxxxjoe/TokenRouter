//go:build integration

package postgres

import (
	"context"
	"database/sql"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/TokenFlux/TokenRouter/internal/identity"
	"github.com/TokenFlux/TokenRouter/internal/testutil/postgrescontainer"
)

// mcp_oauth_integration_test.go exercises consent and credential cleanup against
// migrated PostgreSQL storage. Explicit transaction barriers and database lock
// observations place competing operations at the persistence steps where grant
// creation, revocation, and refresh rotation can otherwise overtake each other.
//
// The consent scenario queues revocation before releasing an uncommitted grant,
// then checks that another consent waits without holding the row revocation needs.
// The cleanup scenario publishes a replacement only after cleanup waits for the
// consuming transaction. Backend identities and blocking relationships establish
// these orderings; deadlines bound failures so unexpected lock ownership cannot
// leave a test waiting indefinitely for a goroutine or SQL statement.

// TestMCPOAuthSaveGrantConcurrentCreationAndRevocation starts two first consents
// before either grant is visible. A queued revocation must finish before the
// second consent renews authorization, without reversing advisory and row locks.
func TestMCPOAuthSaveGrantConcurrentCreationAndRevocation(t *testing.T) {
	db := postgrescontainer.New(t)
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
	defer cancel()
	repo := NewMCPOAuthStore(db)
	var userID int64
	require.NoError(t, db.QueryRowContext(ctx, `INSERT INTO users(email,password_hash,role,status) VALUES ('oauth-locks@example.invalid','fixture','admin','active') RETURNING id`).Scan(&userID))
	client := &identity.MCPOAuthClient{ID: "concurrent-client", Name: "Concurrent consent"}
	first, err := db.BeginTx(ctx, nil)
	require.NoError(t, err)
	// Keep the first grant uncommitted so the second consent initially observes
	// no matching row, while its creator retains every grant creation lock.
	defer func() { _ = first.Rollback() }()
	firstCtx := context.WithValue(ctx, oauthTransactionKey{}, first)
	grant, err := repo.SaveGrant(firstCtx, userID, client, "https://example.invalid/mcp", []string{"groups.list"})
	require.NoError(t, err)
	var firstPID int
	require.NoError(t, first.QueryRowContext(ctx, `SELECT pg_backend_pid()`).Scan(&firstPID))

	secondPID := make(chan int, 1)
	secondDone := make(chan error, 1)
	var renewed *identity.MCPOAuthGrant
	// Channels publish each backend identity before its competing store call.
	// The result channel also publishes the renewed grant after its transaction commits.
	go func() {
		secondDone <- repo.Transaction(ctx, func(ctx context.Context) error {
			var pid int
			if err := repo.query(ctx).QueryRowContext(ctx, `SELECT pg_backend_pid()`).Scan(&pid); err != nil {
				return err
			}
			secondPID <- pid
			var err error
			renewed, err = repo.SaveGrant(ctx, userID, client, "https://example.invalid/mcp", []string{"providers.list"})
			return err
		})
	}()
	secondBackend := receiveOAuthBackend(t, ctx, secondPID)
	waitOAuthBlocker(t, ctx, db, secondBackend, firstPID)

	revokePID := make(chan int, 1)
	revokeLocked := make(chan struct{})
	revokeReady := make(chan struct{})
	revokeDone := make(chan error, 1)
	// Queue revocation on the grant lock while creation remains uncommitted.
	// After creation commits, pause revocation until the second consent waits behind it.
	go func() {
		revokeDone <- repo.Transaction(ctx, func(ctx context.Context) error {
			var pid int
			if err := repo.query(ctx).QueryRowContext(ctx, `SELECT pg_backend_pid()`).Scan(&pid); err != nil {
				return err
			}
			revokePID <- pid
			if err := repo.lockGrant(ctx, grant.ID); err != nil {
				return err
			}
			close(revokeLocked)
			select {
			case <-revokeReady:
			case <-ctx.Done():
				return ctx.Err()
			}
			return repo.RevokeGrant(ctx, userID, grant.ID)
		})
	}()
	revokeBackend := receiveOAuthBackend(t, ctx, revokePID)
	waitOAuthBlocker(t, ctx, db, revokeBackend, firstPID)
	// Committing creation releases the row and advisory locks. Revocation already
	// queued on the grant lock must acquire it before the second consent proceeds.
	require.NoError(t, first.Commit())
	select {
	case <-revokeLocked:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	waitOAuthBlocker(t, ctx, db, secondBackend, revokeBackend)
	close(revokeReady)
	require.NoError(t, receiveOAuthResult(t, ctx, revokeDone))
	require.NoError(t, receiveOAuthResult(t, ctx, secondDone))
	require.NotEqual(t, grant.ID, renewed.ID)
	require.True(t, renewed.Enabled)
	require.Equal(t, []string{"providers.list"}, renewed.Permissions)
	previous, err := repo.GetGrant(ctx, grant.ID)
	require.NoError(t, err)
	require.NotNil(t, previous.RevokedAt)
	t.Log("overlapping first consents and revocation completed with a fresh grant")
}

// TestMCPOAuthCleanupRetainsConcurrentRotation pauses refresh after consuming its
// previous credential. Cleanup must retain that replay record after a replacement
// commits, and delete both records when their entire family later expires.
func TestMCPOAuthCleanupRetainsConcurrentRotation(t *testing.T) {
	db := postgrescontainer.New(t)
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
	defer cancel()
	repo := NewMCPOAuthStore(db)
	var userID int64
	require.NoError(t, db.QueryRowContext(ctx, `INSERT INTO users(email,password_hash,role,status) VALUES ('oauth-cleanup@example.invalid','fixture','admin','active') RETURNING id`).Scan(&userID))
	var grant *identity.MCPOAuthGrant
	require.NoError(t, repo.Transaction(ctx, func(ctx context.Context) error {
		var err error
		grant, err = repo.SaveGrant(ctx, userID, &identity.MCPOAuthClient{ID: "cleanup-client", Name: "Cleanup client"}, "https://example.invalid/mcp", []string{"groups.list"})
		return err
	}))
	expired := time.Now().Add(-time.Minute)
	require.NoError(t, repo.PutSession(ctx, &identity.MCPOAuthSession{
		Kind: "refresh", Signature: "consumed", FamilyID: "rotating-family",
		GrantID: grant.ID, Payload: []byte(`{}`), ExpiresAt: expired, Active: true,
	}))
	require.NoError(t, repo.PutSession(ctx, &identity.MCPOAuthSession{
		Kind: "access", Signature: "expired", FamilyID: "expired-family",
		GrantID: grant.ID, Payload: []byte(`{}`), ExpiresAt: expired, Active: false,
	}))
	rotation, err := db.BeginTx(ctx, nil)
	require.NoError(t, err)
	// Model an admitted exchange at the storage layer after its deadline passes.
	// Its consumed row remains locked until replacement insertion and commit complete.
	defer func() { _ = rotation.Rollback() }()
	rotationCtx := context.WithValue(ctx, oauthTransactionKey{}, rotation)
	_, err = repo.GetSession(rotationCtx, "refresh", "consumed")
	require.NoError(t, err)
	require.NoError(t, repo.InvalidateSession(rotationCtx, "refresh", "consumed"))
	var rotationPID int
	require.NoError(t, rotation.QueryRowContext(ctx, `SELECT pg_backend_pid()`).Scan(&rotationPID))

	cleaned := make(chan error, 1)
	// Start cleanup only after consumption, then observe its database lock wait.
	// This holds replacement insertion until cleanup has selected the expired candidate.
	go func() { cleaned <- repo.Cleanup(ctx) }()
	require.Eventually(t, func() bool {
		var blocked bool
		err := db.QueryRowContext(ctx, `SELECT EXISTS (SELECT 1 FROM pg_stat_activity WHERE $1::int=ANY(pg_blocking_pids(pid)))`, rotationPID).Scan(&blocked)
		return err == nil && blocked
	}, 5*time.Second, 10*time.Millisecond)
	require.NoError(t, repo.PutSession(rotationCtx, &identity.MCPOAuthSession{
		Kind: "refresh", Signature: "replacement", FamilyID: "rotating-family",
		GrantID: grant.ID, Payload: []byte(`{}`), ExpiresAt: time.Now().Add(time.Hour), Active: true,
	}))
	// Publishing the replacement releases cleanup's lock wait. Its following
	// statement must see this committed deadline before deciding whether to delete history.
	require.NoError(t, rotation.Commit())
	require.NoError(t, receiveOAuthResult(t, ctx, cleaned))
	consumed, err := repo.GetSession(ctx, "refresh", "consumed")
	require.NoError(t, err)
	require.False(t, consumed.Active)
	replacement, err := repo.GetSession(ctx, "refresh", "replacement")
	require.NoError(t, err)
	require.True(t, replacement.Active)
	_, err = repo.GetSession(ctx, "access", "expired")
	require.ErrorIs(t, err, identity.ErrMCPTokenNotFound)
	t.Log("cleanup retained the consumed refresh and its live replacement")

	_, err = db.ExecContext(ctx, `UPDATE mcp_oauth_sessions SET expires_at=$1 WHERE family_id='rotating-family'`, expired)
	require.NoError(t, err)
	require.NoError(t, repo.Cleanup(ctx))
	for _, signature := range []string{"consumed", "replacement"} {
		_, err := repo.GetSession(ctx, "refresh", signature)
		require.ErrorIs(t, err, identity.ErrMCPTokenNotFound)
	}
}

// receiveOAuthBackend waits for a transaction's PostgreSQL identity within the
// test deadline. A startup failure therefore fails the test instead of leaving
// its orchestration blocked on a goroutine that has already returned.
func receiveOAuthBackend(t *testing.T, ctx context.Context, backend <-chan int) int {
	t.Helper()
	select {
	case pid := <-backend:
		return pid
	case <-ctx.Done():
		t.Fatal(ctx.Err())
		return 0
	}
}

// waitOAuthBlocker observes the requested transaction dependency in PostgreSQL.
// Polling checks established lock ownership rather than using elapsed time to
// assume which competing transaction has reached its next statement.
func waitOAuthBlocker(t *testing.T, ctx context.Context, db *sql.DB, waiter, blocker int) {
	t.Helper()
	require.Eventually(t, func() bool {
		var blocked bool
		err := db.QueryRowContext(ctx, `SELECT $1::int=ANY(pg_blocking_pids($2))`, blocker, waiter).Scan(&blocked)
		return err == nil && blocked
	}, 5*time.Second, 10*time.Millisecond, "backend %d did not wait for backend %d", waiter, blocker)
}

// receiveOAuthResult joins a competing transaction within the test deadline.
// Each producer uses a buffered result channel so cancellation can unwind its
// SQL transaction even after the test has stopped receiving results.
func receiveOAuthResult(t *testing.T, ctx context.Context, result <-chan error) error {
	t.Helper()
	select {
	case err := <-result:
		return err
	case <-ctx.Done():
		t.Fatal(ctx.Err())
		return ctx.Err()
	}
}

// TestMCPOAuthAdministratorAdmissionUsesTransaction reads account changes made on
// a single pooled connection. Eligibility must follow current role, status, and
// deletion state inside the transaction, and database read failures remain errors.
func TestMCPOAuthAdministratorAdmissionUsesTransaction(t *testing.T) {
	db := postgrescontainer.New(t)
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	repo := NewMCPOAuthStore(db)
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	var userID int64
	require.NoError(t, db.QueryRowContext(ctx, `INSERT INTO users(email,password_hash,role,status) VALUES ('oauth-admission@example.invalid','fixture','admin','active') RETURNING id`).Scan(&userID))
	require.NoError(t, repo.Transaction(ctx, func(ctx context.Context) error {
		for _, state := range []struct {
			role    string // current account global role
			status  string // current account admission status
			deleted bool   // persisted soft deletion state
			allowed bool   // expected administrator admission result
		}{
			{role: "admin", status: "active", allowed: true},
			{role: "user", status: "active"},
			{role: "admin", status: "disabled"},
			{role: "admin", status: "active", deleted: true},
			{role: "admin", status: "active", allowed: true},
		} {
			_, err := repo.query(ctx).ExecContext(ctx, `UPDATE users SET role=$2,status=$3,deleted_at=CASE WHEN $4 THEN NOW() ELSE NULL END WHERE id=$1`, userID, state.role, state.status, state.deleted)
			require.NoError(t, err)
			allowed, err := repo.IsAdministrator(ctx, userID)
			require.NoError(t, err)
			require.Equal(t, state.allowed, allowed, state)
		}
		allowed, err := repo.IsAdministrator(ctx, userID+1000)
		require.NoError(t, err)
		require.False(t, allowed)
		return nil
	}))
	cancel()
	allowed, err := repo.IsAdministrator(ctx, userID)
	require.Error(t, err)
	require.False(t, allowed)
}
