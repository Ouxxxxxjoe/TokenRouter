package apikey

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/dgraph-io/ristretto"
	"github.com/stretchr/testify/require"
)

// authInvalidationRepoStub records worker claim transitions and supplies
// configured health samples.
type authInvalidationRepoStub struct {
	// mu protects events and captured claim/transition records during concurrent
	// worker handlers. Tests configure events before processing; Stats returns the
	// separately configured sample without taking this lock.
	mu         sync.Mutex                       // transition capture serialization lock
	events     []AuthCacheInvalidationEvent     // configured claimed event records
	claimLimit int                              // captured claim batch limit
	scheduled  []int64                          // captured safety-stage event identifiers
	deleted    []int64                          // captured acknowledged event identifiers
	retried    []int64                          // captured retry event identifiers
	retryError string                           // latest captured retry text
	stats      AuthCacheInvalidationOutboxStats // configured durable queue observations
	statsErr   error                            // configured queue observation error
}

// authInvalidationCacheStub records delivery attempts and runs configured cache
// or subscription callbacks.
type authInvalidationCacheStub struct {
	mu sync.Mutex // delivery capture serialization lock
	// deleteFn, publishFn and subscribeFn are installed before worker use.
	// Delivery callbacks run after releasing mu; subscription delegates directly,
	// while captured deletion and publication lists are appended under mu.
	deleteFn    func(context.Context, string) error       // optional shared deletion callback
	publishFn   func(context.Context, string) error       // optional publication result callback
	subscribeFn func(context.Context, func(string)) error // optional subscription lifecycle callback
	deleted     []string                                  // captured shared deletion identities
	published   []string                                  // captured publication cache identities
}

// Claim records the requested limit and returns copied configured event records
// under its mutex. Worker identity, context and lease are ignored; the fixture
// retains its events rather than implementing real lease ownership.
func (r *authInvalidationRepoStub) Claim(_ context.Context, _ string, limit int, _ time.Duration) ([]AuthCacheInvalidationEvent, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.claimLimit = limit
	return append([]AuthCacheInvalidationEvent(nil), r.events...), nil
}

// DeleteClaimed records an acknowledged event ID under the fixture mutex.
// It ignores context and worker identity and succeeds for every ID, so this
// capture establishes deletion intent rather than matching claim ownership.
func (r *authInvalidationRepoStub) DeleteClaimed(_ context.Context, id int64, _ string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.deleted = append(r.deleted, id)
	return nil
}

// ScheduleSecondPass records an event selected for the delayed safety pass.
// Context, worker identity and available time are ignored; capturing an ID
// succeeds without validating its stage or changing the configured event list.
func (r *authInvalidationRepoStub) ScheduleSecondPass(_ context.Context, id int64, _ string, _ time.Time) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.scheduled = append(r.scheduled, id)
	return nil
}

// RetryClaimed records event ID and lastError under the fixture mutex. It
// ignores owner and available time, allowing tests to inspect retry intent
// while leaving database claim enforcement to separate repository tests.
func (r *authInvalidationRepoStub) RetryClaimed(_ context.Context, id int64, _ string, _ time.Time, lastError string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.retried = append(r.retried, id)
	r.retryError = lastError
	return nil
}

// Stats returns configured observations and error for every health read. The
// supplied oldest timestamp pointer remains shared; tests configure these
// values before worker handlers or concurrent health calls begin.
func (r *authInvalidationRepoStub) Stats(context.Context) (AuthCacheInvalidationOutboxStats, error) {
	return r.stats, r.statsErr
}

// GetCreateAttemptCount acknowledges unrelated creation-counter reads with zero
// in this delivery fixture.
func (*authInvalidationCacheStub) GetCreateAttemptCount(context.Context, int64) (int, error) {
	return 0, nil
}

// IncrementCreateAttemptCount acknowledges unrelated creation failures without
// retaining a counter value.
func (*authInvalidationCacheStub) IncrementCreateAttemptCount(context.Context, int64) error {
	return nil
}

// DeleteCreateAttemptCount acknowledges unrelated creation-counter cleanup in
// the delivery fixture.
func (*authInvalidationCacheStub) DeleteCreateAttemptCount(context.Context, int64) error { return nil }

// IncrementDailyUsage accepts unrelated daily-usage calls while retaining no
// counter data.
func (*authInvalidationCacheStub) IncrementDailyUsage(context.Context, string) error { return nil }

// SetDailyUsageExpiry accepts unrelated counter expiration calls in this
// delivery fixture.
func (*authInvalidationCacheStub) SetDailyUsageExpiry(context.Context, string, time.Duration) error {
	return nil
}

// GetAuthCache returns the fixture miss error for every authentication entry
// read.
func (*authInvalidationCacheStub) GetAuthCache(context.Context, string) (*APIKeyAuthCacheEntry, error) {
	return nil, errors.New("miss")
}

// SetAuthCache acknowledges publication requests while storing no
// authentication entry data.
func (*authInvalidationCacheStub) SetAuthCache(context.Context, string, *APIKeyAuthCacheEntry, time.Duration) error {
	return nil
}

// DeleteAuthCache records a deletion attempt under its mutex before invoking
// deleteFn when present. The optional callback runs after unlocking and
// supplies its error; tests install callbacks before concurrent handlers begin.
func (c *authInvalidationCacheStub) DeleteAuthCache(ctx context.Context, key string) error {
	c.mu.Lock()
	c.deleted = append(c.deleted, key)
	c.mu.Unlock()
	if c.deleteFn != nil {
		return c.deleteFn(ctx, key)
	}
	return nil
}

// PublishAuthCacheInvalidation records publication under its mutex, then
// invokes publishFn when configured. The callback runs after unlocking and can
// fail independently; recorded attempts therefore include failures as well as
// successes.
func (c *authInvalidationCacheStub) PublishAuthCacheInvalidation(ctx context.Context, key string) error {
	c.mu.Lock()
	c.published = append(c.published, key)
	c.mu.Unlock()
	if c.publishFn != nil {
		return c.publishFn(ctx, key)
	}
	return nil
}

// SubscribeAuthCacheInvalidation delegates to the configured subscription
// callback when one exists. Missing callbacks return immediately with nil,
// letting wrapper tests model a closed subscription; install callbacks before
// concurrent subscription startup.
func (c *authInvalidationCacheStub) SubscribeAuthCacheInvalidation(ctx context.Context, handler func(string)) error {
	if c.subscribeFn != nil {
		return c.subscribeFn(ctx, handler)
	}
	return nil
}

// TestAuthCacheInvalidationWorker_FirstPassSchedulesSafetyPass supplies an
// initial-stage event to a successful delivery fixture. It checks shared
// deletion, publication and safety scheduling occur while final record deletion
// is deferred.
func TestAuthCacheInvalidationWorker_FirstPassSchedulesSafetyPass(t *testing.T) {
	repo := &authInvalidationRepoStub{}
	cache := &authInvalidationCacheStub{}
	worker := NewAuthCacheInvalidationWorker(repo, cache)
	worker.KeyProcessEvent(context.Background(), AuthCacheInvalidationEvent{ID: 7, CacheKey: "hash", Stage: 0})
	require.Equal(t, []string{"hash"}, cache.deleted)
	require.Equal(t, []string{"hash"}, cache.published)
	require.Equal(t, []int64{7}, repo.scheduled)
	require.Empty(t, repo.deleted)
}

// TestAuthCacheInvalidationWorker_SecondPassCleansEvent supplies a safety-stage
// event to a successful delivery fixture. It checks deletion acknowledgement is
// requested for that event and the worker counts one successful pass.
func TestAuthCacheInvalidationWorker_SecondPassCleansEvent(t *testing.T) {
	repo := &authInvalidationRepoStub{}
	cache := &authInvalidationCacheStub{}
	worker := NewAuthCacheInvalidationWorker(repo, cache)
	worker.KeyProcessEvent(context.Background(), AuthCacheInvalidationEvent{ID: 8, CacheKey: "hash", Stage: 1})
	require.Equal(t, []int64{8}, repo.deleted)
	require.Equal(t, uint64(1), worker.Health(context.Background()).Processed)
}

// TestAuthCacheInvalidationWorker_RetriesRedisAndPublishFailures independently
// fails shared deletion or publication for an event. It checks retry recording,
// publication ordering, retained event intent and a counted failure in worker
// health.
func TestAuthCacheInvalidationWorker_RetriesRedisAndPublishFailures(t *testing.T) {
	for _, tc := range []struct {
		name       string // delivery failure scenario label
		deleteErr  error  // configured shared deletion failure
		publishErr error  // configured publication failure result
		published  int    // expected publication attempt count
	}{
		{name: "redis down", deleteErr: errors.New("redis unavailable")},
		{name: "publish failure after delete", publishErr: errors.New("publish failed"), published: 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			repo := &authInvalidationRepoStub{}
			cache := &authInvalidationCacheStub{
				deleteFn:  func(context.Context, string) error { return tc.deleteErr },
				publishFn: func(context.Context, string) error { return tc.publishErr },
			}
			worker := NewAuthCacheInvalidationWorker(repo, cache)
			worker.KeyProcessEvent(context.Background(), AuthCacheInvalidationEvent{ID: 9, CacheKey: "hash"})
			require.Equal(t, []int64{9}, repo.retried)
			require.Len(t, cache.published, tc.published)
			require.NotEmpty(t, repo.retryError)
			require.Empty(t, repo.deleted)
			require.Equal(t, uint64(1), worker.Health(context.Background()).Failures)
		})
	}
}

// TestAuthCacheInvalidationWorker_RedisSlowIsTimedOut holds shared deletion
// until its delivery context ends. It checks bounded elapsed waiting and a
// captured retry request carrying the delivery deadline failure text.
func TestAuthCacheInvalidationWorker_RedisSlowIsTimedOut(t *testing.T) {
	repo := &authInvalidationRepoStub{}
	cache := &authInvalidationCacheStub{deleteFn: func(ctx context.Context, _ string) error {
		<-ctx.Done()
		return ctx.Err()
	}}
	worker := NewAuthCacheInvalidationWorker(repo, cache)
	started := time.Now()
	worker.KeyProcessEvent(context.Background(), AuthCacheInvalidationEvent{ID: 10, CacheKey: "hash"})
	require.Less(t, time.Since(started), 3*time.Second)
	require.Equal(t, []int64{10}, repo.retried)
	require.Contains(t, repo.retryError, "deadline")
}

// TestAuthCacheInvalidationWorker_BoundedBatchAndHealth supplies queue
// statistics and an empty claimed batch. It checks the configured claim limit,
// stored failure and lag observations, and displayed normal and recovery timing
// estimates.
func TestAuthCacheInvalidationWorker_BoundedBatchAndHealth(t *testing.T) {
	oldest := time.Now().Add(-time.Minute)
	repo := &authInvalidationRepoStub{stats: AuthCacheInvalidationOutboxStats{
		Pending: 12, OldestCreatedAt: &oldest, MaxAttempts: 4, LastError: "redis down",
	}}
	worker := NewAuthCacheInvalidationWorker(repo, &authInvalidationCacheStub{})
	require.NoError(t, worker.KeyProcessBatch(context.Background()))
	require.Equal(t, KeyAuthInvalidationBatchSize, repo.claimLimit)
	KeyHealth := worker.Health(context.Background())
	require.Equal(t, int64(12), KeyHealth.Pending)
	require.Equal(t, 4, KeyHealth.MaxAttempts)
	require.Equal(t, "redis down", KeyHealth.LastError)
	require.GreaterOrEqual(t, KeyHealth.OldestLag, time.Minute)
	require.Equal(t, 35*time.Second, KeyHealth.HealthySLA)
	require.Equal(t, 6*time.Minute, KeyHealth.RecoverySLA)
}

// TestAuthCacheInvalidationWorker_ProcessesClaimedBatchConcurrently delays
// shared deletion for a populated safety-stage batch. It checks all events are
// acknowledged and elapsed time fits concurrent processing of the delayed
// fixture operations.
func TestAuthCacheInvalidationWorker_ProcessesClaimedBatchConcurrently(t *testing.T) {
	events := make([]AuthCacheInvalidationEvent, 32)
	for i := range events {
		events[i] = AuthCacheInvalidationEvent{ID: int64(i + 1), CacheKey: "hash", Stage: 1}
	}
	repo := &authInvalidationRepoStub{events: events}
	cache := &authInvalidationCacheStub{deleteFn: func(context.Context, string) error {
		// Delay each handler to make sequential delivery exceed the asserted
		// elapsed budget while the configured concurrent worker batches can complete within it.
		time.Sleep(100 * time.Millisecond)
		return nil
	}}
	worker := NewAuthCacheInvalidationWorker(repo, cache)
	started := time.Now()
	require.NoError(t, worker.KeyProcessBatch(context.Background()))
	require.Less(t, time.Since(started), time.Second)
	require.Len(t, repo.deleted, 32)
}

// TestAuthCacheInvalidationWorker_LifecycleIsManagedAndIdempotent starts a
// delivery loop with successful fixtures and observes running health. It checks
// repeated synchronous shutdown completes safely and reports the stopped state.
func TestAuthCacheInvalidationWorker_LifecycleIsManagedAndIdempotent(t *testing.T) {
	worker := NewAuthCacheInvalidationWorker(&authInvalidationRepoStub{}, &authInvalidationCacheStub{})
	worker.Start()
	require.Eventually(t, func() bool { return worker.Health(context.Background()).Running }, time.Second, 10*time.Millisecond)
	require.NotPanics(t, func() { worker.Stop(); worker.Stop() })
	require.False(t, worker.Health(context.Background()).Running)
}

// TestAuthInvalidationRetryDelayIsBoundedAndJittered samples retry delays for
// steps within and above the configured exponent range. It checks all sampled
// values remain inside the first-step and capped-step jitter bounds.
func TestAuthInvalidationRetryDelayIsBoundedAndJittered(t *testing.T) {
	for attempt := 1; attempt <= 20; attempt++ {
		delay := KeyAuthInvalidationRetryDelay(attempt)
		require.GreaterOrEqual(t, delay, 800*time.Millisecond)
		require.LessOrEqual(t, delay, 308*time.Second)
	}
}

// TestAuthCacheInvalidationSubscriber_RetriesInitialFailureAndStops fails the
// first subscription attempt and acknowledges its retry. It checks readiness,
// one recorded failure and repeatable shutdown after adding a local cache
// resource.
func TestAuthCacheInvalidationSubscriber_RetriesInitialFailureAndStops(t *testing.T) {
	ready := make(chan struct{})
	var calls int
	cache := &authInvalidationCacheStub{subscribeFn: func(ctx context.Context, _ func(string)) error {
		calls++
		if calls == 1 {
			return errors.New("redis starting")
		}
		// Acknowledge this attempt before signaling the test, so receipt of ready
		// follows the service's connection-health update for that same subscription.
		NotifyAuthCacheSubscriptionReady(ctx)
		close(ready)
		<-ctx.Done()
		return ctx.Err()
	}}
	svc := NewAPIKeyService(nil, nil, nil, nil, nil, cache, nil)
	svc.Start()
	localCache, err := ristretto.NewCache(&ristretto.Config[string, any]{NumCounters: 10, MaxCost: 1, BufferItems: 64})
	require.NoError(t, err)
	// This local cache was supplied outside service startup. Close it after
	// subscriber shutdown so its callbacks cannot read a resource already being closed.
	defer localCache.Close()
	svc.authNegativeCacheL1.Store(localCache)
	svc.StartAuthCacheInvalidationSubscriber(context.Background())
	select {
	case <-ready:
	case <-time.After(2 * time.Second):
		t.Fatal("subscriber did not retry")
	}
	require.Eventually(t, func() bool { return svc.AuthCacheInvalidationSubscriberHealth().Connected }, time.Second, 10*time.Millisecond)
	require.Equal(t, uint64(1), svc.AuthCacheInvalidationSubscriberHealth().Failures)
	require.NotPanics(t, func() { svc.StopAuthCacheInvalidationSubscriber(); svc.StopAuthCacheInvalidationSubscriber() })
}

// TestAuthCacheInvalidationSubscriber_ReconnectsAfterRuntimeDisconnect
// acknowledges one subscription then returns a connection failure before
// retrying. It checks the second acknowledgement, retained failure count and
// final subscriber shutdown.
func TestAuthCacheInvalidationSubscriber_ReconnectsAfterRuntimeDisconnect(t *testing.T) {
	ready := make(chan int, 2)
	var calls int
	cache := &authInvalidationCacheStub{subscribeFn: func(ctx context.Context, _ func(string)) error {
		calls++
		// Acknowledge this attempt before signaling the test, so receipt of ready
		// follows the service's connection-health update for that same subscription.
		NotifyAuthCacheSubscriptionReady(ctx)
		ready <- calls
		if calls == 1 {
			return errors.New("connection dropped")
		}
		<-ctx.Done()
		return ctx.Err()
	}}
	svc := NewAPIKeyService(nil, nil, nil, nil, nil, cache, nil)
	svc.Start()
	localCache, err := ristretto.NewCache(&ristretto.Config[string, any]{NumCounters: 10, MaxCost: 1, BufferItems: 64})
	require.NoError(t, err)
	// This local cache was supplied outside service startup. Close it after
	// subscriber shutdown so its callbacks cannot read a resource already being closed.
	defer localCache.Close()
	svc.authNegativeCacheL1.Store(localCache)
	svc.StartAuthCacheInvalidationSubscriber(context.Background())

	select {
	case call := <-ready:
		require.Equal(t, 1, call)
	case <-time.After(time.Second):
		t.Fatal("initial subscription did not start")
	}
	select {
	case call := <-ready:
		require.Equal(t, 2, call)
	case <-time.After(2 * time.Second):
		t.Fatal("subscriber did not reconnect after runtime disconnect")
	}
	require.Eventually(t, func() bool { return svc.AuthCacheInvalidationSubscriberHealth().Connected }, time.Second, 10*time.Millisecond)
	require.Equal(t, uint64(1), svc.AuthCacheInvalidationSubscriberHealth().Failures)
	svc.StopAuthCacheInvalidationSubscriber()
}
