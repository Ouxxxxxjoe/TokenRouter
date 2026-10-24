//go:build integration

package payment_test

import (
	"context"
	"crypto/md5"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/require"

	dbent "github.com/TokenFlux/TokenRouter/ent"
	"github.com/TokenFlux/TokenRouter/ent/paymentauditlog"
	"github.com/TokenFlux/TokenRouter/internal/billing"
	billingpostgres "github.com/TokenFlux/TokenRouter/internal/billing/postgres"
	"github.com/TokenFlux/TokenRouter/internal/payment"
	paymentpostgres "github.com/TokenFlux/TokenRouter/internal/payment/postgres"
	paymentadapter "github.com/TokenFlux/TokenRouter/internal/payment/provider"
	paymenttestkit "github.com/TokenFlux/TokenRouter/internal/payment/testkit"
	"github.com/TokenFlux/TokenRouter/internal/pkg/apperror"
)

// easypay_scenario_integration_test.go combines provider/easypay.go,
// payment/fulfillment.go, payment/order_lifecycle.go and payment/refund_workflow.go
// with PostgreSQL orders, billing redemption and refund transactions. Local HTTP
// merchants report successful, rejected or unconfirmed operations; assertions
// compare persisted balance, order state and audit records after each attempt.
//
// Callback and polling observations compete for the same paid transition and
// fulfillment lease. Refund tests count submitted requests separately from
// local compensation, preserving prepared deductions when external effects are
// unknown. All endpoints and credentials belong to these fixtures, and package
// cleanup removes their persisted records after workers have completed.

// easyPayPostgresOrder replaces the refund fixture's channel with a local
// EasyPay merchant. It returns the order with that saved binding and its real
// adapter; callers own the supplied HTTP server throughout the operation.
func easyPayPostgresOrder(t *testing.T, endpoint string) (*dbent.Client, *payment.RefundWorkflow, *dbent.PaymentOrder, *paymentadapter.EasyPay) {
	t.Helper()
	client, workflow, order := refundOrderFixture(t, payment.OrderStatusCompleted)
	config := map[string]string{
		"pid": "1000", "pkey": "local-secret", "apiBase": endpoint,
		"notifyUrl": "https://site.example.com/notify", "returnUrl": "https://site.example.com/payment/result",
	}
	encoded, err := json.Marshal(config)
	require.NoError(t, err)
	id, err := strconv.ParseInt(*order.ProviderInstanceID, 10, 64)
	require.NoError(t, err)
	_, err = client.PaymentProviderInstance.UpdateOneID(id).SetProviderKey(payment.TypeEasyPay).
		SetConfig(string(encoded)).SetSupportedTypes(payment.TypeAlipay).Save(context.Background())
	require.NoError(t, err)
	order, err = client.PaymentOrder.UpdateOneID(order.ID).SetPaymentType(payment.TypeAlipay).
		SetProviderKey(payment.TypeEasyPay).SetPaymentTradeNo("epay-trade").Save(context.Background())
	require.NoError(t, err)
	adapter, err := paymentadapter.NewEasyPay(*order.ProviderInstanceID, config)
	require.NoError(t, err)
	return client, workflow, order, adapter
}

// TestEasyPayRefundPostgresOutcomes checks real preparation, compensation and
// completion transactions against local channel replies. Unknown outcomes keep
// the deduction and recovery audit, and subsequent actions cannot resubmit refunds.
func TestEasyPayRefundPostgresOutcomes(t *testing.T) {
	for _, tc := range []struct {
		name    string  // classified refund result
		body    string  // supplied channel response
		balance float64 // expected persisted user balance
		status  string  // expected persisted order state
		audits  int     // expected success audit count
		// firstMissing substitutes a missing-order reply for the first request,
		// requiring the alternate identifier before the configured outcome is returned.
		firstMissing bool
	}{
		{name: "plain success", body: "退款成功！退款金额¥50.00", balance: 50, status: payment.OrderStatusRefunded, audits: 1},
		{name: "JSON zero success", body: `{"code":0,"msg":"退款成功"}`, balance: 50, status: payment.OrderStatusRefunded, audits: 1},
		{name: "explicit failure", body: `{"code":0,"msg":"退款失败，余额不足"}`, balance: 100, status: payment.OrderStatusCompleted},
		{name: "unknown response", body: "unexpected reply", balance: 50, status: payment.OrderStatusRefunding},
		{name: "Alipay system error", body: `{"code":-1,"msg":"ACQ.SYSTEM_ERROR"}`, balance: 50, status: payment.OrderStatusRefunding},
		{name: "WeChat system error", body: `{"code":0,"msg":"SYSTEMERROR"}`, balance: 50, status: payment.OrderStatusRefunding},
		{name: "Chinese system error", body: `{"code":0,"msg":"系统错误"}`, balance: 50, status: payment.OrderStatusRefunding},
		{name: "system error after identifier retry", body: `{"code":-1,"msg":"ACQ.SYSTEM_ERROR"}`, firstMissing: true, balance: 50, status: payment.OrderStatusRefunding},
		{name: "cancelled request", balance: 50, status: payment.OrderStatusRefunding},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			requestCtx, cancel := context.WithCancel(ctx)
			defer cancel()
			var calls atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				call := calls.Add(1)
				_ = r.ParseForm()
				if tc.firstMissing && call == 1 {
					// A definite missing merchant order permits one trade-number attempt.
					// Its later system error must retain the same prepared deduction.
					_, _ = w.Write([]byte(`{"code":0,"msg":"订单不存在"}`))
					return
				}
				if tc.body == "" {
					// Cancel after the submitted refund reaches the merchant, reproducing an
					// unknown external result while retaining a fresh context for state readback.
					cancel()
					<-r.Context().Done()
					return
				}
				_, _ = w.Write([]byte(tc.body))
			}))
			t.Cleanup(server.Close)
			client, workflow, order, _ := easyPayPostgresOrder(t, server.URL)
			plan, early, err := workflow.PrepareRefund(requestCtx, order.ID, 50, "fixture refund", false, true)
			require.NoError(t, err)
			require.Nil(t, early)
			result, err := workflow.ExecuteRefund(requestCtx, plan)
			if tc.status == payment.OrderStatusRefunding {
				require.Equal(t, "REFUND_RECOVERY_REQUIRED", apperror.Reason(err))
				require.Nil(t, result)
				_, _, retryErr := workflow.PrepareRefund(ctx, order.ID, 50, "retry", true, true)
				require.Error(t, retryErr)
				_, queryErr := workflow.QueryAndFinalizeRefund(ctx, order.ID)
				require.Equal(t, "REFUND_QUERY_UNSUPPORTED", apperror.Reason(queryErr))
			} else {
				require.NoError(t, err)
				require.Equal(t, tc.audits == 1, result.Success)
			}
			assertRefundPostgresState(t, ctx, client, order.UserID, order.ID, tc.balance, tc.status, tc.audits)
			prepared, err := client.PaymentAuditLog.Query().Where(
				paymentauditlog.OrderIDEQ(strconv.FormatInt(order.ID, 10)), paymentauditlog.ActionEQ("REFUND_PREPARED")).Count(ctx)
			require.NoError(t, err)
			require.Equal(t, 1, prepared)
			wantCalls := int32(1)
			if tc.firstMissing {
				wantCalls = 2
			}
			require.Equal(t, wantCalls, calls.Load())
		})
	}
}

// TestEasyPayConcurrentCallbackAndQueryCreditsOnce releases a callback and a
// polling observation together for a popup order lacking a transaction number.
// PostgreSQL redemption credits once, and subsequent verified replay retains that balance.
func TestEasyPayConcurrentCallbackAndQueryCreditsOnce(t *testing.T) {
	ctx := context.Background()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"code":1,"status":1,"money":"50.00","trade_no":"epay-trade","pid":1000,"out_trade_no":"test-refund"}`))
	}))
	t.Cleanup(server.Close)
	client, _, order, adapter := easyPayPostgresOrder(t, server.URL)
	order, err := client.PaymentOrder.UpdateOneID(order.ID).SetStatus(payment.OrderStatusPending).
		SetPaymentTradeNo("").ClearPaidAt().Save(ctx)
	require.NoError(t, err)
	repo := billingpostgres.NewRedeemCodeRepository(client)
	reader := &fulfillmentBalance{getByIDUser: &billing.UserSummary{ID: order.UserID}}
	mutations := billingpostgres.NewRedeemMutations(client, billingpostgres.RedeemWriters{Balances: billingpostgres.NewBalanceStore(client)})
	redeemer := billing.NewRedeemService(repo, reader, nil, nil, nil, mutations, nil, nil, billing.RedeemRuntime{})
	core := paymenttestkit.Fulfillment(client, redeemer, nil, nil)
	lifecycle := payment.NewOrderLifecycle(core, nil, nil)
	values := url.Values{
		"pid": {"1000"}, "trade_no": {"epay-trade"}, "out_trade_no": {order.OutTradeNo},
		"type": {"alipay"}, "name": {"test"}, "money": {"50.00"}, "trade_status": {"TRADE_SUCCESS"},
	}
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	pairs := make([]string, 0, len(keys))
	for _, key := range keys {
		pairs = append(pairs, key+"="+values.Get(key))
	}
	digest := md5.Sum([]byte(strings.Join(pairs, "&") + "local-secret"))
	values.Set("sign", hex.EncodeToString(digest[:]))
	notification, err := adapter.VerifyNotification(ctx, values.Encode(), nil)
	require.NoError(t, err)
	queried, err := adapter.QueryOrder(ctx, order.OutTradeNo)
	require.NoError(t, err)
	wrongAmount := *notification
	wrongAmount.Amount = 49
	require.ErrorContains(t, core.HandlePaymentNotification(ctx, &wrongAmount, payment.TypeEasyPay), "amount mismatch")
	before, err := client.User.Get(ctx, order.UserID)
	require.NoError(t, err)
	require.Equal(t, 100.0, before.Balance)
	start := make(chan struct{})
	results := make(chan error, 2)
	// Release both confirmed observations against the same pending database row.
	// Collect both workers before replay and cleanup so their persistent effects are settled.
	go func() {
		<-start
		results <- core.HandlePaymentNotification(ctx, notification, payment.TypeEasyPay)
	}()
	go func() {
		<-start
		_, err := lifecycle.ApplyQueriedPaymentStatus(ctx, paymentpostgres.OrderFromEntity(order), adapter, order.OutTradeNo, queried)
		results <- err
	}()
	close(start)
	for range 2 {
		if err := <-results; err != nil {
			require.Equal(t, "CONFLICT", apperror.Reason(err))
		}
	}
	require.NoError(t, core.HandlePaymentNotification(ctx, notification, payment.TypeEasyPay))
	user, err := client.User.Get(ctx, order.UserID)
	require.NoError(t, err)
	require.Equal(t, 150.0, user.Balance)
	current, err := client.PaymentOrder.Get(ctx, order.ID)
	require.NoError(t, err)
	require.Equal(t, payment.OrderStatusCompleted, current.Status)
	require.Equal(t, "epay-trade", current.PaymentTradeNo)
	code, err := repo.GetByCode(ctx, order.RechargeCode)
	require.NoError(t, err)
	require.Equal(t, 1, code.UsedCount)
	// Conflicting references cannot replace the recorded transaction even after
	// payment completed; refunds must continue using the verified merchant trade identity.
	conflict := *notification
	conflict.TradeNo = "another-trade"
	require.ErrorContains(t, core.HandlePaymentNotification(ctx, &conflict, payment.TypeEasyPay), "conflicts")
	wrongQuery := *queried
	wrongQuery.TradeNo = "another-trade"
	_, err = lifecycle.ApplyQueriedPaymentStatus(ctx, paymentpostgres.OrderFromEntity(current), adapter, order.OutTradeNo, &wrongQuery)
	require.ErrorContains(t, err, "conflicts")
	current, err = client.PaymentOrder.Get(ctx, order.ID)
	require.NoError(t, err)
	require.Equal(t, "epay-trade", current.PaymentTradeNo)
}

// TestEasyPayAbsentPopupOrderCanCancel distinguishes an unopened checkout
// from a failed merchant query. Confirmed absence allows cancellation, while
// an authentication error leaves the pending order available for later payment recovery.
func TestEasyPayAbsentPopupOrderCanCancel(t *testing.T) {
	ctx := context.Background()
	var response atomic.Value
	response.Store(`{"code":-1,"msg":"订单不存在"}`)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		body, ok := response.Load().(string)
		if !ok {
			t.Error("missing response fixture")
			return
		}
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(server.Close)
	client, _, order, _ := easyPayPostgresOrder(t, server.URL)
	_, err := client.PaymentOrder.UpdateOneID(order.ID).SetStatus(payment.OrderStatusPending).
		SetPaymentTradeNo("").ClearPaidAt().Save(ctx)
	require.NoError(t, err)
	instances := paymentpostgres.NewInstanceStore(client)
	registry := payment.NewRegistry()
	bindings := payment.NewProviderBindings(instances, registry, payment.NewDefaultLoadBalancer(instances, nil),
		payment.BindingRuntime{Factory: paymentadapter.CreateProvider}, true)
	core := payment.NewFulfillment(paymentpostgres.NewOrderStore(client), bindings, registry, nil, nil, payment.FulfillmentRuntime{})
	lifecycle := payment.NewOrderLifecycle(core, nil, nil)
	_, err = lifecycle.AdminCancelOrder(ctx, order.ID)
	require.NoError(t, err)
	current, err := client.PaymentOrder.Get(ctx, order.ID)
	require.NoError(t, err)
	require.Equal(t, payment.OrderStatusCancelled, current.Status)
	// Reopen only this fixture and replace its channel observation with an
	// authentication failure, keeping uncertainty distinct from a confirmed absent order.
	response.Store(`{"code":-1,"msg":"商户密钥错误"}`)
	_, err = client.PaymentOrder.UpdateOneID(order.ID).SetStatus(payment.OrderStatusPending).Save(ctx)
	require.NoError(t, err)
	_, err = lifecycle.AdminCancelOrder(ctx, order.ID)
	require.Equal(t, "PAYMENT_STATUS_UNAVAILABLE", apperror.Reason(err))
	current, err = client.PaymentOrder.Get(ctx, order.ID)
	require.NoError(t, err)
	require.Equal(t, payment.OrderStatusPending, current.Status)
}
