package payment

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/TokenFlux/TokenRouter/internal/billing"
	"github.com/TokenFlux/TokenRouter/internal/pkg/apperror"
)

// refund_workflow.go coordinates refund preparation, provider submission,
// compensation, and recovery finalization.
// An external refund can complete while its local final state still needs
// persistence, so refund progress is recorded before provider submission.
// Preparation, compensation, and finalization use separate store transactions,
// with the provider call between them and receipt identity carrying the
// previously committed local recovery.
// An unknown channel outcome retains that preparation for manual verification.
//
// Pending observations restore prepared rights and retain provider identity
// for later query. Immediate success finalizes the prepared deduction, while
// pending success can recover compensated rights again in the final
// transaction. Inconclusive query results require verification, and
// conditional store claims stop a stale failure observation from replacing
// newer success. Wallet results record the returned deduction quantity;
// subscription results retain the requested day bookkeeping even when
// revocation or a missing positive grant ID changes the operation selected.

// ExecuteRefund persists preparation and its deduction receipt before making
// the gateway request. Preparation failure returns before external submission,
// and the store publishes committed mutation results into the plan.
//
// The gateway call runs between short store transactions. An unknown outcome
// retains preparation for verification; other errors choose compensation,
// while a response goes through FinishRefund for pending or successful local
// settlement. A later store failure can leave the already
// committed preparation and externally attempted refund for recovery; this
// method does not resubmit the gateway after that local failure.
func (s *RefundWorkflow) ExecuteRefund(ctx context.Context, p *RefundPlan) (*RefundResult, error) {
	// Commit local preparation before external submission so failed preparation
	// cannot initiate a provider refund and later local recovery has a persisted
	// operation receipt.
	receipt, err := s.store.PrepareRefund(ctx, p, ApplyRefundDeduction)
	if err != nil {
		return nil, err
	}
	// The preparation transaction has returned before this provider call.
	// External progress can therefore survive a later completion or compensation
	// error in its separate transaction.
	resp, err := s.GwRefund(ctx, p)
	if err != nil {
		// The channel may have transferred money before its response was lost.
		// Keep the prepared deduction and claim so another submission cannot double-refund.
		if errors.Is(err, ErrRefundOutcomeUnknown) {
			return nil, RefundRecoveryRequired(err.Error())
		}
		return s.compensateFailure(ctx, p, receipt, err)
	}
	return s.FinishRefund(ctx, p, receipt, resp)
}

// FinishRefund validates the provider observation and advances the prepared
// local refund attempt. Invalid responses choose compensation; pending state
// compensates rights and stores pending recovery before resetting the
// in-memory deduction quantities.
//
// Successful immediate states call CompleteRefund with no second deduction
// because preparation already performed its selected recovery. Store errors
// propagate while the prior preparation remains persisted. Supply the plan and
// matching receipt from preparation; provider identity is recorded for pending
// query, while final success uses local order/operation claims.
func (s *RefundWorkflow) FinishRefund(ctx context.Context, p *RefundPlan, r *RefundReceipt, resp *RefundResponse) (*RefundResult, error) {
	if err := ValidateRefundProviderResponse(resp); err != nil {
		return s.compensateFailure(ctx, p, r, err)
	}
	if strings.TrimSpace(resp.Status) == ProviderStatusPending {
		// Pending settlement restores prepared rights and persists query identity
		// together. Clear the in-memory quantities only after that compensation
		// succeeds so errors retain recoverable intent.
		if err := s.store.CompensateRefund(ctx, p, r, RefundResponseID(resp), "", CompensateRefundDeduction); err != nil {
			return nil, err
		}
		p.BalanceToDeduct = 0
		p.SubDaysToDeduct = 0
		return &RefundResult{Warning: "gateway refund is pending confirmation"}, nil
	}
	// Immediate success finalizes the prepared deduction with no repeated rights
	// callback. The store still checks receipt identity and current order version
	// before accepting completion.
	return s.store.CompleteRefund(ctx, p, r, nil)
}

// compensateFailure asks the store to restore prepared rights and record
// gateway failure together using the matching receipt. A successful
// compensation returns a warning result, while store failure returns both
// gateway cause and local recovery error.
//
// The earlier preparation remains the persisted progress used for later
// recovery until the compensation transaction succeeds. This method uses the
// supplied context and does not create a detached retry budget; it also does
// not make another provider refund request.
func (s *RefundWorkflow) compensateFailure(ctx context.Context, p *RefundPlan, r *RefundReceipt, cause error) (*RefundResult, error) {
	// Use the receipt to compensate exactly this local preparation and record its
	// gateway failure. A failed recovery transaction leaves the earlier prepared
	// state for later verification.
	if err := s.store.CompensateRefund(ctx, p, r, "", cause.Error(), CompensateRefundDeduction); err != nil {
		return nil, fmt.Errorf("gateway refund failed (%v); local recovery remains pending: %w", cause, err)
	}
	return &RefundResult{Warning: "gateway failed: " + cause.Error() + ", rolled back"}, nil
}

// QueryAndFinalizeRefund queries an existing pending or recoverable refunding
// operation and completes local recovery from that observation. It requires
// valid pending detail or prepared receipt before resolving the order's
// refund-query provider; unsupported query capability returns a manual-check
// error.
//
// Query failures and inconclusive responses return while local progress
// remains. An explicit failed prepared result compensates that receipt; a
// failed pending result conditionally records failure and accepts an already
// newer refund success. A valid prepared response reuses FinishRefund, while
// pending success rebuilds deduction intent and invokes one transaction for
// rights and completion. No gateway refund is submitted by this query path.
func (s *RefundWorkflow) QueryAndFinalizeRefund(ctx context.Context, id int64) (*RefundResult, error) {
	order, err := s.store.Order(ctx, id)
	if err != nil {
		return nil, apperror.NotFound("NOT_FOUND", "order not found")
	}
	if order.Status != OrderStatusRefundPending && order.Status != OrderStatusRefunding {
		return nil, apperror.BadRequest("INVALID_STATUS", "only refund pending or recoverable refunding orders can be finalized")
	}
	var receipt *RefundReceipt
	var detail RefundPendingDetail
	if order.Status == OrderStatusRefunding {
		receipt, err = s.store.RefundRecovery(ctx, order)
	} else {
		detail, err = s.store.PendingDetail(ctx, id)
	}
	if err != nil {
		return nil, err
	}
	if receipt != nil {
		detail = receipt.RefundPendingDetail
	}
	provider, err := s.runtime.Provider(ctx, order)
	if err != nil {
		return nil, fmt.Errorf("get refund provider: %w", err)
	}
	query, ok := provider.(RefundQueryProvider)
	if !ok {
		return nil, apperror.BadRequest("REFUND_QUERY_UNSUPPORTED", "this payment provider does not support refund status query; please verify manually")
	}
	finish := s.runtime.Observe(ctx)
	resp, err := query.QueryRefund(ctx, RefundQueryRequest{
		TradeNo:  order.PaymentTradeNo,
		OrderID:  order.OutTradeNo,
		RefundID: detail.RefundID,
		Amount:   FormatGatewayRefundAmount(order.RefundAmount, order),
	})
	finish()
	if err != nil {
		return nil, fmt.Errorf("query refund: %w", err)
	}
	if err = ValidateRefundProviderResponse(resp); err != nil {
		// An inconclusive query cannot establish whether external refund occurred.
		// Retain persisted progress and require verification before local finalization.
		if resp == nil || strings.TrimSpace(resp.Status) != ProviderStatusFailed {
			return nil, RefundRecoveryRequired(err.Error())
		}
		if receipt != nil {
			return s.compensateFailure(ctx, receipt.Plan(order), receipt, err)
		}
		current, saveErr := s.store.FailPendingRefund(ctx, order, detail, err.Error())
		if saveErr != nil {
			return nil, saveErr
		}
		// A later successful finalization can win while this failed provider
		// observation is being stored. Return that newer successful state instead of
		// treating it as refund failure.
		if current.Status == OrderStatusRefunded || current.Status == OrderStatusPartiallyRefunded {
			return &RefundResult{Success: true}, nil
		}
		if current.Status != OrderStatusRefundFailed {
			return nil, apperror.Conflict("CONFLICT", "order status changed")
		}
		return &RefundResult{Warning: "gateway refund failed: " + err.Error()}, nil
	}
	if receipt != nil {
		return s.FinishRefund(ctx, receipt.Plan(order), receipt, resp)
	}
	if strings.TrimSpace(resp.Status) == ProviderStatusPending {
		s.runtime.Audit(ctx, id, "REFUND_QUERY_PENDING", "admin", map[string]any{"refundID": resp.RefundID})
		return &RefundResult{Warning: "gateway refund is still pending confirmation"}, nil
	}
	return s.FinalizePendingRefundSuccess(ctx, s.RefundFinalizePlan(order, detail))
}

// FinalizePendingRefundSuccess delegates a reconstructed pending plan to
// transactional completion with ApplyRefundDeduction. The store validates
// current status, version, and operation identity before recovering
// compensated rights and writing success.
func (s *RefundWorkflow) FinalizePendingRefundSuccess(ctx context.Context, p *RefundPlan) (*RefundResult, error) {
	return s.store.CompleteRefund(ctx, p, nil, ApplyRefundDeduction)
}

// ApplyRefundDeduction applies the plan's selected recovery through
// transaction-bound rights. It records the returned wallet quantity after a
// positive balance deduction, while subscription work requires positive days
// and grant ID.
//
// A subscription adjustment that would expire the grant selects revocation;
// other adjustment errors return. The requested subscription day quantity
// remains in the plan after that choice, so it is not proof of an exact
// elapsed-day change. The owning store completes the surrounding transaction
// and publishes plan results after commit.
func ApplyRefundDeduction(ctx context.Context, rights RefundRights, p *RefundPlan) error {
	if p.DeductionType == DeductionTypeBalance && p.BalanceToDeduct > 0 {
		actual, err := rights.DeductBalance(ctx, p.Order.UserID, p.BalanceToDeduct)
		if err != nil {
			return fmt.Errorf("deduction: %w", err)
		}
		p.BalanceToDeduct = actual
	}
	if p.DeductionType == DeductionTypeSubscription && p.SubDaysToDeduct > 0 && p.SubscriptionID > 0 {
		err := rights.AdjustSubscription(ctx, p.SubscriptionID, -p.SubDaysToDeduct)
		// The requested negative adjustment would end the grant before the allowed
		// time. Revoke that identified subscription through the same transaction,
		// retaining the recorded day quantity for recovery.
		if errors.Is(err, billing.ErrAdjustWouldExpire) {
			if err = rights.RevokeSubscription(ctx, p.SubscriptionID); err != nil {
				return fmt.Errorf("revoke subscription: %w", err)
			}
		} else if err != nil {
			return fmt.Errorf("deduct subscription days: %w", err)
		}
	}
	return nil
}

// CompensateRefundDeduction restores positive wallet recovery or adds recorded
// subscription days through transaction-bound rights. Subscription
// compensation requires a positive grant ID; the store owns commit and
// recovery evidence for this callback.
func CompensateRefundDeduction(ctx context.Context, rights RefundRights, p *RefundPlan) error {
	if p.DeductionType == DeductionTypeBalance && p.BalanceToDeduct > 0 {
		if err := rights.CompensateBalance(ctx, p.Order.UserID, p.BalanceToDeduct); err != nil {
			return err
		}
	}
	if p.DeductionType == DeductionTypeSubscription && p.SubDaysToDeduct > 0 && p.SubscriptionID > 0 {
		return rights.AdjustSubscription(ctx, p.SubscriptionID, p.SubDaysToDeduct)
	}
	return nil
}

// Plan recreates refund intent and recorded deduction quantities from the
// prepared receipt while retaining the supplied order pointer. It copies the
// local operation identity for store claims, with provider refund identity
// handled by the pending path.
func (r *RefundReceipt) Plan(order *Order) *RefundPlan {
	return &RefundPlan{
		OrderID:         r.OrderID,
		Order:           order,
		RefundAmount:    r.RefundAmount,
		GatewayAmount:   r.GatewayAmount,
		Reason:          r.Reason,
		Force:           r.Force,
		DeductBalance:   r.DeductBalance,
		DeductionType:   r.DeductionType,
		BalanceToDeduct: r.BalanceDeducted,
		SubDaysToDeduct: r.SubDaysDeducted,
		SubscriptionID:  r.SubscriptionID,
		OperationID:     r.OperationID,
	}
}
