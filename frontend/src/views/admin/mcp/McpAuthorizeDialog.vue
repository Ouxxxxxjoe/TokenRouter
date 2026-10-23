<template>
  <BaseDialog
    :show="show"
    :title="t('admin.mcp.oauth.authorizeTitle')"
    width="normal"
    :close-on-escape="!submitting"
    @close="close"
    @after-leave="emit('after-leave')"
  >
    <div class="space-y-5" :aria-busy="loading || submitting">
      <p v-if="loading" class="text-sm text-gray-500" role="status">{{ t('common.loading') }}</p>
      <p
        v-if="error"
        class="rounded-control border border-red-200 p-3 text-sm text-red-600 dark:border-red-900 dark:text-red-400"
        role="alert"
        >{{ error }}</p
      >
      <template v-if="review && !loading">
        <dl class="grid gap-4 sm:grid-cols-2">
          <div
            ><dt class="text-sm text-gray-500 dark:text-gray-400">{{
              t('admin.mcp.oauth.account')
            }}</dt
            ><dd class="mt-1 break-all font-medium">{{ auth.user?.email }}</dd></div
          >
          <div
            ><dt class="text-sm text-gray-500 dark:text-gray-400">{{
              t('admin.mcp.oauth.application')
            }}</dt
            ><dd class="mt-1 break-words font-medium">{{
              review.request.client.client_name
            }}</dd></div
          >
          <div class="sm:col-span-2"
            ><dt class="text-sm text-gray-500 dark:text-gray-400">{{
              t('admin.mcp.oauth.client')
            }}</dt
            ><dd class="mt-1 break-all font-mono text-sm">{{
              review.request.client.client_id
            }}</dd></div
          >
          <div
            ><dt class="text-sm text-gray-500 dark:text-gray-400">{{
              t('admin.mcp.oauth.callback')
            }}</dt
            ><dd class="mt-1 break-all text-sm">{{ callbackOrigin }}</dd></div
          >
          <div
            ><dt class="text-sm text-gray-500 dark:text-gray-400">{{
              t('admin.mcp.oauth.requestExpires')
            }}</dt
            ><dd class="mt-1 text-sm">{{ formatDateTime(review.request.expires_at) }}</dd></div
          >
        </dl>
        <p class="text-sm text-gray-600 dark:text-gray-400">{{
          t('admin.mcp.oauth.identityHint')
        }}</p>
        <fieldset :disabled="submitting || expired" class="min-w-0 space-y-4">
          <McpPermissionPicker
            :key="review.request.id"
            v-model="selected"
            :operations="review.operations"
            :skip-browser-confirmation="review.grant?.skip_browser_confirmation ?? false"
          />
        </fieldset>
        <p class="text-sm text-gray-600 dark:text-gray-400">{{
          t('admin.mcp.oauth.lifetimeHint')
        }}</p>
        <p v-if="expired" role="alert" class="text-sm text-amber-700 dark:text-amber-400">{{
          t('admin.mcp.oauth.expired')
        }}</p>
      </template>
      <button
        v-if="error && !review"
        class="btn btn-secondary"
        type="button"
        :disabled="loading"
        @click="load"
        >{{ t('admin.mcp.refresh') }}</button
      >
    </div>
    <template v-if="review && !loading" #footer>
      <div class="flex justify-end gap-2">
        <button
          class="btn btn-secondary"
          type="button"
          :disabled="submitting || expired"
          @click="decide(false)"
          >{{ t('admin.mcp.oauth.deny') }}</button
        >
        <button
          class="btn btn-primary"
          type="button"
          :disabled="submitting || expired || !selected.size"
          @click="decide(true)"
          >{{ submitting ? t('common.processing') : t('admin.mcp.oauth.authorize') }}</button
        >
      </div>
    </template>
  </BaseDialog>
  <TotpStepUpDialog :controller="stepUp" />
</template>

<script setup lang="ts">
import { computed, onBeforeUnmount, ref, watch } from 'vue'
import { useI18n } from 'vue-i18n'
import BaseDialog from '@/components/common/BaseDialog.vue'
import TotpStepUpDialog from '@/components/auth/TotpStepUpDialog.vue'
import { useStepUp, isStepUpCancelled } from '@/composables/useStepUp'
import { useAuthStore } from '@/stores/auth'
import { formatDateTime } from '@/utils/format'
import * as api from '@/api/admin/mcp'
import McpPermissionPicker from './McpPermissionPicker.vue'
import { permissionPresets } from './permissions'

// McpAuthorizeDialog.vue presents a session-bound application request over MCP management.
// The server supplies client identity, callback, and the current operation
// catalogue; the administrator chooses exact permissions and approves or denies.
// First connections start with safe reads, while returning applications show
// their existing permission selection for deliberate review before replacement.
//
// Closing the dialog or changing its request or account cancels pending reads.
// A decision response can navigate only while its request and administrator are
// still current. Failed submissions retain the selected permissions, and local
// expiry disables submission until the client starts a new authorization flow.

// Browser identity and shared verification UI belong to this mounted consent dialog.
const props = defineProps<{
  show: boolean // Parent-owned dialog visibility.
  requestId: string // Incoming OAuth request identifier.
}>()
const emit = defineEmits<{
  (event: 'close'): void // Requests local workflow dismissal.
  (event: 'after-leave'): void // Reports completed dialog exit.
}>()
const { t } = useI18n()
const auth = useAuthStore()
const stepUp = useStepUp()
const review = ref<api.MCPOAuthReview | null>(null)
const selected = ref(new Set<string>())
const loading = ref(false)
const submitting = ref(false)
const error = ref('')
const now = ref(Date.now())
let controller: AbortController | null = null
let disposed = false
// The expiry timer updates display state only; the server independently validates the deadline.
const expiryTimer = setInterval(() => {
  now.value = Date.now()
}, 1000)
const expired = computed(
  () => !!review.value && Date.parse(review.value.request.expires_at) <= now.value,
)
const callbackOrigin = computed(() =>
  review.value ? new URL(review.value.redirect_uri).origin : '',
)

// messageOf exposes server feedback or the supplied localized request failure text.
function messageOf(value: unknown): string {
  return value instanceof Error
    ? value.message
    : value && typeof value === 'object' && 'message' in value
      ? String(value.message)
      : t('admin.mcp.requestFailed')
}

// load binds the current request and publishes only its latest authenticated review.
// A changed request or account aborts the preceding read and clears its approval
// proof. Each successful load initializes permissions from existing consent or safe
// reads, intersected with the current catalogue. The request's controller decides
// which result can update the dialog; an older request cannot replace a newer
// review or end its loading indicator. Missing identifiers leave a dismissible
// error without contacting the authorization API.
async function load() {
  // Replacing a review invalidates both its pending read and any verification
  // prompt, so their results cannot resume a decision for the replaced account.
  controller?.abort()
  stepUp.onCancel()
  const current = new AbortController()
  controller = current
  review.value = null
  error.value = ''
  loading.value = false
  const id = props.requestId
  if (typeof id !== 'string' || !id) {
    error.value = t('admin.mcp.oauth.expired')
    return
  }
  loading.value = true
  try {
    const result = await api.getOAuthReview(id, current.signal)
    if (current.signal.aborted || disposed) return
    const known = new Set(result.operations.map((operation) => operation.operation_id))
    selected.value = new Set(
      (
        result.grant?.permissions ??
        permissionPresets(result.operations).find((preset) => preset.id === 'readOnly')
          ?.permissions ??
        []
      ).filter((permission) => known.has(permission)),
    )
    review.value = result
  } catch (cause) {
    if (!current.signal.aborted && !disposed) error.value = messageOf(cause)
  } finally {
    if (controller === current) loading.value = false
  }
}

// decide submits the current permission choice and navigates after a committed decision.
// TOTP verification retries the same session-bound request. Failures retain the
// draft, and account changes prevent an old callback from navigating the new session.
// The administrator and review are captured before submission, then checked again
// after verification and the API call. The returned URL must match the reviewed
// callback origin and path before navigation; a changed dialog or request leaves
// the response unused. Concurrent submissions are ignored until the pending one ends.
async function decide(approve: boolean) {
  const current = review.value
  const userID = auth.user?.id
  if (!current || expired.value || submitting.value || (approve && !selected.value.size)) return
  submitting.value = true
  error.value = ''
  const permissions = [...selected.value]
  try {
    const target = await stepUp.run(() =>
      api.decideOAuthRequest(current.request.id, current.nonce, approve, permissions),
    )
    // A completed decision belongs to the original administrator and request;
    // leaving this workflow must prevent its callback from replacing the current page.
    if (
      disposed ||
      !props.show ||
      props.requestId !== current.request.id ||
      review.value !== current ||
      auth.user?.id !== userID
    )
      return
    const expected = new URL(current.redirect_uri)
    const callback = new URL(target)
    if (
      callback.origin !== expected.origin ||
      callback.pathname !== expected.pathname ||
      callback.hash
    )
      throw new Error(t('admin.mcp.oauth.callbackInvalid'))
    window.location.assign(callback.href)
  } catch (cause) {
    if (
      !disposed &&
      props.show &&
      review.value === current &&
      auth.user?.id === userID &&
      !isStepUpCancelled(cause)
    )
      error.value = messageOf(cause)
  } finally {
    submitting.value = false
  }
}

// close rejects a usable request before returning to its validated client callback.
// An expired request or failed workflow can be dismissed locally. In-flight
// decisions keep the dialog open until their result can be presented safely.
function close() {
  if (submitting.value) return
  if (review.value && !expired.value && !error.value) {
    void decide(false)
    return
  }
  emit('close')
}

// Watch scalar identities so ordinary profile refreshes cannot reset the draft.
// Closing retains rendered content for the shell's exit and cancels pending reads.
watch(
  [() => props.show, () => props.requestId, () => auth.user?.id],
  ([show]) => {
    if (show) void load()
    else {
      controller?.abort()
      stepUp.onCancel()
    }
  },
  { immediate: true },
)
// Disposal cancels pending reads and verification, then releases the local expiry
// timer so an unmounted dialog cannot keep updating its review state.
onBeforeUnmount(() => {
  disposed = true
  controller?.abort()
  stepUp.onCancel()
  clearInterval(expiryTimer)
})
</script>
