import { flushPromises, mount, type VueWrapper } from '@vue/test-utils'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import McpManagementView from '../McpManagementView.vue'

// McpManagementView.spec.ts exercises permission selection and token creation through
// the page's actual form events. API replacements distinguish failed writes from
// successful creation followed by failed readback, protecting both retained drafts
// and immediate credential delivery from unrelated list refresh failures.

// Shared API replacements allow each case to select its write and readback outcomes.
const api = vi.hoisted(() => ({
  listTokens: vi.fn(),
  listOAuthGrants: vi.fn(),
  getOAuthStatus: vi.fn(),
  updateOAuthGrant: vi.fn(),
  revokeOAuthGrant: vi.fn(),
  listOperations: vi.fn(),
  createToken: vi.fn(),
  updateToken: vi.fn(),
  revokeToken: vi.fn(),
  getCredential: vi.fn(),
  getConfirmation: vi.fn(),
  approveConfirmation: vi.fn(),
  downloadFile: vi.fn(),
}))
vi.mock('@/api/admin/mcp', () => api)
// Route fixtures select incoming confirmation or file workflows before mounting the page.
const route = vi.hoisted(() => ({ name: 'AdminMCP', query: {} as Record<string, string> }))
const routerReplace = vi.hoisted(() => vi.fn())
const saveAs = vi.hoisted(() => vi.fn())
vi.mock('file-saver', () => ({ saveAs }))
vi.mock('vue-router', async (importOriginal) => ({
  ...(await importOriginal<typeof import('vue-router')>()),
  useRoute: () => route,
  useRouter: () => ({ replace: routerReplace }),
  RouterLink: { name: 'RouterLink', props: ['to'], template: '<a><slot /></a>' },
}))
vi.mock('vue-i18n', async (importOriginal) => ({
  ...(await importOriginal<typeof import('vue-i18n')>()),
  useI18n: () => ({ t: (key: string) => key, te: () => false, locale: { value: 'en' } }),
}))
vi.mock('@/stores/app', () => ({ useAppStore: () => ({ showSuccess: vi.fn() }) }))
// Clipboard replacement records the exact text copied by an explicit row action.
const copyToClipboard = vi.hoisted(() => vi.fn())
vi.mock('@/composables/useClipboard', () => ({
  useClipboard: () => ({ copyToClipboard }),
}))
vi.mock('@/composables/useStepUp', () => ({
  useStepUp: () => ({ run: (action: () => Promise<void>) => action(), onCancel: vi.fn() }),
  isStepUpCancelled: () => false,
}))

// catalogue mixes routine queries, gateway writes, and sensitive actions for preset assertions.
const catalogue = [
  {
    operation_id: 'groups.list',
    module: 'groups',
    title: 'List groups',
    read_only: true,
    sensitive: false,
  },
  {
    operation_id: 'users.create',
    module: 'users',
    title: 'Create user',
    read_only: false,
    sensitive: true,
  },
  {
    operation_id: 'providers.create',
    module: 'providers',
    title: 'Create provider',
    read_only: false,
    sensitive: false,
  },
  {
    operation_id: 'providers.export',
    module: 'providers',
    title: 'Export credentials',
    read_only: true,
    sensitive: true,
    response_mode: 'file',
  },
  {
    operation_id: 'mcp.tokens.create',
    module: 'mcp',
    title: 'Delegate permissions',
    read_only: false,
    sensitive: true,
  },
]

// page mounts form-bearing slots while replacing unrelated shell and overlay machinery.
function page() {
  return mount(McpManagementView, {
    global: {
      stubs: {
        AppLayout: { template: '<main><slot /></main>' },
        TablePageLayout: {
          template: '<div><slot name="actions"/><slot name="filters"/><slot name="table"/></div>',
        },
        DataTable: {
          props: ['data'],
          template:
            '<div><template v-for="row in data"><slot name="cell-name" :row="row"/><slot name="cell-prefix" :row="row" :value="row.prefix"/><slot name="cell-enabled" :row="row"/><slot name="cell-actions" :row="row"/></template><slot v-if="!data?.length" name="empty"/></div>',
        },
        BaseDialog: {
          props: ['show', 'title'],
          template:
            '<section v-if="show"><h2>{{ title }}</h2><slot/><slot name="footer"/></section>',
        },
        Teleport: true,
        MotionTransition: { props: ['name'], template: '<slot />' },
        ConfirmDialog: true,
        TotpStepUpDialog: true,
        McpAuthorizeDialog: {
          name: 'McpAuthorizeDialog',
          props: ['show', 'requestId'],
          emits: ['close', 'after-leave'],
          template: '<div v-if="show" data-test="authorization-dialog">{{ requestId }}</div>',
        },
        Icon: true,
        DateTimePicker: true,
        Select: true,
        Toggle: true,
        EndpointPopover: true,
      },
    },
  })
}

// clickText activates the uniquely labelled page button used by the scenario.
async function clickText(wrapper: VueWrapper, label: string) {
  const button = wrapper.findAll('button').find((value) => value.text() === label)
  expect(button).toBeDefined()
  await button!.trigger('click')
}

describe('MCP token management', () => {
  beforeEach(() => {
    vi.resetAllMocks()
    route.query = {}
    route.name = 'AdminMCP'
    routerReplace.mockResolvedValue(undefined)
    copyToClipboard.mockResolvedValue(true)
    api.listTokens.mockResolvedValue([])
    api.listOAuthGrants.mockResolvedValue([])
    api.getOAuthStatus.mockResolvedValue({ enabled: false, issuer: '', resource: '' })
    api.listOperations.mockResolvedValue(catalogue)
  })

  // A selected grant becomes hidden by another search before submission. The saved
  // token must retain that exact operation without granting the newly visible action.
  it('retains selected permissions across filtering and submits exact grants', async () => {
    api.createToken.mockResolvedValue({ credential: 'tr_mcp_fixture_only', token: { id: 1 } })
    const wrapper = page()
    await flushPromises()
    await clickText(wrapper, 'admin.mcp.create')
    await wrapper.get('input[required]').setValue('Catalogue viewer')
    const label = wrapper.findAll('label').find((value) => value.text().includes('List groups'))
    expect(label).toBeDefined()
    await label!.get('input[type="checkbox"]').setValue(true)
    await wrapper.get('input[aria-label="admin.mcp.permissionSearch"]').setValue('users')
    await wrapper.get('#mcp-token-form').trigger('submit')
    await flushPromises()
    expect(api.createToken).toHaveBeenCalledWith(
      expect.objectContaining({
        name: 'Catalogue viewer',
        enabled: true,
        skip_browser_confirmation: false,
        permissions: ['groups.list'],
      }),
    )
    expect(wrapper.text()).toContain('tr_mcp_fixture_only')
    wrapper.unmount()
  })

  // A rejected save leaves the editor open with its entered name and selected grant.
  // Users can correct the failure without reconstructing the permission selection.
  it('retains the draft and reports a failed write', async () => {
    api.createToken.mockRejectedValue(new Error('Permission validation failed'))
    const wrapper = page()
    await flushPromises()
    await clickText(wrapper, 'admin.mcp.create')
    await wrapper.get('input[required]').setValue('Retry this draft')
    await wrapper.get('#mcp-token-form').trigger('submit')
    await flushPromises()
    expect((wrapper.get('input[required]').element as HTMLInputElement).value).toBe(
      'Retry this draft',
    )
    expect(wrapper.text()).toContain('Permission validation failed')
    expect(wrapper.find('#mcp-token-form').exists()).toBe(true)
    wrapper.unmount()
  })

  // Creation succeeds before the following list read fails. The secret-delivery dialog
  // must still display the credential so immediate client setup can continue despite the list failure.
  it('keeps the setup credential when post-save readback fails', async () => {
    api.createToken.mockResolvedValue({ credential: 'tr_mcp_readback_fixture', token: { id: 2 } })
    const wrapper = page()
    await flushPromises()
    await clickText(wrapper, 'admin.mcp.create')
    await wrapper.get('input[required]').setValue('Saved token')
    api.listTokens.mockRejectedValueOnce(new Error('Readback unavailable'))
    await wrapper.get('#mcp-token-form').trigger('submit')
    await flushPromises()
    expect(wrapper.text()).toContain('tr_mcp_readback_fixture')
    expect(wrapper.text()).toContain('Readback unavailable')
    expect(wrapper.find('#mcp-token-form').exists()).toBe(false)
    wrapper.unmount()
  })

  // A preset is chosen while the list is filtered to users. It must select the
  // complete gateway grant set, omit sensitive exports and delegation, and preserve
  // the explicitly enabled confirmation preference when saving.
  it('applies complete presets independently of search and saves confirmation preference', async () => {
    api.createToken.mockResolvedValue({ credential: 'tr_mcp_preset_fixture', token: { id: 3 } })
    const wrapper = page()
    await flushPromises()
    await clickText(wrapper, 'admin.mcp.create')
    await wrapper.get('input[required]').setValue('Gateway assistant')
    await wrapper.get('input[aria-label="admin.mcp.permissionSearch"]').setValue('users')
    wrapper.getComponent('[aria-label="admin.mcp.preset"]').vm.$emit('update:modelValue', 'gateway')
    wrapper
      .getComponent('[aria-label="admin.mcp.skipBrowserConfirmation"]')
      .vm.$emit('update:modelValue', true)
    await wrapper.get('#mcp-token-form').trigger('submit')
    await flushPromises()
    expect(api.createToken).toHaveBeenCalledWith(
      expect.objectContaining({
        permissions: ['groups.list', 'providers.create'],
        skip_browser_confirmation: true,
      }),
    )
    wrapper.unmount()
  })

  // An administrator selects read-only access and then changes one grant manually.
  // The editor returns to custom mode and submits only the resulting explicit set.
  it('keeps manual choices after a preset is applied', async () => {
    api.createToken.mockResolvedValue({ credential: 'tr_mcp_manual_fixture', token: { id: 4 } })
    const wrapper = page()
    await flushPromises()
    await clickText(wrapper, 'admin.mcp.create')
    await wrapper.get('input[required]').setValue('Custom reader')
    const preset = wrapper.getComponent('[aria-label="admin.mcp.preset"]')
    preset.vm.$emit('update:modelValue', 'readOnly')
    await flushPromises()
    await clickText(wrapper, 'admin.mcp.adjustPermissions')
    const label = wrapper.findAll('label').find((value) => value.text().includes('Create provider'))
    await label!.get('input[type="checkbox"]').setValue(true)
    expect(preset.attributes('modelvalue')).toBe('custom')
    await wrapper.get('#mcp-token-form').trigger('submit')
    await flushPromises()
    expect(api.createToken).toHaveBeenCalledWith(
      expect.objectContaining({
        permissions: ['groups.list', 'providers.create'],
        skip_browser_confirmation: false,
      }),
    )
    wrapper.unmount()
  })

  // Disabling a token updates admission but must retain its saved confirmation policy.
  // The row refresh reads back the disabled token with the same explicit preference.
  it('preserves the confirmation preference when toggling admission', async () => {
    const token = {
      id: 1,
      name: 'Direct assistant',
      prefix: 'tr_mcp_fixture',
      permissions: ['groups.list'],
      enabled: true,
      skip_browser_confirmation: true,
      expires_at: null,
      revoked_at: null,
    }
    api.listTokens.mockResolvedValueOnce([token])
    const wrapper = page()
    await flushPromises()
    await clickText(wrapper, 'common.more')
    expect(wrapper.getComponent({ name: 'RouterLink' }).props('to')).toEqual({
      path: '/admin/audit-logs',
      query: { q: token.prefix, auth_method: 'mcp_token' },
    })
    api.listTokens.mockResolvedValue([{ ...token, enabled: false }])
    await clickText(wrapper, 'keys.disable')
    await flushPromises()
    expect(api.updateToken).toHaveBeenCalledWith(
      1,
      expect.objectContaining({ enabled: false, skip_browser_confirmation: true }),
    )
    wrapper.unmount()
  })

  // Editing configuration after admission controls move to row actions must preserve
  // the saved status. Both enabled and disabled tokens retain their state after saving.
  it.each([true, false])(
    'preserves enabled=%s when saving the editor without a status switch',
    async (enabled) => {
      const token = {
        id: 12,
        name: 'Existing token',
        prefix: 'tr_mcp_edit_fixture',
        permissions: ['groups.list'],
        enabled,
        skip_browser_confirmation: false,
        expires_at: null,
        revoked_at: null,
      }
      api.listTokens.mockResolvedValue([token])
      api.updateToken.mockResolvedValue(token)
      const wrapper = page()
      await flushPromises()
      await clickText(wrapper, 'common.edit')
      expect(wrapper.findComponent('[aria-label="admin.mcp.enabled"]').exists()).toBe(false)
      await wrapper.get('input[required]').setValue('Renamed token')
      await wrapper.get('#mcp-token-form').trigger('submit')
      await flushPromises()
      expect(api.updateToken).toHaveBeenCalledWith(
        12,
        expect.objectContaining({ name: 'Renamed token', enabled }),
      )
      wrapper.unmount()
    },
  )

  // The table displays a prefix while the copy endpoint returns its complete credential.
  // Copying must use the fetched value and keep reusable secrets out of rendered rows.
  it('copies the full credential on demand and keeps row metadata masked', async () => {
    api.listTokens.mockResolvedValue([
      { id: 9, prefix: 'tr_mcp_display', name: 'Copy fixture', permissions: [], enabled: true },
    ])
    api.getCredential.mockResolvedValue('tr_mcp_complete_secret_fixture')
    const wrapper = page()
    await flushPromises()
    await wrapper.get('button[aria-label="keys.copyToClipboard"]').trigger('click')
    await flushPromises()
    expect(api.getCredential).toHaveBeenCalledWith(9)
    expect(copyToClipboard).toHaveBeenCalledWith('tr_mcp_complete_secret_fixture')
    expect(wrapper.text()).not.toContain('tr_mcp_complete_secret_fixture')
    expect(wrapper.get('button[aria-label="keys.copyToClipboard"]').attributes('title')).toBe(
      'keys.copied',
    )
    expect(wrapper.findComponent('[aria-label="admin.mcp.enabled"]').exists()).toBe(false)
    await clickText(wrapper, 'common.more')
    await clickText(wrapper, 'admin.mcp.revoke')
    expect(wrapper.getComponent({ name: 'ConfirmDialog' }).attributes('show')).toBe('true')
    expect(api.revokeToken).not.toHaveBeenCalled()
    wrapper.unmount()
  })

  // A credential retrieval failure must leave the clipboard untouched. A delayed
  // successful retrieval after leaving the page must also avoid writing a secret.
  it('does not copy prefixes or publish a late credential after disposal', async () => {
    api.listTokens.mockResolvedValue([
      { id: 9, prefix: 'tr_mcp_display', permissions: [], enabled: true },
    ])
    api.getCredential.mockRejectedValueOnce(new Error('Credential unavailable'))
    const wrapper = page()
    await flushPromises()
    await wrapper.get('button[aria-label="keys.copyToClipboard"]').trigger('click')
    await flushPromises()
    expect(copyToClipboard).not.toHaveBeenCalled()
    expect(wrapper.text()).toContain('Credential unavailable')
    let resolve!: (secret: string) => void
    api.getCredential.mockImplementationOnce(
      () =>
        new Promise<string>((done) => {
          resolve = done
        }),
    )
    await wrapper.get('button[aria-label="keys.copyToClipboard"]').trigger('click')
    wrapper.unmount()
    resolve('tr_mcp_late_fixture')
    await flushPromises()
    expect(copyToClipboard).not.toHaveBeenCalled()
  })

  // Concurrent changes on separate rows keep their own locks through write and readback.
  // Completing the first disable must not unlock the other row or permit an editor to capture its old enabled state.
  it('keeps each row locked until its own mutation settles', async () => {
    const a = {
      id: 31,
      name: 'A',
      prefix: 'a',
      permissions: [],
      enabled: true,
      skip_browser_confirmation: false,
      expires_at: null,
      revoked_at: null,
      updated_at: '2026-10-22T09:00:00Z',
    }
    const b = { ...a, id: 32, name: 'B', prefix: 'b' }
    api.listTokens.mockResolvedValue([a, b])
    let finishA!: () => void
    let finishB!: () => void
    api.updateToken
      .mockImplementationOnce(
        () =>
          new Promise<void>((resolve) => {
            finishA = resolve
          }),
      )
      .mockImplementationOnce(
        () =>
          new Promise<void>((resolve) => {
            finishB = resolve
          }),
      )
    const wrapper = page()
    await flushPromises()
    const disable = wrapper.findAll('button').filter((button) => button.text() === 'keys.disable')
    await disable[0]!.trigger('click')
    await disable[1]!.trigger('click')
    let edit = wrapper.findAll('button').filter((button) => button.text() === 'common.edit')
    expect(edit.every((button) => button.attributes('disabled') !== undefined)).toBe(true)
    await edit[0]!.trigger('click')
    expect(wrapper.find('#mcp-token-form').exists()).toBe(false)
    api.listTokens.mockResolvedValue([{ ...a, enabled: false }, b])
    finishA()
    await flushPromises()
    edit = wrapper.findAll('button').filter((button) => button.text() === 'common.edit')
    expect(edit[0]!.attributes('disabled')).toBeUndefined()
    expect(edit[1]!.attributes('disabled')).toBeDefined()
    expect(api.updateToken).toHaveBeenCalledWith(
      31,
      expect.objectContaining({ enabled: false, expected_updated_at: a.updated_at }),
    )
    finishB()
    await flushPromises()
    wrapper.unmount()
  })

  // An editor snapshot can become stale after it opens in another session.
  // Its version is submitted unchanged, and a conflict preserves the administrator's entered name for recovery.
  it('submits the editor version and retains input after a stale-write conflict', async () => {
    const token = {
      id: 35,
      name: 'Versioned',
      prefix: 'v',
      permissions: [],
      enabled: true,
      skip_browser_confirmation: false,
      expires_at: null,
      revoked_at: null,
      updated_at: '2026-10-22T09:00:00.123456Z',
    }
    api.listTokens.mockResolvedValue([token])
    api.updateToken.mockRejectedValue(new Error('Token changed; reload before saving'))
    const wrapper = page()
    await flushPromises()
    await clickText(wrapper, 'common.edit')
    await wrapper.get('input[required]').setValue('My edited name')
    await wrapper.get('#mcp-token-form').trigger('submit')
    await flushPromises()
    expect(api.updateToken).toHaveBeenCalledWith(
      token.id,
      expect.objectContaining({ expected_updated_at: token.updated_at }),
    )
    expect((wrapper.get('input[required]').element as HTMLInputElement).value).toBe(
      'My edited name',
    )
    expect(wrapper.text()).toContain('Token changed; reload before saving')
    wrapper.unmount()
  })

  // Confirmation previews arrive as already formatted strings containing exact numeric identifiers.
  // The browser must display those bytes without rounding them through JavaScript numeric parsing.
  it('displays the server confirmation preview without rounding large identifiers', async () => {
    route.query = { confirmation_id: 'preview' }
    api.getConfirmation.mockResolvedValue({
      id: 'preview',
      state: 'pending',
      operation: catalogue[1],
      preview: '{\n  "user_ids": [9007199254740993]\n}',
    })
    const wrapper = page()
    await flushPromises()
    expect(wrapper.text()).toContain('9007199254740993')
    expect(wrapper.text()).not.toContain('9007199254740992')
    wrapper.unmount()
  })

  // Protected bytes and their suggested filename travel through the same download response.
  // Saving uses that filename after any step-up retry rather than discarding the extension.
  it('saves a protected download with its server filename', async () => {
    route.query = { file_id: 'archive' }
    const blob = new Blob(['archive'], { type: 'application/gzip' })
    api.downloadFile.mockResolvedValue({ blob, filename: 'backup.sql.gz' })
    const wrapper = page()
    await flushPromises()
    await clickText(wrapper, 'admin.mcp.download')
    await flushPromises()
    expect(saveAs).toHaveBeenCalledWith(blob, 'backup.sql.gz')
    wrapper.unmount()
  })
})

// Applications and manual tokens can share a numeric ID. Editing an application
// must use its OAuth endpoint and observed version, while retaining the manual row.
it('edits an application through its independent authorization endpoint', async () => {
  const grant = {
    id: 1,
    user_id: 1,
    source: 'oauth',
    name: 'ChatGPT',
    prefix: 'oauth:1',
    client_id: 'https://chatgpt.com/oauth/client.json',
    client_name: 'ChatGPT',
    permissions: ['groups.list'],
    enabled: true,
    skip_browser_confirmation: false,
    expires_at: null,
    last_used_at: null,
    created_at: '2026-10-23T00:00:00Z',
    updated_at: '2026-10-23T00:00:00Z',
    revoked_at: null,
  }
  api.listTokens.mockResolvedValue([{ ...grant, source: '', name: 'Manual token' }])
  api.listOAuthGrants.mockResolvedValue([grant])
  api.listOperations.mockResolvedValue(catalogue)
  api.getOAuthStatus.mockResolvedValue({
    enabled: true,
    issuer: 'https://gateway.example',
    resource: 'https://gateway.example/mcp',
  })
  api.updateOAuthGrant.mockResolvedValue(grant)
  const wrapper = page()
  await flushPromises()
  await wrapper.get('[data-test="scope-dropdown-trigger"]').trigger('click')
  await wrapper.get('[data-test="scope-option-applications"]').trigger('click')
  await clickText(wrapper, 'common.edit')
  await wrapper.get('input[required]').setValue('My application')
  await wrapper.get('form').trigger('submit')
  await flushPromises()
  expect(api.updateOAuthGrant).toHaveBeenCalledWith(
    1,
    expect.objectContaining({ name: 'My application', expected_updated_at: grant.updated_at }),
  )
  wrapper.unmount()
})

// The authorization URL reuses management and opens a modal over applications.
// Closing removes the request from navigation while retaining unrelated query state.
it('opens OAuth consent over the application list and clears its URL on dismissal', async () => {
  route.name = 'AdminMCPAuthorize'
  route.query = { request: 'review-request', retained: 'yes' }
  api.listTokens.mockResolvedValue([])
  api.listOAuthGrants.mockResolvedValue([])
  api.listOperations.mockResolvedValue(catalogue)
  api.getOAuthStatus.mockResolvedValue({
    enabled: true,
    issuer: 'https://gateway.example',
    resource: 'https://gateway.example/mcp',
  })
  routerReplace.mockResolvedValue(undefined)
  const wrapper = page()
  await flushPromises()
  expect(wrapper.get('[data-test="scope-dropdown-trigger"]').text()).toContain(
    'admin.mcp.oauth.applications',
  )
  expect(wrapper.get('[data-test="authorization-dialog"]').text()).toBe('review-request')
  wrapper.findComponent({ name: 'McpAuthorizeDialog' }).vm.$emit('close')
  await flushPromises()
  expect(routerReplace).toHaveBeenCalledWith({ name: 'AdminMCP', query: { retained: 'yes' } })
  wrapper.unmount()
  route.name = 'AdminMCP'
  route.query = {}
})
