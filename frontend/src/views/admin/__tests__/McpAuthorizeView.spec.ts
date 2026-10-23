import { mount, flushPromises } from '@vue/test-utils'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import McpAuthorizeView from '../McpAuthorizeView.vue'

// McpAuthorizeView.spec.ts exercises consent defaults, explicit submission, and
// failed-decision recovery. Browser navigation is avoided by failed API fixtures;
// the real component still retains its session-bound request and selected grants.

// API and authenticated-route fixtures represent one administrator reviewing one request.
const api = vi.hoisted(() => ({ getOAuthReview: vi.fn(), decideOAuthRequest: vi.fn() }))
const route = vi.hoisted(() => ({ query: { request: 'request-one' } }))
vi.mock('@/api/admin/mcp', () => api)
vi.mock('vue-router', () => ({ useRoute: () => route }))
vi.mock('@/stores/auth', () => ({
  useAuthStore: () => ({ user: { id: 1, email: 'admin@example.invalid' } }),
}))
vi.mock('vue-i18n', async (importOriginal) => ({
  ...(await importOriginal<typeof import('vue-i18n')>()),
  useI18n: () => ({ t: (key: string) => key, te: () => false, locale: { value: 'en' } }),
}))
vi.mock('@/composables/useStepUp', () => ({
  useStepUp: () => ({ run: (action: () => Promise<unknown>) => action(), onCancel: vi.fn() }),
  isStepUpCancelled: () => false,
}))

// review creates a live request with routine reads, writes, and sensitive reads.
function review() {
  return {
    request: {
      id: 'request-one',
      expires_at: new Date(Date.now() + 600000).toISOString(),
      client: { client_id: 'https://client.example/client.json', client_name: 'Client' },
    },
    redirect_uri: 'https://client.example/callback',
    nonce: 'browser-nonce',
    grant: null,
    operations: [
      {
        operation_id: 'groups.list',
        module: 'groups',
        title: 'List groups',
        read_only: true,
        sensitive: false,
      },
      {
        operation_id: 'groups.create',
        module: 'groups',
        title: 'Create group',
        read_only: false,
        sensitive: false,
      },
      {
        operation_id: 'providers.export',
        module: 'providers',
        title: 'Export credentials',
        read_only: true,
        sensitive: true,
      },
    ],
  }
}

// page mounts consent and replaces only unrelated layout and step-up dialog rendering.
function page() {
  return mount(McpAuthorizeView, {
    global: {
      stubs: {
        AppLayout: { template: '<main><slot /></main>' },
        TotpStepUpDialog: true,
        Icon: true,
        Select: true,
      },
    },
  })
}

describe('MCP application consent', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    api.getOAuthReview.mockResolvedValue(review())
  })

  // A first-time application receives safe reads as its initial draft. No
  // approval is sent until the administrator clicks, and a failed submission preserves it.
  it('defaults to safe reads and retains consent after a failed submission', async () => {
    api.decideOAuthRequest.mockRejectedValue(new Error('Connection interrupted'))
    const wrapper = page()
    await flushPromises()
    expect(api.decideOAuthRequest).not.toHaveBeenCalled()
    await wrapper
      .findAll('button')
      .find((button) => button.text() === 'admin.mcp.oauth.authorize')!
      .trigger('click')
    await flushPromises()
    expect(api.decideOAuthRequest).toHaveBeenCalledWith('request-one', 'browser-nonce', true, [
      'groups.list',
    ])
    expect(wrapper.text()).toContain('Connection interrupted')
    expect(wrapper.text()).toContain('admin@example.invalid')
    wrapper.unmount()
  })

  // Returning applications show the exact prior permissions rather than gaining
  // newly available operations. Denial submits the same nonce with approve=false.
  it('retains existing permissions and submits an explicit denial', async () => {
    api.getOAuthReview.mockResolvedValue({
      ...review(),
      grant: { permissions: ['groups.create'], skip_browser_confirmation: false },
    })
    api.decideOAuthRequest.mockRejectedValue(new Error('Retry available'))
    const wrapper = page()
    await flushPromises()
    await wrapper
      .findAll('button')
      .find((button) => button.text() === 'admin.mcp.oauth.deny')!
      .trigger('click')
    await flushPromises()
    expect(api.decideOAuthRequest).toHaveBeenCalledWith('request-one', 'browser-nonce', false, [
      'groups.create',
    ])
    wrapper.unmount()
  })

  // An expired request still shows its reviewed application, but both decisions
  // are disabled. The administrator must return to the client to start again.
  it('disables decisions after the request has expired', async () => {
    const expired = review()
    expired.request.expires_at = new Date(Date.now() - 1000).toISOString()
    api.getOAuthReview.mockResolvedValue(expired)
    const wrapper = page()
    await flushPromises()
    expect(
      wrapper
        .findAll('button')
        .find((button) => button.text() === 'admin.mcp.oauth.authorize')!
        .attributes('disabled'),
    ).toBeDefined()
    expect(api.decideOAuthRequest).not.toHaveBeenCalled()
    wrapper.unmount()
  })
})
