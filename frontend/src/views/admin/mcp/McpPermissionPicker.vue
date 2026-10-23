<template>
  <div class="space-y-3">
    <div class="flex flex-wrap items-center justify-between gap-2">
      <h3 class="input-label mb-0">{{ t('admin.mcp.permissions') }}</h3>
      <span class="text-xs text-gray-500 dark:text-dark-400" aria-live="polite">{{
        t('admin.mcp.selected', { count: selected.size })
      }}</span>
    </div>
    <p class="input-hint">{{ t('admin.mcp.permissionHint') }}</p>
    <div>
      <label class="input-label">{{ t('admin.mcp.preset') }}</label>
      <Select
        :model-value="selectedPreset"
        :options="presetOptions"
        :aria-label="t('admin.mcp.preset')"
        @update:model-value="applyPreset"
      />
      <p class="input-hint">{{ t(`admin.mcp.presetHints.${selectedPreset}`) }}</p>
    </div>
    <p v-if="unknownPermissions" class="text-sm text-amber-700 dark:text-amber-400">{{
      t('admin.mcp.unknownPermissions')
    }}</p>
    <button
      type="button"
      class="input-label mb-0 flex items-center gap-2"
      :aria-expanded="permissionsExpanded"
      @click="permissionsExpanded = !permissionsExpanded"
    >
      <Icon
        name="chevronDown"
        size="sm"
        class="transition-transform duration-fast"
        :class="permissionsExpanded ? 'rotate-180' : ''"
      />
      {{ t('admin.mcp.adjustPermissions') }}
    </button>
    <div v-if="permissionsExpanded" class="space-y-3">
      <div class="grid gap-2 sm:grid-cols-2">
        <input
          v-model="permissionSearch"
          class="input"
          :placeholder="t('admin.mcp.permissionSearch')"
          :aria-label="t('admin.mcp.permissionSearch')"
        />
        <Select
          v-model="moduleFilter"
          :options="moduleOptions"
          :aria-label="t('admin.mcp.allModules')"
        />
      </div>
      <label class="flex items-center gap-2 text-sm"
        ><input v-model="selectedOnly" type="checkbox" class="checkbox" />{{
          t('admin.mcp.selectedOnly')
        }}</label
      >
      <div
        class="max-h-80 overflow-y-auto rounded-surface border border-gray-200 dark:border-dark-700"
      >
        <section
          v-for="group in permissionGroups"
          :key="group.name"
          class="border-b border-gray-100 last:border-0 dark:border-dark-800"
        >
          <div
            class="sticky top-0 z-10 flex items-center justify-between gap-3 bg-gray-50 px-4 py-2 dark:bg-dark-800"
          >
            <h4 class="input-label mb-0">{{ moduleLabel(group.name) }}</h4>
            <button
              class="text-xs text-primary-800 hover:text-primary-900 dark:text-primary-400 dark:hover:text-primary-300"
              type="button"
              @click="selectGroup(group.items)"
              >{{
                t(
                  group.items.every((op) => selected.has(op.operation_id))
                    ? 'admin.mcp.clearVisible'
                    : 'admin.mcp.selectVisible',
                )
              }}</button
            >
          </div>
          <div v-for="operation in group.items" :key="operation.operation_id">
            <label
              class="flex cursor-pointer items-start gap-3 px-4 py-3 transition-colors duration-fast hover:bg-gray-50 dark:hover:bg-dark-800/50"
            >
              <input
                :checked="selected.has(operation.operation_id)"
                class="checkbox mt-1"
                type="checkbox"
                @change="
                  selectOperation(
                    operation.operation_id,
                    ($event.target as HTMLInputElement).checked,
                  )
                "
              />
              <span class="min-w-0 flex-1">
                <span class="flex flex-wrap items-center justify-between gap-2 text-sm"
                  ><span>{{ operationLabel(operation) }}</span
                  ><span
                    v-if="operation.sensitive"
                    class="text-xs text-amber-700 dark:text-amber-400"
                    >{{
                      t(
                        skipBrowserConfirmation
                          ? 'admin.mcp.sensitiveOperation'
                          : 'admin.mcp.sensitive',
                      )
                    }}</span
                  ><span v-else class="text-xs text-gray-500 dark:text-gray-400">{{
                    t(operation.read_only ? 'admin.mcp.read' : 'admin.mcp.write')
                  }}</span></span
                >
                <span
                  class="mt-1 block break-all font-mono text-xs text-gray-500 dark:text-gray-400"
                  >{{ operation.operation_id }}</span
                >
              </span>
            </label>
            <details v-if="operation.sensitive" class="px-4 pb-3 text-sm">
              <summary class="cursor-pointer text-gray-600 dark:text-gray-400">{{
                t('admin.mcp.operationDetails')
              }}</summary>
              <p class="mt-2 whitespace-pre-wrap text-gray-600 dark:text-gray-400">{{
                operation.description
              }}</p>
            </details>
          </div>
        </section>
        <p v-if="!permissionGroups.length" class="p-6 text-center text-sm text-gray-500">{{
          t('admin.mcp.noResults')
        }}</p>
      </div>
      <p v-if="!skipBrowserConfirmation" class="input-hint">{{ t('admin.mcp.sensitiveHint') }}</p>
    </div>
  </div>
</template>
<script setup lang="ts">
import { computed, ref, watch } from 'vue'
import { useI18n } from 'vue-i18n'
import Select from '@/components/common/Select.vue'
import Icon from '@/components/icons/Icon.vue'
import type { MCPOperation } from '@/api/admin/mcp'
import { permissionPresets } from './permissions'

// McpPermissionPicker.vue selects exact management operations for manual tokens
// and OAuth applications. Presets expand the current catalogue into a draft;
// filtering changes visible choices while retaining selections outside the filter.
// The owning page decides when the draft is persisted or approved.

// The picker receives the current catalogue and confirmation policy from its owner.
const props = withDefaults(
  defineProps<{
    operations: MCPOperation[] // Current mounted operation catalogue.
    skipBrowserConfirmation?: boolean // Current sensitive confirmation preference.
    unknownPermissions?: boolean // Saved operations missing from the catalogue.
  }>(),
  { skipBrowserConfirmation: false, unknownPermissions: false },
)
const selected = defineModel<Set<string>>({ required: true })
const { t, te, locale } = useI18n()
const operations = computed(() => props.operations)
// Filter and disclosure state belong to this mounted permission draft only.
const selectedPreset = ref('custom')
const permissionsExpanded = ref(true)
const permissionSearch = ref('')
const moduleFilter = ref('')
const selectedOnly = ref(false)
// presets expand the mounted catalogue only when the administrator chooses a preset.
const presets = computed(() => permissionPresets(operations.value))
const presetOptions = computed(() => [
  { value: 'custom', label: t('admin.mcp.presets.custom') },
  ...presets.value.map((preset) => ({
    value: preset.id,
    label: `${t(`admin.mcp.presets.${preset.id}`)} · ${t('admin.mcp.permissionCount', { count: preset.permissions.length })}`,
  })),
])

// applyPreset replaces the complete permission draft with one current preset.
// Search and module filters do not narrow this selection. Choosing custom keeps
// the current grants available for manual adjustment instead of adding future permissions.
function applyPreset(value: string | number | boolean | null) {
  const id = String(value ?? 'custom')
  selectedPreset.value = id
  const preset = presets.value.find((item) => item.id === id)
  if (preset) selected.value = new Set(preset.permissions)
  permissionsExpanded.value = !preset
}
const moduleOptions = computed(() => [
  { value: '', label: t('admin.mcp.allModules') },
  ...[...new Set(operations.value.map((op) => op.module))]
    .sort()
    .map((module) => ({ value: module, label: moduleLabel(module) })),
])

// permissionGroups groups the visible matches without changing hidden selected grants.
const permissionGroups = computed(() => {
  const groups = new Map<string, MCPOperation[]>()
  for (const operation of operations.value) {
    if (moduleFilter.value && operation.module !== moduleFilter.value) continue
    if (selectedOnly.value && !selected.value.has(operation.operation_id)) continue
    if (
      !`${operation.title} ${operation.title_zh ?? ''} ${operation.operation_id}`
        .toLowerCase()
        .includes(permissionSearch.value.toLowerCase())
    )
      continue
    const items = groups.get(operation.module) ?? []
    items.push(operation)
    groups.set(operation.module, items)
  }
  return [...groups].map(([name, items]) => ({ name, items }))
})

// moduleLabel resolves catalogue grouping names through presentation-only translations.
function moduleLabel(module: string): string {
  const key = `admin.mcp.modules.${module}`
  return te(key) ? t(key) : module
}

// selectOperation replaces the selected set so permission summaries update together.
function selectOperation(id: string, checked: boolean) {
  selectedPreset.value = 'custom'
  const next = new Set(selected.value)
  if (checked) next.add(id)
  else next.delete(id)
  selected.value = next
}

// selectGroup selects or clears exactly the currently displayed matching operations.
function selectGroup(items: MCPOperation[]) {
  selectedPreset.value = 'custom'
  const checked = !items.every((op) => selected.value.has(op.operation_id))
  const next = new Set(selected.value)
  for (const operation of items) {
    if (checked) next.add(operation.operation_id)
    else next.delete(operation.operation_id)
  }
  selected.value = next
}

// operationLabel displays a translated action when the catalogue supplies one.
function operationLabel(operation: MCPOperation): string {
  return locale.value.startsWith('zh') && operation.title_zh ? operation.title_zh : operation.title
}

// Initial disclosure reflects the supplied draft, including a consent dialog's safe-read default.
watch(
  () => props.operations,
  () => {
    selectedPreset.value =
      presets.value.find(
        (preset) =>
          preset.permissions.length === selected.value.size &&
          preset.permissions.every((id) => selected.value.has(id)),
      )?.id ?? 'custom'
    permissionsExpanded.value = selectedPreset.value === 'custom'
  },
  { immediate: true },
)
</script>
