<template>
  <ScopeSelector
    :model-value="modelValue"
    :options="options"
    :label="t('team.scopeSwitch')"
    data-tour="keys-scope-switch"
    @update:model-value="setScope"
  />
</template>

<script setup lang="ts">
import { computed } from 'vue'
import { useI18n } from 'vue-i18n'
import { useRoute, useRouter } from 'vue-router'
import ScopeSelector from '@/components/common/ScopeSelector.vue'

// ScopeDropdown.vue connects the shared toolbar selector to personal and team
// key ownership. The parent receives selection immediately, while change is
// emitted after route replacement so loading follows the persisted scope. Other
// query parameters remain available to the key page and its existing workflows.

// DataScope selects personal or team ownership for the consuming key list.
export type DataScope = 'personal' | 'team'

// The parent owns the current list scope while this wrapper persists its URL state.
const props = defineProps<{ modelValue: DataScope /* Parent-owned list scope. */ }>()
const emit = defineEmits<{
  (event: 'update:modelValue', value: DataScope): void // Selected ownership scope.
  (event: 'change', value: DataScope): void // URL-persisted scope selection.
}>()
const route = useRoute()
const router = useRouter()
const { t } = useI18n()
const options = computed(() => [
  { value: 'personal', label: t('team.personalKeys'), icon: 'user' as const },
  { value: 'team', label: t('team.teamKeys'), icon: 'users' as const },
])

// setScope publishes a valid ownership change before replacing its route query.
// The completed change event follows navigation so the key page can reload;
// same-value selections and values outside the ownership choices leave state intact.
async function setScope(value: string) {
  if ((value !== 'personal' && value !== 'team') || value === props.modelValue) return
  emit('update:modelValue', value)
  await router.replace({ query: { ...route.query, scope: value } })
  emit('change', value)
}
</script>
