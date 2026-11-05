<script setup lang="ts">
import { computed } from 'vue'
import Term from './Term.vue'

// Copy text marks a glossary term as {{term:id}}. This renders the marks as Term popovers and the rest as text.
const props = defineProps<{ text: string }>()
const MARK = /^\{\{term:(?<id>[a-z0-9-]+)\}\}$/
const parts = computed(() => props.text.split(/(?<mark>\{\{term:[a-z0-9-]+\}\})/).filter(Boolean).map(p => ({ text: p, term: MARK.exec(p)?.groups?.id ?? '' })))
</script>

<template>
  <span><template v-for="(p, i) in parts" :key="i"><Term v-if="p.term" :id="p.term" /><template v-else>{{ p.text }}</template></template></span>
</template>
