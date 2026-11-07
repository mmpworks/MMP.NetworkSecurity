<script setup lang="ts">
import { computed } from 'vue'
import { specParts } from '../specs'
import SpecCard from './SpecCard.vue'

// Plain text with each spec name turned into a spec card. Used for tour text, glossary text, and any text the engine or Host sends.
const props = defineProps<{ text: string }>()
const parts = computed(() => specParts(props.text ?? ''))
</script>

<template>
  <span><template v-for="(p, i) in parts" :key="i"><SpecCard v-if="p.kind === 'spec'" :id="p.id" :label="p.text" /><template v-else>{{ p.text }}</template></template></span>
</template>
