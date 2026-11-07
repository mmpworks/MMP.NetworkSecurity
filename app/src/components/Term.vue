<script setup lang="ts">
import { computed } from 'vue'
import { GLOSSARY } from '../tour'
import { openGlossary } from '../store'
import { sec } from '../security'

const props = defineProps<{ id: string; label?: string }>()
const entry = computed(() => GLOSSARY.get(props.id))
// The wizard is a dialog over the page. A glossary opened then would land behind it, so a term in the wizard keeps only its hover.
function openEntry() { if (!sec.run) openGlossary(props.id) }
</script>

<template>
  <v-tooltip v-if="entry" location="bottom" open-delay="300" max-width="320" :content-props="{ 'data-testid': 'term-popover' }">
    <template #activator="{ props: act }">
      <span v-bind="act" class="term" tabindex="0" :data-testid="`term-${id}`" role="button" @click="openEntry" @keydown.enter.prevent="openEntry" @keydown.space.prevent="openEntry">{{ label ?? entry.term }}</span>
    </template>
    <div class="term-pop">
      <div data-testid="term-popover-short">{{ entry.short }}</div>
      <div v-if="!sec.run" class="term-more">Click for its glossary entry.</div>
    </div>
  </v-tooltip>
  <span v-else :data-testid="`term-${id}`">{{ label ?? id }}</span>
</template>
