<script setup lang="ts">
import { computed } from 'vue'
import { GLOSSARY } from '../tour'
import { openGlossary } from '../store'

const props = defineProps<{ id: string; label?: string }>()
const entry = computed(() => GLOSSARY.get(props.id))
</script>

<template>
  <v-tooltip v-if="entry" location="bottom" open-delay="300" max-width="320" :content-props="{ 'data-testid': 'term-popover' }">
    <template #activator="{ props: act }">
      <span v-bind="act" class="term" tabindex="0" :data-testid="`term-${id}`" role="button" @click="openGlossary(id)" @keydown.enter.prevent="openGlossary(id)">{{ label ?? entry.term }}</span>
    </template>
    <div class="term-pop">
      <div data-testid="term-popover-short">{{ entry.short }}</div>
      <div class="term-more">Click for its glossary entry.</div>
    </div>
  </v-tooltip>
  <span v-else :data-testid="`term-${id}`">{{ label ?? id }}</span>
</template>
