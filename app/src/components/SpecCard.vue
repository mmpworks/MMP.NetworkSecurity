<script setup lang="ts">
import { computed, ref } from 'vue'
import { SPECS } from '../specs'

// A named spec on screen: hover, focus or tap opens a card with a short synopsis and one link (walkthrough-design.md section 2.2h).
// The card stays open while the pointer is on it, so the link can be clicked. Esc, leaving it, or a tap elsewhere closes it.
// The link is a plain new-window link. In Electron the link rule (electron/link-hosts.cjs) opens a listed host in the learner's own browser.
const props = defineProps<{ id: string; label?: string }>()
const spec = computed(() => SPECS.get(props.id))
// Focus opens the card only on keyboard focus (Vuetify checks :focus-visible). Enter and Space open it too, as on any role="button".
const open = ref(false)
const host = computed(() => (spec.value ? new URL(spec.value.url).hostname : ''))
</script>

<template>
  <v-menu v-if="spec" v-model="open" open-on-hover open-on-focus open-on-click :close-on-content-click="false" location="bottom" open-delay="200" close-delay="250" max-width="360">
    <template #activator="{ props: act }">
      <span v-bind="act" class="spec" tabindex="0" role="button" :data-testid="`spec-${id}`" @keydown.enter.prevent="open = !open" @keydown.space.prevent="open = !open">{{ label ?? spec.name }}</span>
    </template>
    <div class="spec-card" :data-testid="`spec-card-${id}`">
      <div class="spec-name">{{ spec.name }}</div>
      <div data-testid="spec-synopsis">{{ spec.synopsis }}</div>
      <a class="spec-link" :href="spec.url" target="_blank" rel="noopener noreferrer" data-testid="spec-link">{{ spec.title }}</a>
      <div class="muted spec-host">Opens on {{ host }}, in your web browser.</div>
    </div>
  </v-menu>
  <span v-else>{{ label ?? id }}</span>
</template>

<style scoped>
.spec { text-decoration: underline dotted; text-underline-offset: 3px; cursor: help; }
.spec:focus-visible { outline: 2px solid rgb(var(--v-theme-primary)); outline-offset: 2px; }
.spec-card { background: rgb(var(--v-theme-surface)); color: rgb(var(--v-theme-on-surface)); border: 1px solid rgba(var(--v-border-color), var(--v-border-opacity)); border-radius: 6px; padding: 10px 12px; display: grid; gap: 6px; }
.spec-name { font-weight: 600; }
.spec-link { color: rgb(var(--v-theme-primary)); }
.spec-host { font-size: 0.85em; }
</style>
