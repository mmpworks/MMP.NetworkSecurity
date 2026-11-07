<script setup lang="ts">
import { onBeforeUnmount, onMounted, ref } from 'vue'
import { setTheme, ui } from '../store'

// Speed, theme and keyboard keys live here, so the top bar keeps one row. The menu stays mounted while closed, so a saved value can still be read from it.
const open = ref(false)
const wrap = ref<HTMLElement | null>(null)
const button = ref<HTMLButtonElement | null>(null)

function onDocumentClick(e: MouseEvent) {
  if (open.value && !wrap.value?.contains(e.target as Node)) open.value = false
}
function closeWithKey() {
  if (!open.value) return
  open.value = false
  button.value?.focus()
}
function showKeyboardKeys() {
  open.value = false
  ui.shortcuts = true
}
onMounted(() => document.addEventListener('click', onDocumentClick))
onBeforeUnmount(() => document.removeEventListener('click', onDocumentClick))
</script>

<template>
  <span ref="wrap" class="menuwrap" @keydown.esc="closeWithKey">
    <button ref="button" type="button" class="tool" data-testid="settings-button" :aria-expanded="open" @click="open = !open"><v-icon size="15">mdi-cog-outline</v-icon>Settings</button>
    <div v-show="open" class="settings-menu" role="group" aria-label="Settings" data-testid="settings-menu">
      <label>Speed<select v-model.number="ui.speed" class="ns-select" data-testid="speed-select" aria-label="Animation speed"><option :value="0.5">0.5x</option><option :value="1">1x</option><option :value="2">2x</option></select></label>
      <label>Theme<select :value="ui.theme" class="ns-select" data-testid="theme-select" aria-label="Theme" @change="e => setTheme((e.target as HTMLSelectElement).value as any)"><option value="system">System</option><option value="light">Light</option><option value="dark">Dark</option></select></label>
      <div class="settings-row">Keyboard keys<button type="button" class="tool" aria-label="Keyboard shortcuts" data-testid="shortcuts-button" @click="showKeyboardKeys">Show</button></div>
    </div>
  </span>
</template>
