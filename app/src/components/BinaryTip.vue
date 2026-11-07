<script setup lang="ts">
import { onBeforeUnmount, onMounted, ref } from 'vue'

// Binary hover on hex: any element marked data-hex-byte shows its byte in binary. The tip reads the text on screen, so it never shows more than the cell does.
const tip = ref<{ text: string; x: number; y: number } | null>(null)
const HEX_BYTE = /^[0-9a-f]{2}$/i

function onOver(e: MouseEvent) {
  const cell = (e.target as Element | null)?.closest?.('[data-hex-byte]') as HTMLElement | null
  const text = cell?.textContent?.trim() ?? ''
  if (!cell || !HEX_BYTE.test(text)) { tip.value = null; return }
  const bits = parseInt(text, 16).toString(2).padStart(8, '0')
  const r = cell.getBoundingClientRect()
  // Below the cell, so the tip never covers the label line above a grid. Above it when the window bottom is too close.
  const below = r.bottom + 30 <= innerHeight
  tip.value = { text: `${text.toLowerCase()} = ${bits.slice(0, 4)} ${bits.slice(4)}`, x: Math.max(8, Math.min(r.left, innerWidth - 150)), y: below ? r.bottom + 4 : Math.max(8, r.top - 30) }
}
const hide = () => { tip.value = null }
onMounted(() => { document.addEventListener('mouseover', onOver); window.addEventListener('scroll', hide, true) })
onBeforeUnmount(() => { document.removeEventListener('mouseover', onOver); window.removeEventListener('scroll', hide, true) })
</script>

<template>
  <div v-if="tip" class="binary-tip" data-testid="binary-tip" aria-hidden="true" :style="{ left: `${tip.x}px`, top: `${tip.y}px` }">{{ tip.text }}</div>
</template>
