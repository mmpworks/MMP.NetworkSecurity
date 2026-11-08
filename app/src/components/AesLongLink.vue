<script setup lang="ts">
import { onBeforeUnmount, onMounted, ref } from 'vue'
import { CURRENT_STRIP_BLOCK } from '../aesWalkState'

// The link line from the strip's current block down to the walk's state grid (docs/sections-plan.md item 2). It shows only while the
// walk shows a value from the text, which is while state cells are on screen. It reads layout boxes and nothing else, so it follows
// a scroll, a resize, or a new stop. It is a layout read on a short interval, not a motion, so it sits outside the walk's clock.

const box = ref<{ left: number; top: number; height: number } | null>(null)
const FROM = `aes-long-block-${CURRENT_STRIP_BLOCK}`
let timer = 0

function measure() {
  const block = document.querySelector(`[data-testid="${FROM}"]`)
  const strip = document.querySelector('[data-testid="aes-long-strip"]')
  const cell = document.querySelector('[data-testid="aes-walk-cell-0-0"]')
  if (!block || !strip || !cell) { box.value = null; return }
  const b = block.getBoundingClientRect(), s = strip.getBoundingClientRect(), c = cell.getBoundingClientRect()
  const height = c.top - s.bottom
  box.value = height > 4 ? { left: b.left + 12, top: s.bottom, height } : null
}

onMounted(() => { measure(); timer = window.setInterval(measure, 150) })
onBeforeUnmount(() => window.clearInterval(timer))
</script>

<template>
  <div
    v-if="box" class="aw-link" data-testid="aes-long-link" :data-from="FROM" aria-hidden="true"
    :style="{ left: `${box.left}px`, top: `${box.top}px`, height: `${box.height}px` }"
  />
</template>
