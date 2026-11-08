<script setup lang="ts">
import { onBeforeUnmount, onMounted, ref } from 'vue'
import { CURRENT_STRIP_BLOCK } from '../aesWalkState'

// The link line from the strip's current block down to the walk's state grid (docs/sections-plan.md item 2). It shows only while the
// walk shows a value from the text, which is while state cells are on screen. It reads layout boxes and nothing else, so it follows
// a scroll, a resize, or a new stop. It is a layout read on a short interval, not a motion, so it sits outside the walk's clock.

// An L: down the left gutter from the current block, then across into the grid's first cell, so it crosses no words.
const box = ref<{ left: number; top: number; height: number; width: number } | null>(null)
const FROM = `aes-long-block-${CURRENT_STRIP_BLOCK}`
let timer = 0

function measure() {
  const block = document.querySelector(`[data-testid="${FROM}"]`)
  const strip = document.querySelector('[data-testid="aes-long-strip"]')
  const cell = document.querySelector('[data-testid="aes-walk-cell-0-0"]')
  if (!block || !strip || !cell) { box.value = null; return }
  const b = block.getBoundingClientRect(), s = strip.getBoundingClientRect(), c = cell.getBoundingClientRect()
  const left = b.left + 4, height = c.top + c.height / 2 - s.bottom
  box.value = height > 4 && c.left > left ? { left, top: s.bottom, height, width: c.left - left } : null
}

onMounted(() => { measure(); timer = window.setInterval(measure, 150) })
onBeforeUnmount(() => window.clearInterval(timer))
</script>

<template>
  <div
    v-if="box" class="aw-link" data-testid="aes-long-link" :data-from="FROM" aria-hidden="true"
    :style="{ left: `${box.left}px`, top: `${box.top}px`, height: `${box.height}px`, width: `${box.width}px` }"
  />
</template>
