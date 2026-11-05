<script setup lang="ts">
import { computed, onMounted, ref, watch } from 'vue'
import { pictureByMessage } from '../lab'
import { selectedEvent, shownEvents, ui } from '../store'
import { parseDetail } from '../lab'

// Lesson 1: the same 64 by 64 picture, clear and locked. The pixels come from the event's `plain` and from its `cipher` field, never from a file.
const pic = computed(() => pictureByMessage(shownEvents.value, selectedEvent.value?.message ?? ''))
const eve = computed(() => ui.view === 'eavesdropper')
const clear = ref<HTMLCanvasElement | null>(null)
const locked = ref<HTMLCanvasElement | null>(null)

function paint(canvas: HTMLCanvasElement | null, bytes: number[] | undefined) {
  const ctx = canvas?.getContext('2d')
  if (!canvas || !ctx || !bytes) return
  const img = ctx.createImageData(64, 64)
  for (let i = 0; i < 4096; i++) { const v = bytes[i] ?? 0; img.data[i * 4] = v; img.data[i * 4 + 1] = v; img.data[i * 4 + 2] = v; img.data[i * 4 + 3] = 255 }
  ctx.putImageData(img, 0, 0)
}
function draw() { paint(clear.value, pic.value?.clear); paint(locked.value, pic.value?.locked) }
onMounted(draw)
watch([pic, eve], () => requestAnimationFrame(draw), { flush: 'post' })

// The measure event of the same message says how many cipher blocks repeat.
const repeats = computed(() => {
  const m = shownEvents.value.find(e => e.type === 'measure.result' && e.message === pic.value?.mode)
  const d = m ? parseDetail(m.detail) : null
  return d ? { repeats: Number(d.repeats ?? 0), blocks: Number(d.blocks ?? 0) } : null
})
</script>

<template>
  <div class="picture" data-testid="picture-lab">
    <div v-if="!pic" class="empty-note">Pick a picture message in the diagram to see it clear and locked.</div>
    <template v-else>
      <div class="pic-grid">
        <figure v-if="!eve">
          <canvas ref="clear" width="64" height="64" class="pic-canvas" data-testid="picture-clear" aria-label="The clear picture" />
          <figcaption>Clear picture</figcaption>
        </figure>
        <figure>
          <canvas ref="locked" width="64" height="64" class="pic-canvas" data-testid="picture-locked" :aria-label="`The picture locked with ${pic.mode}`" />
          <figcaption>Locked with {{ pic.mode.replace('Picture', '') }}{{ eve ? ' (what the eavesdropper sees)' : '' }}</figcaption>
        </figure>
      </div>
      <div v-if="repeats" class="muted" data-testid="picture-repeats">{{ repeats.repeats }} of {{ repeats.blocks }} locked blocks repeat an earlier block</div>
    </template>
  </div>
</template>
