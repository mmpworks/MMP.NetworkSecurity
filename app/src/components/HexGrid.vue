<script setup lang="ts">
import { computed, ref } from 'vue'
import { ASCII, h2, hexToBytes } from '../layout'

// One hex grid with virtual rows: 16 bytes a row, an offset column, and the readable characters at the end.
// The parent says which bytes are lit (and in which field color), which byte is picked, and what to draw while the bytes scramble.
const props = defineProps<{
  hex: string
  /** testid prefix of each byte: `<idPrefix>-<offset>`. */
  idPrefix: string
  /** Field color class (`k-nonce` style) of a lit byte, or '' when the byte is not lit. */
  litClass: (offset: number) => string
  /** Offsets where a field starts, with the field name, for the `inspector-span-<name>` marks. */
  marks?: ReadonlyMap<number, string>
  selected?: number | null
  /** Text of a byte while it scrambles; null draws the real byte. */
  scramble?: ((offset: number) => string | null) | null
  /** True for a byte the key locked. It draws in the encrypted color, the same amber as a locked arrow. */
  encrypted?: (offset: number) => boolean
}>()
const emit = defineEmits<{ (e: 'pick', offset: number): void }>()

const PER_ROW = 16
const ROW_H = 20
const bytes = computed(() => hexToBytes(props.hex))
const scroller = ref<HTMLElement | null>(null)
const top = ref(0)
const height = ref(240)
const rowCount = computed(() => Math.ceil(bytes.value.length / PER_ROW))
const firstRow = computed(() => Math.max(0, Math.floor(top.value / ROW_H) - 2))
const lastRow = computed(() => Math.min(rowCount.value, Math.ceil((top.value + height.value) / ROW_H) + 2))
const rows = computed(() => Array.from({ length: Math.max(0, lastRow.value - firstRow.value) }, (_, i) => firstRow.value + i))
function onScroll() { top.value = scroller.value?.scrollTop ?? 0; height.value = scroller.value?.clientHeight ?? 240 }
const text = (i: number) => props.scramble?.(i) ?? h2(bytes.value[i])
const offsetsOf = (r: number) => Array.from({ length: Math.min(PER_ROW, bytes.value.length - r * PER_ROW) }, (_, i) => r * PER_ROW + i)
</script>

<template>
  <div ref="scroller" class="hex-scroll" :data-bytes="bytes.length" @scroll="onScroll">
    <div class="hex-space" :style="{ height: rowCount * ROW_H + 'px' }">
      <div v-for="r in rows" :key="r" class="hex-row" :style="{ top: r * ROW_H + 'px' }">
        <span class="hex-off">{{ (r * PER_ROW).toString(16).padStart(4, '0') }}</span>
        <span class="hex-cells">
          <template v-for="o in offsetsOf(r)" :key="o">
            <i v-if="marks?.has(o)" class="span-mark" :data-testid="`inspector-span-${marks.get(o)}`" />
            <span
              class="hb" :class="[litClass(o) ? ['lit', litClass(o)] : '', { sel: selected === o, enc: encrypted?.(o) }]"
              :data-testid="`${idPrefix}-${o}`" data-hex-byte @click="emit('pick', o)"
            >{{ text(o) }}</span>
          </template>
        </span>
        <span class="hex-ascii">{{ bytes.slice(r * PER_ROW, r * PER_ROW + PER_ROW).map(ASCII).join('') }}</span>
      </div>
    </div>
  </div>
</template>
