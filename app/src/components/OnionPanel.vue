<script setup lang="ts">
import { computed } from 'vue'
import { onionOf } from '../lab'
import { allEvents, upToSeq } from '../store'

// Lesson 9: one PIN in three wrappers. The inner box stays closed at the gateway. Only the bank opens it, and a changed bit shows there and nowhere earlier.
const onion = computed(() => onionOf(allEvents.value, upToSeq.value))
const layer = (n: number) => onion.value.layers.find(l => l.n === n)!
const word = { absent: 'not sent yet', closed: 'closed', open: 'opened', broken: 'refused: the bank check failed' } as const
</script>

<template>
  <div class="onion" data-testid="onion-panel">
    <div class="outer" :data-testid="'onion-layer-3'" :data-state="layer(3).state" :class="layer(3).state">
      <div class="olabel">{{ layer(3).name }} · {{ word[layer(3).state] }}</div>
      <div class="mid" data-testid="onion-layer-2" :data-state="layer(2).state" :class="layer(2).state">
        <div class="olabel">{{ layer(2).name }} · {{ word[layer(2).state] }}</div>
        <div class="inner" data-testid="onion-layer-1" :data-state="layer(1).state" :class="layer(1).state">
          <div class="olabel">{{ layer(1).name }} · {{ word[layer(1).state] }}</div>
        </div>
      </div>
    </div>
    <div v-if="onion.gatewayNote" class="muted" data-testid="onion-gateway-note">{{ onion.gatewayNote }}</div>
  </div>
</template>
