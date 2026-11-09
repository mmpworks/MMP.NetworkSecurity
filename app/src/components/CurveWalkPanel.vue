<script setup lang="ts">
import { computed } from 'vue'
import { useWalk } from '../walkFetch'
import type { ToyCurve } from '../curveWalk'
import RealCurveCard from './RealCurveCard.vue'
import ToyCurveCard from './ToyCurveCard.vue'
import CurveScalarCard from './CurveScalarCard.vue'
import CurveSignCard from './CurveSignCard.vue'

// The elliptic-curve walk (slice P8a; docs/sections-plan.md R7). It teaches in the order of video 4Tfmwxr0I34: the chord rule on the real
// curve, the same curve over GF(17) with picks, k·G hops, double-and-add and the ladder, then ECDH and ECDSA nonce reuse. The toy curve is
// one engine reply (GET /api/walk/toy-curve); the cards below read it and compute nothing (R5).
const toy = useWalk<ToyCurve>('/api/walk/toy-curve')
const t = computed(() => toy.data)
</script>

<template>
  <div class="cw" data-testid="curve-walk-panel">
    <header class="cw-head">
      <h2>Elliptic curves: adding points</h2>
      <p class="muted">X25519, Ed25519 and ECDSA all add points on a curve. This walk shows how, first on a curve you can see, then on a tiny curve you can count.</p>
    </header>
    <RealCurveCard />
    <p v-if="toy.error" class="walk-error">{{ toy.error }} <button type="button" class="retry" @click="toy.load()">Try again</button></p>
    <p v-else-if="!t" class="muted">Loading the toy curve from the engine.</p>
    <template v-else>
      <ToyCurveCard :toy="t" />
      <CurveScalarCard :toy="t" />
      <CurveSignCard :toy="t" />
    </template>
  </div>
</template>
