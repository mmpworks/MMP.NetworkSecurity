<script setup lang="ts">
import { sec, setShowKeys } from '../security'

// A native checkbox with the switch role: the test id sits on the input, so `checked` and `aria-checked` both read true or false.
// The Host holds the value. This control sends the change and shows what the Host answers.
defineProps<{ testid: string }>()
const TIP = 'On: this course shows your keys on screen and in saved files. Off: it shows a short fingerprint instead, a code that stands for the key.'
</script>

<template>
  <v-tooltip location="bottom" max-width="340">
    <template #activator="{ props: p }">
      <label v-bind="p" class="keys-switch">
        <input type="checkbox" role="switch" :checked="sec.showKeys" :aria-checked="sec.showKeys" :data-testid="testid" @change="e => setShowKeys((e.target as HTMLInputElement).checked)" />
        <span class="ks-track" aria-hidden="true"><span class="ks-thumb" /></span>
        <span class="ks-label">Show keys</span>
      </label>
    </template>
    <span>{{ TIP }}</span>
  </v-tooltip>
</template>
