<script setup lang="ts">
import { computed } from 'vue'
import { hostKeys } from '../lab'
import { allEvents, selectedEvent, upToSeq } from '../store'

// Lesson 8: the host key the client saw, in OpenSSH fingerprint form, and what the known_hosts check said about it.
const upTo = upToSeq
const keys = computed(() => hostKeys(allEvents.value, upTo.value))
const words = { pass: 'matches the key this client remembers', fail: 'is not the key this client remembers', pending: 'not checked yet' } as const
</script>

<template>
  <div class="hostkey" data-testid="hostkey-panel">
    <div v-if="!keys.length" class="empty-note">The host key appears here when the server shows it.</div>
    <div v-for="(k, i) in keys" :key="i" data-testid="hostkey-card">
      <div class="side-title">HOST KEY · {{ k.protocol === 'ssh-legacy' ? 'legacy round' : 'modern round' }}</div>
      <code v-if="k.fingerprint" data-testid="hostkey-fingerprint">{{ k.fingerprint }}</code>
      <div v-else class="muted" data-testid="hostkey-refused">The server offered a key this client did not accept, so no fingerprint was shown.</div>
      <div class="hk-status" :class="k.status" :data-status="k.status" data-testid="hostkey-status">{{ k.status === 'fail' ? '✕' : k.status === 'pass' ? '✓' : '…' }} This key {{ words[k.status] }}.</div>
    </div>
  </div>
</template>
