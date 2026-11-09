<script setup lang="ts">
import { ref } from 'vue'
import { useWalk } from '../walkFetch'

// The TLS 1.1 RSA key-transport walk (docs/sections-plan.md R8, slice P4b): the encrypted pre-master, its decryption with the server's key,
// the master secret from the pre-master and both randoms, and the key block split into its 4 keys. One fixed teaching run on the course's
// built-in training key. This screen shows the reply and computes nothing (R5).
interface Reply {
  keySource: string; serverKeyId: string; suite: string; serverPublicKey: string; clientRandom: string; serverRandom: string
  encryptedPremaster: string; premaster: string; premasterVersion: number
  masterSecret: { label: string; seed: string; value: string }
  keyBlock: { label: string; seed: string; value: string; clientMacKey: string; serverMacKey: string; clientKey: string; serverKey: string }
  keyLogLine: string
}

const walk = useWalk<Reply>('/api/walk/tls11/schedule')
// The server's public key and the encrypted pre-master are 256 bytes each. They show their first 32 bytes until the learner opens them.
const open = ref(new Set<string>())
const toggle = (k: string) => { const s = new Set(open.value); if (s.has(k)) s.delete(k); else s.add(k); open.value = s }
const SHORT = 64
/** The engine sends the version as a number (770). The screen writes it as the 2 bytes the pre-master starts with (03 02). */
const versionHex = (v: number | string) => { const n = Number(v); return Number.isFinite(n) ? `${(n >> 8).toString(16).padStart(2, '0')} ${(n & 255).toString(16).padStart(2, '0')}` : String(v) }
const shown = (k: string, hex: string) => (open.value.has(k) || hex.length <= SHORT ? hex : `${hex.slice(0, SHORT)}…`)
</script>

<template>
  <div class="schedule" data-testid="tls11-schedule-panel">
    <header class="schedule-head">
      <h2>TLS 1.1 with RSA: from the pre-master to the keys</h2>
      <p class="muted">The client makes the secret and sends it locked with the server's RSA key. Whoever holds that key later can open a recording.</p>
      <p class="key-source" data-testid="tls11-key-source" :data-key-source="walk.data?.keySource ?? ''">
        Key: the course's built-in training key. It is public in the source, so this walk stays open with Show keys off.
      </p>
    </header>
    <p v-if="walk.error" class="walk-error" data-testid="tls11-schedule-error">{{ walk.error }} <button type="button" class="retry" @click="walk.load()">Try again</button></p>
    <p v-else-if="!walk.data" class="muted">Loading the TLS 1.1 run from the engine.</p>
    <ol v-else class="steps">
      <li class="step">
        <div class="step-head"><span class="step-num">1</span><b>The randoms and the server's key</b></div>
        <div class="step-label muted">{{ walk.data.suite }}, server key {{ walk.data.serverKeyId }}</div>
        <div class="step-in"><span class="io-name muted">client random</span><code class="hex">{{ walk.data.clientRandom }}</code></div>
        <div class="step-in"><span class="io-name muted">server random</span><code class="hex">{{ walk.data.serverRandom }}</code></div>
        <div class="step-in">
          <span class="io-name muted">server public key</span><code class="hex">{{ shown('pub', walk.data.serverPublicKey) }}</code>
          <button v-if="walk.data.serverPublicKey.length > SHORT" type="button" class="retry" @click="toggle('pub')">{{ open.has('pub') ? 'Show less' : 'Show all' }}</button>
        </div>
      </li>
      <li class="step">
        <div class="step-head"><span class="step-num">2</span><b>The pre-master secret</b></div>
        <div class="step-label">The client picks it and encrypts it with the server's public key. The server decrypts it with its private key.</div>
        <div class="step-in">
          <span class="io-name muted">encrypted pre-master</span><code class="hex">{{ shown('enc', walk.data.encryptedPremaster) }}</code>
          <button v-if="walk.data.encryptedPremaster.length > SHORT" type="button" class="retry" @click="toggle('enc')">{{ open.has('enc') ? 'Show less' : 'Show all' }}</button>
        </div>
        <div class="step-out"><span class="io-name">pre-master</span><code class="hex out" data-testid="tls11-premaster">{{ walk.data.premaster }}</code></div>
        <div class="step-label muted" data-testid="tls11-premaster-version">Its first 2 bytes are the version the client offered: {{ versionHex(walk.data.premasterVersion) }}.</div>
      </li>
      <li class="step">
        <div class="step-head"><span class="step-num">3</span><b>The master secret</b></div>
        <div class="step-label">PRF(pre-master, "{{ walk.data.masterSecret.label }}", {{ walk.data.masterSecret.seed }})</div>
        <div class="step-out"><span class="io-name">master secret</span><code class="hex out" data-testid="tls11-master">{{ walk.data.masterSecret.value }}</code></div>
      </li>
      <li class="step">
        <div class="step-head"><span class="step-num">4</span><b>The key block, split into 4 keys</b></div>
        <div class="step-label">PRF(master secret, "{{ walk.data.keyBlock.label }}", {{ walk.data.keyBlock.seed }})</div>
        <div class="step-in"><span class="io-name muted">key block</span><code class="hex">{{ walk.data.keyBlock.value }}</code></div>
        <div class="step-out"><span class="io-name">client MAC key</span><code class="hex out" data-testid="tls11-client-mac-key">{{ walk.data.keyBlock.clientMacKey }}</code></div>
        <div class="step-out"><span class="io-name">server MAC key</span><code class="hex out" data-testid="tls11-server-mac-key">{{ walk.data.keyBlock.serverMacKey }}</code></div>
        <div class="step-out"><span class="io-name">client key</span><code class="hex out" data-testid="tls11-client-key">{{ walk.data.keyBlock.clientKey }}</code></div>
        <div class="step-out"><span class="io-name">server key</span><code class="hex out" data-testid="tls11-server-key">{{ walk.data.keyBlock.serverKey }}</code></div>
      </li>
      <li class="step">
        <div class="step-head"><span class="step-num">5</span><b>The key log line</b></div>
        <div class="step-label">Wireshark reads this line to open the recorded session. It needs only the client random and the master secret.</div>
        <code class="hex keylog" data-testid="tls11-key-log">{{ walk.data.keyLogLine }}</code>
      </li>
    </ol>
  </div>
</template>
