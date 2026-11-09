<script setup lang="ts">
import { useWalk } from '../walkFetch'

// The TLS 1.3 key schedule walk (docs/sections-plan.md section 4, slice P4): every Extract and Derive-Secret of RFC 8446 section 7.1,
// with its label and transcript hash, on RFC 8448 section 3's public inputs. The engine runs each step and checks the rungs against the
// real key schedule (TLS13_WALK_DIVERGED). This screen shows the reply and computes nothing (R5).
interface Step { name: string; kind: string; label: string | null; messages: string[] | null; salt: string | null; ikm: string | null; secret: string | null; context: string | null; output: string }
interface Reply { source: string; suite: string; keySource: string; steps: Step[] }

const walk = useWalk<Reply>('/api/walk/tls13/schedule')

/**
 * The step as a formula. The label is the engine's own string. Derive-Secret shows its expanded form from RFC 8446 section 7.1,
 * HKDF-Expand-Label(Secret, Label, Transcript-Hash(Messages), Hash.length), because the panel shows the transcript hash as an input
 * (Richard and Jared on #324). The length is the output's own size in bytes.
 */
function formula(s: Step): string {
  const label = s.label ? `"${s.label}"` : ''
  const length = s.output.length / 2
  switch (s.kind) {
    case 'TranscriptHash': return `Transcript-Hash(${(s.messages ?? []).join(', ')})`
    case 'KeyAgreement': return 'X25519(client private key, server public key)'
    case 'Extract': return 'HKDF-Extract(salt, input key)'
    case 'DeriveSecret': return `Derive-Secret: HKDF-Expand-Label(secret, ${label}, transcript hash, ${length})`
    case 'ExpandLabel': return `HKDF-Expand-Label(secret, ${label}, "", ${length})`
    case 'VerifyData': return 'HMAC(finished key, transcript hash)'
    default: return s.kind
  }
}

/** The inputs a step's kind uses, with the names RFC 8446 gives them. A field the kind does not use is null in the reply. */
function inputs(s: Step): { name: string; hex: string }[] {
  const names: Record<string, [keyof Step, string][]> = {
    KeyAgreement: [['secret', 'client private key'], ['context', 'server public key']],
    Extract: [['salt', 'salt'], ['ikm', 'input key']],
    DeriveSecret: [['secret', 'secret'], ['context', 'transcript hash']],
    ExpandLabel: [['secret', 'secret']],
    VerifyData: [['secret', 'finished key'], ['context', 'transcript hash']],
  }
  return (names[s.kind] ?? []).map(([k, name]) => ({ name, hex: String(s[k] ?? '') })).filter(i => i.hex)
}
</script>

<template>
  <div class="schedule" data-testid="tls13-schedule-panel">
    <header class="schedule-head">
      <h2>The TLS 1.3 key schedule</h2>
      <p class="muted">Each row is one step of RFC 8446 section 7.1, run by the engine. A row's output feeds the rows after it.</p>
      <p class="muted" data-testid="tls13-label-note">Each label shows without its "tls13 " prefix, because HKDF-Expand-Label adds that prefix itself.</p>
      <p class="key-source" data-testid="tls13-key-source" :data-key-source="walk.data?.keySource ?? ''">
        Key: RFC 8448's published test key (section 3). Every input is public, so this walk stays open with Show keys off.
      </p>
    </header>
    <p v-if="walk.error" class="walk-error" data-testid="tls13-schedule-error">{{ walk.error }} <button type="button" class="retry" @click="walk.load()">Try again</button></p>
    <p v-else-if="!walk.data" class="muted">Loading the key schedule from the engine.</p>
    <ol v-else class="steps">
      <li v-for="(s, i) in walk.data.steps" :key="s.name" class="step" :data-testid="`tls13-step-${i}`" :data-name="s.name" :data-kind="s.kind">
        <div class="step-head"><span class="step-num">{{ i + 1 }}</span><code class="step-name">{{ s.name }}</code></div>
        <div class="step-label" :data-testid="`tls13-step-label-${i}`">{{ formula(s) }}</div>
        <div v-for="x in inputs(s)" :key="x.name" class="step-in"><span class="io-name muted">{{ x.name }}</span><code class="hex">{{ x.hex }}</code></div>
        <div class="step-out"><span class="io-name">output</span><code class="hex out" :data-testid="`tls13-step-output-${i}`">{{ s.output }}</code></div>
      </li>
    </ol>
  </div>
</template>
