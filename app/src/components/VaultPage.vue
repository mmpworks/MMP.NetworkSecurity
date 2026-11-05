<script setup lang="ts">
import { computed, ref } from 'vue'
import { sec, words } from '../security'
import {
  checkChain, closeVault, deriveLabel, revealCheck, showAudit, showScreen, signText, tryExport, vault, vaultWords, type VaultScreen,
} from '../vault'

const message = ref('hello vault')
const label = ref('pump-reader-4')
const SCREENS: { id: VaultScreen; title: string }[] = [
  { id: 'sign-derive', title: 'Sign and derive' }, { id: 'refuse', title: 'Refuse' }, { id: 'audit', title: 'Audit' },
]
const testKeysLine = computed(() => (sec.showKeys ? words('wizard.common.test-keys-only') : words('wizard.common.test-keys-hidden')))
const refuseKey = computed(() => vault.keys.find(k => k.hidden))
const sameLabel = computed(() => {
  const d = vault.derived
  const last = d[d.length - 1]
  const prior = last ? d.slice(0, -1).find(x => x.label === last.label) : undefined
  if (!last || d.length < 2) return ''
  if (prior) return prior.fingerprint === last.fingerprint ? words('wizard.vault.derive.same') : ''
  return d.slice(0, -1).some(x => x.fingerprint === last.fingerprint) ? '' : words('wizard.vault.derive.different')
})
const short = (h: string) => (h.length > 16 ? `${h.slice(0, 8)}...${h.slice(-8)}` : h)
</script>

<template>
  <section class="sec-page vault" data-testid="vault-exercise" aria-label="Practice vault">
    <header class="sec-head">
      <h1 class="sec-title">{{ words('wizard.vault.title') }}</h1>
      <v-btn variant="text" prepend-icon="mdi-arrow-left" data-testid="vault-back" @click="closeVault">Back to the map</v-btn>
    </header>
    <p class="sec-line" data-testid="vault-statement">{{ words('wizard.vault.statement') }}</p>

    <v-alert v-if="vault.fault" type="error" density="compact" class="mb-3" data-testid="vault-fault">
      <span data-testid="vault-fault-code">{{ vault.fault.code }}</span> {{ vaultWords(vault.fault) }}
      <span v-if="vault.fault.retryable" class="muted" data-testid="vault-fault-retry"> You can try again.</span>
    </v-alert>

    <div class="vault-keys" data-testid="vault-keys">
      <div v-for="k in vault.keys" :key="k.name" class="vault-key" :data-testid="`vault-key-${k.name}`">
        <b>{{ k.name }}</b>
        <span class="muted">{{ k.algorithm }}, version {{ k.versions }}</span>
        <code :data-testid="`vault-key-fingerprint-${k.name}`">{{ k.fingerprint }}</code>
        <span v-if="sec.showKeys && k.publicHex" class="muted">Public key <code :data-testid="`vault-key-public-${k.name}`">{{ short(k.publicHex) }}</code></span>
        <span v-if="k.hidden" class="vault-hidden" :data-testid="`vault-key-hidden-${k.name}`">{{ words('wizard.vault.hidden-key') }}</span>
      </div>
    </div>

    <nav class="vault-tabs" aria-label="Vault exercise screens">
      <v-btn v-for="s in SCREENS" :key="s.id" :variant="vault.screen === s.id ? 'flat' : 'tonal'" :color="vault.screen === s.id ? 'primary' : undefined" :aria-current="vault.screen === s.id ? 'step' : undefined" :data-testid="`vault-tab-${s.id}`" @click="showScreen(s.id)">{{ s.title }}</v-btn>
    </nav>

    <section v-if="vault.screen === 'sign-derive'" class="vault-screen" data-testid="vault-sign-derive">
      <p class="test-keys-line" data-testid="vault-test-keys-line">{{ testKeysLine }}</p>
      <p>{{ words('wizard.vault.sign-derive.what') }}</p>

      <h2 class="wiz-h">Sign</h2>
      <p>{{ words('wizard.vault.sign.what') }}</p>
      <label class="wiz-file"><span>Message</span><input v-model="message" class="ns-input" type="text" spellcheck="false" aria-label="Message to sign" data-testid="vault-sign-message" /></label>
      <v-btn color="primary" :disabled="vault.busy || !message" data-testid="vault-sign-run" @click="signText(message)">Sign it</v-btn>
      <div v-if="vault.sign" class="wiz-fact" data-testid="vault-sign-result">
        <dl>
          <dt>Key</dt><dd>{{ vault.sign.keyName }}, version {{ vault.sign.version }}</dd>
          <dt>Signature</dt><dd><code data-testid="vault-sign-signature">{{ vault.sign.signatureHex }}</code></dd>
          <dt>Public key</dt><dd><code data-testid="vault-sign-public">{{ vault.sign.publicKeyHex }}</code></dd>
        </dl>
        <v-btn :disabled="vault.signChecked" data-testid="vault-sign-check" @click="revealCheck">Check it</v-btn>
        <template v-if="vault.signChecked">
          <code class="wiz-cmd" data-testid="prove-command">{{ vault.sign.command }}</code>
          <pre class="wiz-out" data-testid="prove-output">{{ vault.sign.output }}</pre>
          <p class="muted" data-testid="vault-sign-code">{{ vault.sign.code }}</p>
        </template>
      </div>

      <h2 class="wiz-h">Derive</h2>
      <p>{{ words('wizard.vault.derive.what') }}</p>
      <p class="muted" data-testid="vault-derive-note">{{ words('wizard.vault.derive.note') }}</p>
      <label class="wiz-file"><span>Label</span><input v-model="label" class="ns-input" type="text" spellcheck="false" aria-label="Label for the derived key" data-testid="vault-derive-label" /></label>
      <v-btn color="primary" :disabled="vault.busy || !label" data-testid="vault-derive-run" @click="deriveLabel(label)">Derive</v-btn>
      <ul v-if="vault.derived.length" class="wiz-parts" data-testid="vault-derive-result">
        <li v-for="(d, i) in vault.derived" :key="i" :data-testid="`vault-derived-${i}`">
          <b>{{ d.label }}</b> <code :data-testid="`vault-derived-fingerprint-${i}`">{{ d.fingerprint }}</code>
          <code v-if="sec.showKeys" class="muted" :data-testid="`vault-derived-hex-${i}`">{{ d.outputHex }}</code>
        </li>
      </ul>
      <p v-if="sameLabel" class="muted" data-testid="vault-derive-compare">{{ sameLabel }}</p>
    </section>

    <section v-else-if="vault.screen === 'refuse'" class="vault-screen" data-testid="vault-refuse">
      <p>{{ words('wizard.vault.refuse.what') }}</p>
      <p v-if="refuseKey" class="muted" data-testid="vault-refuse-key">{{ refuseKey.name }}: <code>{{ refuseKey.fingerprint }}</code></p>
      <p v-if="refuseKey" class="vault-hidden">{{ words('wizard.vault.hidden-key') }}</p>
      <v-btn color="primary" :disabled="vault.busy" data-testid="vault-refuse-run" @click="tryExport">Try to read this key out</v-btn>
      <div v-if="vault.refused" class="wiz-error" data-testid="vault-refuse-result" role="alert">
        <code data-testid="vault-refuse-code">{{ vault.refused.code }}</code>
        <p>{{ vaultWords(vault.refused) }}</p>
      </div>
    </section>

    <section v-else class="vault-screen" data-testid="vault-audit">
      <p>{{ words('wizard.vault.audit.what') }}</p>
      <div class="wiz-actions">
        <v-btn color="primary" :disabled="vault.busy" data-testid="vault-audit-run" @click="showAudit">Show the audit list</v-btn>
        <v-btn :disabled="vault.busy" data-testid="vault-audit-check" @click="checkChain">Check the chain</v-btn>
      </div>
      <p v-if="vault.chain" class="wiz-fact" data-testid="vault-audit-chain">
        <code data-testid="vault-audit-chain-code">{{ vault.chain.code }}</code>
        <span v-if="vault.chain.firstBadSeq === 0">{{ words('wizard.vault.audit.whole') }}</span>
        <span v-else>Row {{ vault.chain.firstBadSeq }} {{ words('wizard.vault.audit.bad') }}</span>
      </p>
      <template v-if="vault.auditShown">
        <p class="muted" data-testid="vault-audit-note">{{ words('wizard.vault.audit.caller-note') }}</p>
        <table class="vault-audit-table">
          <thead><tr><th scope="col">Row</th><th scope="col">Time</th><th scope="col">Who</th><th scope="col">What</th><th scope="col">Result</th><th scope="col">Code of the row before</th></tr></thead>
          <tbody>
            <tr v-for="r in vault.audit" :key="r.seq" :data-testid="`vault-audit-row-${r.seq}`">
              <td>{{ r.seq }}</td><td>{{ r.at }}</td><td>{{ r.caller }}</td><td>{{ r.op }} {{ r.name }}</td><td>{{ r.result }}</td><td><code>{{ short(r.prevHash) }}</code></td>
            </tr>
          </tbody>
        </table>
      </template>
    </section>
  </section>
</template>
