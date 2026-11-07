<script setup lang="ts">
import { computed, onBeforeUnmount, onMounted, reactive, ref, watch } from 'vue'
import TextWithSpecs from './TextWithSpecs.vue'
import { FLOWS, backToLesson, chipFor, closeSheet, sec, sendEvent, setMode, typeRow, words } from '../security'
import TermText from './TermText.vue'

// The Host's step decides everything. This sheet draws the step and sends back an event the Host allowed.
const step = computed(() => sec.run!)
const screen = computed(() => ({ explain: 'intro', choose: 'make', generate: 'make', file: 'files', review: 'review', prove: 'check', done: 'done' } as Record<string, string>)[step.value.kind] ?? 'intro')
const screenNo = computed(() => ({ intro: 1, make: 2, files: 2, review: 3, check: 4, done: 5 } as Record<string, number>)[screen.value] ?? 1)
const flow = computed(() => FLOWS.find(f => f.flowId === step.value.flowId))
const prefix = computed(() => `wizard.${step.value.flowId}.${screen.value}`)
const block = (...keys: string[]): string => keys.map(k => words(`${prefix.value}.${k}`)).find(Boolean) ?? ''
const what = computed(() => block('what-this-is', 'what-happened'))
const why = computed(() => block('why-it-exists', 'which-lessons-use-them'))
const doNow = computed(() => block('what-you-do-now'))
const good = computed(() => block('what-good-looks-like'))
const title = computed(() => words(`wizard.flow.${step.value.flowId}.title`, step.value.flowId))

const can = (e: string) => step.value.allowed.includes(e)
const forward = computed(() => ['next', 'continue', 'finish'].find(can) ?? '')
const sourceEvent = (source: 'make' | 'files') => ({ event: source === 'files' && can('use-files') ? 'use-files' : source, data: undefined as Record<string, unknown> | undefined })

const error = computed(() => step.value.errors[0] ?? null)
const errorWords = computed(() => (error.value ? words(`wizard.error.${error.value.code}`, error.value.message) : ''))
const warning = computed(() => step.value.warnings.find(w => w.code === 'KEY_PATH_PERSONAL') ?? null)

const reason = computed(() => {
  if (sec.busy) return ''
  if (forward.value && !error.value) return ''
  if (error.value) return 'Fix the problem above first.'
  if (step.value.kind === 'generate' || step.value.kind === 'choose') return 'Choose Make it for me, or Use my own files.'
  if (step.value.kind === 'prove') return 'Choose Check it first.'
  if (step.value.kind === 'file') return 'Choose a file for each key.'
  return 'This step cannot go on yet.'
})

const paths = reactive<Record<string, string>>({})
const cancelAsk = ref(false)
const onEsc = (e: KeyboardEvent) => { if (e.key === "Escape") cancelAsk.value = true }
onMounted(() => window.addEventListener("keydown", onEsc))
onBeforeUnmount(() => window.removeEventListener("keydown", onEsc))
watch(() => step.value.state, () => { cancelAsk.value = false })

const factOf = (id: string) => step.value.facts.find(f => f.typeId === id) ?? {}
const startLesson = computed(() => sec.returnLesson)

function make() { const { event, data } = sourceEvent('make'); void sendEvent(event, data) }
function useFiles() { const { event, data } = sourceEvent('files'); void sendEvent(event, data) }
const checkValue = ref('')
function sendPaths() { void sendEvent('files', { checkValue: checkValue.value.trim() || undefined, paths: Object.fromEntries(Object.entries(paths).filter(([, v]) => v.trim())) }) }
// Leaving the Done screen ends the run on the Host, so no "Setup paused" remains for a finished set.
async function finish() { if (forward.value) await sendEvent(forward.value); await closeSheet(true) }
async function builtinAgain() { await finish(); for (const t of flow.value?.types ?? []) await setMode(t, 'BuiltIn') }
async function toLesson() { await finish(); backToLesson() }
</script>

<template>
  <v-dialog :model-value="true" persistent max-width="720" scrollable>
    <v-card data-testid="wizard-sheet" class="wizard">
      <div data-testid="flow-sheet" class="wiz-inner" :aria-busy="sec.busy">
        <header class="wiz-head">
          <h2 class="wiz-title" data-testid="wizard-title"><span data-testid="flow-title">{{ title }}</span></h2>
          <span class="wiz-progress" data-testid="wizard-progress"><span data-testid="flow-part-progress">Screen {{ screenNo }} of 5</span></span>
          <v-btn icon="mdi-close" size="small" variant="text" aria-label="Close" data-testid="wizard-close" @click="cancelAsk = true" />
        </header>

        <section :data-testid="`flow-${step.flowId}-${screen}`" class="wiz-body">
          <p v-if="screen === 'intro'" class="test-keys-line" data-testid="wizard-test-keys-line">{{ sec.showKeys ? words('wizard.common.test-keys-only') : words('wizard.common.test-keys-hidden') }}</p>

          <h3 class="wiz-h">What this is</h3>
          <p data-testid="wizard-what"><TermText :text="what" /></p>
          <h3 class="wiz-h">Why it exists in the real world</h3>
          <p data-testid="wizard-why"><TermText :text="why" /></p>
          <h3 class="wiz-h">What you do now</h3>
          <p data-testid="wizard-do"><TermText :text="doNow" /></p>

          <div class="wiz-control" data-testid="wizard-control">
            <template v-if="screen === 'make'">
              <p v-if="words(`${prefix}.the-two-parts-one-line-each`)" class="wiz-parts-line"><TermText :text="words(`${prefix}.the-two-parts-one-line-each`)" /></p>
              <ul class="wiz-parts">
                <li v-for="t in flow?.types ?? []" :key="t" :data-testid="`flow-part-${t}`"><b>{{ words(`wizard.type.${t}.title`, t) }}</b> <span class="muted">{{ words(`wizard.type.${t}.why`) }}</span></li>
              </ul>
              <v-btn color="primary" :disabled="sec.busy || !can('make')" data-testid="flow-make-button" @click="make">Make it for me <v-chip size="x-small" class="ml-2">Recommended</v-chip></v-btn>
              <a v-if="can('use-files') || can('files')" href="#" class="wiz-link" data-testid="flow-files-link" @click.prevent="useFiles">{{ words(`${prefix}.link`, 'Use my own files') }}</a>
            </template>

            <template v-else-if="screen === 'files'">
              <div v-if="warning" class="wiz-warn" data-testid="wizard-warning-ssh-path" role="alert">
                <p>{{ words('wizard.warning.KEY_PATH_PERSONAL', warning.message) }}</p>
                <v-btn size="small" data-testid="wizard-warning-pick-another" @click="void sendEvent('back')">Pick another file</v-btn>
                <v-btn size="small" variant="text" data-testid="wizard-warning-use-anyway" @click="sendPaths">Use it anyway</v-btn>
              </div>
              <label v-for="t in flow?.types ?? []" :key="t" class="wiz-file" :data-testid="`flow-file-row-${t}`">
                <span>{{ words(`wizard.type.${t}.title`, t) }}</span>
                <input v-model="paths[t]" class="ns-input" type="text" spellcheck="false" :aria-label="`File for ${words(`wizard.type.${t}.title`, t)}`" :data-testid="`flow-file-path-${t}`" />
              </label>
              <label v-if="(flow?.types as readonly string[] | undefined)?.includes('dukpt.bdk')" class="wiz-file" data-testid="flow-file-check-value">
                <span>{{ words('wizard.field.check-value', 'Check value from the vendor (optional)') }}</span>
                <input v-model="checkValue" class="ns-input" type="text" spellcheck="false" :aria-label="words('wizard.field.check-value', 'Check value from the vendor (optional)')" />
              </label>
              <v-btn color="primary" :disabled="sec.busy || !can('files')" data-testid="flow-files-send" @click="sendPaths">Use these files</v-btn>
            </template>

            <template v-else-if="screen === 'review'">
              <div v-for="t in flow?.types ?? []" :key="t" class="wiz-fact" :data-testid="`review-fact-${t}`">
                <b>{{ words(`wizard.type.${t}.title`, t) }}</b>
                <dl>
                  <dt>Kind</dt><dd :data-testid="`review-algorithm-${t}`">{{ factOf(t).algorithm }}</dd>
                  <dt>Fingerprint</dt><dd><code :data-testid="`review-fingerprint-${t}`">{{ factOf(t).fingerprint }}</code></dd>
                  <template v-if="sec.showKeys && (factOf(t).publicHex || factOf(t).hex)"><dt>Public key</dt><dd><code :data-testid="`review-key-${t}`">{{ factOf(t).publicHex || factOf(t).hex }}</code></dd></template>
                  <template v-if="factOf(t).name"><dt>Name</dt><dd>{{ factOf(t).name }}</dd></template>
                  <template v-if="factOf(t).notAfter"><dt>Valid until</dt><dd>{{ factOf(t).notAfter }}</dd></template>
                </dl>
              </div>
              <p class="muted" data-testid="wizard-fixed-dates">{{ words('wizard.review.fixed-dates') }}</p>
              <p class="muted" data-testid="wizard-test-keys-note"><TermText :text="words(`${prefix}.line-under-both`)" /></p>
            </template>

            <template v-else-if="screen === 'check'">
              <div v-for="t in flow?.types ?? []" :key="t" class="wiz-fact" :data-testid="`check-fact-${t}`">
                <b>{{ words(`wizard.type.${t}.title`, t) }}</b>
                <template v-if="factOf(t).typeId">
                  <v-chip size="small" :color="factOf(t).judge === 'none' ? 'warning' : factOf(t).passed ? 'success' : 'error'" :data-testid="`check-says-${t}`">
                    <v-icon start size="14">{{ factOf(t).judge === 'none' ? 'mdi-shield-alert-outline' : factOf(t).passed ? 'mdi-check-circle-outline' : 'mdi-close-circle-outline' }}</v-icon>
                    {{ factOf(t).judge === 'none' ? words('wizard.chip.no-outside-check') : words(`wizard.says.${factOf(t).says}`, factOf(t).says) }}
                  </v-chip>
                  <p v-if="factOf(t).judge === 'none'" class="muted" :data-testid="`check-note-${t}`">{{ words(`wizard.says.${factOf(t).says}.${t}`, words(`wizard.says.${factOf(t).says}`)) }}</p>
                  <template v-else>
                    <code class="wiz-cmd" :data-testid="`check-command-${t}`">{{ factOf(t).command }}</code>
                    <pre class="wiz-out" :data-testid="`check-output-${t}`">{{ factOf(t).output }}</pre>
                  </template>
                </template>
              </div>
              <v-btn color="primary" :disabled="sec.busy || !can('check')" data-testid="flow-check-button" @click="void sendEvent('check')">Check it</v-btn>
            </template>

            <template v-else-if="screen === 'done'">
              <ul class="wiz-parts">
                <li v-for="t in flow?.types ?? []" :key="t" :data-testid="`done-chip-${t}`">
                  <b>{{ words(`wizard.type.${t}.title`, t) }}</b>
                  <v-chip v-if="typeRow(t)" size="small" :color="chipFor(typeRow(t)!).tone"><v-icon start size="14">{{ chipFor(typeRow(t)!).icon }}</v-icon>{{ chipFor(typeRow(t)!).text }}</v-chip>
                </li>
              </ul>
              <div class="wiz-actions">
                <v-btn v-if="startLesson != null" color="primary" data-testid="wizard-back-to-lesson" @click="toLesson">Back to lesson {{ startLesson }}</v-btn>
                <v-btn data-testid="flow-done-map" @click="finish">Back to the map</v-btn>
                <v-btn variant="text" data-testid="flow-done-builtin" @click="builtinAgain">Use built-in keys again</v-btn>
              </div>
            </template>
          </div>

          <h3 class="wiz-h">What good looks like</h3>
          <p data-testid="wizard-good"><TermText :text="good" /></p>

          <div v-if="error" class="wiz-error" data-testid="wizard-error" role="alert">
            <code data-testid="wizard-error-code">{{ error.code }}</code>
            <p data-testid="wizard-error-fix">{{ errorWords }}</p>
            <p v-if="error.message && error.message !== errorWords" class="muted" data-testid="wizard-error-detail"><TextWithSpecs :text="error.message" /></p>
          </div>
        </section>

        <footer class="wiz-foot">
          <v-btn variant="text" :disabled="sec.busy || !can('back')" data-testid="wizard-back" @click="void sendEvent('back')">Back</v-btn>
          <v-spacer />
          <span class="muted wiz-reason" data-testid="wizard-next-reason" aria-live="polite">{{ reason }}</span>
          <v-btn variant="text" data-testid="wizard-cancel" @click="cancelAsk = true">Cancel setup</v-btn>
          <v-btn v-if="screen !== 'done'" color="primary" :disabled="sec.busy || !forward || !!error" data-testid="wizard-next" @click="void sendEvent(forward)">Continue</v-btn>
          <v-btn v-else color="primary" data-testid="wizard-next" @click="finish">Done</v-btn>
        </footer>
      </div>

      <div v-if="cancelAsk" class="wiz-cancel" data-testid="wizard-cancel-sheet" role="alertdialog" aria-label="Cancel setup">
        <p>{{ words('wizard.cancel.title') }}</p>
        <v-btn color="primary" data-testid="wizard-cancel-keep" @click="void closeSheet(true)">Keep my place</v-btn>
        <v-btn variant="text" data-testid="wizard-cancel-discard" @click="void closeSheet(false)">Throw it away</v-btn>
        <v-btn variant="text" data-testid="wizard-cancel-back" @click="cancelAsk = false">Go on with setup</v-btn>
      </div>
    </v-card>
  </v-dialog>
</template>
