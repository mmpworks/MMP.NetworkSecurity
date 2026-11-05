<script setup lang="ts">
import { computed, onBeforeUnmount, onMounted, ref, watch } from 'vue'
import { Pane, Splitpanes } from 'splitpanes'
import { vuetify } from './theme'
import {
  CE_LABEL, GLASS_NOTE, TARGET_DEVICES, active, addr, allEvents, cePanel, clearError, connect, hostState, onTheme, pauseEngine, retryConnect, runEngine, selectEvent, selectedEvent,
  setMode, setTheme, shownEvents, stepEngine, switchSession, tour, tourBack, tourNext, tourReplay, trainingChip, ui,
} from './store'
import type { ViewMode } from './types'
import ByteInspector from './components/ByteInspector.vue'
import EventLog from './components/EventLog.vue'
import LessonRail from './components/LessonRail.vue'
import SecretsPanel from './components/SecretsPanel.vue'
import SequenceDiagram from './components/SequenceDiagram.vue'
import TourPanel from './components/TourPanel.vue'
import PicturePanel from './components/PicturePanel.vue'
import MeasurePanel from './components/MeasurePanel.vue'
import ChainPanel from './components/ChainPanel.vue'
import LadderPanel from './components/LadderPanel.vue'
import HostKeyPanel from './components/HostKeyPanel.vue'
import TokenPanel from './components/TokenPanel.vue'
import TimingPanel from './components/TimingPanel.vue'
import OnionPanel from './components/OnionPanel.vue'
import { isLadderEvent, pictureOf, protocols, raceStats } from './lab'
import type { TraceEvent } from './types'
import NeedsBanner from './components/NeedsBanner.vue'
import SecurityPage from './components/SecurityPage.vue'
import ShowKeysSwitch from './components/ShowKeysSwitch.vue'
import WizardSheet from './components/WizardSheet.vue'
import { badgeCount, closeSecurity, keysChip, loadSecurity, openSecurity, sec } from './security'

const lightbox = ref(false)
const mineCountColor = computed(() => (keysChip.value === 'Keys: built-in' ? undefined : 'primary'))
const hostChip = computed(() => (hostState.value === 'connected' ? 'engine connected' : hostState.value === 'connecting' ? 'engine starting' : 'engine offline'))
const hostColor = computed(() => (hostState.value === 'connected' ? 'success' : hostState.value === 'connecting' ? 'warning' : 'error'))
const engineText = computed(() => {
  if (tour.driving) return 'stepping'
  if (ui.engine === 'waiting') { const w = shownEvents.value[shownEvents.value.length - 1]?.waiting; return w ? `waiting for ${w}` : 'waiting' }
  return ui.engine
})
const position = computed(() => {
  const i = selectedEvent.value ? shownEvents.value.findIndex(e => e.seq === selectedEvent.value!.seq) + 1 : 0
  return `event ${i} of ${allEvents.value.length}`
})
const sessionTabs = computed(() => ui.sessions.filter(s => s.lesson === ui.lesson))

// Lesson views: tabs appear only when the shown events carry that kind of data. A new selection of that kind opens its tab.
type TabId = 'bytes' | 'picture' | 'chain' | 'ladder' | 'measures' | 'hostkey' | 'token' | 'timing' | 'onion'
const tabs = computed(() => {
  const list: { id: TabId; label: string }[] = [{ id: 'bytes', label: 'Bytes' }]
  const ev = shownEvents.value
  if (ev.some(e => pictureOf(e))) list.push({ id: 'picture', label: 'Picture' })
  if (ev.some(e => e.type === 'ca.certificate.issued')) list.push({ id: 'chain', label: 'Chain' })
  if (ev.some(e => e.type === 'ssh.hostkey.seen' || e.check?.name === 'known_hosts match')) list.push({ id: 'hostkey', label: 'Host key' })
  if (ev.some(e => isLadderEvent(e))) list.push({ id: 'ladder', label: 'Keys' })
  if (ev.some(e => e.fields.some(f => f.name === 'tokenHeader' || f.name === 'proofHeader') || (e.type === 'measure.result' && (e.message === 'token claims' || e.message === 'proof claims')))) list.push({ id: 'token', label: 'Token' })
  if (ev.some(e => e.type.startsWith('timing.'))) list.push({ id: 'timing', label: 'Timing' })
  if (ev.some(e => e.type === 'pin.block.locked')) list.push({ id: 'onion', label: 'Onion' })
  if (ev.some(e => e.type === 'measure.result' && e.message !== 'Reader registers')) list.push({ id: 'measures', label: 'Measures' })
  return list
})
const hasTab = (id: TabId) => tabs.value.some(t => t.id === id)
function tabFor(e: TraceEvent): TabId {
  if (e.message.startsWith('Picture')) return 'picture'
  if (e.type === 'ca.certificate.issued') return 'chain'
  if (e.type === 'ssh.hostkey.seen') return 'hostkey'
  if (e.fields.some(f => f.name === 'tokenHeader' || f.name === 'proofHeader') || e.message === 'token claims' || e.message === 'proof claims') return 'token'
  if (e.type.startsWith('timing.')) return 'timing'
  if (e.type === 'pin.block.locked' || e.type === 'gateway.envelope.relayed' || e.type === 'ce.reply.relayed') return 'onion'
  if (isLadderEvent(e) || e.message === 'Reader registers') return 'ladder'
  if (e.type === 'measure.result') return 'measures'
  return 'bytes'
}
// A new selection opens the tab that shows its kind of data. A tab whose data went away closes.
watch(selectedEvent, e => { if (e) { const t = tabFor(e); ui.inspectorTab = hasTab(t) ? t : 'bytes' } })
watch(tabs, () => { if (!hasTab(ui.inspectorTab)) ui.inspectorTab = 'bytes' })

// Lesson 7: when the session holds both TLS 1.1 and TLS 1.3 streams, the diagram splits into a race.
const raceMode = computed(() => { const p = protocols(shownEvents.value); return p.has('tls11') && p.has('tls13') })
const raceView = computed(() => (ui.view === 'eavesdropper' ? 'eavesdropper' : 'endpoints') as 'endpoints' | 'eavesdropper')
const raceUpTo = computed(() => selectedEvent.value?.seq ?? Infinity)
const race = computed(() => ({ left: raceStats(shownEvents.value, raceUpTo.value, 'tls11'), right: raceStats(shownEvents.value, raceUpTo.value, 'tls13') }))

function setView(v: ViewMode) { ui.view = v }
function toggleTransport() { ui.transport = ui.transport === 'os' ? 'glass' : 'os' }

function moveSelection(d: number) {
  const list = shownEvents.value
  if (!list.length) return
  const cur = selectedEvent.value ? list.findIndex(e => e.seq === selectedEvent.value!.seq) : list.length - 1
  selectEvent(list[Math.min(list.length - 1, Math.max(0, cur + d))].seq)
}

function onKey(ev: KeyboardEvent) {
  const t = ev.target as HTMLElement | null
  if (t && (t.tagName === 'INPUT' || t.tagName === 'SELECT' || t.tagName === 'TEXTAREA')) return
  if (ev.ctrlKey || ev.metaKey || ev.altKey) return
  const k = ev.key
  const inDiagram = !!t?.closest?.('.diagram')
  if (sec.open) { if (k === 'Escape' && !sec.run) closeSecurity(); return }
  if (k === 'Escape') { lightbox.value = false; ui.shortcuts = false }
  else if (k === 'ArrowRight' && !ev.shiftKey || k === 'n' || k === 'N') void tourNext()
  else if (k === 'ArrowLeft' && !ev.shiftKey || k === 'b' || k === 'B') tourBack()
  else if (k === ' ') { ev.preventDefault(); if (ui.mode === 'free') stepEngine(); else tourReplay() }
  else if (k === 'r' || k === 'R') { if (ui.engine === 'running') pauseEngine(); else runEngine() }
  else if (k === 'ArrowUp' && !ev.shiftKey) { ev.preventDefault(); moveSelection(-1) }
  else if (k === 'ArrowDown' && !ev.shiftKey) { ev.preventDefault(); moveSelection(1) }
  else if (k === 'e' || k === 'E') ui.view = ui.view === 'eavesdropper' ? 'endpoints' : 'eavesdropper'
  else if (k === 't' || k === 'T') setMode(ui.mode === 'tour' ? 'free' : 'tour')
  else if (k === 'f' || k === 'F') lightbox.value = !lightbox.value
  else if (k === '?') ui.shortcuts = !ui.shortcuts
  void inDiagram
}

watch(hostState, s => { if (s === 'connected') void loadSecurity() })
onMounted(() => { onTheme(name => { vuetify.theme.global.name.value = name }); connect(); window.addEventListener('keydown', onKey) })
onBeforeUnmount(() => window.removeEventListener('keydown', onKey))
const shortcuts: [string, string][] = [
  ['Right or N', 'Next step'], ['Left or B', 'Back'], ['Space', 'Step one event (free play) or replay the step'], ['R', 'Run or pause'],
  ['Up and Down', 'Pick the previous or next event'], ['E', 'Switch endpoints and eavesdropper'], ['T', 'Switch tour and free play'],
  ['+  -  0', 'Zoom the focused diagram: in, out, fit'], ['Shift + arrows', 'Pan the zoomed diagram'], ['F', 'Open the diagram in a full window'], ['?', 'This sheet'], ['Esc', 'Close'],
]
</script>

<template>
  <v-app>
    <v-main>
      <div class="shell" data-testid="app-root">
        <header class="topbar">
          <span class="app-title">Network Security Lab</span>
          <v-tooltip location="bottom" max-width="340">
            <template #activator="{ props: p }">
              <v-chip v-bind="p" :color="trainingChip === 'OS TRANSPORT' ? 'info' : 'warning'" data-testid="training-only-label" tabindex="0">
                <v-icon start size="14">{{ trainingChip === 'OS TRANSPORT' ? 'mdi-lock-outline' : 'mdi-lock-open-variant-outline' }}</v-icon>{{ trainingChip }}
              </v-chip>
            </template>
            <span v-if="trainingChip === 'TRAINING ONLY'">This engine shows its keys on purpose. Never use it with real secrets. {{ GLASS_NOTE }}</span>
            <span v-else>The OS handles the keys and this course shows none of them.</span>
          </v-tooltip>
          <v-tooltip location="bottom" max-width="340">
            <template #activator="{ props: p }">
              <v-chip v-bind="p" :color="mineCountColor" tabindex="0" data-testid="keys-chip" @click="openSecurity">
                <v-icon start size="14">mdi-key-outline</v-icon>{{ keysChip }}
              </v-chip>
            </template>
            <span>Whose key signs: the course's own, or yours. Click to change.</span>
          </v-tooltip>
          <v-chip :color="hostColor" data-testid="host-chip">{{ hostChip }}</v-chip>
          <v-btn size="small" variant="tonal" prepend-icon="mdi-shield-key-outline" data-testid="security-setup-button" @click="openSecurity">
            Security setup
            <v-badge v-if="badgeCount" :content="badgeCount" color="warning" inline data-testid="security-badge" />
          </v-btn>
          <label class="target-label">Target device
            <select v-model="ui.target" class="ns-select" data-testid="target-select"><option v-for="d in TARGET_DEVICES" :key="d.id" :value="d.id" :disabled="!d.enabled">{{ d.label }}</option></select>
          </label>
          <v-spacer />
          <v-btn-toggle :model-value="ui.mode" mandatory density="compact" data-testid="mode-switch" @update:model-value="v => v && setMode(v)">
            <v-btn value="tour" data-testid="mode-tour">Tour</v-btn><v-btn value="free" data-testid="mode-free">Free play</v-btn>
          </v-btn-toggle>
          <v-btn-toggle :model-value="ui.view" mandatory density="compact" data-testid="view-switch" @update:model-value="v => v && setView(v)">
            <v-btn value="endpoints" data-testid="view-endpoints">Endpoints</v-btn><v-btn value="eavesdropper" data-testid="view-eavesdropper">Eavesdropper</v-btn><v-btn value="both" data-testid="view-both">Both</v-btn>
          </v-btn-toggle>
          <ShowKeysSwitch testid="show-keys-switch" />
          <v-btn :variant="ui.transport === 'os' ? 'flat' : 'tonal'" :color="ui.transport === 'os' ? 'info' : undefined" data-testid="transport-switch" :aria-pressed="ui.transport === 'os'" @click="toggleTransport">OS transport</v-btn>
          <select v-model.number="ui.speed" class="ns-select" data-testid="speed-select" aria-label="Animation speed"><option :value="0.5">0.5x</option><option :value="1">1x</option><option :value="2">2x</option></select>
          <select :value="ui.theme" class="ns-select" data-testid="theme-select" aria-label="Theme" @change="e => setTheme((e.target as HTMLSelectElement).value as any)"><option value="system">System</option><option value="light">Light</option><option value="dark">Dark</option></select>
          <v-btn size="small" icon="mdi-keyboard-outline" aria-label="Keyboard shortcuts" @click="ui.shortcuts = true" />
        </header>

        <v-alert v-if="hostState === 'offline'" type="error" class="banner" data-testid="host-offline">
          The engine is offline (port {{ addr.port }}).
          <template #append><v-btn size="small" data-testid="error-retry" @click="retryConnect">Retry</v-btn></template>
        </v-alert>
        <v-alert v-else-if="ui.error" type="error" class="banner" closable data-testid="error-banner" @click:close="clearError">
          <span data-testid="error-code">{{ ui.error.code }}</span>: {{ ui.error.message }}
          <span class="muted"> retryable: {{ ui.error.retryable ? 'yes' : 'no' }}{{ ui.error.requestId ? ` · request ${ui.error.requestId}` : '' }}</span>
          <template v-if="ui.error.retryable" #append><v-btn size="small" data-testid="error-retry" @click="retryConnect">Retry</v-btn></template>
        </v-alert>

        <NeedsBanner />
        <SecurityPage v-if="sec.open" />
        <WizardSheet v-if="sec.run" />

        <Splitpanes v-show="!sec.open" class="main-split">
          <Pane :size="17" :min-size="11"><LessonRail /></Pane>
          <Pane :size="50" :min-size="30">
            <Splitpanes horizontal>
              <Pane :size="60" :min-size="25">
                <div class="panel">
                  <div v-if="sessionTabs.length > 1" class="tabs-row">
                    <button v-for="(s, i) in sessionTabs" :key="s.id" type="button" class="stab" :class="{ on: s.id === ui.activeId }" :data-testid="`session-tab-${i}`" @click="switchSession(s.id)">{{ s.label }}</button>
                  </div>
                  <div v-if="!active" class="empty-note big" data-testid="empty-state">
                    <template v-if="ui.lesson == null">Pick a lesson to see its messages here.</template>
                    <template v-else>Press Start tour in the tour panel to see the first message.</template>
                  </div>
                  <div v-else-if="raceMode" class="race" data-testid="race">
                    <div v-for="side in ([['left', 'tls11', 'TLS 1.1 (2006)'], ['right', 'tls13', 'TLS 1.3']] as const)" :key="side[0]" class="race-col" :data-testid="`race-${side[0]}`">
                      <div class="race-head">
                        <span class="rname">{{ side[2] }}</span>
                        <span class="race-counts">
                          <span>messages <b :data-testid="`race-count-messages-${side[0]}`">{{ race[side[0]].messages }}</b></span>
                          <span>round trips before data <b :data-testid="`race-count-roundtrips-${side[0]}`">{{ race[side[0]].roundTrips ?? '…' }}</b></span>
                          <span>bytes <b :data-testid="`race-count-bytes-${side[0]}`">{{ race[side[0]].bytes }}</b></span>
                        </span>
                      </div>
                      <SequenceDiagram :view="raceView" :protocol="side[1]" @lightbox="lightbox = true" />
                    </div>
                  </div>
                  <div v-else class="diagrams" :class="{ both: ui.view === 'both' }">
                    <SequenceDiagram v-if="ui.view !== 'eavesdropper'" view="endpoints" @lightbox="lightbox = true" />
                    <SequenceDiagram v-if="ui.view !== 'endpoints'" view="eavesdropper" @lightbox="lightbox = true" />
                  </div>
                </div>
              </Pane>
              <Pane :size="40" :min-size="18">
                <div class="panel">
                  <div v-if="tabs.length > 1" class="tabs-inline" data-testid="inspector-tabs">
                    <button v-for="t in tabs" :key="t.id" type="button" class="stab" :class="{ on: ui.inspectorTab === t.id }" :data-testid="`inspector-tab-${t.id}`" @click="ui.inspectorTab = t.id">{{ t.label }}</button>
                  </div>
                  <PicturePanel v-if="ui.inspectorTab === 'picture' && hasTab('picture')" />
                  <ChainPanel v-else-if="ui.inspectorTab === 'chain' && hasTab('chain')" />
                  <HostKeyPanel v-else-if="ui.inspectorTab === 'hostkey' && hasTab('hostkey')" />
                  <TokenPanel v-else-if="ui.inspectorTab === 'token' && hasTab('token')" />
                  <TimingPanel v-else-if="ui.inspectorTab === 'timing' && hasTab('timing')" />
                  <OnionPanel v-else-if="ui.inspectorTab === 'onion' && hasTab('onion')" />
                  <LadderPanel v-else-if="ui.inspectorTab === 'ladder' && hasTab('ladder')" />
                  <MeasurePanel v-else-if="ui.inspectorTab === 'measures' && hasTab('measures')" />
                  <ByteInspector v-else />
                </div>
              </Pane>
            </Splitpanes>
          </Pane>
          <Pane :size="33" :min-size="22">
            <Splitpanes horizontal>
              <Pane :size="55" :min-size="25"><div class="panel"><EventLog v-if="ui.mode === 'free'" /><TourPanel v-else /></div></Pane>
              <Pane :size="45" :min-size="20"><div class="panel"><SecretsPanel /></div></Pane>
            </Splitpanes>
          </Pane>
        </Splitpanes>

        <footer class="statusbar" data-testid="status-bar">
          <span data-testid="engine-state">engine: {{ engineText }}</span>
          <span v-if="active">session {{ active.id }} · seed {{ active.seed }}</span>
          <span>{{ position }}</span>
          <v-chip v-if="active?.replay" size="x-small" color="info" data-testid="replay-chip">REPLAY</v-chip>
          <span v-if="tour.driving" class="muted" data-testid="engine-waiting">waiting for the engine</span>
          <v-spacer />
          <span class="muted" data-testid="ce-label">CE lab: {{ cePanel?.label ?? CE_LABEL }}</span>
        </footer>
      </div>

      <v-dialog v-model="lightbox" fullscreen>
        <div class="lightbox" data-testid="lightbox">
          <v-btn class="lb-close" icon="mdi-close" aria-label="Close" data-testid="lightbox-close" @click="lightbox = false" />
          <SequenceDiagram :view="ui.view === 'eavesdropper' ? 'eavesdropper' : 'endpoints'" in-lightbox />
        </div>
      </v-dialog>
      <v-dialog v-model="ui.shortcuts" max-width="520">
        <v-card class="pa-4" data-testid="shortcut-sheet">
          <div class="side-title mb-2">KEYBOARD</div>
          <div v-for="[k, d] in shortcuts" :key="k" class="sc-row"><kbd>{{ k }}</kbd><span>{{ d }}</span></div>
        </v-card>
      </v-dialog>
    </v-main>
  </v-app>
</template>
