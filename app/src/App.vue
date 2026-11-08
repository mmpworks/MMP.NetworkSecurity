<script setup lang="ts">
import { computed, onBeforeUnmount, onMounted, ref, watch } from 'vue'
import TextWithSpecs from './components/TextWithSpecs.vue'
import { Pane, Splitpanes } from 'splitpanes'
import { vuetify } from './theme'
import {
  CE_LABEL, active, addr, allEvents, cePanel, clearError, connect, hostState, onTheme, pauseEngine, retryConnect, runEngine, selectEvent, selectedEvent,
  closeGlossary, setMode, showAttackIndex, shownEvents, stepEngine, switchSession, tour, tourBack, tourNext, tourReplay, ui,
} from './store'
import TopBar from './components/TopBar.vue'
import BinaryTip from './components/BinaryTip.vue'
import { paneShares } from './panes'
import ByteInspector from './components/ByteInspector.vue'
import EventLog from './components/EventLog.vue'
import LessonRail from './components/LessonRail.vue'
import SectionRail from './components/SectionRail.vue'
import { sectionOf, walkStatus } from './sections'
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
import { closedToListener, isLadderEvent, listenerLabel, pictureOf, protocols, raceStats } from './lab'
import type { TraceEvent } from './types'
import NeedsBanner from './components/NeedsBanner.vue'
import SecurityPage from './components/SecurityPage.vue'
import GlossaryPage from './components/GlossaryPage.vue'
import AesWalkPanel from './components/AesWalkPanel.vue'
import AesLongStrip from './components/AesLongStrip.vue'
import AesLongLink from './components/AesLongLink.vue'
import AttackIndex from './components/AttackIndex.vue'
import { openAesWalk } from './aesWalkState'
import VaultPage from './components/VaultPage.vue'
import { closeVault, vault } from './vault'
import WizardSheet from './components/WizardSheet.vue'
import { closeSecurity, loadSecurity, sec, words } from './security'

const lightbox = ref(false)
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
  const list: { id: TabId; label: string }[] = [{ id: 'bytes', label: 'Message bytes' }]
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
// The AES walk tab shows when the run holds aes.key and has sent its text, which is when the engine can build the block (AesWalkFacts reads both).
// It opens Techniques at the AES walk, on this run's block.
const hasAesKey = computed(() => !!active.value && shownEvents.value.some(e => e.secrets.some(s => s.name === 'aes.key')) && shownEvents.value.some(e => e.type === 'aes.message.sent'))
const aesWalkOpen = computed(() => ui.section === 'techniques' && ui.walkItem.techniques === 'aes')
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
// The Eavesdropper view closes a tab that holds what only an endpoint knows, and it says so.
const listenerNote = computed(() => (ui.view === 'eavesdropper' ? closedToListener(ui.inspectorTab, allEvents.value) : null))
const tabLabel = computed(() => (ui.view === 'eavesdropper' ? listenerLabel(ui.inspectorTab, allEvents.value) : null))
const raceMode = computed(() => { const p = protocols(shownEvents.value); return p.has('tls11') && p.has('tls13') })
const raceView = computed(() => (ui.view === 'eavesdropper' ? 'eavesdropper' : 'endpoints') as 'endpoints' | 'eavesdropper')
const raceUpTo = computed(() => selectedEvent.value?.seq ?? Infinity)
const race = computed(() => ({ left: raceStats(shownEvents.value, raceUpTo.value, 'tls11'), right: raceStats(shownEvents.value, raceUpTo.value, 'tls13') }))

// The Message bytes pane keeps at least 360 px: a short message with every row and field in view, also under the 50 px Show keys banner. A narrow window stacks the field list under the grids, so it keeps 480 px. The diagram scrolls, so it gives up the height.
// The share follows the window live. A share set only when the window opened left the Before grid too short after a resize, and its rows covered the line under it.
const win = ref({ w: window.innerWidth, h: window.innerHeight })
const onResize = () => { win.value = { w: window.innerWidth, h: window.innerHeight } }
const shares = computed(() => paneShares(win.value.w, win.value.h))
const placeholderItem = computed(() => sectionOf(ui.section).items.find(i => i.id === ui.walkItem[ui.section]) ?? null)
const bytesPanePercent = computed(() => shares.value.bytes)

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
  if (ui.glossaryOpen) { if (k === 'Escape') closeGlossary(); return }
  if (sec.open) { if (k === 'Escape' && !sec.run) { if (vault.open) closeVault(); else closeSecurity() } return }
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
onMounted(() => { onTheme(name => { vuetify.theme.global.name.value = name }); connect(); window.addEventListener('keydown', onKey); window.addEventListener('resize', onResize) })
onBeforeUnmount(() => { window.removeEventListener('keydown', onKey); window.removeEventListener('resize', onResize) })
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
        <TopBar />

        <v-alert v-if="hostState === 'offline'" type="error" class="banner" data-testid="host-offline">
          The engine is offline (port {{ addr.port }}).
          <template #append><v-btn size="small" data-testid="error-retry" @click="retryConnect">Retry</v-btn></template>
        </v-alert>
        <v-alert v-else-if="ui.error" type="error" class="banner" closable data-testid="error-banner" @click:close="clearError">
          <span data-testid="error-code">{{ ui.error.code }}</span>: <TextWithSpecs :text="ui.error.message" />
          <span class="muted"> retryable: {{ ui.error.retryable ? 'yes' : 'no' }}{{ ui.error.requestId ? ` · request ${ui.error.requestId}` : '' }}</span>
          <template v-if="ui.error.retryable" #append><v-btn size="small" data-testid="error-retry" @click="retryConnect">Retry</v-btn></template>
        </v-alert>

        <NeedsBanner />
        <v-alert v-if="!sec.showKeys" type="info" class="banner" data-testid="show-keys-off-banner">{{ words('wizard.keys.off-banner') }}</v-alert>
        <GlossaryPage v-if="ui.glossaryOpen" />
        <SecurityPage v-if="sec.open && !vault.open && !ui.glossaryOpen" />
        <VaultPage v-if="sec.open && vault.open && !ui.glossaryOpen" />
        <WizardSheet v-if="sec.run" />

        <Splitpanes v-show="!sec.open && !ui.glossaryOpen" class="main-split">
          <Pane :size="shares.rail" :min-size="11"><LessonRail v-if="ui.section === 'lessons'" /><SectionRail v-else /></Pane>
          <Pane :size="100 - shares.rail" :min-size="60">
            <div class="workspace" data-testid="workspace">
            <!-- R1: the long text stays pinned above the walk on every Techniques item, as a sibling of walk-root, so the walk's clip cannot cut it. -->
            <AesLongStrip v-if="ui.section === 'techniques'" />
            <!-- The AES walk mounts here and replaces the panels. Its tips and spec cards go to overlay-layer, outside this clip. -->
            <section v-if="aesWalkOpen" data-testid="walk-root" class="walk-root"><AesWalkPanel /></section>
            <AesLongLink v-if="aesWalkOpen" />
            <!-- Handshake and Techniques: the walk screens arrive in their slices. Until then the workspace says which slice brings the picked walk. -->
            <section v-if="ui.section !== 'lessons' && !aesWalkOpen" class="section-placeholder" data-testid="section-placeholder">
              <h2>{{ sectionOf(ui.section).label }}</h2>
              <p v-if="placeholderItem">{{ placeholderItem.label }}: {{ walkStatus(placeholderItem) }}.</p>
              <p v-else>Pick a walk on the left.</p>
            </section>
            <!-- The attack index replaces the lesson panes while it is open (sections-plan item 3). The panes stay mounted, so a run keeps its state. -->
            <AttackIndex v-if="ui.section === 'lessons' && ui.attackIndex" />
            <Splitpanes v-show="ui.section === 'lessons' && !ui.attackIndex">
          <Pane :size="100 - shares.side" :min-size="36">
            <Splitpanes horizontal>
              <Pane :size="100 - bytesPanePercent" :min-size="25">
                <div class="panel">
                  <div v-if="sessionTabs.length > 1 || ui.attackKept" class="tabs-row">
                    <!-- A run opened from the attack index offers the way back to its row, here at the top where it always shows (sections-plan item 3). -->
                    <button v-if="ui.attackKept" type="button" class="stab stab-back" data-testid="attack-back-to-index" @click="showAttackIndex(true)"><v-icon size="14">mdi-arrow-left</v-icon> Attack runs</button>
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
              <Pane :size="bytesPanePercent" :min-size="18">
                <div class="panel">
                  <div v-if="tabs.length > 1 || hasAesKey" class="tabs-inline" data-testid="inspector-tabs">
                    <button v-for="t in tabs" :key="t.id" type="button" class="stab" :class="{ on: ui.inspectorTab === t.id }" :data-testid="`inspector-tab-${t.id}`" @click="ui.inspectorTab = t.id">{{ t.label }}</button>
                    <button v-if="hasAesKey" type="button" class="stab stab-walk" data-testid="aes-walk-tab" @click="openAesWalk(active!.id, ui.lesson)">AES walk</button>
                  </div>
                  <div v-if="tabLabel" class="muted listener-public" data-testid="inspector-public">{{ tabLabel }}</div>
                  <div v-if="listenerNote" class="empty-note" data-testid="inspector-closed">{{ listenerNote }}</div>
                  <PicturePanel v-else-if="ui.inspectorTab === 'picture' && hasTab('picture')" />
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
          <Pane :size="shares.side" :min-size="26">
            <Splitpanes horizontal>
              <Pane :size="55" :min-size="25"><div class="panel"><EventLog v-if="ui.mode === 'free'" /><TourPanel v-else /></div></Pane>
              <Pane :size="45" :min-size="20"><div class="panel"><SecretsPanel /></div></Pane>
            </Splitpanes>
          </Pane>
            </Splitpanes>
            </div>
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
      <div class="overlay-layer" data-testid="overlay-layer"><BinaryTip /></div>

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
