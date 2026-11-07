<script setup lang="ts">
import { computed, nextTick, onMounted, reactive, ref, watch } from 'vue'
import TextWithSpecs from './TextWithSpecs.vue'
import raw from '../glossary.json'
import { closeGlossary, ui } from '../store'
import { isMethod, matches, sourceLabel, type Claim, type Glossary, type Method, type Side } from '../glossaryData'

// The glossary page: methods as a table with a status tag, the symmetric and asymmetric comparison as 2 columns, then the plain terms.
// Every source opens in the learner's own browser through the Electron link rule. A claim with no source says so.
const g = raw as unknown as Glossary
const query = ref('')
const open = reactive(new Set<string>())
const methods = computed(() => g.terms.filter(isMethod).filter(m => matches(m, query.value)))
const terms = computed(() => g.terms.filter(t => !isMethod(t)).filter(t => matches(t, query.value)))
const src = (id: string) => g.sources[id]
const sides: [string, string, Side][] = [['symmetric', 'Symmetric: one shared key', g.comparison.symmetric], ['asymmetric', 'Asymmetric: a key pair', g.comparison.asymmetric]]
const STATUS_WORDS: Record<Method['status'], string> = {
  current: 'Fine to use for new protection.',
  legacy: 'Old data may still be read or checked. New protection must not use it.',
  broken: 'Do not use. A known attack defeats it.',
}
const toggle = (id: string) => { if (open.has(id)) open.delete(id); else open.add(id) }
const lessonsText = (n: number[]) => (n.length ? n.join(', ') : 'none')
const claimKey = (c: Claim, i: number) => `${i}-${c.text.slice(0, 16)}`

// A term link opens the page at its entry: the entry scrolls into view, opens if it is a method, and shows a ring for a moment.
const flash = ref<string | null>(null)
async function focusEntry(id: string | null) {
  if (!id) return
  query.value = ''
  if (g.terms.some(t => t.id === id && isMethod(t))) open.add(id)
  await nextTick()
  document.getElementById(`glossary-entry-${id}`)?.scrollIntoView({ block: 'center' })
  flash.value = id
  setTimeout(() => { if (flash.value === id) flash.value = null }, 1600)
}
onMounted(() => void focusEntry(ui.glossaryFocus))
watch(() => ui.glossaryFocus, id => void focusEntry(id))
</script>

<template>
  <section class="sec-page glossary" data-testid="glossary-page" aria-label="Glossary">
    <header class="sec-head">
      <h1 class="sec-title">Glossary</h1>
      <v-btn variant="text" prepend-icon="mdi-arrow-left" data-testid="glossary-back" @click="closeGlossary">Back to lessons</v-btn>
      <v-spacer />
      <input v-model="query" class="ns-input gl-search" type="search" placeholder="Search terms and methods" aria-label="Search terms and methods" data-testid="glossary-search" />
    </header>
    <p class="muted gl-line">Sources read on {{ g.sourcesRead }}. A source opens in your own web browser. A mark says when a claim rests on reasoning or on a draft.</p>

    <h2 class="gl-h">Methods</h2>
    <div class="gl-table-wrap">
      <table class="gl-table" data-testid="glossary-methods">
        <thead><tr><th>Method</th><th>Kind</th><th>Does</th><th>Key sizes</th><th>Status</th><th>Lessons</th></tr></thead>
        <tbody>
          <template v-for="m in methods" :key="m.id">
            <tr
              :id="`glossary-entry-${m.id}`" class="gl-row" :class="{ open: open.has(m.id), flash: flash === m.id }" :data-testid="`glossary-method-${m.id}`"
              tabindex="0" :aria-expanded="open.has(m.id)" @click="toggle(m.id)" @keydown.enter.prevent="toggle(m.id)" @keydown.space.prevent="toggle(m.id)"
            >
              <td><b>{{ m.term }}</b><div class="muted"><TextWithSpecs :text="m.short" /></div></td>
              <td>{{ m.kind }}</td>
              <td>{{ m.does.join(', ') }}</td>
              <td>{{ m.keySizes ?? 'n/a' }}</td>
              <td>
                <span class="gl-status" :class="`st-${m.status}`" :title="STATUS_WORDS[m.status]" :data-testid="`glossary-status-${m.id}`">{{ m.status }}</span>
                <span v-if="m.statusBasis === 'draft'" class="gl-mark" title="Only a draft standard states this status." :data-testid="`glossary-draft-${m.id}`">draft</span>
              </td>
              <td>{{ lessonsText(m.lessons) }}</td>
            </tr>
            <tr v-if="open.has(m.id)" class="gl-detail" :data-testid="`glossary-detail-${m.id}`">
              <td colspan="6">
                <p v-if="m.strength"><b>Strength.</b> {{ m.strength }}</p>
                <p v-if="m.strengthNote">{{ m.strengthNote }}</p>
                <p v-if="m.statusNote"><b>Status.</b> <TextWithSpecs :text="m.statusNote" /></p>
                <p v-if="m.reasoning"><span class="gl-mark" title="This follows from how the method works. It cites no source.">reasoning</span> {{ m.reasoning }}</p>
                <p v-if="m.unsourced"><span class="gl-mark warn" title="This claim cites no primary source yet.">no source yet</span> {{ m.unsourced }}</p>
                <p v-if="m.namedIn?.length" class="muted">Named, but not run, in lessons {{ m.namedIn.join(', ') }}.</p>
                <p class="gl-sources">
                  <b>Sources.</b>
                  <template v-for="id in m.sources" :key="id">
                    <a v-if="src(id)" :href="src(id).url" target="_blank" rel="noopener noreferrer" class="gl-link" data-testid="glossary-source-link">{{ sourceLabel(src(id)) }}</a>
                    <span v-if="src(id)?.draft" class="gl-mark">draft</span>
                  </template>
                </p>
              </td>
            </tr>
          </template>
          <tr v-if="!methods.length"><td colspan="6" class="muted">No method matches.</td></tr>
        </tbody>
      </table>
    </div>

    <template v-if="!query">
      <h2 class="gl-h">{{ g.comparison.title }}</h2>
      <div class="gl-compare">
        <div v-for="[key, title, side] in sides" :key="key" class="gl-side" :data-testid="`glossary-compare-${key}`">
          <h3>{{ title }}</h3>
          <p>{{ side.meaning }}</p>
          <template v-for="[label, list] in ([['Strengths', side.strengths], ['Weaknesses', side.weaknesses]] as const)" :key="label">
            <h4>{{ label }}</h4>
            <ul>
              <li v-for="(c, i) in list" :key="claimKey(c, i)">
                {{ c.text }}
                <span v-if="c.basis === 'reasoning'" class="gl-mark" title="This follows from how the method works. It cites no source." data-testid="glossary-reasoning-mark">reasoning</span>
                <template v-for="id in c.sources ?? []" :key="id">
                  <a v-if="src(id)" :href="src(id).url" target="_blank" rel="noopener noreferrer" class="gl-link" data-testid="glossary-source-link">{{ sourceLabel(src(id)) }}</a>
                  <span v-if="src(id)?.draft" class="gl-mark">draft</span>
                </template>
              </li>
            </ul>
          </template>
          <p v-if="side.notAllEncrypt" class="gl-note">{{ side.notAllEncrypt }}</p>
        </div>
      </div>
      <div class="gl-myth" data-testid="glossary-myth">
        <p><b>Myth.</b> {{ g.comparison.myth.claim }}</p>
        <p><b>What is true.</b> {{ g.comparison.myth.truth }}
          <a v-for="id in g.comparison.myth.sources" :key="id" :href="src(id).url" target="_blank" rel="noopener noreferrer" class="gl-link" data-testid="glossary-source-link">{{ sourceLabel(src(id)) }}</a>
        </p>
      </div>
      <div class="gl-tls" data-testid="glossary-tls">
        <h3>TLS 1.3 uses both</h3>
        <ol><li v-for="(s, i) in g.comparison.tlsUsesBoth.steps" :key="i">{{ s }}</li></ol>
        <p>{{ g.comparison.tlsUsesBoth.why }}
          <a v-for="id in g.comparison.tlsUsesBoth.sources" :key="id" :href="src(id).url" target="_blank" rel="noopener noreferrer" class="gl-link" data-testid="glossary-source-link">{{ sourceLabel(src(id)) }}</a>
        </p>
        <p class="muted">Lessons {{ g.comparison.tlsUsesBoth.lessons.join(', ') }} run these steps.</p>
      </div>
    </template>

    <h2 class="gl-h">Terms</h2>
    <dl class="gl-terms" data-testid="glossary-terms">
      <div v-for="t in terms" :id="`glossary-entry-${t.id}`" :key="t.id" class="gl-term" :class="{ flash: flash === t.id }" :data-testid="`glossary-term-${t.id}`">
        <dt>{{ t.term }}</dt><dd><TextWithSpecs :text="t.short" /></dd>
      </div>
      <p v-if="!terms.length" class="muted">No term matches.</p>
    </dl>
  </section>
</template>
