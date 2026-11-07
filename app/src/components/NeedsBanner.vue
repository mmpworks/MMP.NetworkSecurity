<script setup lang="ts">
import { ref } from 'vue'
import TextWithSpecs from './TextWithSpecs.vue'
import { dismissNeeds, sec, setUpNow, useBuiltinForLesson, words } from '../security'

const confirm = ref(false)
const title = (typeId: string) => words(`wizard.type.${typeId}.title`, typeId)
const count = () => sec.needs?.problems.length ?? 0
</script>

<template>
  <v-alert v-if="sec.needs" type="warning" class="banner needs" closable data-testid="security-needs-banner" @click:close="dismissNeeds">
    <b>Lesson {{ sec.needs.lesson }} needs {{ count() }} {{ count() === 1 ? 'key' : 'keys' }} that still {{ count() === 1 ? 'needs' : 'need' }} setting up.</b>
    <div v-for="p in sec.needs.problems" :key="p.typeId" class="needs-row" :data-testid="`needs-row-${p.typeId}`">
      <span>{{ title(p.typeId) }}: <span :data-testid="`needs-code-${p.typeId}`">{{ p.code }}</span>. <TextWithSpecs :text="p.detail" /></span>
      <v-btn size="small" variant="tonal" :data-testid="`needs-setup-${p.typeId}`" @click="setUpNow(p.typeId)">Set up now</v-btn>
    </div>
    <template #append>
      <v-btn v-if="!confirm" size="small" data-testid="needs-use-builtin" @click="confirm = true">{{ words('wizard.refusal.use-builtin') }}</v-btn>
      <span v-else class="needs-confirm" data-testid="needs-confirm">
        {{ words('wizard.refusal.confirm') }}
        <v-btn size="small" color="primary" data-testid="needs-confirm-yes" @click="useBuiltinForLesson">Yes, use built-in keys</v-btn>
        <v-btn size="small" variant="text" data-testid="needs-confirm-no" @click="confirm = false">No</v-btn>
      </span>
    </template>
  </v-alert>
</template>
