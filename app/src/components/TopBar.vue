<script setup lang="ts">
import { computed } from 'vue'
import { GLASS_NOTE, TARGET_DEVICES, hostState, trainingChip, ui } from '../store'
import { SECTIONS } from '../sections'
import type { ViewMode } from '../types'
import { badgeCount, keysChip, openSecurity } from '../security'
import SettingsMenu from './SettingsMenu.vue'
import ShowKeysSwitch from './ShowKeysSwitch.vue'

// Grouped by job: the section and the view, where it runs, your keys. Tour and Free play sit inside Lessons, at the head of their panel. OS transport stays here at every width, because clause A16.ui.os-transport-label-and-hidden-secrets clicks it.
const VIEWS: readonly (readonly [ViewMode, string])[] = [['endpoints', 'Endpoints'], ['eavesdropper', 'Eavesdropper'], ['both', 'Both']]
const hostWord = computed(() => (hostState.value === 'connected' ? 'Connected' : hostState.value === 'connecting' ? 'Starting' : 'Offline'))
const ownKeys = computed(() => keysChip.value !== 'Keys: built-in')
function toggleTransport() { ui.transport = ui.transport === 'os' ? 'glass' : 'os' }
</script>

<template>
  <header class="topbar" data-testid="top-bar">
    <span class="app-title">Network Security Lab</span>
    <v-tooltip location="bottom" max-width="340">
      <template #activator="{ props: p }">
        <v-chip v-bind="p" label variant="outlined" size="small" :color="trainingChip === 'OS TRANSPORT' ? 'info' : 'warning'" data-testid="training-only-label" tabindex="0">
          <v-icon start size="14">{{ trainingChip === 'OS TRANSPORT' ? 'mdi-lock-outline' : 'mdi-lock-open-variant-outline' }}</v-icon>{{ trainingChip }}
        </v-chip>
      </template>
      <span v-if="trainingChip === 'TRAINING ONLY'">This engine shows its keys on purpose. Never use it with real secrets. {{ GLASS_NOTE }}</span>
      <span v-else>The OS handles the keys and this course shows none of them.</span>
    </v-tooltip>
    <span class="seg" role="group" aria-label="Section" data-testid="section-switch">
      <button v-for="s in SECTIONS" :key="s.id" type="button" :aria-pressed="ui.section === s.id" :data-testid="`section-${s.id}`" @click="ui.section = s.id">{{ s.label }}</button>
    </span>
    <span v-if="ui.section === 'lessons'" class="seg" role="group" aria-label="View" data-testid="view-switch">
      <button v-for="[id, label] in VIEWS" :key="id" type="button" :aria-pressed="ui.view === id" :data-testid="`view-${id}`" @click="ui.view = id">{{ label }}</button>
    </span>
    <v-spacer />
    <label class="field">Target device
      <select v-model="ui.target" data-testid="target-select"><option v-for="d in TARGET_DEVICES" :key="d.id" :value="d.id" :disabled="!d.enabled">{{ d.label }}</option></select>
    </label>
    <v-tooltip location="bottom" max-width="340">
      <template #activator="{ props: p }">
        <button v-bind="p" type="button" class="tool" data-testid="security-setup-button" @click="openSecurity">
          <v-icon size="15">mdi-shield-key-outline</v-icon>Security setup
          <span class="tool-count" :class="{ mine: ownKeys }" data-testid="keys-chip">{{ keysChip }}</span>
          <v-badge v-if="badgeCount" :content="badgeCount" color="warning" inline data-testid="security-badge" />
        </button>
      </template>
      <span>Whose key signs: the course's own, or yours. Click to change.</span>
    </v-tooltip>
    <ShowKeysSwitch testid="show-keys-switch" />
    <button type="button" class="tool" data-testid="transport-switch" :aria-pressed="ui.transport === 'os'" @click="toggleTransport">OS transport</button>
    <span class="engine" :class="hostState" data-testid="host-chip" :title="`Engine: ${hostWord}`"><i aria-hidden="true" /><b>{{ hostWord }}</b></span>
    <SettingsMenu />
  </header>
</template>
