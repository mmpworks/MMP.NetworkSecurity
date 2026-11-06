import { createVuetify } from 'vuetify'
import * as components from 'vuetify/components'
import * as directives from 'vuetify/directives'
import { aliases, mdi } from 'vuetify/iconsets/mdi'

// Two themes, nsDark and nsLight. The CSS variables for the same names live in style.css under :root[data-theme].
// Readable vs encrypted is a blue and amber pair that stays distinct under the common forms of color blindness (ux-design.md section 4.1).
export const vuetify = createVuetify({
  components,
  directives,
  icons: { defaultSet: 'mdi', aliases, sets: { mdi } },
  theme: {
    defaultTheme: 'nsDark',
    themes: {
      nsDark: {
        dark: true,
        colors: { background: '#10141f', surface: '#1a2030', 'surface-variant': '#232b3e', 'on-surface-variant': '#e9edf6', primary: '#8ea6ff', 'on-primary': '#10141f', secondary: '#b39dff', success: '#3fb950', warning: '#e0a82e', error: '#ff6b6b', info: '#56b4e9' },
      },
      nsLight: {
        dark: false,
        colors: { background: '#eef1f7', surface: '#ffffff', 'surface-variant': '#e2e7f1', 'on-surface-variant': '#141b2d', primary: '#2748c9', secondary: '#6a4fc2', success: '#176f32', warning: '#8a6100', error: '#c4242f', info: '#0072b2' },
      },
    },
  },
  defaults: {
    VBtn: { density: 'comfortable', variant: 'tonal', size: 'small', class: 'text-none' },
    VChip: { size: 'small', variant: 'outlined', label: true },
    VCard: { variant: 'flat', rounded: 'lg' },
    VAlert: { density: 'compact', variant: 'tonal' },
  },
})
