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
        colors: { background: '#0e1318', surface: '#151c23', 'surface-variant': '#1d2630', 'on-surface-variant': '#e6edf3', primary: '#56b4e9', secondary: '#b39dff', success: '#3fb950', warning: '#e0a82e', error: '#ff6b6b', info: '#56b4e9' },
      },
      nsLight: {
        dark: false,
        colors: { background: '#f6f8fa', surface: '#ffffff', 'surface-variant': '#e8edf2', 'on-surface-variant': '#1f2933', primary: '#0072b2', secondary: '#6a4fc2', success: '#176f32', warning: '#8a6100', error: '#c4242f', info: '#0072b2' },
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
