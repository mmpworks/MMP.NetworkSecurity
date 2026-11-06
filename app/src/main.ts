import { createApp } from 'vue'
import 'vuetify/dist/vuetify.min.css'
import '@mdi/font/css/materialdesignicons.css'
import 'splitpanes/dist/splitpanes.css'
import App from './App.vue'
import { vuetify } from './theme'
// The fonts ship inside the app, so it works offline. Only the Latin subset and the weights in use are bundled.
import '@fontsource/atkinson-hyperlegible/latin-400.css'
import '@fontsource/atkinson-hyperlegible/latin-700.css'
import '@fontsource/familjen-grotesk/latin-500.css'
import '@fontsource/familjen-grotesk/latin-700.css'
import '@fontsource/jetbrains-mono/latin-400.css'
import '@fontsource/jetbrains-mono/latin-600.css'
import './style.css'
import './lessons.css'

createApp(App).use(vuetify).mount('#app')
