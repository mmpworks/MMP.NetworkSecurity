// The renderer gets the Host address and token from the main process through window.netsec.host.
const { contextBridge } = require('electron')
const arg = name => (process.argv.find(a => a.startsWith(`--${name}=`)) || '').slice(name.length + 3)
contextBridge.exposeInMainWorld('netsec', { host: { port: Number(arg('netsec-port')) || 5180, token: arg('netsec-token') } })
