// The first window size. The app asks for 1440 x 900, but a 1080p screen at 125 percent scale gives a work area of about
// 1536 x 824, so a 900-high window ran under the taskbar and cut off the status bar. The window now takes the smaller
// of the wish and the work area, and sits centered inside the work area.
const WANT = { width: 1440, height: 900 }

/** @param {{ x: number, y: number, width: number, height: number }} area the display work area */
function fitWindow(area, want = WANT) {
  const width = Math.min(want.width, area.width)
  const height = Math.min(want.height, area.height)
  return { width, height, x: area.x + Math.round((area.width - width) / 2), y: area.y + Math.round((area.height - height) / 2) }
}

module.exports = { fitWindow, WANT }
