// The hosts the app may open in the learner's own web browser. Every other link is refused.
// The list equals the hosts of the sources in src/glossary.json; e2e/links.spec.ts fails when the two differ.
// A host matches only in full: no suffix or prefix match, so evil-csrc.nist.gov.example is refused.
// Rule text: docs/ux-design.md, section 5a.
const HOSTS = new Set([
  'csrc.nist.gov',
  'doi.org',
  'w2.eff.org',
  'webstore.ansi.org',
  'www.govinfo.gov',
  'www.rfc-editor.org',
  'x9.org',
])

/** True only for an https URL on the default port whose host is on the list, with no user info. A URL that does not parse is refused. */
function isAllowedLink(url) {
  try {
    const u = new URL(url)
    return u.protocol === 'https:' && HOSTS.has(u.hostname) && u.port === '' && !u.username && !u.password
  } catch {
    return false
  }
}

module.exports = { HOSTS, isAllowedLink }
