<script setup lang="ts">
import { ptText, type ToyCurve } from '../curveWalk'

// ECDH and ECDSA on the toy curve, and what a reused nonce gives away (slice P8a; R7, the end of video 4Tfmwxr0I34). The keys are the video's
// public teaching values (keySource "toy"), never a session's key, so the card stays open with Show keys off. Every number is the engine's (R5).
const props = defineProps<{ toy: ToyCurve }>()
const n = () => props.toy.curve.order
</script>

<template>
  <section class="cw-card" data-testid="curve-sign-card" aria-label="ECDH and ECDSA on the toy curve">
    <h3>5. ECDH: two sides, one shared point</h3>
    <div class="cw-ecdh">
      <p>Alice keeps <b>{{ toy.ecdh.alicePrivate }}</b> and sends {{ toy.ecdh.alicePrivate }}·G = <b>{{ ptText(toy.ecdh.alicePublic) }}</b>.</p>
      <p>Bob keeps <b>{{ toy.ecdh.bobPrivate }}</b> and sends {{ toy.ecdh.bobPrivate }}·G = <b>{{ ptText(toy.ecdh.bobPublic) }}</b>.</p>
      <p>Alice: {{ toy.ecdh.alicePrivate }} × Bob's point = <b>{{ ptText(toy.ecdh.aliceShared) }}</b>. Bob: {{ toy.ecdh.bobPrivate }} × Alice's point = <b>{{ ptText(toy.ecdh.bobShared) }}</b>. The same point, and it never crossed the wire.</p>
    </div>

    <h3>6. ECDSA: sign twice with one nonce, and the key falls out</h3>
    <p class="muted">A signature is r and s. r comes from a fresh secret nonce k. If the signer uses the same k twice, both signatures share r, and anyone can work out k and then the private key.</p>
    <div class="cw-reuse" data-testid="curve-reuse-panel">
      <table class="cw-table">
        <thead><tr><th></th><th>message hash z</th><th>nonce k</th><th>r</th><th>s</th></tr></thead>
        <tbody>
          <tr><th>Signature 1</th><td data-testid="curve-reuse-z1">{{ toy.ecdsa.first.z }}</td><td data-testid="curve-reuse-k">{{ toy.ecdsa.first.nonce }}</td><td data-testid="curve-reuse-r">{{ toy.ecdsa.first.r }}</td><td data-testid="curve-reuse-s1">{{ toy.ecdsa.first.s }}</td></tr>
          <tr><th>Signature 2</th><td data-testid="curve-reuse-z2">{{ toy.ecdsa.second.z }}</td><td>{{ toy.ecdsa.second.nonce }}</td><td>{{ toy.ecdsa.second.r }}</td><td data-testid="curve-reuse-s2">{{ toy.ecdsa.second.s }}</td></tr>
        </tbody>
      </table>
      <p>The signer's private key: <b data-testid="curve-reuse-d">{{ toy.ecdsa.signerPrivate }}</b>. A listener sees only z, r and s.</p>
      <ol class="cw-recover">
        <li>Same r twice, so the nonce was reused.</li>
        <li>k = (z1 − z2) × (s1 − s2)⁻¹ mod {{ n() }}. The inverse of (s1 − s2) is {{ toy.ecdsa.recovery.sDifferenceInverse.value }}, so k = <b>{{ toy.ecdsa.recovery.nonce }}</b>.</li>
        <li>d = (s1 × k − z1) × r⁻¹ mod {{ n() }}. The inverse of r is {{ toy.ecdsa.recovery.rInverse.value }}, so d = <b data-testid="curve-reuse-recovered-d">{{ toy.ecdsa.recovery.privateKey }}</b>.</li>
      </ol>
      <p class="muted cw-small">This is why a signer must never reuse a nonce. Ed25519 makes its nonce from the key and the message, so it cannot repeat by accident.</p>
    </div>
  </section>
</template>
