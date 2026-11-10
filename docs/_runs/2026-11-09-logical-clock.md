# Logical clock kill condition, 2026-11-09

Result: 58 of 58 cases give every engine-stream event the same clock in 20 of 20 runs (10 idle, 10 beside a CPU burner on every core).

Command, under `tools/heavy_lock.py`: `NETSEC_CLOCK_RUNS=1 dotnet test tests/NetSec.Host.Tests -c Release --filter FullyQualifiedName~LogicalClockRunTests.Same_seed`.

Two runs make up this record:
1. Branch `feat/logical-clock` at 51ad050 (42b300e and later after the rebase): all 58 cases. 56 were 20 of 20. `L4-unknown-ca` (19 of 20) and `L10-remove-client-cert` (13 of 20) varied at a stream's tail, compared whole.
2. At 10322b0 (ff5c8d4 after the rebase onto db2bce3), which adds those 2 forks to the up-to-the-catch list (plan, lead's option A): the 2 forks again, 20 of 20 each. The clock code is the same in both runs; only the list changed.

| Case | Same clocks | Compared | Catch |
|---|---|---|---|
| `L10-stolen-token` | 20 of 20 | whole | server/auth-call#3 |
| `L2-flip-hash-message` | 20 of 20 | up to the catch | server/seal#4 |
| `L8-flip-exchange-signature` | 20 of 20 | whole | client/ssh#14 |
| `L3-flip-mlkem-ciphertext` | 20 of 20 | up to the catch | server/kex#15 |
| `L4-expired-cert` | 20 of 20 | whole | client/tls13#19 |
| `L2-flip-hmac-message` | 20 of 20 | up to the catch | server/seal#10 |
| `L8-refused-tunnel` | 20 of 20 | whole | server/ssh#50 |
| `L6-ask-past-key` | 20 of 20 | whole | reader/dukpt#15 |
| `L4-flip-cert-verify` | 20 of 20 | whole | client/tls13#25 |
| `lesson 10` | 20 of 20 | whole | none |
| `L0-flip-wire-byte` | 20 of 20 | whole | client/echo#4 |
| `lesson 7` | 20 of 20 | whole | none |
| `L8-flip-packet` | 20 of 20 | whole | server/ssh#36 |
| `L10-wrong-client-name` | 20 of 20 | whole | server/auth-mtls#24 |
| `L10-unissued-challenge` | 20 of 20 | whole | issuer/auth-login#7 |
| `L6-replay-sale` | 20 of 20 | whole | bank/dukpt#10 |
| `L10-ungranted-capability` | 20 of 20 | whole | server/auth-call#23 |
| `L5-replace-key-share` | 20 of 20 | whole | client/tls13#18 |
| `L10-unknown-device` | 20 of 20 | whole | issuer/auth-login#3 |
| `L10-replay-proof` | 20 of 20 | whole | server/auth-call#13 |
| `L8-wrong-user-key` | 20 of 20 | whole | server/ssh#37 |
| `L8-legacy-flip-signature` | 20 of 20 | whole | client/ssh-legacy#17 |
| `L8-change-host-key` | 20 of 20 | whole | client/ssh#14 |
| `lesson 11` | 20 of 20 | whole | none |
| `L4-flip-cert-byte` | 20 of 20 | whole | client/tls13#19 |
| `L2-extend-hmac` | 20 of 20 | up to the catch | server/seal#10 |
| `L5-flip-finished` | 20 of 20 | whole | client/tls13#30 |
| `L10-wrong-audience` | 20 of 20 | whole | server/auth-call#3 |
| `L10-replay-challenge` | 20 of 20 | whole | issuer/auth-login#14 |
| `L5-clear-close-notify` | 20 of 20 | whole | server/tls13#28 |
| `L1-flip-gcm` | 20 of 20 | up to the catch | server/aes#5 |
| `lesson 1` | 20 of 20 | whole | none |
| `L9-tamper-hop2` | 20 of 20 | whole | server/tls13#28 |
| `L8-zero-share` | 20 of 20 | whole | client/ssh#14 |
| `L7-downgrade` | 20 of 20 | up to the catch | client/tls13#4 |
| `L6-flip-pin-block` | 20 of 20 | whole | bank/dukpt#5 |
| `L10-corrupt-client-cert` | 20 of 20 | whole | server/auth-mtls#24 |
| `L7-flip-record` | 20 of 20 | whole | server/tls11#25 |
| `L2-flip-cmac-message` | 20 of 20 | whole | server/seal#13 |
| `L5-flip-record-byte` | 20 of 20 | whole | client/tls13#18 |
| `L2-flip-hmac-tag` | 20 of 20 | up to the catch | server/seal#10 |
| `L2-flip-cmac-tag` | 20 of 20 | whole | server/seal#13 |
| `L4-wrong-name` | 20 of 20 | whole | client/tls13#19 |
| `L5-flip-mlkem-ciphertext` | 20 of 20 | whole | client/tls13#18 |
| `lesson 9` | 20 of 20 | whole | none |
| `L10-expired-token` | 20 of 20 | whole | server/auth-call#3 |
| `L5-flip-record-length` | 20 of 20 | whole | client/tls13#29 |
| `L3-swap-server-share` | 20 of 20 | up to the catch | server/kex#8 |
| `L10-wrong-role` | 20 of 20 | whole | server/auth-call#3 |
| `L1-reuse-nonce` | 20 of 20 | whole | server/aes#24 |
| `L9-flip-pin-block` | 20 of 20 | whole | bank/bridge#1 |
| `L9-tamper-hop1` | 20 of 20 | whole | gateway/ssh#43 |
| `L10-change-token-claim` | 20 of 20 | whole | server/auth-call#3 |
| `L7-decrypt-recording` | 20 of 20 | whole | attacker/tls11#2 |
| `L7-modern-server` | 20 of 20 | whole | server/tls13#3 |
| `L11-guess-constant-time` | 20 of 20 | whole | attacker/timing#1 |
| `L4-unknown-ca` (run 2) | 20 of 20 | up to the catch | client/tls13#19 |
| `L10-remove-client-cert` (run 2) | 20 of 20 | up to the catch | server/auth-mtls#24 |

Run 1's first differences for the 2 forks, as the test printed them:

```
L4-unknown-ca: same clocks in 19 of 20 (whole, catch client/tls13#19)
  idle run 4: server/tls13 entry 17: run 1 'server/tls13#17 secret.derived  clock=18', this run '(end)'
L10-remove-client-cert: same clocks in 13 of 20 (whole, catch server/auth-mtls#24)
  idle run 2: client/auth-mtls entry 40: run 1 'client/auth-mtls#40 tls.alert.received alert level 2, number 116 clock=42', this run '(end)'
  idle run 4: client/auth-mtls entry 40: run 1 'client/auth-mtls#40 tls.alert.received alert level 2, number 116 clock=42', this run '(end)'
  idle run 6: client/auth-mtls entry 40: run 1 'client/auth-mtls#40 tls.alert.received alert level 2, number 116 clock=42', this run '(end)'
  idle run 8: client/auth-mtls entry 40: run 1 'client/auth-mtls#40 tls.alert.received alert level 2, number 116 clock=42', this run '(end)'
  idle run 9: client/auth-mtls entry 40: run 1 'client/auth-mtls#40 tls.alert.received alert level 2, number 116 clock=42', this run '(end)'
  idle run 10: client/auth-mtls entry 40: run 1 'client/auth-mtls#40 tls.alert.received alert level 2, number 116 clock=42', this run '(end)'
  load run 17: client/auth-mtls entry 40: run 1 'client/auth-mtls#40 tls.alert.received alert level 2, number 116 clock=42', this run '(end)'
```
