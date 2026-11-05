# Lesson 6: names the lab emits

Status: stable. The tour and the UI bind to these names. A change goes through Richard. Date: 2026-11-05.

The rules in `docs/lessons-1-3-names.md`, section "Rules for all three lessons" and section "Try-it actions", apply here too. Read them first.

Lab id: `lab-06-dukpt`. Protocol: `dukpt`. Lanes: `reader`, `bank`.

## The run

The reader makes 4 sales, one at a time. Each sale uses the next counter, 1 to 4. The bank answers `SaleApproved` to sales 1, 2, 3, and `SaleDone` to sale 4.

| Message | Direction | Field names in order | `visibleToWire` |
|---|---|---|---|
| `Sale` | reader to bank | `type`, `length`, `ksn`, `pinBlock` | `pinBlock` false, the others true |
| `SaleApproved` | bank to reader | `type`, `length` | true |
| `SaleDone` | bank to reader | `type`, `length` | true |

`ksn` is 12 bytes: the 8-byte initial key id, then the 4-byte counter. `pinBlock` is 16 bytes. `plain` on `dukpt.message.sent` holds the PIN digits as text. `plain` on `dukpt.message.received` at the bank holds the PIN digits it opened.

## Events

`<c>` is the counter of that sale, as a decimal number.

| Event type | `actor` | `message` | Carries |
|---|---|---|---|
| `dukpt.key.derived` | `bank` | `dukpt.bdk` | `secrets[]`: `dukpt.bdk`, 16 bytes. The base key. It stays at the bank for the whole run |
| `dukpt.key.derived` | `reader`, `bank` | `dukpt.initial` | `secrets[]`: `dukpt.initial`, 16 bytes. Compare the two sides |
| `dukpt.key.erased` | `reader` | `dukpt.initial` | Nothing more. The reader loaded its registers and erased the initial key |
| `measure.result` | `reader` | `Reader registers` | `detail`: `held=<n>;next=<c>`. One after the load and one after each sale |
| `dukpt.key.derived` | `reader`, `bank` | `dukpt.pinKey.<c>` | `secrets[]`: one entry, 16 bytes. Compare the two sides for one sale. `derivedFrom` names the parent |
| `dukpt.key.erased` | `reader` | `dukpt.derivationKey.<c>` | Nothing more. Bind moment 5 here: this rung burns |
| `check.result` | `bank` | `KSN already seen` | Pass on each sale |
| `check.result` | `bank` | `PIN block format check` | Pass on each sale |

Order on the reader for one sale: `dukpt.key.derived`, `dukpt.message.sent`, `wire.sent`, `dukpt.key.erased`, `measure.result`.

Order on the bank for one sale: `dukpt.message.received`, `check.result` (`KSN already seen`), `dukpt.key.derived`, `check.result` (`PIN block format check`), `dukpt.message.sent`, `wire.sent`.

The reader's `held` values in a run: 32 after the load, then 31, 31, 30, 31. So the count does not fall on every sale. A sale erases one register, and it can fill lower ones with child keys. The UI reads `held` from the event and invents no number.

## Attacks

| Attack id | What it does | `Expect` | Code | Check name | Actor that catches it |
|---|---|---|---|---|---|
| `L6-replay-sale` | After sale 1 is approved, the reader sends the same `Sale` bytes again | `Rejected` | `DUKPT_KSN_REPLAY` | `KSN already seen` | `bank` |
| `L6-flip-pin-block` | Flips one bit in the `pinBlock` of sale 1 | `Rejected` | `DUKPT_PINBLOCK_FORMAT` | `PIN block format check` | `bank` |
| `L6-ask-past-key` | After sale 2 is approved, the reader tries to build the key of counter 1 from its registers | `Rejected` | `DUKPT_KEY_NOT_HELD` | `key not in reader state` | `reader` |

## Facts the tour needs

1. A managed heap can keep copies, so erasing a register does not prove the bytes are gone from memory. A3 reads this statement in `lesson-06.json`.
2. The tour step label from accuracy rule 7: `Built to show the parts. Do not copy.`
3. All keys here are made up. `dukpt-bdk-128` comes from `TrainingKeySource`, and anyone can read it in the source.
4. The bank keeps the base key and derives each key again from the KSN. It holds no per-reader key.
