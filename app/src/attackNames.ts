// A readable name for each attack run, from attacks.json. The Host's lesson list gives the run's id, lesson and check; the name is
// course copy, so it lives beside the guard words. A run the file does not name yet shows the fallback the caller gives.
import data from './attacks.json'

const NAMES: ReadonlyMap<string, string> = new Map(
  (data as { runs: { attackId: string; name?: string }[] }).runs.filter(r => r.name).map(r => [r.attackId, r.name as string]),
)

export const attackName = (attackId: string, fallback: string): string => NAMES.get(attackId) ?? fallback
