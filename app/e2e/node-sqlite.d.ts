// Types for node:sqlite, only the members app/e2e/vault-v1.spec.ts uses. @types/node 20 predates the module (Node 22.5 and later have it; this
// machine runs Node 24). A bump of @types/node can replace this file later, as its own change.
declare module 'node:sqlite' {
  export class DatabaseSync {
    constructor(path: string)
    exec(sql: string): void
    close(): void
  }
}
