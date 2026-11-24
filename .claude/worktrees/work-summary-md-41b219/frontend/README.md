# Frontend (Member 5)

Next.js App Router UI for Software Supply Chain Guardian: submit a public GitHub URL, poll scan
status, view inventory / normalized SBOM, and explore the Cytoscape dependency graph.
Contracts are defined in the root [`README.md`](../README.md) and `backend/app/schemas` (v1.0).

## Run

```bash
npm ci
cp .env.local.example .env.local          # PowerShell: Copy-Item .env.local.example .env.local
npm run dev                               # http://localhost:3000
```

Offline sample mode (no backend): add `NEXT_PUBLIC_USE_MOCKS=true` to your local `.env.local`
and restart. The UI then shows a **Sample data (offline)** badge; fixtures live in `src/mocks/`
and are synthetic. Real API failures never fall back to mock data.

## Checks

```bash
npm run lint
npm run typecheck
npm run test      # vitest + jsdom; Cytoscape is stubbed, verify the canvas manually in a browser
npm run build
```

## Layout

- `src/types/` — TypeScript mirrors of the v1.0 API, SBOM and graph contracts
- `src/services/` — `api` (axios), `mockApi` (deterministic stage progression), `scanService` selector, error mapping
- `src/hooks/useScan.ts` — single-timer polling with backoff, then parallel artifact fetch
- `src/lib/graph.ts` — pure search / filter / large-graph limiting / payload validation
- `src/components/graph/` — client-only Cytoscape canvas (dagre layout), toolbar, inspector
