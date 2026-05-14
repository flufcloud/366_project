# Repository security scan

- **Root:** `/mnt/c/Users/Sidd/Desktop/academic/projects/datapipe`
- **Generated (UTC):** 2026-05-14 00:45:29Z
- **Files matched allowlist:** 141
- **Redaction pattern matches (total):** 0

## Overview

This section is a **deterministic inventory** from allowlisted source files (counts, paths, redaction totals). A **concise LLM narrative** is appended when LLM credentials are configured (`--set-token llm`); otherwise only this inventory is emitted (no full-repo code dump).

## File index

| Path | Ext | Bytes | Lines | Redactions | Notes |
|------|-----|------:|------:|-----------:|-------|
| `AGENTS.md` | .md | 1326 | 36 | 0 |  |
| `README.md` | .md | 12943 | 443 | 0 |  |
| `apps/execution-engine/.local/token-vault.json` | .json | 1170 | 46 | 0 |  |
| `apps/execution-engine/AGENTS.md` | .md | 759 | 29 | 0 |  |
| `apps/execution-engine/package-lock.json` | .json | 39920 | 1096 | 0 |  |
| `apps/execution-engine/package.json` | .json | 347 | 19 | 0 |  |
| `apps/execution-engine/src/app.js` | .js | 13874 | 472 | 0 |  |
| `apps/execution-engine/src/integrations/spotify-adapter.js` | .js | 16707 | 562 | 0 |  |
| `apps/execution-engine/src/integrations/token-vault.js` | .js | 2905 | 109 | 0 |  |
| `apps/execution-engine/src/server.js` | .js | 222 | 8 | 0 |  |
| `apps/execution-engine/test/api.test.js` | .js | 12634 | 382 | 0 |  |
| `apps/orchestrator/AGENTS.md` | .md | 857 | 31 | 0 |  |
| `apps/orchestrator/_build/dev/lib/phoenix/priv/static/phoenix.cjs.js` | .js | 46906 | 1577 | 0 |  |
| `apps/orchestrator/_build/dev/lib/phoenix/priv/static/phoenix.js` | .js | 50015 | 1578 | 0 |  |
| `apps/orchestrator/_build/dev/lib/phoenix/priv/static/phoenix.min.js` | .js | 22941 | 2 | 0 |  |
| `apps/orchestrator/_build/dev/lib/phoenix/priv/static/phoenix.mjs` | .mjs | 45934 | 1555 | 0 |  |
| `apps/orchestrator/_build/dev/lib/phoenix/priv/templates/phx.gen.socket/socket.js` | .js | 2313 | 64 | 0 |  |
| `apps/orchestrator/_build/test/lib/phoenix/priv/static/phoenix.cjs.js` | .js | 46906 | 1577 | 0 |  |
| `apps/orchestrator/_build/test/lib/phoenix/priv/static/phoenix.js` | .js | 50015 | 1578 | 0 |  |
| `apps/orchestrator/_build/test/lib/phoenix/priv/static/phoenix.min.js` | .js | 22941 | 2 | 0 |  |
| `apps/orchestrator/_build/test/lib/phoenix/priv/static/phoenix.mjs` | .mjs | 45934 | 1555 | 0 |  |
| `apps/orchestrator/_build/test/lib/phoenix/priv/templates/phx.gen.socket/socket.js` | .js | 2313 | 64 | 0 |  |
| `apps/orchestrator/data/graphs/phase2_runtime.json` | .json | 1233 | 65 | 0 |  |
| `apps/orchestrator/data/graphs/phase3_debug.json` | .json | 1902 | 91 | 0 |  |
| `apps/orchestrator/data/graphs/phase3_runtime.json` | .json | 1904 | 91 | 0 |  |
| `apps/orchestrator/data/graphs/phase3_runtime_ok.json` | .json | 2833 | 136 | 0 |  |
| `apps/orchestrator/data/graphs/phase4_hardening_runtime.json` | .json | 6838 | 265 | 0 |  |
| `apps/orchestrator/data/graphs/phase4_runtime_ok.json` | .json | 6714 | 263 | 0 |  |
| `apps/orchestrator/data/graphs/proj_demo.json` | .json | 716 | 34 | 0 |  |
| `apps/orchestrator/deps/castore/README.md` | .md | 1854 | 56 | 0 |  |
| `apps/orchestrator/deps/cowboy_telemetry/README.md` | .md | 2925 | 70 | 0 |  |
| `apps/orchestrator/deps/dns_cluster/CHANGELOG.md` | .md | 348 | 13 | 0 |  |
| `apps/orchestrator/deps/dns_cluster/LICENSE.md` | .md | 1071 | 22 | 0 |  |
| `apps/orchestrator/deps/dns_cluster/README.md` | .md | 1101 | 45 | 0 |  |
| `apps/orchestrator/deps/jason/CHANGELOG.md` | .md | 3656 | 132 | 0 |  |
| `apps/orchestrator/deps/jason/README.md` | .md | 5244 | 157 | 0 |  |
| `apps/orchestrator/deps/mime/CHANGELOG.md` | .md | 1078 | 51 | 0 |  |
| `apps/orchestrator/deps/mime/README.md` | .md | 1026 | 32 | 0 |  |
| `apps/orchestrator/deps/phoenix/CHANGELOG.md` | .md | 11046 | 287 | 0 |  |
| `apps/orchestrator/deps/phoenix/LICENSE.md` | .md | 1071 | 22 | 0 |  |
| `apps/orchestrator/deps/phoenix/README.md` | .md | 3209 | 94 | 0 |  |
| `apps/orchestrator/deps/phoenix/assets/js/phoenix/ajax.js` | .js | 2455 | 83 | 0 |  |
| `apps/orchestrator/deps/phoenix/assets/js/phoenix/channel.js` | .js | 8730 | 311 | 0 |  |
| `apps/orchestrator/deps/phoenix/assets/js/phoenix/constants.js` | .js | 785 | 29 | 0 |  |
| `apps/orchestrator/deps/phoenix/assets/js/phoenix/index.js` | .js | 7445 | 207 | 0 |  |
| `apps/orchestrator/deps/phoenix/assets/js/phoenix/longpoll.js` | .js | 5575 | 175 | 0 |  |
| `apps/orchestrator/deps/phoenix/assets/js/phoenix/presence.js` | .js | 4871 | 162 | 0 |  |
| `apps/orchestrator/deps/phoenix/assets/js/phoenix/push.js` | .js | 2556 | 128 | 0 |  |
| `apps/orchestrator/deps/phoenix/assets/js/phoenix/serializer.js` | .js | 4305 | 112 | 0 |  |
| `apps/orchestrator/deps/phoenix/assets/js/phoenix/socket.js` | .js | 20161 | 657 | 0 |  |
| `apps/orchestrator/deps/phoenix/assets/js/phoenix/timer.js` | .js | 1041 | 42 | 0 |  |
| `apps/orchestrator/deps/phoenix/assets/js/phoenix/utils.js` | .js | 213 | 9 | 0 |  |
| `apps/orchestrator/deps/phoenix/package.json` | .json | 738 | 26 | 0 |  |
| `apps/orchestrator/deps/phoenix/priv/static/phoenix.cjs.js` | .js | 46906 | 1577 | 0 |  |
| `apps/orchestrator/deps/phoenix/priv/static/phoenix.js` | .js | 50015 | 1578 | 0 |  |
| `apps/orchestrator/deps/phoenix/priv/static/phoenix.min.js` | .js | 22941 | 2 | 0 |  |
| `apps/orchestrator/deps/phoenix/priv/static/phoenix.mjs` | .mjs | 45934 | 1555 | 0 |  |
| `apps/orchestrator/deps/phoenix/priv/templates/phx.gen.socket/socket.js` | .js | 2313 | 64 | 0 |  |
| `apps/orchestrator/deps/phoenix_pubsub/CHANGELOG.md` | .md | 1225 | 45 | 0 |  |
| `apps/orchestrator/deps/phoenix_pubsub/LICENSE.md` | .md | 1071 | 22 | 0 |  |
| `apps/orchestrator/deps/phoenix_pubsub/README.md` | .md | 1180 | 56 | 0 |  |
| `apps/orchestrator/deps/phoenix_template/CHANGELOG.md` | .md | 262 | 21 | 0 |  |
| `apps/orchestrator/deps/phoenix_template/LICENSE.md` | .md | 1071 | 22 | 0 |  |
| `apps/orchestrator/deps/phoenix_template/README.md` | .md | 536 | 21 | 0 |  |
| `apps/orchestrator/deps/plug/CHANGELOG.md` | .md | 12427 | 405 | 0 |  |
| `apps/orchestrator/deps/plug/README.md` | .md | 12419 | 372 | 0 |  |
| `apps/orchestrator/deps/plug_cowboy/CHANGELOG.md` | .md | 2832 | 165 | 0 |  |
| `apps/orchestrator/deps/plug_cowboy/README.md` | .md | 1776 | 64 | 0 |  |
| `apps/orchestrator/deps/plug_crypto/CHANGELOG.md` | .md | 1698 | 57 | 0 |  |
| `apps/orchestrator/deps/plug_crypto/README.md` | .md | 1213 | 30 | 0 |  |
| `apps/orchestrator/deps/telemetry/CHANGELOG.md` | .md | 4972 | 141 | 0 |  |
| `apps/orchestrator/deps/telemetry/README.md` | .md | 7326 | 260 | 0 |  |
| `apps/orchestrator/deps/telemetry_metrics/CHANGELOG.md` | .md | 4602 | 133 | 0 |  |
| `apps/orchestrator/deps/telemetry_metrics/README.md` | .md | 1607 | 29 | 0 |  |
| `apps/orchestrator/deps/telemetry_poller/CHANGELOG.md` | .md | 4736 | 133 | 0 |  |
| `apps/orchestrator/deps/telemetry_poller/README.md` | .md | 4525 | 122 | 0 |  |
| `apps/orchestrator/deps/websock/README.md` | .md | 3513 | 74 | 0 |  |
| `apps/orchestrator/deps/websock_adapter/CHANGELOG.md` | .md | 1319 | 68 | 0 |  |
| `apps/orchestrator/deps/websock_adapter/README.md` | .md | 3256 | 102 | 0 |  |
| `apps/orchestrator/tmp/test_graphs/persisted_4_1774560510561825.json` | .json | 143 | 9 | 0 |  |
| `apps/orchestrator/tmp/test_graphs/proj_10_1774560510878651.json` | .json | 3430 | 152 | 0 |  |
| `apps/orchestrator/tmp/test_graphs/proj_11_1774560510908040.json` | .json | 139 | 9 | 0 |  |
| `apps/orchestrator/tmp/test_graphs/proj_12_1774560510909678.json` | .json | 3568 | 153 | 0 |  |
| `apps/orchestrator/tmp/test_graphs/proj_13_1774560510939988.json` | .json | 553 | 31 | 0 |  |
| `apps/orchestrator/tmp/test_graphs/proj_14_1774560510950843.json` | .json | 1390 | 74 | 0 |  |
| `apps/orchestrator/tmp/test_graphs/proj_15_1774560510966203.json` | .json | 1950 | 103 | 0 |  |
| `apps/orchestrator/tmp/test_graphs/proj_16_1774560510992417.json` | .json | 3584 | 153 | 0 |  |
| `apps/orchestrator/tmp/test_graphs/proj_17_1774560511146222.json` | .json | 1398 | 61 | 0 |  |
| `apps/orchestrator/tmp/test_graphs/proj_1_1774560510575956.json` | .json | 7418 | 298 | 0 |  |
| `apps/orchestrator/tmp/test_graphs/proj_2_1774560510649070.json` | .json | 1975 | 79 | 0 |  |
| `apps/orchestrator/tmp/test_graphs/proj_3_1774560510662792.json` | .json | 3982 | 165 | 0 |  |
| `apps/orchestrator/tmp/test_graphs/proj_4_1774560510750651.json` | .json | 697 | 34 | 0 |  |
| `apps/orchestrator/tmp/test_graphs/proj_5_1774560510757204.json` | .json | 1396 | 61 | 0 |  |
| `apps/orchestrator/tmp/test_graphs/proj_6_1774560510767547.json` | .json | 552 | 31 | 0 |  |
| `apps/orchestrator/tmp/test_graphs/proj_7_1774560510773896.json` | .json | 1563 | 77 | 0 |  |
| `apps/orchestrator/tmp/test_graphs/proj_8_1774560510794171.json` | .json | 2002 | 95 | 0 |  |
| `apps/orchestrator/tmp/test_graphs/proj_9_1774560510876910.json` | .json | 138 | 9 | 0 |  |
| `apps/web/AGENTS.md` | .md | 722 | 30 | 0 |  |
| `apps/web/index.html` | .html | 307 | 12 | 0 |  |
| `apps/web/package-lock.json` | .json | 135769 |  | 0 | file too large for inline snippet (>96000 bytes) |
| `apps/web/package.json` | .json | 646 | 28 | 0 |  |
| `apps/web/src/App.tsx` | .tsx | 53215 | 1397 | 0 |  |
| `apps/web/src/components/ConnectionStatus.tsx` | .tsx | 701 | 22 | 0 |  |
| `apps/web/src/components/GraphCanvas.tsx` | .tsx | 9475 | 321 | 0 |  |
| `apps/web/src/lib/bluetoothGenerator.ts` | .ts | 5017 | 173 | 0 |  |
| `apps/web/src/lib/graphDraft.ts` | .ts | 1380 | 46 | 0 |  |
| `apps/web/src/lib/graphState.test.ts` | .ts | 2535 | 92 | 0 |  |
| `apps/web/src/lib/graphState.ts` | .ts | 2652 | 85 | 0 |  |
| `apps/web/src/lib/nodeCatalog.ts` | .ts | 2556 | 105 | 0 |  |
| `apps/web/src/lib/packetState.test.ts` | .ts | 1011 | 28 | 0 |  |
| `apps/web/src/lib/packetState.ts` | .ts | 1611 | 49 | 0 |  |
| `apps/web/src/lib/parseChannelPayload.test.ts` | .ts | 3235 | 132 | 0 |  |
| `apps/web/src/lib/parseChannelPayload.ts` | .ts | 6389 | 227 | 0 |  |
| `apps/web/src/lib/projectChannel.ts` | .ts | 3407 | 123 | 0 |  |
| `apps/web/src/lib/requestId.ts` | .ts | 280 | 7 | 0 |  |
| `apps/web/src/lib/spotifyConsumer.test.ts` | .ts | 4122 | 135 | 0 |  |
| `apps/web/src/lib/spotifyConsumer.ts` | .ts | 7410 | 241 | 0 |  |
| `apps/web/src/main.tsx` | .tsx | 360 | 16 | 0 |  |
| `apps/web/src/styles.css` | .css | 8679 | 509 | 0 |  |
| `apps/web/src/types/graph.ts` | .ts | 1124 | 53 | 0 |  |
| `apps/web/src/types/phoenix.d.ts` | .ts | 983 | 29 | 0 |  |
| `apps/web/src/types/websocket.ts` | .ts | 2295 | 97 | 0 |  |
| `apps/web/src/vite-env.d.ts` | .ts | 227 | 10 | 0 |  |
| `apps/web/tsconfig.json` | .json | 635 | 23 | 0 |  |
| `apps/web/tsconfig.node.json` | .json | 225 | 10 | 0 |  |
| `apps/web/vite.config.ts` | .ts | 178 | 9 | 0 |  |
| `apps/web/vitest.config.ts` | .ts | 252 | 10 | 0 |  |
| `docs/adrs/001-monorepo-and-service-boundaries.md` | .md | 508 | 23 | 0 |  |
| `docs/adrs/002-orchestrator-as-source-of-truth.md` | .md | 502 | 19 | 0 |  |
| `docs/adrs/003-http-contract-for-execution-engine.md` | .md | 498 | 19 | 0 |  |
| `docs/agent-kickoff.md` | .md | 2744 | 98 | 0 |  |
| `docs/contracts/execution-engine-api.md` | .md | 8725 | 430 | 0 |  |
| `docs/contracts/graph-schema.md` | .md | 3456 | 151 | 0 |  |
| `docs/contracts/packet-schema.md` | .md | 1495 | 66 | 0 |  |
| `docs/contracts/websocket-events.md` | .md | 3036 | 127 | 0 |  |
| `docs/developer-guide.md` | .md | 11984 | 447 | 0 |  |
| `docs/implementation-roadmap.md` | .md | 5313 | 183 | 0 |  |
| `docs/integration-checkpoint.md` | .md | 6016 | 109 | 0 |  |
| `docs/phase-5-spec.md` | .md | 5163 | 143 | 0 |  |
| `docs/subagent-prompts.md` | .md | 3095 | 100 | 0 |  |
| `package-lock.json` | .json | 87 | 6 | 0 |  |

---

> **LLM narrative unavailable.** Gemini HTTP 429: {
  "error": {
    "code": 429,
    "message": "You exceeded your current quota, please check your plan and billing details. For more information on this error, head to: https://ai.google.dev/gemini-api/docs/rate-limits. To monitor your current usage, head to: https://ai.dev/rate-limit. \n* Quota exceeded for metric: generativelanguage.googleapis.com/generate_content_free_tier_requests, limit: 0, model: gemini-2.0-flash\n* Quota exceeded for metric: generativelanguage.googleapis.com/generate_content_free_tier_requests, limit: 0, model: gemini-2.0-flash\n* Quota exceeded for metric: generativelanguage.googleapis.com/generate_content_free_tier_input_token_count, limit: 0, model: gemini-2.0-flash\nPlease retry in 22.63160764s.",
    "status": "RESOURCE_EXHAUSTED",
    "details": [
      {
        "@type": "type.googleapis.com/google.rpc.Help",
        "links": [
          {
            "description": "Learn more about Gemini API quotas",
            "url": "https://ai.google.dev/gemini-api/docs/rate-limits"
          }
        ]
      },
      {
        "@type": "type.googleapis.com/google.rpc.QuotaFailure",
        "violations": [
          {
            "quotaMetric": "generativelan
