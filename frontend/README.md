# BanGuard frontend
`npm i && npm run dev` (needs FastAPI on :8000; /api is proxied, CORS not needed).
Assumed routes (edit src/api.ts): POST /analyze/url {url}, POST /analyze/message {text}, POST /reports, POST /reports/{id}/verify.
If the backend is down the UI falls back to labelled demo data.
