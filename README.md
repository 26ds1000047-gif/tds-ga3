# Invoice Action Agent (A2A 1.0, HTTP+JSON) on Vercel

FastAPI on Vercel's Python runtime, state in free Postgres (Neon). Layers are separate on purpose:

| File | Layer | Calls the model? |
|---|---|---|
| `invoice_agent/main.py` | HTTP: auth, version, media types, envelopes | never |
| `invoice_agent/service.py` | Task lifecycle, idempotency, receipt gate, cancel race | never |
| `invoice_agent/store.py` | Postgres, transactions, decision cache | never |
| `invoice_agent/llm.py` | One batched model call, strict validation, cache by package content | only here |

## Why it differs from a normal server
Vercel runs your code as short-lived functions, possibly many copies at once:
no writable disk (so no SQLite), no shared memory (so no in-process locks). So:
* all state lives in **Postgres**;
* "same message sent twice at once" is solved with a **claim row** (primary key on principal + messageId);
* "receipt vs cancel at the same moment" is solved with a **row lock** on the task, so exactly one wins.

## Deploy (step by step)

**1. Put the project on GitHub.** Vercel deploys on every push.
```bash
cd invoice-agent
git init && git add . && git commit -m "invoice a2a agent"
# create an empty repo on github.com, then:
git remote add origin https://github.com/<you>/<repo>.git
git branch -M main && git push -u origin main
```

**2. Import it in Vercel.** vercel.com -> Add New -> Project -> pick the repo. Vercel detects
FastAPI from `pyproject.toml` (`[tool.vercel] entrypoint`). Do not change build settings. Deploy.

**3. Add the free database.** Project -> **Storage** -> Create / Connect **Neon** (Postgres), free plan,
connect it to the project for Production. It adds `DATABASE_URL` automatically. Pick a region near
the function region (default `iad1`, i.e. US East). Tables are created on the first request.

**4. Add environment variables** (Project -> Settings -> Environment Variables, Production):
* `LLM_API_KEY` = your key (Google AI Studio is free: https://aistudio.google.com/apikey)
* `LLM_MODEL` = a current free Flash model name from your provider
* optional: `LLM_EXTRA_BODY={"reasoning_effort":"none"}` for speed on Gemini 2.5

Then **Redeploy** (Deployments -> ... -> Redeploy) so the variables take effect.

**5. Your submission URL** is
```
https://<project-name>.vercel.app/a2a/
```
(`PUBLIC_BASE_URL` is built automatically from Vercel's `VERCEL_PROJECT_PRODUCTION_URL`. Set it yourself
only if you use a custom domain.) Use the **production** domain, not a per-deployment URL: preview
URLs can sit behind Vercel login, which would block the grader.

**6. Smoke test before spending a Check** (all from a terminal, no browser login):
```bash
curl -i https://<project>.vercel.app/.well-known/agent-card.json      # 200, JSON, url matches your submission
curl -i https://<project>.vercel.app/a2a/tasks \
     -H "Authorization: Bearer test" -H "A2A-Version: 1.0"            # 200 {"tasks":[]}
curl -i https://<project>.vercel.app/a2a/tasks                         # 401
```
If the card fetch returns an HTML login page, Deployment Protection is on for that URL: use the production domain.

**7. See the real package format.** After the first real Check, Project -> Logs: search `SAMPLE_BATCH`.
It prints the structure of the first package so you can tune `SYSTEM_PROMPT` in `invoice_agent/llm.py`
(bump `PROMPT_VERSION` after editing so cached decisions are not reused).

## Limits that matter (checked against Vercel docs)
* Hobby functions default to 300 s max duration, so the grader's 45 s request limit is not a platform problem.
* Request/response bodies are capped at 4.5 MB; batches are far smaller.
* Free Neon databases pause when idle and wake in about a second. Open the agent-card URL and run the `/tasks` curl right before a Check.

## Test locally (free: mock model, spends none of your 10 grader checks)
```bash
python -m venv .venv && source .venv/bin/activate && pip install -r requirements.txt
export TEST_DATABASE_URL=postgresql://user:pw@host/db   # any throwaway Postgres (a free Neon branch works)
python test_local.py
```
It starts two server processes against the same database to imitate two serverless instances.

Run the real thing locally with `vercel dev` (needs Vercel CLI) or
`uvicorn invoice_agent.main:app --port 8000 --workers 1` after exporting the variables in `.env.example`.

## Behaviour choices you can flip with env vars
| Variable | Default | Why it exists |
|---|---|---|
| `AUTH_TOKENS` | empty (open) | Empty: any Bearer token is its own isolated user, so the grader's outsider token works. |
| `EVIDENCE_REF_STYLE` | `bracketed` | `[REF-1]` vs `REF-1`. Check against a real sample. |
| `RECEIPTS_IN_SAME_ARTIFACT` | `false` | Receipts as 2nd artifact vs 2nd Part of the proposals artifact. |
| `MAX_LLM_CALLS_PER_DAY` | 300 | Stops strangers burning your free quota. |

## Free dress rehearsal (uses none of your 10 Checks)
```bash
python3 scripts/rehearsal.py https://<project>.vercel.app/a2a
```
Sends 12 synthetic decoy-heavy packages to the live agent, plays the grader (results, receipts, replay,
outsider token) and prints timing, action accuracy and PASS/FAIL for the lifecycle.
