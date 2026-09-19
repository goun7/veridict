# Real-LLM canary run — what you need to provide

The stub jury measures the harness, not a model. To measure what a real
jury catches, set these environment variables and run the script. The
script NEVER logs keys, NEVER writes them anywhere, and exits 2 with a
message if anything is missing.

## Required

```bash
# Juror 1 (any OpenAI-compatible endpoint)
export VERIDICT_JURY_URL="https://api.openai.com/v1"
export VERIDICT_JURY_KEY="sk-..."
export VERIDICT_JURY_MODEL="gpt-4o-mini"

# Juror 2 — a DIFFERENT model, same or different gateway
export VERIDICT_JURY_URL2="https://api.openai.com/v1"
export VERIDICT_JURY_KEY2="sk-..."
export VERIDICT_JURY_MODEL2="gpt-4o"
```

Then:

```bash
python3 scripts/canary_real_llm.py
# optional: persist the sheet with model names
VERIDICT_CANARY_OUT=sheet.json python3 scripts/canary_real_llm.py
```

## Why two different models

A one-model jury reviewing its own output is the §5.2 self-preference
the rule exists to forbid — same model through two gateways is still one
opinion counted twice. Two different models from the same gateway count
as two families (the family is the model line, not the billing account).

## What counts as a valid endpoint

Any OpenAI-compatible `/v1/chat/completions` endpoint: OpenAI itself,
Together, Groq, OpenRouter, a local vLLM/Ollama with `--port`. The
provider returns a strict-JSON opinion; a model that refuses the JSON
format is an abstention, not a failure.

## Current state

- corpus: 25 defect classes, 28 cases
- stub baseline (what the script replaces): 22 catches / 3 honest
  misses / 0 false positives — **measured with a scripted jury, not a
  real LLM. Do not quote it as a real-model figure.**
- previous real-LLM run (L0-3, qwen3.8-flash): 13 classes, score 1.0 —
  that corpus is retired; the number does not transfer to 25 classes.
