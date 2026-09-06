# Model endpoints

These requirements describe the current v4 release candidate. See [Getting started](getting-started.md)
for availability and exact revisions. The probe costs one model turn and catches an unsupported server
before a full review spends its budget. Retries may add billable HTTP attempts.

## Required protocol

The endpoint must:

- expose an OpenAI-compatible chat-completions base URL;
- accept `stream: true` and return a valid server-sent event stream;
- support native tool declarations and return native tool calls;
- report the model that actually served the request;
- keep every attempt on the requested model instead of silently substituting another;
- keep one choice index and scalar tool-call identities across every streamed fragment;
- accept the model identifier Shard sends; only OpenRouter resolves Shard's known aliases.

Shard has no ordinary-JSON fallback. A buffering proxy can still satisfy the framing probe, but may
cause timeouts or poor review behavior because Shard cannot act until buffered events arrive.
One response may carry at most 4 MiB across 131,072 SSE lines. Larger, excessively nested or
self-contradictory responses are refused without exposing a partial tool call.

## Run the probe

```bash
set -euo pipefail
export SHARD_MODEL_ENDPOINT='https://your-endpoint.example/v1'
export SHARD_MODEL='the-exact-model-id'
(
  read -rsp 'Shard model API key: ' SHARD_MODEL_API_KEY
  printf '\n'
  export SHARD_MODEL_API_KEY
  trap 'unset SHARD_MODEL_API_KEY' EXIT

  shard preflight --repo . \
    --probe-endpoint \
    --model-endpoint "$SHARD_MODEL_ENDPOINT" \
    --model "$SHARD_MODEL" \
    --api-key-env SHARD_MODEL_API_KEY \
    --json
)
```

The subshell keeps the credential out of the parent shell and clears it on every exit path.

Interpret the verdict:

| Verdict | Meaning | Next action |
|---|---|---|
| `validated` | SSE framing and native tool calls worked on the requested model | use the same URL, model and key variable in CI |
| `compatible` | the round trip worked on the requested model, but Shard has no measurements for it | supported; run report-only and calibrate limits on your own reviews |
| `unsupported` | the response did not satisfy the protocol | fix server flags or the gateway before a review |

Authentication and transport failures, an empty completion, zero tool calls, a missing model identity,
or an HTTP 200 from substituted weights all produce `unsupported`. The `why` field explains the
failure; `observed` records the requested and served identities when the response exposed them.

## Compatibility status

OpenRouter is verified end to end. Every other OpenAI-compatible deployment—including vLLM, Ollama,
TGI, llama.cpp, Vertex AI's OpenAI-compatible URL, Azure OpenAI and a SageMaker-hosted server—must pass
the probe with its exact URL, server flags and model identifier; no end-to-end claim is made for those
deployments.

Native AWS Bedrock and native Vertex APIs are unsupported: `model_endpoint: bedrock` and
`model_endpoint: vertex` are refused. Use a customer-operated streaming OpenAI-compatible gateway and
probe it.

## Keys

`api_key_env` names an environment variable, never the secret. Pass the secret through the workflow's
`env` as shown in [Getting started](getting-started.md); never put it in `with:`, an argument, a
repository variable or a checkout file. A local endpoint that ignores bearer authentication still
needs a non-empty placeholder in that secret variable.

## Cost accounting

Most self-hosted servers report tokens but no dollar price. Use `max_spend_usd: 0` and bound the run
with time, steps and calibrated tokens. A positive dollar cap follows endpoint-reported cost; it cannot
predict the first request or a later price change and is not provider-side hard enforcement. When the
endpoint reports no price, a positive dollar cap cannot bind spend or make the run fail closed.

Request totals include every attempt Shard starts. `abandoned_requests` counts attempts whose final
usage record was not trustworthy, so their tokens and price are unavailable and reported totals remain
a floor.

## Data sent to the endpoint

Diff mode sends prompts containing the change, selected source excerpts, tool results and prior model
turns. This is the intended analysis path. The endpoint does not receive the model credential in prompt
content, and hostile commands do not receive it at all.

Basic `survey` and basic `preflight` make no endpoint request. `preflight --probe-endpoint` performs one
model turn; the transport may retry failed HTTP attempts. See [SECURITY.md](../SECURITY.md) for every
optional network destination.
