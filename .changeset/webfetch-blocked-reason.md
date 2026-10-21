---
"agents": patch
---

`agents/webfetch`: a custom source can say why a fetch was blocked with `WebFetchError`'s `reason`, which the model reads instead of the generic bot-challenge line. See [Failures](https://github.com/cloudflare/agents/blob/main/docs/agents/fetch-the-web.md#failures).
