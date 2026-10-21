---
"agents": patch
---

`agents/webfetch` now reports challenge and block pages sent without `cf-mitigated` as `web_fetch_blocked`, spotted by their text, and exports `isChallengePage`. See [Fetch the web](https://github.com/cloudflare/agents/blob/main/docs/agents/fetch-the-web.md).
