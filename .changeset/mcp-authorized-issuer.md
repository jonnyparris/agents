---
"agents": patch
---

Add `DurableObjectOAuthClientProvider.authorizedIssuer()` and `authorizationIssuerFor(authUrl)`, to check that an MCP re-authorization URL goes to the authorization server the user approved. See [Checking which authorization server the user approved](https://github.com/cloudflare/agents/blob/main/docs/agents/mcp-client.md#checking-which-authorization-server-the-user-approved).
