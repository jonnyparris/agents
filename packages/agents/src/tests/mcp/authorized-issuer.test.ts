import { describe, expect, it } from "vitest";
import type { MCPClientManager } from "../../mcp/client";
import type { DurableObjectOAuthClientProvider } from "../../mcp/client/do-oauth-client-provider";
import { withMcpHarness } from "../shared/mcp-harness";

/**
 * `DurableObjectOAuthClientProvider.authorizedIssuer()` end to end: the real
 * SDK transport, `auth()` and provider run against a fake OAuth-protected MCP
 * server (reached through the transport's `fetch` option) whose protected
 * resource metadata can swap to a second authorization server.
 */

const MCP_ORIGIN = "https://issuer-mcp.example.com";
const MCP_URL = `${MCP_ORIGIN}/mcp`;
const AS_A = "https://as-a.example.com";
const AS_B = "https://as-b.example.com";
const CALLBACK_URL = "http://localhost:3000/callback";

function createFakeServer() {
  const accessTokens = new Set<string>();
  const codes = new Set<string>();
  const tokenRequests: { as: string; grantType: string | null }[] = [];
  const options = { authorizationServer: AS_A, failRefresh: false };

  const json = (body: unknown, status = 200) =>
    new Response(JSON.stringify(body), {
      status,
      headers: { "content-type": "application/json" }
    });

  const fetch: typeof globalThis.fetch = async (input, init) => {
    const request = new Request(input, init);
    const url = new URL(request.url);

    if (url.origin === MCP_ORIGIN) {
      if (url.pathname.startsWith("/.well-known/oauth-protected-resource")) {
        return json({
          resource: MCP_URL,
          authorization_servers: [options.authorizationServer]
        });
      }
      if (url.pathname.startsWith("/.well-known/")) {
        return new Response("Not found", { status: 404 });
      }
      if (url.pathname !== "/mcp") {
        return new Response("Not found", { status: 404 });
      }
      const token = (request.headers.get("authorization") ?? "").replace(
        /^Bearer /,
        ""
      );
      if (!accessTokens.has(token)) {
        return new Response("", {
          status: 401,
          headers: {
            "www-authenticate": `Bearer resource_metadata="${MCP_ORIGIN}/.well-known/oauth-protected-resource/mcp"`
          }
        });
      }
      if (request.method === "GET" || request.method === "DELETE") {
        return new Response(null, { status: 405 });
      }
      const message = (await request.json()) as {
        id?: number;
        method?: string;
      };
      if (message.id === undefined) return new Response(null, { status: 202 });
      const ok = (result: unknown) =>
        new Response(
          JSON.stringify({ jsonrpc: "2.0", id: message.id, result }),
          {
            status: 200,
            headers: {
              "content-type": "application/json",
              "mcp-session-id": "session-1"
            }
          }
        );
      switch (message.method) {
        case "initialize":
          return ok({
            protocolVersion: "2025-06-18",
            capabilities: { tools: {} },
            serverInfo: { name: "fake-issuer", version: "1.0.0" }
          });
        case "tools/list":
          return ok({
            tools: [
              { name: "echo", inputSchema: { type: "object", properties: {} } }
            ]
          });
        case "tools/call":
          return ok({ content: [{ type: "text", text: "ok" }] });
        default:
          return ok({});
      }
    }

    if (url.origin === AS_A || url.origin === AS_B) {
      const as = url.origin;
      if (url.pathname.startsWith("/.well-known/oauth-authorization-server")) {
        return json({
          issuer: as,
          authorization_endpoint: `${as}/authorize`,
          token_endpoint: `${as}/token`,
          registration_endpoint: `${as}/register`,
          response_types_supported: ["code"],
          code_challenge_methods_supported: ["S256"],
          grant_types_supported: ["authorization_code", "refresh_token"],
          token_endpoint_auth_methods_supported: ["none"]
        });
      }
      if (url.pathname.startsWith("/.well-known/")) {
        return new Response("Not found", { status: 404 });
      }
      if (url.pathname === "/register") {
        const body = (await request.json()) as Record<string, unknown>;
        return json({ ...body, client_id: "client-1" }, 201);
      }
      if (url.pathname === "/token") {
        const params = new URLSearchParams(await request.text());
        const grantType = params.get("grant_type");
        tokenRequests.push({ as, grantType });
        const granted =
          grantType === "authorization_code"
            ? codes.delete(params.get("code") ?? "")
            : !options.failRefresh;
        if (!granted) return json({ error: "invalid_grant" }, 400);
        const accessToken = `${new URL(as).hostname}-token-${tokenRequests.length}`;
        accessTokens.add(accessToken);
        return json({
          access_token: accessToken,
          token_type: "Bearer",
          refresh_token: `refresh-${accessToken}`,
          expires_in: 3600
        });
      }
    }

    throw new Error(`Unexpected fetch: ${request.url}`);
  };

  return {
    fetch,
    codes,
    tokenRequests,
    options,
    revokeAccessTokens: () => accessTokens.clear()
  };
}

function providerOf(
  manager: MCPClientManager,
  serverId: string
): DurableObjectOAuthClientProvider {
  const provider = manager.mcpConnections[serverId]?.options.transport
    .authProvider as DurableObjectOAuthClientProvider | undefined;
  if (!provider) throw new Error("expected an auth provider");
  return provider;
}

async function connectThroughCallback(
  manager: MCPClientManager,
  server: ReturnType<typeof createFakeServer>,
  serverId: string
): Promise<{ linkIssuer: string | undefined }> {
  await manager.registerServer(serverId, {
    url: MCP_URL,
    name: "Issuer server",
    callbackUrl: CALLBACK_URL,
    client: {},
    transport: { type: "streamable-http", fetch: server.fetch }
  });
  const connected = await manager.connectToServer(serverId);
  if (connected.state !== "authenticating") {
    throw new Error(`expected authenticating, got ${connected.state}`);
  }
  const linkIssuer = await providerOf(manager, serverId).authorizationIssuerFor(
    connected.authUrl
  );
  const state = new URL(connected.authUrl).searchParams.get("state") ?? "";
  const code = `code-${crypto.randomUUID()}`;
  server.codes.add(code);
  const result = await manager.handleCallbackRequest(
    new Request(
      `${CALLBACK_URL}?code=${code}&state=${encodeURIComponent(state)}`
    )
  );
  expect(result.authSuccess).toBe(true);
  await manager.establishConnection(serverId);
  expect(manager.mcpConnections[serverId].connectionState).toBe("ready");
  return { linkIssuer };
}

describe("DurableObjectOAuthClientProvider.authorizedIssuer", () => {
  it("records the issuer of the OAuth callback's code exchange", async () => {
    await withMcpHarness(async (harness) => {
      const manager = harness.createManager();
      const server = createFakeServer();
      const { linkIssuer } = await connectThroughCallback(
        manager,
        server,
        "issuer-exchange"
      );

      expect(linkIssuer).toBe(AS_A);
      const provider = providerOf(manager, "issuer-exchange");
      expect(await provider.authorizedIssuer()).toBe(AS_A);
      expect((await provider.tokens())?.issuer).toBe(AS_A);
    });
  });

  it("keeps the exchange issuer when the SDK stamps a legacy grant with a swapped authorization server", async () => {
    await withMcpHarness(async (harness) => {
      const manager = harness.createManager();
      const server = createFakeServer();
      const serverId = "issuer-legacy-swap";
      await connectThroughCallback(manager, server, serverId);
      const provider = providerOf(manager, serverId);

      // A grant saved before SEP-2352 stamping: tokens with no issuer.
      const saved = await provider.tokens();
      if (!saved) throw new Error("expected saved tokens");
      const { issuer: _issuer, ...legacy } = saved;
      await harness.storage.put(provider.tokenKey(provider.clientId), legacy);

      // The MCP server now points at another authorization server, and the
      // access token stops working, so the next request runs auth().
      server.options.authorizationServer = AS_B;
      server.revokeAccessTokens();
      const result = await manager.callTool({
        serverId,
        name: "echo",
        arguments: {}
      });
      expect(result.content).toEqual([{ type: "text", text: "ok" }]);

      // The SDK stamped the legacy grant with AS B and refreshed there. This
      // is the stamp authorizedIssuer() must not trust.
      expect(server.tokenRequests.at(-1)).toEqual({
        as: AS_B,
        grantType: "refresh_token"
      });
      expect((await provider.tokens())?.issuer).toBe(AS_B);
      expect(await provider.authorizedIssuer()).toBe(AS_A);
    });
  });

  it("resolves a re-authorization link to a swapped authorization server, while the approved one stays", async () => {
    await withMcpHarness(async (harness) => {
      const manager = harness.createManager();
      const server = createFakeServer();
      const serverId = "issuer-swap-link";
      await connectThroughCallback(manager, server, serverId);
      const provider = providerOf(manager, serverId);

      // Stamped grant, then the MCP server moves to AS B: the SDK drops the
      // AS A grant and builds a link to AS B.
      server.options.authorizationServer = AS_B;
      server.revokeAccessTokens();
      await expect(
        manager.callTool({ serverId, name: "echo", arguments: {} })
      ).rejects.toThrow();
      expect(
        server.tokenRequests.some(
          (request) =>
            request.as === AS_B && request.grantType === "refresh_token"
        )
      ).toBe(false);

      const link = provider.authUrl ?? "";
      expect(new URL(link).origin).toBe(AS_B);
      expect(await provider.authorizationIssuerFor(link)).toBe(AS_B);
      expect(await provider.authorizedIssuer()).toBe(AS_A);
    });
  });

  it("is not written by a refresh", async () => {
    await withMcpHarness(async (harness) => {
      const manager = harness.createManager();
      const server = createFakeServer();
      const serverId = "issuer-refresh";
      await connectThroughCallback(manager, server, serverId);
      const provider = providerOf(manager, serverId);
      await harness.storage.delete(provider.authorizedIssuerKey());

      server.revokeAccessTokens();
      await manager.callTool({ serverId, name: "echo", arguments: {} });

      expect(server.tokenRequests.at(-1)).toEqual({
        as: AS_A,
        grantType: "refresh_token"
      });
      expect((await provider.tokens())?.issuer).toBe(AS_A);
      expect(await provider.authorizedIssuer()).toBeUndefined();
    });
  });

  it("survives the token drop after a failed refresh, and is cleared with the server", async () => {
    await withMcpHarness(async (harness) => {
      const manager = harness.createManager();
      const server = createFakeServer();
      const serverId = "issuer-failed-refresh";
      await connectThroughCallback(manager, server, serverId);
      const provider = providerOf(manager, serverId);

      // invalid_grant on refresh: the SDK calls invalidateCredentials("tokens")
      // and builds a new authorization URL. The app needs the issuer now.
      server.revokeAccessTokens();
      server.options.failRefresh = true;
      await expect(
        manager.callTool({ serverId, name: "echo", arguments: {} })
      ).rejects.toThrow();
      expect(await provider.tokens()).toBeUndefined();
      expect(await provider.authorizedIssuer()).toBe(AS_A);
      // The re-authorization link the SDK built goes to the approved server.
      expect(provider.authUrl).toBeDefined();
      expect(
        await provider.authorizationIssuerFor(provider.authUrl ?? "")
      ).toBe(AS_A);

      await manager.removeServer(serverId);
      expect(await harness.storage.get(provider.authorizedIssuerKey())).toBe(
        undefined
      );
    });
  });
});
