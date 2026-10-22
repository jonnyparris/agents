import type {
  OAuthClientInformationContext,
  OAuthClientMetadata,
  OAuthClientProvider,
  OAuthDiscoveryState,
  StoredOAuthClientInformation,
  StoredOAuthTokens
} from "@modelcontextprotocol/client";
import { AsyncLocalStorage } from "node:async_hooks";
import { nanoid } from "nanoid";

const STATE_EXPIRATION_MS = 10 * 60 * 1000; // 10 minutes

const codeVerifierStateStorage = new AsyncLocalStorage<{
  state: string;
  /** Set once `codeVerifier()` serves this state's verifier. */
  servedKey?: string;
  /**
   * Issuer the served verifier's authorization link was built for, if
   * recorded (see redirectToAuthorization). Absent for legacy verifiers.
   */
  linkIssuer?: string;
  /** Set by the first saveTokens after the verifier was served. */
  exchangeSaved?: boolean;
}>();

interface StoredState {
  nonce: string;
  serverId: string;
  createdAt: number;
}

interface StoredCodeVerifier {
  verifier: string;
  createdAt: number;
  /** Issuer of the discovery the authorization link was built from. */
  issuer?: string;
}

interface StoredAuthorizedIssuer {
  issuer: string;
  authorizedAt: number;
}

// A slight extension to the standard OAuthClientProvider interface because `redirectToAuthorization` doesn't give us the interface we need
// This allows us to track authentication for a specific server and associated dynamic client registration
export interface AgentMcpOAuthProvider extends OAuthClientProvider {
  authUrl: string | undefined;
  clientId: string | undefined;
  serverId: string | undefined;
  checkState(
    state: string
  ): Promise<{ valid: boolean; serverId?: string; error?: string }>;
  consumeState(state: string): Promise<void>;
  runWithCodeVerifierState?<T>(
    state: string,
    callback: () => Promise<T>
  ): Promise<T>;
  deleteCodeVerifier(): Promise<void>;
  /**
   * Issuer of the authorization server where the user last approved access
   * for this server: recorded only by an OAuth callback's code exchange whose
   * tokens come from the issuer bound to that callback's link.
   */
  authorizedIssuer?(): Promise<string | undefined>;
  /**
   * Issuer of the authorization server an authorization URL built by this
   * provider points at, or `undefined` if unknown (expired, already used,
   * or built without matching discovery).
   */
  authorizationIssuerFor?(authUrl: string): Promise<string | undefined>;
}

function parseOAuthState(
  state: string
): { nonce: string; serverId: string } | undefined {
  const parts = state.split(".");
  if (parts.length !== 2) {
    return undefined;
  }

  const [nonce, serverId] = parts;
  if (!nonce || !serverId) {
    return undefined;
  }

  return { nonce, serverId };
}

function base64UrlEncode(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) {
    binary += String.fromCharCode(byte);
  }
  return btoa(binary)
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
}

async function createCodeChallenge(verifier: string): Promise<string> {
  const digest = await crypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode(verifier)
  );
  return base64UrlEncode(new Uint8Array(digest));
}

function isExpired(createdAt: number): boolean {
  return Date.now() - createdAt > STATE_EXPIRATION_MS;
}

/** Same rule as the MCP SDK's `issuersMatch`: one trailing `/` may differ. */
function issuersMatch(a: string, b: string): boolean {
  return a.replace(/\/$/, "") === b.replace(/\/$/, "");
}

/**
 * Issuer of `discovery` if `authUrl` is a link built from it: same origin and
 * path as its authorization endpoint (the SDK's `startAuthorization` uses
 * `/authorize` on the server URL when there is no metadata).
 */
function issuerForLink(
  authUrl: URL,
  discovery: OAuthDiscoveryState | undefined
): string | undefined {
  if (!discovery) return undefined;
  const metadata = discovery.authorizationServerMetadata;
  let endpoint: URL;
  try {
    endpoint = metadata
      ? new URL(metadata.authorization_endpoint)
      : new URL("/authorize", discovery.authorizationServerUrl);
  } catch {
    return undefined;
  }
  if (
    endpoint.origin !== authUrl.origin ||
    endpoint.pathname !== authUrl.pathname
  ) {
    return undefined;
  }
  return metadata?.issuer ?? discovery.authorizationServerUrl;
}

/**
 * @deprecated Use {@link AgentMcpOAuthProvider} instead.
 */
export type AgentsOAuthProvider = AgentMcpOAuthProvider;

export class DurableObjectOAuthClientProvider implements AgentMcpOAuthProvider {
  private _authUrl_: string | undefined;
  private _serverId_: string | undefined;
  private _clientId_: string | undefined;

  constructor(
    public storage: DurableObjectStorage,
    public clientName: string,
    public baseRedirectUrl: string
  ) {
    if (!storage) {
      throw new Error(
        "DurableObjectOAuthClientProvider requires a valid DurableObjectStorage instance"
      );
    }
  }

  get clientMetadata(): OAuthClientMetadata {
    return {
      client_name: this.clientName,
      client_uri: this.clientUri,
      grant_types: ["authorization_code", "refresh_token"],
      redirect_uris: [this.redirectUrl],
      response_types: ["code"],
      token_endpoint_auth_method: "none"
    };
  }

  get clientUri() {
    return new URL(this.redirectUrl).origin;
  }

  get redirectUrl() {
    return this.baseRedirectUrl;
  }

  get clientId() {
    if (!this._clientId_) {
      throw new Error("Trying to access clientId before it was set");
    }
    return this._clientId_;
  }

  set clientId(clientId_: string) {
    this._clientId_ = clientId_;
  }

  get serverId() {
    if (!this._serverId_) {
      throw new Error("Trying to access serverId before it was set");
    }
    return this._serverId_;
  }

  set serverId(serverId_: string) {
    this._serverId_ = serverId_;
  }

  keyPrefix(clientId: string) {
    return `/${this.clientName}/${this.serverId}/${clientId}`;
  }

  clientInfoKey(clientId: string) {
    return `${this.keyPrefix(clientId)}/client_info/`;
  }

  discoveryStateKey() {
    return `/${this.clientName}/${this.serverId}/oauth_discovery`;
  }

  async saveDiscoveryState(state: OAuthDiscoveryState): Promise<void> {
    await this.storage.put(this.discoveryStateKey(), state);
  }

  async discoveryState(): Promise<OAuthDiscoveryState | undefined> {
    return (
      (await this.storage.get<OAuthDiscoveryState>(this.discoveryStateKey())) ??
      undefined
    );
  }

  async clientInformation(
    _context?: OAuthClientInformationContext
  ): Promise<StoredOAuthClientInformation | undefined> {
    if (!this._clientId_) return undefined;
    return (
      (await this.storage.get<StoredOAuthClientInformation>(
        this.clientInfoKey(this.clientId)
      )) ?? undefined
    );
  }

  async saveClientInformation(
    clientInformation: StoredOAuthClientInformation,
    _context?: OAuthClientInformationContext
  ): Promise<void> {
    this.clientId = clientInformation.client_id;
    // Round-trip the SDK's issuer stamp verbatim. The SDK treats a credential
    // stamped for another issuer as absent, so one durable slot per MCP server
    // is both sufficient and safer than maintaining our own issuer index.
    await this.storage.put(
      this.clientInfoKey(clientInformation.client_id),
      clientInformation
    );
  }

  tokenKey(clientId: string) {
    return `${this.keyPrefix(clientId)}/token`;
  }

  async tokens(
    _context?: OAuthClientInformationContext
  ): Promise<StoredOAuthTokens | undefined> {
    if (!this._clientId_) return undefined;
    return (
      (await this.storage.get<StoredOAuthTokens>(
        this.tokenKey(this.clientId)
      )) ?? undefined
    );
  }

  async saveTokens(
    tokens: StoredOAuthTokens,
    _context?: OAuthClientInformationContext
  ): Promise<void> {
    // Keep the SDK-owned issuer stamp intact for SEP-2352 validation. Discovery
    // is needed across the browser redirect, but once token issuance succeeds
    // it must not pin later re-authorization to this AS: a subsequent 401 must
    // re-read PRM so an authorization-server migration can be observed.
    await this.storage.put(this.tokenKey(this.clientId), tokens);
    // Record the issuer only for the tokens of a code exchange: inside the
    // callback's state context, after that state's verifier was served, and
    // only if the tokens come from the authorization server that state's link
    // was built for. A refresh, or the SDK stamping a pre-SEP-2352 grant with
    // whatever AS its next auth() discovered, never writes it. See
    // authorizedIssuer().
    // Only the first save after the verifier was served is the exchange.
    // Store the link's issuer (equal to the tokens' up to a trailing `/`) so
    // authorizedIssuer() and authorizationIssuerFor() compare exactly.
    const context = codeVerifierStateStorage.getStore();
    if (context?.servedKey && !context.exchangeSaved) {
      context.exchangeSaved = true;
      const linkIssuer = context.linkIssuer;
      if (
        linkIssuer !== undefined &&
        typeof tokens.issuer === "string" &&
        issuersMatch(linkIssuer, tokens.issuer)
      ) {
        const record: StoredAuthorizedIssuer = {
          issuer: linkIssuer,
          authorizedAt: Date.now()
        };
        await this.storage.put(this.authorizedIssuerKey(), record);
      }
    }
    await this.storage.delete(this.discoveryStateKey());
  }

  authorizedIssuerKey() {
    return `/${this.clientName}/${this.serverId}/authorized_issuer`;
  }

  /**
   * Issuer of the authorization server where the user last approved access
   * for this MCP server, recorded when an OAuth callback's code exchange saved
   * tokens through `MCPClientManager.handleCallbackRequest()`, and only when
   * the tokens come from the authorization server that callback's link was
   * built for. `undefined` if no such exchange has happened since this was
   * added. The deprecated `connectToServer({ reconnect: { oauthCode } })`
   * path does not record it. Kept when only the tokens are invalidated;
   * cleared with the server.
   *
   * Use it to check that a re-authorization during a session (after a 401 or
   * `403 insufficient_scope`) goes to the same authorization server the user
   * approved before you show its URL.
   *
   * Why not `tokens().issuer`? The MCP SDK (SEP-2352) stamps tokens saved
   * before issuer stamping existed on their next `auth()`, with whatever
   * authorization server that run discovered. If the MCP server had swapped
   * `authorization_servers` by then, that stamp names the swapped server, and
   * nothing distinguishes it later from a real one. This value is written only
   * for a code exchange whose tokens name the issuer recorded with that
   * state's link when the link was built. (The SDK's own callback check
   * compares against the latest discovery, which a later auth() can replace
   * while a link is pending.)
   */
  async authorizedIssuer(): Promise<string | undefined> {
    const record = await this.storage.get<StoredAuthorizedIssuer>(
      this.authorizedIssuerKey()
    );
    return typeof record?.issuer === "string" ? record.issuer : undefined;
  }

  /**
   * Issuer of the authorization server that `authUrl` (an authorization URL
   * this provider built, carrying its `state`) points at, as recorded when
   * the URL was built. `undefined` if the state is unknown, expired or
   * already used, or the URL was not built from the stored discovery.
   * Compare it with {@link authorizedIssuer} before showing the URL.
   */
  async authorizationIssuerFor(authUrl: string): Promise<string | undefined> {
    if (!this._clientId_) return undefined;
    let state: string | null;
    try {
      state = new URL(authUrl).searchParams.get("state");
    } catch {
      return undefined;
    }
    const parsed = state ? parseOAuthState(state) : undefined;
    if (!parsed || parsed.serverId !== this._serverId_) return undefined;
    // A consumed state (including a stale callback) means the link is used.
    if (!(await this.storage.get(this.stateKey(parsed.nonce)))) {
      return undefined;
    }
    const stored = await this.storage.get<StoredCodeVerifier>(
      this.stateCodeVerifierKey(this.clientId, parsed.nonce)
    );
    if (!stored || isExpired(stored.createdAt)) return undefined;
    return typeof stored.issuer === "string" ? stored.issuer : undefined;
  }

  get authUrl() {
    return this._authUrl_;
  }

  stateKey(nonce: string) {
    return `/${this.clientName}/${this.serverId}/state/${nonce}`;
  }

  async state(): Promise<string> {
    const nonce = nanoid();
    const state = `${nonce}.${this.serverId}`;
    const storedState: StoredState = {
      nonce,
      serverId: this.serverId,
      createdAt: Date.now()
    };
    await this.storage.put(this.stateKey(nonce), storedState);
    return state;
  }

  async checkState(
    state: string
  ): Promise<{ valid: boolean; serverId?: string; error?: string }> {
    const parsed = parseOAuthState(state);
    if (!parsed) {
      return { valid: false, error: "Invalid state format" };
    }

    const { nonce, serverId } = parsed;
    const key = this.stateKey(nonce);
    const storedState = await this.storage.get<StoredState>(key);

    if (!storedState) {
      return { valid: false, error: "State not found or already used" };
    }

    if (storedState.serverId !== serverId) {
      await this.storage.delete(key);
      return { valid: false, error: "State serverId mismatch" };
    }

    if (isExpired(storedState.createdAt)) {
      const deleteKeys = [key];
      if (this._clientId_) {
        deleteKeys.push(this.stateCodeVerifierKey(this.clientId, nonce));
      }
      await this.storage.delete(deleteKeys);
      return { valid: false, error: "State expired" };
    }

    return { valid: true, serverId };
  }

  async consumeState(state: string): Promise<void> {
    const parsed = parseOAuthState(state);
    if (!parsed) {
      // This should never happen since checkState validates format first.
      // Log for debugging but don't throw - state consumption is best-effort.
      console.warn(`[OAuth] consumeState called with invalid state format`);
      return;
    }
    await this.storage.delete(this.stateKey(parsed.nonce));
  }

  async redirectToAuthorization(authUrl: URL): Promise<void> {
    this._authUrl_ = authUrl.toString();

    const clientId = this._clientId_;
    const serverId = this._serverId_;
    if (!clientId || !serverId) {
      return;
    }

    const state = authUrl.searchParams.get("state");
    const codeChallenge = authUrl.searchParams.get("code_challenge");
    if (!state || !codeChallenge) {
      return;
    }

    const parsed = parseOAuthState(state);
    if (!parsed || parsed.serverId !== serverId) {
      return;
    }

    const challengeKey = this.challengeCodeVerifierKey(clientId, codeChallenge);
    const pendingVerifier =
      await this.storage.get<StoredCodeVerifier>(challengeKey);
    if (!pendingVerifier) {
      return;
    }

    if (isExpired(pendingVerifier.createdAt)) {
      await this.storage.delete(challengeKey);
      return;
    }

    // The SDK saves discovery for this auth() run before it builds the link.
    // Discovery is one slot per server, so an overlapping auth() run may have
    // replaced it since: bind the issuer only if this link was built from the
    // discovery now stored. (Residual: an overlapping run's AS whose metadata
    // names this link's authorization endpoint would still be bound.)
    const linkIssuer = issuerForLink(authUrl, await this.discoveryState());
    const boundVerifier: StoredCodeVerifier = {
      verifier: pendingVerifier.verifier,
      createdAt: pendingVerifier.createdAt,
      ...(typeof linkIssuer === "string" ? { issuer: linkIssuer } : {})
    };
    await this.storage.put(
      this.stateCodeVerifierKey(clientId, parsed.nonce),
      boundVerifier
    );
    await this.storage.delete(challengeKey);
  }

  async invalidateCredentials(
    scope: "all" | "client" | "tokens" | "verifier" | "discovery"
  ): Promise<void> {
    const deleteKeys: string[] = [];

    if (scope === "all" || scope === "discovery") {
      deleteKeys.push(this.discoveryStateKey());
    }

    // Not on "tokens": the SDK drops tokens when a refresh gets invalid_grant
    // and then builds a new authorization URL. That URL is exactly what
    // authorizedIssuer() exists to check.
    if (scope === "all") {
      deleteKeys.push(this.authorizedIssuerKey());
    }

    if (this._clientId_) {
      const clientId = this.clientId;
      if (scope === "all" || scope === "client") {
        deleteKeys.push(this.clientInfoKey(clientId));
      }
      if (scope === "all" || scope === "tokens") {
        deleteKeys.push(this.tokenKey(clientId));
      }
      if (scope === "all" || scope === "verifier") {
        deleteKeys.push(
          ...(await this.codeVerifierKeys(clientId, {
            includeChallengeKeys: true
          }))
        );
      }
    }

    if (deleteKeys.length > 0) {
      await this.storage.delete([...new Set(deleteKeys)]);
    }
  }

  /**
   * Delete every key this provider stores for its server: tokens and client
   * info for any client ID, verifiers, pending states and discovery state.
   * Used when the server is removed. Other servers' keys are untouched.
   */
  async clearServerStorage(): Promise<void> {
    const keys = [
      ...(
        await this.storage.list({
          prefix: `/${this.clientName}/${this.serverId}/`
        })
      ).keys()
    ];
    // DO storage caps a multi-key delete at 128 keys.
    for (let i = 0; i < keys.length; i += 128) {
      await this.storage.delete(keys.slice(i, i + 128));
    }
  }

  codeVerifierKey(clientId: string) {
    return `${this.keyPrefix(clientId)}/code_verifier`;
  }

  stateCodeVerifierPrefix(clientId: string) {
    return `${this.keyPrefix(clientId)}/code_verifier/`;
  }

  stateCodeVerifierKey(clientId: string, nonce: string) {
    return `${this.stateCodeVerifierPrefix(clientId)}${nonce}`;
  }

  challengeCodeVerifierPrefix(clientId: string) {
    return `${this.keyPrefix(clientId)}/code_verifier_challenge/`;
  }

  challengeCodeVerifierKey(clientId: string, codeChallenge: string) {
    return `${this.challengeCodeVerifierPrefix(clientId)}${codeChallenge}`;
  }

  async codeVerifierKeys(
    clientId: string,
    options: { includeChallengeKeys?: boolean } = {}
  ): Promise<string[]> {
    const legacyKey = this.codeVerifierKey(clientId);
    const keys: string[] = [];

    if (await this.storage.get(legacyKey)) {
      keys.push(legacyKey);
    }

    const stateKeys = await this.storage.list({
      prefix: this.stateCodeVerifierPrefix(clientId)
    });
    keys.push(...stateKeys.keys());

    if (options.includeChallengeKeys) {
      const challengeKeys = await this.storage.list({
        prefix: this.challengeCodeVerifierPrefix(clientId)
      });
      keys.push(...challengeKeys.keys());
    }

    return keys;
  }

  async saveCodeVerifier(verifier: string): Promise<void> {
    await this.deleteExpiredChallengeCodeVerifiers(this.clientId);

    const codeChallenge = await createCodeChallenge(verifier);
    const storedVerifier: StoredCodeVerifier = {
      verifier,
      createdAt: Date.now()
    };

    await this.storage.put(
      this.challengeCodeVerifierKey(this.clientId, codeChallenge),
      storedVerifier
    );
  }

  private async deleteExpiredChallengeCodeVerifiers(
    clientId: string
  ): Promise<void> {
    const challengeVerifiers = await this.storage.list<StoredCodeVerifier>({
      prefix: this.challengeCodeVerifierPrefix(clientId)
    });
    const expiredKeys = [...challengeVerifiers.entries()]
      .filter(([, storedVerifier]) => isExpired(storedVerifier.createdAt))
      .map(([key]) => key);
    if (expiredKeys.length > 0) {
      await this.storage.delete(expiredKeys);
    }
  }

  async codeVerifier(): Promise<string> {
    const context = codeVerifierStateStorage.getStore();
    if (context) {
      const stateVerifier = await this.codeVerifierForState(context.state);
      if (stateVerifier) {
        context.servedKey = stateVerifier.key;
        context.linkIssuer = stateVerifier.issuer;
        return stateVerifier.verifier;
      }
    }

    const legacyVerifier = await this.storage.get<string>(
      this.codeVerifierKey(this.clientId)
    );
    if (legacyVerifier) {
      if (context) {
        context.servedKey = this.codeVerifierKey(this.clientId);
      }
      return legacyVerifier;
    }

    if (context) {
      throw new Error("No code verifier found for OAuth state");
    }

    const pendingVerifiers = await this.storage.list<StoredCodeVerifier>({
      prefix: this.stateCodeVerifierPrefix(this.clientId)
    });
    const unexpiredPendingVerifiers = [...pendingVerifiers.entries()].filter(
      ([, storedVerifier]) => !isExpired(storedVerifier.createdAt)
    );
    const expiredKeys = [...pendingVerifiers.entries()]
      .filter(([, storedVerifier]) => isExpired(storedVerifier.createdAt))
      .map(([key]) => key);
    if (expiredKeys.length > 0) {
      await this.storage.delete(expiredKeys);
    }

    if (unexpiredPendingVerifiers.length === 1) {
      const [[, storedVerifier]] = unexpiredPendingVerifiers;
      return storedVerifier.verifier;
    }

    if (unexpiredPendingVerifiers.length > 1) {
      throw new Error(
        "Multiple OAuth code verifiers are pending; complete authorization with the callback state"
      );
    }

    throw new Error("No code verifier found");
  }

  private async codeVerifierForState(
    state: string
  ): Promise<{ key: string; verifier: string; issuer?: string } | undefined> {
    const parsed = parseOAuthState(state);
    if (!parsed) {
      throw new Error("Invalid state format");
    }

    const key = this.stateCodeVerifierKey(this.clientId, parsed.nonce);
    const storedVerifier = await this.storage.get<StoredCodeVerifier>(key);
    if (!storedVerifier) {
      return undefined;
    }

    if (isExpired(storedVerifier.createdAt)) {
      await this.storage.delete(key);
      throw new Error("Code verifier expired");
    }

    return {
      key,
      verifier: storedVerifier.verifier,
      issuer: storedVerifier.issuer
    };
  }

  async runWithCodeVerifierState<T>(
    state: string,
    callback: () => Promise<T>
  ): Promise<T> {
    return codeVerifierStateStorage.run({ state }, callback);
  }

  async deleteCodeVerifier(): Promise<void> {
    const context = codeVerifierStateStorage.getStore();
    if (context?.servedKey) {
      await this.storage.delete(context.servedKey);
      return;
    }

    if (context) {
      const parsed = parseOAuthState(context.state);
      if (parsed) {
        await this.storage.delete(
          this.stateCodeVerifierKey(this.clientId, parsed.nonce)
        );
        return;
      }
    }

    const keys = await this.codeVerifierKeys(this.clientId);
    if (keys.length > 0) {
      await this.storage.delete(keys);
    }
  }
}
