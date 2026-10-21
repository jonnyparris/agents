/**
 * Spot a bot-challenge interstitial by its text.
 *
 * The `cf-mitigated: challenge` header catches Cloudflare challenges sent to
 * a plain fetch, but plenty of challenge and block pages arrive without it:
 * a Cloudflare block page, other vendors' walls (DataDome, PerimeterX/HUMAN,
 * Imperva, Akamai), or the interstitial a headless browser renders. Those
 * pages have almost no content and a handful of stock phrases, so a short
 * body plus one of those phrases is a reliable signal.
 */

/** Interstitials are short; a real page that quotes these phrases is not. */
export const CHALLENGE_MAX_BODY_CHARS = 2_000;

/**
 * Phrases bot-protection interstitials put on the page in place of the
 * content: Cloudflare (managed/JS challenge, Turnstile, block page),
 * DataDome, PerimeterX/HUMAN, Imperva/Incapsula, Akamai, Distil, and
 * generic captcha walls.
 */
const CHALLENGE_PATTERNS: readonly RegExp[] = [
  /performing security verification/i,
  /verif(?:y|ying) (?:that )?you are (?:a )?human/i,
  /checking (?:if the site connection is secure|your browser before accessing)/i,
  /needs to review the security of your connection/i,
  /enable javascript and cookies to continue/i,
  /this website uses a security service to protect/i,
  /attention required!? \| cloudflare/i,
  /(?:^|\n)\s*(?:#+\s*|title:\s*["']?)just a moment\.\.\./i,
  /sorry, you have been blocked/i,
  /press (?:&|and) hold to confirm you are a human/i,
  /access to this page has been denied/i,
  /captcha-delivery\.com/i,
  /incapsula incident id/i,
  /pardon our interruption/i,
  /you don't have permission to access .{0,200} on this server/i,
  /please (?:complete the security check|verify you are (?:a )?human)/i
];

/** The body without the YAML frontmatter (title, description) `toMarkdown` puts on top. */
function bodyText(markdown: string): string {
  return markdown
    .replace(/^\s*---\r?\n[\s\S]*?\r?\n---[ \t]*(\r?\n|$)/, "")
    .trim();
}

/**
 * Whether `content` (Markdown or plain text) is a bot-challenge
 * interstitial rather than the page: a short body plus a phrase only those
 * pages use. Frontmatter, such as a "Just a moment..." title, counts
 * toward the match but not toward the length; so does `title`, the page's
 * `<title>` when the caller has it apart from the content.
 *
 * `createDirectWebFetch` already applies this to what it fetches. Use it
 * directly to check content from another source, such as a page rendered
 * in a browser.
 */
export function isChallengePage(content: string, title?: string): boolean {
  if (bodyText(content).length > CHALLENGE_MAX_BODY_CHARS) return false;
  const text = title ? `title: ${title}\n${content}` : content;
  return CHALLENGE_PATTERNS.some((pattern) => pattern.test(text));
}
