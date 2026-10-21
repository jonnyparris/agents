import { describe, expect, it } from "vitest";
import { CHALLENGE_MAX_BODY_CHARS, isChallengePage } from "../../../web/fetch";

/** The shape Browser Run rendered for a Cloudflare managed challenge. */
const CF_INTERSTITIAL = `---
title: Just a moment...
---

# www.example.com

## Performing security verification

This website uses a security service to protect against malicious bots. This page is displayed while the website verifies you are not a bot.

Ray ID: 9a1b2c3d4e5f6789

Performance and Security by Cloudflare`;

describe("isChallengePage", () => {
  it.each([
    ["a Cloudflare managed challenge", CF_INTERSTITIAL],
    [
      "a Cloudflare JS challenge",
      "# Just a moment...\n\nChecking if the site connection is secure\n\nexample.com needs to review the security of your connection before proceeding."
    ],
    [
      "a Cloudflare block page",
      "# Attention Required! | Cloudflare\n\nSorry, you have been blocked"
    ],
    ["Turnstile", "Verify you are human by completing the action below."],
    [
      "PerimeterX",
      "# Access to this page has been denied\n\nPress & Hold to confirm you are a human (and not a bot)."
    ],
    [
      "DataDome",
      "Please enable JS and disable any ad blocker\n\n![](https://geo.captcha-delivery.com/captcha/?initialCid=x)"
    ],
    ["Imperva", "Request unsuccessful. Incapsula incident ID: 123-456"],
    [
      "Akamai",
      '# Access Denied\n\nYou don\'t have permission to access "http://e.com/" on this server.\n\nReference #18.abc'
    ]
  ])("spots %s", (_name, content) => {
    expect(isChallengePage(content)).toBe(true);
  });

  it("matches on a title passed apart from the content", () => {
    expect(isChallengePage("Checking.", "Just a moment...")).toBe(true);
    expect(isChallengePage("Checking.", "Just a moment in time")).toBe(false);
  });

  it("leaves real pages alone, including long ones that quote the phrases", () => {
    expect(
      isChallengePage(`# Title\n\n${"Some real content here. ".repeat(20)}`)
    ).toBe(false);
    expect(isChallengePage("# Just a moment in time\n\nA short story.")).toBe(
      false
    );
    const article = `# How Cloudflare's challenge works\n\nThe page says "Performing security verification" while it runs.\n\n${"Detail. ".repeat(400)}`;
    expect(article.length).toBeGreaterThan(CHALLENGE_MAX_BODY_CHARS);
    expect(isChallengePage(article)).toBe(false);
  });

  it("does not count frontmatter toward the length", () => {
    const frontmatter = `---\ntitle: Just a moment...\ndescription: ${"x".repeat(CHALLENGE_MAX_BODY_CHARS)}\n---\n\nChecking.`;
    expect(isChallengePage(frontmatter)).toBe(true);
  });
});
