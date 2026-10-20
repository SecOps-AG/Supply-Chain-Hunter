// Star count for the dashboard header. One request when the page loads.
// The link in the page still works if this request fails.
"use strict";

const GITHUB_STARS_API = "https://api.github.com/repos/SecOps-AG/Supply-Chain-Hunter";

function formatStarCount(count) {
  return new Intl.NumberFormat("en-US").format(count);
}

async function loadGitHubStars() {
  const link = document.getElementById("gh-stars");
  const countEl = document.getElementById("gh-star-count");
  if (!link || !countEl) return;
  try {
    const res = await fetch(GITHUB_STARS_API, {
      method: "GET",
      cache: "no-store",
      credentials: "omit",
    });
    if (!res || !res.ok) return;
    const body = await res.json();
    const count = body && body.stargazers_count;
    if (typeof count !== "number" || !Number.isInteger(count) || count < 0) return;
    const text = formatStarCount(count);
    countEl.textContent = text;
    link.setAttribute("aria-label", text + " GitHub stars");
  } catch (err) {
    // Leave the number blank. Do not invent a count.
  }
}

if (document.readyState === "loading") {
  document.addEventListener("DOMContentLoaded", loadGitHubStars);
} else {
  loadGitHubStars();
}
