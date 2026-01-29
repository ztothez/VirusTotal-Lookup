function base64EncodeUrl(url) {
  // Make btoa safe for Unicode
  const bytes = new TextEncoder().encode(url);
  let binary = "";
  for (const b of bytes) binary += String.fromCharCode(b);

  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function extractActualUrlFromGoogleRedirect(googleUrl) {
  try {
    const urlObj = new URL(googleUrl);

    // /url?url=... or /url?q=...
    if (urlObj.pathname === "/url") {
      const param = urlObj.searchParams.get("url") || urlObj.searchParams.get("q");
      if (param) {
        const extractedUrl = decodeURIComponent(param);
        if (/(google\.com|shopping|aclk)/i.test(extractedUrl)) return null;
        return extractedUrl;
      }
    }

    // /aclk?adurl=...
    if (urlObj.pathname === "/aclk") {
      const adUrl = urlObj.searchParams.get("adurl") || urlObj.searchParams.get("q");
      if (!adUrl) return null;
      const extractedUrl = decodeURIComponent(adUrl);
      if (/(google\.com|shopping)/i.test(extractedUrl)) return null;
      return extractedUrl;
    }

    // generic q=
    if (urlObj.searchParams.has("q")) {
      return decodeURIComponent(urlObj.searchParams.get("q"));
    }
  } catch (_) {}

  return null;
}

function getVirusTotalUrl(inputRaw) {
  const input = (inputRaw || "").trim();
  if (!input) return null;

  const hashRegex = /^[a-fA-F0-9]{32,64}$/;
  const ipRegex = /^(?:\d{1,3}\.){3}\d{1,3}$/;
  const domainOnlyRegex = /^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/;
  const urlRegex = /^https?:\/\/[^\s]+$/i;

  // Hash
  if (hashRegex.test(input)) return `https://www.virustotal.com/gui/file/${input}`;

  // IP
  if (ipRegex.test(input)) return `https://www.virustotal.com/gui/ip-address/${input}`;

  // Full URL
  if (urlRegex.test(input)) {
    const encodedUrl = base64EncodeUrl(input);
    return `https://www.virustotal.com/gui/url/${encodedUrl}/detection`;
  }

  // Bare domain
  if (domainOnlyRegex.test(input)) return `https://www.virustotal.com/gui/domain/${input}`;

  // Fallback: VT search (better for CVEs, keywords, etc.)
  return `https://www.virustotal.com/gui/search/${encodeURIComponent(input)}`;
}

function handleDirectDownloadLink(url) {
  const fileExtensions = /\.(exe|msi|zip|rar|7z|tar|gz|dmg|pdf|doc|docx)$/i;
  if (!fileExtensions.test(url)) return false;

  const encodedUrl = base64EncodeUrl(url);
  browser.tabs.create({ url: `https://www.virustotal.com/gui/url/${encodedUrl}/detection` });
  return true;
}

const MENU_ID = "searchVirusTotal";

browser.runtime.onInstalled.addListener(() => {
  browser.contextMenus.removeAll().catch(() => {}).finally(() => {
    browser.contextMenus.create({
      id: MENU_ID,
      title: "Search on VirusTotal",
      contexts: ["selection", "link"]
    });
  });
});

browser.contextMenus.onClicked.addListener((info) => {
  let input = (info.linkUrl || info.selectionText || "").trim();
  if (!input) return;

  // Google redirect handling (more flexible)
  if (/^https?:\/\/(www\.)?google\./i.test(input)) {
    const extracted = extractActualUrlFromGoogleRedirect(input);
    if (extracted === null) return; // skip ads/sponsored
    if (extracted) input = extracted;
  }

  if (handleDirectDownloadLink(input)) return;

  const queryUrl = getVirusTotalUrl(input);
  if (!queryUrl) return;

  browser.tabs.create({ url: queryUrl });
});
