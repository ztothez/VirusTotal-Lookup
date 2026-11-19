import { base64EncodeUrl, formatUrlForVirusTotal, extractActualUrlFromGoogleRedirect } from "./utils.js";

const SUSPICIOUS_FILE_EXTENSIONS = /\.(exe|msi|zip|rar|7z|tar|gz|dmg|pdf|doc|docx|js|jar|apk|bat|ps1|sh|iso|msix)$/i;

function handleDirectDownloadLink(url) {
  if (!SUSPICIOUS_FILE_EXTENSIONS.test(url)) return false;

  const encodedUrl = base64EncodeUrl(url);
  browser.tabs.create({ url: `https://www.virustotal.com/gui/url/${encodedUrl}/detection` });
  return true;
}

function getVirusTotalUrl(inputRaw) {
  const input = (inputRaw || "").trim();
  if (!input) return null;

  const hashRegex = /^[a-fA-F0-9]{32,64}$/;
  const ipRegex = /^(?:\d{1,3}\.){3}\d{1,3}$/;
  const domainOnlyRegex = /^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/;
  const urlRegex = /^https?:\/\/[^\s]+$/i;

  const value = input.includes(" ") ? formatUrlForVirusTotal(input) : input;

  // Hash
  if (hashRegex.test(value)) return `https://www.virustotal.com/gui/file/${value}`;

  // IP
  if (ipRegex.test(value)) return `https://www.virustotal.com/gui/ip-address/${value}`;

  // Full URL
  if (urlRegex.test(value)) {
    const encodedUrl = base64EncodeUrl(value);
    return `https://www.virustotal.com/gui/url/${encodedUrl}/detection`;
  }

  // Bare domain
  if (domainOnlyRegex.test(value)) return `https://www.virustotal.com/gui/domain/${value}`;

  // Fallback: VT search (better for CVEs, keywords, etc.)
  return `https://www.virustotal.com/gui/search/${encodeURIComponent(value)}`;
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

// Toolbar icon click: scan the current tab's URL directly
browser.action.onClicked.addListener((tab) => {
  if (!tab || !tab.url) return;
  const queryUrl = getVirusTotalUrl(tab.url);
  if (queryUrl) browser.tabs.create({ url: queryUrl });
});
