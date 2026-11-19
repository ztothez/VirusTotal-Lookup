// background.js

import { base64EncodeUrl, formatUrlForVirusTotal, extractActualUrlFromGoogleRedirect } from './utils.js';

const SUSPICIOUS_FILE_EXTENSIONS = /\.(exe|msi|zip|rar|7z|tar|gz|dmg|pdf|doc|docx|js|jar|apk|bat|ps1|sh|iso|msix)$/i;

// Function to detect direct download links and send to VirusTotal
function handleDirectDownloadLink(url) {
    if (!SUSPICIOUS_FILE_EXTENSIONS.test(url)) return false;

    const encodedUrl = base64EncodeUrl(url);
    const virusTotalUrl = `https://www.virustotal.com/gui/url/${encodedUrl}/detection`;
    chrome.tabs.create({ url: virusTotalUrl });
    return true;
}

// Function to determine the VirusTotal URL based on the input type
function getVirusTotalUrl(inputRaw) {
    const input = (inputRaw || "").trim();
    if (!input) return null;

    const hashRegex = /^[a-fA-F0-9]{32,64}$/;
    const ipRegex = /^(?:\d{1,3}\.){3}\d{1,3}$/;
    const domainRegex = /^(?!https?:\/\/)[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/;
    const urlRegex = /^https?:\/\/[^\s]+$/i;

    const value = input.includes(" ") ? formatUrlForVirusTotal(input) : input;

    if (hashRegex.test(value)) {
        return `https://www.virustotal.com/gui/file/${value}`;
    } else if (ipRegex.test(value)) {
        return `https://www.virustotal.com/gui/ip-address/${value}`;
    } else if (urlRegex.test(value)) {
        const encodedUrl = base64EncodeUrl(value);
        return `https://www.virustotal.com/gui/url/${encodedUrl}/detection`;
    } else if (domainRegex.test(value)) {
        return `https://www.virustotal.com/gui/domain/${value}`;
    }
    // Fallback: VT's own search handles CVEs, keywords, and anything unrecognized better
    // than blindly guessing it's a domain.
    return `https://www.virustotal.com/gui/search/${encodeURIComponent(value)}`;
}

// Function to create the context menu
function createContextMenu() {
    chrome.contextMenus.removeAll(() => {
        chrome.contextMenus.create({
            id: "searchVirusTotal",
            title: "Search on VirusTotal",
            contexts: ["selection", "link"]
        });
    });
}

// Initialize context menu on installation or startup
chrome.runtime.onInstalled.addListener(() => createContextMenu());
chrome.runtime.onStartup.addListener(() => createContextMenu());

// Listener for when the context menu item is clicked
chrome.contextMenus.onClicked.addListener((info, tab) => {
    let input = (info.linkUrl || info.selectionText || "").trim();
    if (!input) return;

    if (/^https?:\/\/(www\.)?google\./i.test(input)) {
        const extracted = extractActualUrlFromGoogleRedirect(input);
        if (extracted === null) return; // skip ads/sponsored links
        if (extracted) input = extracted;
    }

    if (handleDirectDownloadLink(input)) return;

    const queryUrl = getVirusTotalUrl(input);
    if (queryUrl) chrome.tabs.create({ url: queryUrl });
});

// Toolbar icon click: scan the current tab's URL directly
chrome.action.onClicked.addListener((tab) => {
    if (!tab || !tab.url) return;
    const queryUrl = getVirusTotalUrl(tab.url);
    if (queryUrl) chrome.tabs.create({ url: queryUrl });
});
