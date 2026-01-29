// background.js

import { base64EncodeUrl, formatUrlForVirusTotal } from './utils.js';

// Function to detect direct download links and send to VirusTotal
function handleDirectDownloadLink(url) {
    const fileExtensions = /\.(exe|msi|zip|rar|7z|tar|gz|dmg|pdf|doc|docx)$/i;
    if (fileExtensions.test(url)) {
        const encodedUrl = base64EncodeUrl(url);
        const virusTotalUrl = `https://www.virustotal.com/gui/url/${encodedUrl}/detection`;
        chrome.tabs.create({ url: virusTotalUrl });
        return true;
    }
    return false;
}

// Function to extract the actual URL from Google redirect structures
function extractActualUrlFromGoogleRedirect(googleUrl) {
    try {
        const urlObj = new URL(googleUrl);

        // Handle standard Google search redirects (e.g., /url?url=...)
        if (urlObj.pathname === "/url" && urlObj.searchParams.has("url")) {
            const extractedUrl = decodeURIComponent(urlObj.searchParams.get("url"));

            // Skip sponsored or unwanted links
            if (extractedUrl.includes("google.com") || extractedUrl.includes("shopping") || extractedUrl.includes("aclk")) {
                return null;
            }
            return extractedUrl;
        }

        // Handle sponsored ad links (e.g., /aclk?adurl=...)
        if (urlObj.pathname === "/aclk") {
            const adUrl = urlObj.searchParams.get("adurl");
            if (adUrl) {
                const extractedUrl = decodeURIComponent(adUrl);

                if (extractedUrl.includes("google.com") || extractedUrl.includes("shopping")) {
                    return null;
                }
                return extractedUrl;
            }

            const fallbackUrl = urlObj.searchParams.get("q");
            if (fallbackUrl) {
                return decodeURIComponent(fallbackUrl);
            }
            return null;
        }

        // Fallback for other Google links that may contain a "q" parameter
        if (urlObj.searchParams.has("q")) {
            const extractedUrl = decodeURIComponent(urlObj.searchParams.get("q"));
            return extractedUrl;
        }
    } catch (error) {
        console.error("Error decoding Google redirect URL:", error);
    }

    const rootDomain = googleUrl.match(/https?:\/\/(www\.)?([a-zA-Z0-9.-]+)/);
    if (rootDomain && rootDomain[0]) {
        return rootDomain[0];
    }
    return null;
}

// Function to determine the VirusTotal URL based on the input type
function getVirusTotalUrl(input) {
    const hashRegex = /^[a-fA-F0-9]{32,64}$/;
    const ipRegex = /^(?:\d{1,3}\.){3}\d{1,3}$/;
    const domainRegex = /^(?!https?:\/\/)[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/;
    const urlRegex = /^https?:\/\/[^\s]+$/i;

    if (input.includes(" ")) input = formatUrlForVirusTotal(input);

    if (hashRegex.test(input)) {
        return `https://www.virustotal.com/gui/file/${input}`;
    } else if (ipRegex.test(input)) {
        return `https://www.virustotal.com/gui/ip-address/${input}`;
    } else if (domainRegex.test(input)) {
        return `https://www.virustotal.com/gui/domain/${input}`;
    } else if (urlRegex.test(input)) {
        const encodedUrl = base64EncodeUrl(input);
        return `https://www.virustotal.com/gui/url/${encodedUrl}/detection`;
    }
    return `https://www.virustotal.com/gui/domain/${input}`;
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

    if (input && input.includes("https://www.google.com/")) {
        input = extractActualUrlFromGoogleRedirect(input);
    }

    if (input && handleDirectDownloadLink(input)) {
        return;
    }

    if (input) {
        const queryUrl = getVirusTotalUrl(input);
        if (queryUrl) chrome.tabs.create({ url: queryUrl });
    }
});
