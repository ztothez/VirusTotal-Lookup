// Utility function to base64 encode a URL for VirusTotal's URL format
function base64EncodeUrl(url) {
    return btoa(url).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

// Function to URL encode spaces and special characters if needed
function formatUrlForVirusTotal(url) {
    return encodeURI(url); // Ensures spaces and special characters are encoded
}

// Enhanced function to extract the actual URL from various Google redirect structures
function extractActualUrlFromGoogleRedirect(googleUrl) {
    console.log("Original Google URL:", googleUrl);
    try {
        const urlObj = new URL(googleUrl);

        // Handle standard Google search redirects (e.g., /url?url=...)
        if (urlObj.pathname === "/url" && urlObj.searchParams.has("url")) {
            const extractedUrl = decodeURIComponent(urlObj.searchParams.get("url"));
            console.log("Extracted URL from /url:", extractedUrl);

            // Skip sponsored product or unwanted links
            if (extractedUrl.includes("google.com") || extractedUrl.includes("shopping") || extractedUrl.includes("aclk")) {
                console.log("Skipping sponsored or ad link:", extractedUrl);
                return null; // Ignore this link
            }

            return extractedUrl;
        }
        
        // Handle sponsored ad links specifically (e.g., /aclk?adurl=...)
        if (urlObj.pathname === "/aclk") {
            const adUrl = urlObj.searchParams.get("adurl");
            if (adUrl) {
                const extractedUrl = decodeURIComponent(adUrl);
                console.log("Extracted URL from /aclk:", extractedUrl);

                // Skip if it's a sponsored ad link
                if (extractedUrl.includes("google.com") || extractedUrl.includes("shopping")) {
                    console.log("Skipping sponsored ad link:", extractedUrl);
                    return null;
                }

                return extractedUrl;
            }

            // Fallback to `q` parameter if `adurl` is not found
            const fallbackUrl = urlObj.searchParams.get("q");
            if (fallbackUrl) {
                console.log("No valid adurl found, using fallback `q` parameter:", fallbackUrl);
                return decodeURIComponent(fallbackUrl);
            }

            console.log("No valid adurl or fallback `q` parameter found, skipping this sponsored link.");
            return null; // Ignore this link if no valid URL is found
        }

        // Fallback for other Google links that may contain a "q" parameter
        if (urlObj.searchParams.has("q")) {
            const extractedUrl = decodeURIComponent(urlObj.searchParams.get("q"));
            console.log("Extracted URL from 'q' parameter:", extractedUrl);
            return extractedUrl;
        }
    } catch (error) {
        console.error("Error decoding Google redirect URL:", error);
    }

    // Final fallback to use the root domain itself if nothing else is found
    const rootDomain = googleUrl.match(/https?:\/\/(www\.)?([a-zA-Z0-9.-]+)/);
    if (rootDomain && rootDomain[0]) {
        console.log("Using fallback root domain:", rootDomain[0]);
        return rootDomain[0];
    }

    // Return null if extraction fails
    console.log("No extraction performed, ignoring this link.");
    return null;
}

// Function to determine the VirusTotal URL based on the input type
function getVirusTotalUrl(input) {
    const hashRegex = /^[a-fA-F0-9]{32,64}$/; // For file hashes
    const ipRegex = /^(?:\d{1,3}\.){3}\d{1,3}$/; // For IPv4 addresses
    const domainRegex = /^(?!https?:\/\/)[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/; // For domains without "http" or "https"
    const urlRegex = /^https?:\/\/[^\s]+$/i; // For full URLs, allowing encoded characters

    // Ensure spaces in URLs are properly encoded
    if (input.includes(" ")) {
        input = formatUrlForVirusTotal(input);
    }

    if (hashRegex.test(input)) {
        console.log("Detected as file hash.");
        return `https://www.virustotal.com/gui/file/${input}`;
    } else if (ipRegex.test(input)) {
        console.log("Detected as IP address.");
        return `https://www.virustotal.com/gui/ip-address/${input}`;
    } else if (domainRegex.test(input)) {
        console.log("Detected as domain.");
        return `https://www.virustotal.com/gui/domain/${input}`;
    } else if (urlRegex.test(input)) {
        console.log("Detected as full URL, encoding for VirusTotal.");
        const encodedUrl = base64EncodeUrl(input); // Encode the URL for VirusTotal
        return `https://www.virustotal.com/gui/url/${encodedUrl}/detection`;
    } else {
        console.log("Default case: treating as domain.");
        return `https://www.virustotal.com/gui/domain/${input}`;
    }
}

// Detect direct download links (with file extensions) and send to VirusTotal
function handleDirectDownloadLink(url) {
    const fileExtensions = /\.(exe|msi|zip|rar|7z|tar|gz|dmg|pdf|doc|docx)$/i;
    if (fileExtensions.test(url)) {
        console.log("Direct download link detected:", url);

        // Send the direct download URL to VirusTotal
        const encodedUrl = base64EncodeUrl(url);
        const virusTotalUrl = `https://www.virustotal.com/gui/url/${encodedUrl}/detection`;
        browser.tabs.create({ url: virusTotalUrl });

        return true;
    }
    return false;
}

// Create context menu item for both selected text and links
browser.contextMenus.create({
    id: "searchVirusTotal",
    title: "Search on VirusTotal",
    contexts: ["selection", "link"]
});

// Listener for when the context menu item is clicked
browser.contextMenus.onClicked.addListener((info, tab) => {
    let input = info.linkUrl || info.selectionText.trim();
    
    // If it's a Google redirect link, attempt to extract the actual destination URL
    if (input && input.includes("https://www.google.com/")) {
        input = extractActualUrlFromGoogleRedirect(input);
    }

    // Only proceed if input is valid and not null
    if (input && handleDirectDownloadLink(input)) {
        return;
    }

    // Proceed only if input is still valid and was not skipped
    if (input) {
        const queryUrl = getVirusTotalUrl(input);
        console.log("Final VirusTotal Query URL:", queryUrl);
        browser.tabs.create({ url: queryUrl });
    }
});
