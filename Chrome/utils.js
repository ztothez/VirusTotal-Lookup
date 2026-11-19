// utils.js

// Utility function to base64 encode a URL for VirusTotal's URL format (Unicode-safe)
function base64EncodeUrl(url) {
    const bytes = new TextEncoder().encode(url);
    let binary = "";
    for (const b of bytes) binary += String.fromCharCode(b);
    return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

// Function to URL encode spaces and special characters if needed
function formatUrlForVirusTotal(url) {
    return encodeURI(url);
}

// Extract the actual URL from Google redirect/sponsored-link structures
function extractActualUrlFromGoogleRedirect(googleUrl) {
    try {
        const urlObj = new URL(googleUrl);

        // Handle standard Google search redirects (e.g., /url?url=... or /url?q=...)
        if (urlObj.pathname === "/url") {
            const param = urlObj.searchParams.get("url") || urlObj.searchParams.get("q");
            if (param) {
                const extractedUrl = decodeURIComponent(param);
                if (/(google\.com|shopping|aclk)/i.test(extractedUrl)) return null;
                return extractedUrl;
            }
        }

        // Handle sponsored ad links (e.g., /aclk?adurl=...)
        if (urlObj.pathname === "/aclk") {
            const adUrl = urlObj.searchParams.get("adurl") || urlObj.searchParams.get("q");
            if (!adUrl) return null;
            const extractedUrl = decodeURIComponent(adUrl);
            if (/(google\.com|shopping)/i.test(extractedUrl)) return null;
            return extractedUrl;
        }

        // Fallback for other Google links that may contain a "q" parameter
        if (urlObj.searchParams.has("q")) {
            return decodeURIComponent(urlObj.searchParams.get("q"));
        }
    } catch (error) {
        console.error("Error decoding Google redirect URL:", error);
    }

    return null;
}

export { base64EncodeUrl, formatUrlForVirusTotal, extractActualUrlFromGoogleRedirect };
