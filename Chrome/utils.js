// utils.js

// Utility function to base64 encode a URL for VirusTotal's URL format
function base64EncodeUrl(url) {
    return btoa(url).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

// Function to URL encode spaces and special characters if needed
function formatUrlForVirusTotal(url) {
    return encodeURI(url);
}

export { base64EncodeUrl, formatUrlForVirusTotal };
