// utils.js

function base64EncodeUrl(url) {
  // Make btoa safe for Unicode
  const bytes = new TextEncoder().encode(url);
  let binary = "";
  for (const b of bytes) binary += String.fromCharCode(b);

  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function formatUrlForVirusTotal(url) {
  return encodeURI(url);
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

export { base64EncodeUrl, formatUrlForVirusTotal, extractActualUrlFromGoogleRedirect };
