# VirusTotal Lookup Extension

VirusTotal Lookup is an open-source browser extension for quickly searching indicators of compromise on VirusTotal. It supports IP addresses, domains, URLs, and file hashes, and is designed for security analysts, researchers, and incident responders.

## Features

- **Right-click lookup**  
    Search selected text or links directly on VirusTotal.
    
- **Automatic indicator detection**
    - IP addresses
    - Domains
    - URLs
    - File hashes (MD5, SHA-1, SHA-256)
        
- **Google redirect resolution**  
    Extracts the real destination from Google redirect URLs before searching.
    
- **Direct download detection**  
    Identifies direct file download URLs (now including `.js`, `.jar`, `.apk`, `.bat`, `.ps1`, `.sh`, `.iso`, `.msix`) to ensure accurate VirusTotal lookups.

- **One-click current-tab scan**  
    Click the toolbar icon to send the active tab's URL straight to VirusTotal.

## What's New (v1.3 / 2.1)
* Unicode-safe URL encoding (previously non-Latin1 URLs could fail to open on Chrome)
* Smarter Google-redirect detection shared between both builds
* Unmatched input now falls back to a VirusTotal search instead of a misleading domain-page guess
* Expanded list of flagged download extensions
* New: clicking the toolbar icon scans the current tab's URL directly

## Usage
1. Highlight text or right-click a link.
2. Select **Search on VirusTotal**.
3. Review existing VirusTotal results in a new browser tab.

Alternatively, click the toolbar icon to scan the page you're currently on.

**Note:** This extension does not upload files or initiate scans automatically.

## Permissions
- **Context menus**
- **Tabs / activeTab**

No background requests, telemetry, or data collection are performed.

## Installation
- **Firefox Add-ons**  
    [https://addons.mozilla.org/firefox/addon/virustotalsearch/](https://addons.mozilla.org/firefox/addon/virustotalsearch/)
    
- **Chrome Web Store:**  
    [updated once review passed]

## Open Source & License
This project is licensed under the MIT License.
Source code:  
[https://github.com/ztothez/VirusTotal-Lookup](https://github.com/ztothez/VirusTotal-Lookup)

## Privacy Policy
This extension does not collect, store, or track personal data.  
For full details, see the privacy policy below.

[Privacy Policy](https://ztothez.github.io/VirusTotal-Lookup/)
