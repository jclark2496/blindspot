# Blindspot for Chrome privacy notice

Blindspot scans only when you click the extension on the current tab or paste text into its popup.

## Data the extension reads

For a user-initiated page scan, Blindspot reads up to 80,000 characters of selected text or page text plus at most 100 attack-surface samples, each capped at 4,000 characters, from metadata, structured data, HTML comments, hidden text, and relevant `alt`/`title` attributes in that tab. Paste scans read only the text entered in the popup.

## Data handling

All detection runs locally in the browser against rules packaged with the extension. Blindspot does not transmit page content, findings, URLs, or usage data. It has no telemetry, analytics, advertising, remote API, account, or cloud storage. Scan results exist only in the popup's memory and are discarded when the popup closes. The extension does not alter page content.

## Permissions

- `activeTab`: temporary access to the tab where the user invoked Blindspot.
- `scripting`: injects the local extraction script into that tab after the user invokes Blindspot.

Blindspot requests no host permissions and installs no persistent content script.

## Limitations

Blindspot is deterministic static analysis. It can miss novel, obfuscated, contextual, or dynamically loaded attacks and can report benign text. A clean result is not a guarantee of safety. Browser-protected pages such as `chrome://` pages, the Chrome Web Store, and some PDF/viewer or restricted frames cannot be scanned; Blindspot reports that limitation without attempting a fallback upload.
