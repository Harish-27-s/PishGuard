# PhishGuard Chrome Extension (Manifest V3)

Minimal toolbar popup that sends the **current tab URL** to the PhishGuard API and displays verdict, score, and reasons.

## Requirements

- Chrome / Chromium / Edge (MV3)
- PhishGuard API running (default `http://localhost:8000`)

```bash
# from repo root
uvicorn app.main:app --reload --port 8000
```

## Load the extension

1. Open `chrome://extensions`
2. Enable **Developer mode**
3. Click **Load unpacked** → select the `extension/` folder

## Configure API URL

In the popup, edit **API base URL** (default `http://localhost:8000`) and click **Save**. The value is stored in `chrome.storage.sync`.

To allow a non-localhost API, add its origin to `host_permissions` in `manifest.json` and reload the extension.

## Permissions

| Permission | Reason |
|------------|--------|
| `activeTab` | Read the current tab URL when the popup is opened |
| `storage` | Persist the configurable API base URL |
| `host_permissions` for localhost | Call the local FastAPI server |

## Icons

Placeholder icons are included under `icons/`. Replace with final branding assets if desired.
