# File Signature Analyzer

This is the Electron + React desktop frontend for the File Signature Analysis and Recovery project.

## Prerequisites
- Node.js 18+
- Python 3.10+ (must be in system PATH)
- Dependencies installed:
  - Inside `gui/electron/`: `npm install`
  - Inside `gui/api/`: `pip install -r requirements_api.txt`

## How to run in development mode
1. Install node modules: `npm install`
2. Start the Vite dev server and Electron process:
   ```bash
   npm run start
   ```

## How to build for Windows
Creates an `.exe` NSIS installer safely wrapping all models and the python backend.
```bash
npm run package:win
```
The installer will be located in the `dist-electron` folder.

## How to build for Linux
Creates a `.AppImage` standalone executable.
```bash
npm run package:linux
```
The AppImage will be located in the `dist-electron` folder.

## Build All
```bash
npm run package:all
```
