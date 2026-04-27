# JewWare

JewWare is a modern desktop UI for working with Hydrogen, MacSploit, and OpiumWare with a streamlined script editor, local script management, account tools, and a bundled info site.

## Features

- Alt Manager for encrypted account storage, import/export, and one-click launching
- Monaco-based Luau editor with syntax highlighting and completions
- JewWare AI sidebar for code assistance
- ScriptBlox integration for browsing and loading scripts
- Local script saving, renaming, deleting, and auto-execute toggles
- Built-in Roblox console monitoring and game detection
- Multiple UI themes and frameless macOS window controls
- JewWare Direct menubar access for saved scripts

## Local Site

The bundled JewWare website lives in `website/index.html`.

## Build

Run the desktop build from the `src` directory:

```bash
cd src
npm install
npm run build
```

That produces `src/JewWareCompressed.zip` plus architecture-specific `.app` bundles during the build step.

## Install

Install the latest prebuilt release:

```bash
./install.sh
```

From GitHub raw:

```bash
bash <(curl -fsSL "https://raw.githubusercontent.com/Davonsudo/jewware/main/install.sh")
```

The installer downloads the correct `JewWare-ARM64.dmg` or `JewWare-x86_64.dmg` release asset for the current Mac and installs `JewWare.app` into `/Applications`.

## Usage

1. Launch `JewWare.app`.
2. Open Roblox and join a game.
3. Write or load a script in the editor.
4. Execute the script from the main editor or JewWare Direct.

## Keyboard Shortcuts

| Shortcut | Action |
|----------|--------|
| ⌘+S | Save current script |
| ⌘+T | Create new tab |
| ⌘+W | Close current tab |
| ⌘+[1-9] | Switch to a specific tab |
| ⌘+I | Open the AI sidebar |
| ⌘+. | Open JewWare Direct from any app |

## Data Migration

If older Nitrogen data exists in `~/Nitrogen` or `~/Documents/Nitrogen`, the installer copies it into `~/JewWare`.

## Legal

JewWare is provided for educational purposes only. Users are responsible for complying with Roblox's Terms of Service.
