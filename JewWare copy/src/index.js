const { app, BrowserWindow, ipcMain, Tray, Menu, nativeImage, shell, dialog, globalShortcut, session } = require('electron');
const path = require('path');
const fs = require('fs');
const os = require('os');
const axios = require('axios');
const net = require('net');
const { spawn, exec } = require('child_process');
const zlib = require('zlib');
const crypto = require('crypto');
const https = require('https');

function getAppVersion() {
    const packagePath = path.join(__dirname, 'package.json');
    try {
        const pkg = JSON.parse(fs.readFileSync(packagePath, 'utf8'));
        return pkg.version ? `v${pkg.version}` : 'v0.0.0';
    } catch (e) {
        console.error('Error reading version from package.json:', e);
    }
    return 'v0.0.0';
} 

const QUICK_SCRIPTS = [
    {
        label: 'Infinite Yield',
        script: 'loadstring(game:HttpGet("https://raw.githubusercontent.com/EdgeIY/infiniteyield/master/source"))()'
    }
];

const AI_SERVICE_URL_FALLBACK = Buffer.from(
    'aHR0cDovL25pdHJvYm90LnZlcmNlbC5hcHAvZ2VuZXJhdGU=',
    'base64'
).toString('utf8');

const DISCORD_PRESENCE = {
    clientId: (process.env.JEWWARE_DISCORD_CLIENT_ID || '').trim(),
    largeImageKey: (process.env.JEWWARE_DISCORD_LARGE_IMAGE || 'jewware-icon').trim(),
    largeImageText: 'JewWare',
    activeState: 'Customizing scripts',
    backgroundState: 'Running in background'
};

const SUPPORTED_SCRIPT_EXTENSIONS = new Set(['.lua', '.txt']);

function isSupportedScriptFile(fileName) {
    return SUPPORTED_SCRIPT_EXTENSIONS.has(path.extname(fileName || '').toLowerCase());
}

function normalizeScriptFileName(fileName, defaultExtension = '.lua') {
    const rawName = String(fileName || '').trim() || 'script';
    const baseName = path.basename(rawName).replace(/[^a-zA-Z0-9. _-]/g, '');
    const currentExt = path.extname(baseName).toLowerCase();
    const extension = SUPPORTED_SCRIPT_EXTENSIONS.has(currentExt) ? currentExt : defaultExtension;
    const stem = path.basename(baseName, path.extname(baseName)).replace(/\.+$/g, '').trim() || 'script';
    return `${stem}${extension}`;
}

function makeUniqueScriptFileName(directory, desiredName) {
    const normalized = normalizeScriptFileName(desiredName);
    const extension = path.extname(normalized);
    const stem = path.basename(normalized, extension);

    let candidate = normalized;
    let counter = 2;
    while (fs.existsSync(path.join(directory, candidate))) {
        candidate = `${stem}-${counter}${extension}`;
        counter += 1;
    }

    return candidate;
}

class JewWareAPI {
    constructor() {
        this.logMonitorProcess = null;
        this.logRefreshRate = 0.5;
        this.mainWindow = null;
        this.tray = null;
        this.lastTrayMenu = null;
        this.discordPresenceSocket = null;
        this.discordPresenceReady = false;
        this.discordPresenceBuffer = Buffer.alloc(0);
        this.discordReconnectTimeout = null;
        this.isQuitting = false;
        this.directory = path.join(os.homedir(), 'JewWare');
        this.scriptsDirectory = path.join(this.directory, 'scripts');
        this.accountsDirectory = path.join(this.directory, 'accounts');
        this.accountsFile = path.join(this.accountsDirectory, 'accounts.dat');
        this.metadataFile = path.join(this.directory, 'metadata.json');
        this.hydrogenAutoexecDir = path.join(os.homedir(), 'Hydrogen', 'autoexecute');
        this.macsploitAutoexecDir = path.join(os.homedir(), 'Documents', 'Macsploit Automatic Execution');
        this.opiumwareAutoexecDir = path.join(os.homedir(), 'Opiumware', 'autoexec');

        this.ensureDirectories();
        this.syncAutoexecFolders();
    }

    ensureDirectories() {
        if (!fs.existsSync(this.directory)) {
            fs.mkdirSync(this.directory, { recursive: true });
        }
        if (!fs.existsSync(this.scriptsDirectory)) {
            fs.mkdirSync(this.scriptsDirectory, { recursive: true });
        }
        if (!fs.existsSync(this.accountsDirectory)) {
            fs.mkdirSync(this.accountsDirectory, { recursive: true });
        }
    }

    syncAutoexecFolders() {
        try {
            const dirs = [
                { path: this.hydrogenAutoexecDir, name: 'Hydrogen' },
                { path: this.macsploitAutoexecDir, name: 'MacSploit' },
                { path: this.opiumwareAutoexecDir, name: 'OpiumWare' }
            ].filter(d => fs.existsSync(d.path));

            if (dirs.length === 0) return;

            const allScripts = {};
            dirs.forEach(({ path: dir, name }) => {
                fs.readdirSync(dir).filter(f => f.endsWith('.lua')).forEach(filename => {
                    try {
                        if (!allScripts[filename]) {
                            allScripts[filename] = fs.readFileSync(path.join(dir, filename), 'utf8');
                        }
                    } catch (e) {
                        console.error(`Error reading ${name} script ${filename}: ${e.message}`);
                    }
                });
            });

            for (const [scriptName, content] of Object.entries(allScripts)) {
                dirs.forEach(({ path: dir, name }) => {
                    const scriptPath = path.join(dir, scriptName);
                    if (!fs.existsSync(scriptPath)) {
                        try { fs.writeFileSync(scriptPath, content); }
                        catch (e) { console.error(`Error syncing ${scriptName} to ${name}: ${e.message}`); }
                    }
                });
            }
        } catch (e) {
            console.error(`Error syncing autoexec folders: ${e.message}`);
        }
    }

    async getLatestVersion() {
        return null;
    }

    async getLatestReleaseInfo() {
        const currentVersion = getAppVersion();
        const release = {
            version: currentVersion,
            name: 'JewWare',
            description: 'JewWare release notes are not configured yet.\n\nBuild and package the app locally for now.',
            published_at: '',
            html_url: ''
        };

        return {
            status: 'success',
            version: release.version,
            name: release.name,
            description: release.description,
            published_at: release.published_at,
            html_url: release.html_url,
            isOutdated: false,
            latestVersion: release.version,
            allReleases: [release],
            currentReleaseIndex: 0
        };
    }

    getVersion() { return { version: getAppVersion() }; }

    openScriptsFolder() {
        try { shell.openPath(this.scriptsDirectory); }
        catch (e) { console.error(`Error opening scripts folder: ${e.message}`); }
    }

    static HYDRO_START = 6969;
    static HYDRO_END = 7069;
    static MACSPLOIT_START = 5553;
    static MACSPLOIT_END = 5563;
    static OPIUM_START = 8392;
    static OPIUM_END = 8397;

    async checkPortStatus() {
        const portStatus = [];
        
        for (let port = JewWareAPI.MACSPLOIT_START; port <= JewWareAPI.MACSPLOIT_END; port++) {
            try {
                const client = new net.Socket();
                const isOnline = await new Promise((resolve) => {
                    const timeout = setTimeout(() => {
                        client.destroy();
                        resolve(false);
                    }, 500);

                    client.connect(port, '127.0.0.1', () => {
                        clearTimeout(timeout);
                        client.destroy();
                        resolve(true);
                    });

                    client.on('error', () => {
                        clearTimeout(timeout);
                        resolve(false);
                    });
                });

                portStatus.push({
                    port: port,
                    type: 'macsploit',
                    online: isOnline,
                    label: `MacSploit :${port}`
                });
            } catch (e) {
                portStatus.push({
                    port: port,
                    type: 'macsploit',
                    online: false,
                    label: `MacSploit :${port}`
                });
            }
        }

        return portStatus;
    }

    async executeScriptOnPort(scriptContent, targetPort) {
        if (!targetPort || targetPort === 'auto') {
            return this.executeScript(scriptContent);
        }

        const port = parseInt(targetPort);
        const messages = [];

        try {
            const client = new net.Socket();
            await new Promise((resolve, reject) => {
                const timeout = setTimeout(() => {
                    client.destroy();
                    reject(new Error('Timeout'));
                }, 3000);

                client.connect(port, '127.0.0.1', () => {
                    clearTimeout(timeout);
                    const header = Buffer.alloc(16);
                    header.writeUInt32LE(scriptContent.length + 1, 8);
                    const data = Buffer.concat([header, Buffer.from(scriptContent), Buffer.from('\0')]);
                    
                    client.write(data);
                    client.end();
                    resolve();
                });

                client.on('error', (err) => {
                    clearTimeout(timeout);
                    reject(err);
                });
            });

            return {
                status: 'success',
                message: `Script executed successfully via MacSploit on port ${port}`,
                details: messages
            };
        } catch (e) {
            return {
                status: 'error',
                message: `Error: Failed to execute on port ${port}. Make sure the instance is running.`,
                details: messages
            };
        }
    }

    async executeScript(scriptContent) {
        const { HYDRO_START, HYDRO_END, MACSPLOIT_START, MACSPLOIT_END, OPIUM_START, OPIUM_END } = JewWareAPI;
        let serverPort = null;

        try {
            for (let port = HYDRO_START; port <= HYDRO_END; port++) {
                try {
                    const response = await axios.get(`http://127.0.0.1:${port}/secret`, { 
                        timeout: 1000,
                        validateStatus: () => true
                    });
                    if (response.status === 200 && response.data === '0xdeadbeef') {
                        serverPort = port;
                        break;
                    }
                } catch (e) {
                    continue;
                }
            }

            if (serverPort) {
                const response = await axios.post(`http://127.0.0.1:${serverPort}/execute`, scriptContent, {
                    headers: { 
                        'Content-Type': 'text/plain',
                        'User-Agent': 'JewWare/6.1'
                    },
                    timeout: 10000,
                    validateStatus: () => true
                });

                if (response.status === 200) {
                    return {
                        status: 'success',
                        message: 'Script executed successfully via Hydrogen'
                    };
                }
            }
        } catch (e) {
        }

        for (let port = OPIUM_START; port <= OPIUM_END; port++) {
            try {
                const client = new net.Socket();
                await new Promise((resolve, reject) => {
                    const timeout = setTimeout(() => {
                        client.destroy();
                        reject(new Error('Timeout'));
                    }, 3000);

                    client.connect(port, '127.0.0.1', () => {
                        clearTimeout(timeout);
                        const formattedScript = `OpiumwareScript ${scriptContent}`;
                        const codeBytes = Buffer.from(formattedScript, 'utf8');
                        const compressed = zlib.deflateSync(codeBytes);
                        
                        client.write(compressed);
                        client.end();
                        resolve();
                    });

                    client.on('error', (err) => {
                        clearTimeout(timeout);
                        reject(err);
                    });
                });

                return {
                    status: 'success',
                    message: `Script executed successfully via OpiumWare on port ${port}`
                };
            } catch (e) {
                continue;
            }
        }

        const macsploitResults = [];
        const macsploitPromises = [];
        
        for (let port = MACSPLOIT_START; port <= MACSPLOIT_END; port++) {
            macsploitPromises.push(
                (async (currentPort) => {
                    try {
                        const client = new net.Socket();
                        await new Promise((resolve, reject) => {
                            const timeout = setTimeout(() => {
                                client.destroy();
                                reject(new Error('Timeout'));
                            }, 3000);

                            client.connect(currentPort, '127.0.0.1', () => {
                                clearTimeout(timeout);
                                const header = Buffer.alloc(16);
                                header.writeUInt32LE(scriptContent.length + 1, 8);
                                const data = Buffer.concat([header, Buffer.from(scriptContent), Buffer.from('\0')]);
                                
                                client.write(data);
                                client.end();
                                resolve();
                            });

                            client.on('error', (err) => {
                                clearTimeout(timeout);
                                reject(err);
                            });
                        });

                        macsploitResults.push({ port: currentPort, success: true });
                    } catch (e) {
                    }
                })(port)
            );
        }

        await Promise.all(macsploitPromises);

        if (macsploitResults.length > 0) {
            return {
                status: 'success',
                message: `Script executed successfully via MacSploit on port(s): ${macsploitResults.map(r => r.port).join(', ')}`
            };
        }

        return {
            status: 'error',
            message: 'Error: No compatible executor detected. Make sure Roblox is running and a compatible executor is installed.'
        };
    }

    async getGameName(universeId) {
        try {
            const response = await axios.get(`https://games.roblox.com/v1/games?universeIds=${universeId}`);
            const game = response.data?.data?.[0];
            return game?.name 
                ? { status: 'success', game_name: game.name }
                : { status: 'error', message: 'Game not found' };
        } catch (e) {
            return { status: 'error', message: e.message };
        }
    }

    async getScripts(script) {
        try {
            const url = script === "" 
                ? "https://scriptblox.com/api/script/fetch"
                : `https://scriptblox.com/api/script/search?q=${encodeURIComponent(script)}`;
            const response = await axios.get(url);
            return response.status === 200 ? response.data : { status: 'error', message: `HTTP ${response.status}` };
        } catch (e) {
            return { status: 'error', message: e.message };
        }
    }

    async openRoblox() {
        try {
            spawn('/Applications/Roblox.app/Contents/MacOS/RobloxPlayer', [], { stdio: 'ignore', detached: true });
            return { status: 'success', message: 'Roblox instance launched successfully' };
        } catch (e) {
            return { status: 'error', message: `Failed to open Roblox: ${e.message}` };
        }
    }

    getWebsitePath() {
        const candidates = [
            path.join(process.resourcesPath || '', 'website', 'index.html'),
            path.join(__dirname, 'website', 'index.html'),
            path.join(__dirname, '..', 'website', 'index.html')
        ];

        return candidates.find(candidate => candidate && fs.existsSync(candidate)) || null;
    }

    joinWebsite() {
        try {
            const websitePath = this.getWebsitePath();
            if (!websitePath) {
                return { status: 'error', message: 'JewWare website files were not found' };
            }

            shell.openPath(websitePath);
            return { status: 'success', message: 'Website opened successfully' };
        } catch (e) {
            return { status: 'error', message: `Failed to open website: ${e.message}` };
        }
    }

    collectScriptFilesFromDirectory(directory) {
        const collected = [];
        const stack = [directory];

        while (stack.length > 0) {
            const currentDirectory = stack.pop();
            const entries = fs.readdirSync(currentDirectory, { withFileTypes: true });

            entries.forEach(entry => {
                const fullPath = path.join(currentDirectory, entry.name);
                if (entry.isDirectory()) {
                    stack.push(fullPath);
                    return;
                }

                if (entry.isFile() && isSupportedScriptFile(entry.name)) {
                    collected.push(fullPath);
                }
            });
        }

        return collected.sort((a, b) => a.localeCompare(b));
    }

    importScriptFolder() {
        try {
            if (!fs.existsSync(this.scriptsDirectory)) {
                fs.mkdirSync(this.scriptsDirectory, { recursive: true });
            }

            return dialog.showOpenDialog(this.mainWindow, {
                title: 'Import Script Folder',
                properties: ['openDirectory']
            }).then(result => {
                if (result.canceled || !result.filePaths?.length) {
                    return { status: 'cancelled', count: 0, scripts: [] };
                }

                const sourceDirectory = result.filePaths[0];
                const filePaths = this.collectScriptFilesFromDirectory(sourceDirectory);

                if (filePaths.length === 0) {
                    return {
                        status: 'error',
                        message: 'No .lua or .txt files were found in the selected folder.',
                        count: 0,
                        scripts: []
                    };
                }

                const importedScripts = filePaths.map(filePath => {
                    const content = fs.readFileSync(filePath, 'utf8');
                    const targetName = makeUniqueScriptFileName(this.scriptsDirectory, path.basename(filePath));
                    const targetPath = path.join(this.scriptsDirectory, targetName);
                    fs.writeFileSync(targetPath, content, 'utf8');
                    return {
                        name: targetName,
                        path: targetPath,
                        sourcePath: filePath,
                        content,
                        autoExec: false
                    };
                });

                this.updateTrayMenu();

                return {
                    status: 'success',
                    count: importedScripts.length,
                    scripts: importedScripts,
                    directory: sourceDirectory
                };
            });
        } catch (e) {
            return {
                status: 'error',
                message: `Failed to import folder: ${e.message}`,
                count: 0,
                scripts: []
            };
        }
    }

    saveScript(name, content, autoExec = false, options = {}) {
        try {
            const silent = Boolean(options && options.silent);
            name = normalizeScriptFileName(name);
            autoExec = path.extname(name).toLowerCase() === '.lua' ? Boolean(autoExec) : false;

            if (!fs.existsSync(this.scriptsDirectory)) {
                fs.mkdirSync(this.scriptsDirectory, { recursive: true });
            }

            const filePath = path.join(this.scriptsDirectory, name);
            fs.writeFileSync(filePath, content);

            const autoexecDirs = [this.hydrogenAutoexecDir, this.macsploitAutoexecDir, this.opiumwareAutoexecDir];
            autoexecDirs.forEach(dir => {
                const autoexecPath = path.join(dir, name);
                if (autoExec && fs.existsSync(dir)) {
                    fs.writeFileSync(autoexecPath, content);
                } else if (fs.existsSync(autoexecPath)) {
                    fs.unlinkSync(autoexecPath);
                }
            });

            this.updateTrayMenu();

            return {
                status: 'success',
                message: silent ? `Autosaved ${name}` : `Script saved to ${filePath}`,
                path: filePath,
                autoExec: autoExec
            };
        } catch (e) {
            return {
                status: 'error',
                message: `Failed to save script: ${e.message}`
            };
        }
    }

    toggleAutoExec(scriptName, enabled) {
        try {
            const scriptPath = path.join(this.scriptsDirectory, scriptName);
            if (!fs.existsSync(scriptPath)) {
                return { status: 'error', message: `Script ${scriptName} not found` };
            }

            const content = enabled ? fs.readFileSync(scriptPath, 'utf8') : null;
            const autoexecDirs = [this.hydrogenAutoexecDir, this.macsploitAutoexecDir, this.opiumwareAutoexecDir];
            
            autoexecDirs.forEach(dir => {
                const autoexecPath = path.join(dir, scriptName);
                if (enabled && fs.existsSync(dir)) {
                    fs.writeFileSync(autoexecPath, content);
                } else if (fs.existsSync(autoexecPath)) {
                    fs.unlinkSync(autoexecPath);
                }
            });

            return { status: 'success', message: `Auto-execute ${enabled ? 'enabled' : 'disabled'} for ${scriptName}` };
        } catch (e) {
            return { status: 'error', message: `Failed to update auto-execute status: ${e.message}` };
        }
    }

    getLocalScripts() {
        try {
            if (!fs.existsSync(this.scriptsDirectory)) {
                fs.mkdirSync(this.scriptsDirectory, { recursive: true });
            }

            const autoexecDirs = [this.hydrogenAutoexecDir, this.macsploitAutoexecDir, this.opiumwareAutoexecDir];
            const scripts = fs.readdirSync(this.scriptsDirectory)
                .filter(file => isSupportedScriptFile(file))
                .map(filename => {
                    try {
                        const filePath = path.join(this.scriptsDirectory, filename);
                        const isLuaScript = path.extname(filename).toLowerCase() === '.lua';
                        return {
                            name: filename,
                            path: filePath,
                            content: fs.readFileSync(filePath, 'utf8'),
                            type: path.extname(filename).slice(1).toLowerCase(),
                            autoExec: isLuaScript && autoexecDirs.some(dir => fs.existsSync(path.join(dir, filename)))
                        };
                    } catch (e) {
                        console.error(`Error reading file ${filename}: ${e.message}`);
                        return null;
                    }
                }).filter(Boolean);

            return { status: 'success', scripts };
        } catch (e) {
            return { status: 'error', message: e.message };
        }
    }

    deleteScript(scriptName) {
        try {
            const scriptPath = path.join(this.scriptsDirectory, scriptName);
            if (!fs.existsSync(scriptPath)) {
                return { status: 'error', message: `Script "${scriptName}" not found` };
            }

            fs.unlinkSync(scriptPath);
            [this.hydrogenAutoexecDir, this.macsploitAutoexecDir, this.opiumwareAutoexecDir].forEach(dir => {
                const autoexecPath = path.join(dir, scriptName);
                if (fs.existsSync(autoexecPath)) fs.unlinkSync(autoexecPath);
            });

            this.updateTrayMenu();
            return { status: 'success', message: `Script "${scriptName}" deleted successfully` };
        } catch (e) {
            return { status: 'error', message: `Failed to delete script: ${e.message}` };
        }
    }

    renameScript(oldName, newName) {
        try {
            newName = normalizeScriptFileName(newName);

            const oldPath = path.join(this.scriptsDirectory, oldName);
            const newPath = path.join(this.scriptsDirectory, newName);

            if (!fs.existsSync(oldPath)) {
                return {
                    status: 'error',
                    message: `Script "${oldName}" not found`
                };
            }

            if (fs.existsSync(newPath) && oldName !== newName) {
                return {
                    status: 'error',
                    message: `Script "${newName}" already exists`
                };
            }

            fs.renameSync(oldPath, newPath);
            const content = fs.readFileSync(newPath, 'utf8');

            [this.hydrogenAutoexecDir, this.macsploitAutoexecDir, this.opiumwareAutoexecDir].forEach(dir => {
                const oldAutoexecPath = path.join(dir, oldName);
                const newAutoexecPath = path.join(dir, newName);

                if (fs.existsSync(oldAutoexecPath)) {
                    fs.writeFileSync(newAutoexecPath, content);
                    fs.unlinkSync(oldAutoexecPath);
                }
            });

            this.updateTrayMenu();

            return {
                status: 'success',
                message: `Script renamed from "${oldName}" to "${newName}"`
            };
        } catch (e) {
            return {
                status: 'error',
                message: `Failed to rename script: ${e.message}`
            };
        }
    }

    async sendAiPrompt(prompt, editorContent = "", history = []) {
        try {
            const url = this.getAiServiceUrl();
            const response = await axios.post(url, {
                prompt,
                context: editorContent,
                history,
                timestamp: Date.now() / 1000
            });

            if (response.status === 429) {
                return { status: 'error', message: 'Rate limit exceeded. Please wait a moment before trying again.' };
            }

            const { error, code = '', explanation = '' } = response.data;
            if (error) return { status: 'error', message: error };

            return { status: 'success', result: code.trim(), explanation: explanation.trim() };
        } catch (e) {
            const errorMessages = {
                429: 'Rate limit exceeded. Please wait a moment before trying again.',
                404: 'AI service endpoint could not be reached.',
                ECONNREFUSED: 'Connection error. Please check your internet connection.',
                ENOTFOUND: 'Connection error. Please check your internet connection.',
                ECONNABORTED: 'Request timed out. Please try again.'
            };
            
            let message = errorMessages[e.response?.status] || errorMessages[e.code];
            if (!message && e.response?.status >= 500) message = 'AI service is currently unavailable. Please try again later.';
            
            return { status: 'error', message: message || `Error: ${e.message}` };
        }
    }

    quitApp() { app.quit(); }
    minimizeApp() { this.mainWindow?.hide(); }
    toggleFullscreen() {
        if (!this.mainWindow || this.mainWindow.isDestroyed()) {
            return { status: 'error', message: 'Window unavailable', isFullScreen: false };
        }

        const nextState = !this.mainWindow.isFullScreen();
        this.mainWindow.setFullScreen(nextState);
        return { status: 'success', isFullScreen: nextState };
    }

    getMetadata() {
        try {
            if (!fs.existsSync(this.metadataFile)) {
                return { 
                    status: 'new',
                    data: { theme: 'glassmorphism' }
                };
            }
            const data = fs.readFileSync(this.metadataFile, 'utf8');
            const metadata = JSON.parse(data);
            return { 
                status: 'success',
                data: metadata
            };
        } catch (e) {
            console.error('Error reading metadata:', e);
            return { 
                status: 'error',
                data: { theme: 'glassmorphism' }
            };
        }
    }

    saveMetadata(metadata) {
        try {
            fs.writeFileSync(this.metadataFile, JSON.stringify(metadata, null, 2), 'utf8');
            return { status: 'success' };
        } catch (e) {
            console.error('Error saving metadata:', e);
            return { status: 'error', message: e.message };
        }
    }

    getEncryptionKey() {
        const machineId = `${process.env.USER || 'user'}-${process.platform}-jewware-accounts-v1`;
        return crypto.createHash('sha256').update(machineId).digest();
    }

    encryptData(data) {
        const key = this.getEncryptionKey();
        const iv = crypto.randomBytes(16);
        const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
        
        const jsonString = JSON.stringify(data);
        let encrypted = cipher.update(jsonString, 'utf8', 'base64');
        encrypted += cipher.final('base64');
        
        const authTag = cipher.getAuthTag();
        
        return `${iv.toString('base64')}:${authTag.toString('base64')}:${encrypted}`;
    }

    decryptData(encryptedString) {
        try {
            const key = this.getEncryptionKey();
            const parts = encryptedString.split(':');
            
            if (parts.length !== 3) {
                throw new Error('Invalid encrypted data format');
            }
            
            const iv = Buffer.from(parts[0], 'base64');
            const authTag = Buffer.from(parts[1], 'base64');
            const encryptedData = parts[2];
            
            const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
            decipher.setAuthTag(authTag);
            
            let decrypted = decipher.update(encryptedData, 'base64', 'utf8');
            decrypted += decipher.final('utf8');
            
            return JSON.parse(decrypted);
        } catch (error) {
            throw new Error('Failed to decrypt data: ' + error.message);
        }
    }

    isEncrypted(content) {
        const parts = content.split(':');
        if (parts.length !== 3) return false;
        
        const base64Regex = /^[A-Za-z0-9+/]+=*$/;
        return parts.every(part => base64Regex.test(part) && part.length > 0);
    }

    loadAccounts() {
        try {
            if (fs.existsSync(this.accountsFile)) {
                const content = fs.readFileSync(this.accountsFile, 'utf8').trim();
                
                if (!content) return [];
                
                if (this.isEncrypted(content)) {
                    return this.decryptData(content);
                } else {
                    try {
                        const accounts = JSON.parse(content);
                        this.saveAccounts(accounts);
                        return accounts;
                    } catch {
                        return [];
                    }
                }
            }
        } catch (e) {
            console.error('Error loading accounts:', e);
        }
        return [];
    }

    saveAccounts(accounts) {
        try {
            const encrypted = this.encryptData(accounts);
            fs.writeFileSync(this.accountsFile, encrypted, 'utf8');
        } catch (e) {
            console.error('Error saving accounts:', e);
        }
    }

    httpsRequest(options) {
        return new Promise((resolve, reject) => {
            const req = https.request(options, (res) => {
                let data = '';
                res.on('data', (chunk) => data += chunk);
                res.on('end', () => {
                    if (res.statusCode === 403) {
                        const error = new Error('Account access forbidden');
                        error.statusCode = 403;
                        reject(error);
                    } else if (res.statusCode !== 200) {
                        const error = new Error(`Request failed: ${res.statusCode}`);
                        error.statusCode = res.statusCode;
                        reject(error);
                    } else {
                        try {
                            resolve(JSON.parse(data));
                        } catch {
                            reject(new Error('Failed to parse response'));
                        }
                    }
                });
            });
            req.on('error', reject);
            req.end();
        });
    }

    async getRobloxProfile(cookie) {
        const json = await this.httpsRequest({
            hostname: 'users.roblox.com',
            path: '/v1/users/authenticated',
            method: 'GET',
            headers: {
                'Cookie': `.ROBLOSECURITY=${cookie}`,
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
            }
        });
        return { id: json.id, name: json.name, displayName: json.displayName };
    }

    async getRobloxThumbnail(userId, size = '150x150', retries = 3) {
        const json = await this.httpsRequest({
            hostname: 'thumbnails.roblox.com',
            path: `/v1/users/avatar-bust?userIds=${userId}&size=${size}&format=Png&isCircular=true`,
            method: 'GET',
            headers: { 'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36' }
        });

        if (!json.data?.length) throw new Error('No thumbnail data found');

        const thumbnail = json.data[0];
        if (thumbnail.state !== 'Completed') {
            if (thumbnail.state === 'Pending' && retries > 0) {
                await new Promise(r => setTimeout(r, 1500));
                return this.getRobloxThumbnail(userId, size, retries - 1);
            }
            return `https://www.roblox.com/headshot-thumbnail/image?userId=${userId}&width=150&height=150&format=png`;
        }
        return thumbnail.imageUrl;
    }

    async getRobloxUserData(cookie) {
        try {
            const profile = await this.getRobloxProfile(cookie);
            const thumbnail = await this.getRobloxThumbnail(profile.id);
            return { ...profile, thumbnail };
        } catch (error) {
            if (error.statusCode === 403) {
                const newError = new Error('Account access forbidden (403)');
                newError.code = 'FORBIDDEN';
                throw newError;
            }
            throw error;
        }
    }

    toCocoaTimestamp(unixMillis) {
        return (unixMillis / 1000) - 978307200;
    }

    buildBinaryCookies(cookieValue) {
        const now = Date.now();
        const expirationDate = now + (30 * 24 * 60 * 60 * 1000);

        const creationTime = this.toCocoaTimestamp(now);
        const expirationTime = this.toCocoaTimestamp(expirationDate);

        const domain = '.roblox.com';
        const name = '.ROBLOSECURITY';
        const pathStr = '/';
        const value = cookieValue;

        const domainBytes = Buffer.from(domain + '\0', 'utf8');
        const nameBytes = Buffer.from(name + '\0', 'utf8');
        const pathBytes = Buffer.from(pathStr + '\0', 'utf8');
        const valueBytes = Buffer.from(value + '\0', 'utf8');

        const domainOffset = 56;
        const nameOffset = domainOffset + domainBytes.length;
        const pathOffset = nameOffset + nameBytes.length;
        const valueOffset = pathOffset + pathBytes.length;
        const cookieSize = valueOffset + valueBytes.length;

        const flags = 0x5;

        const cookieBuffer = Buffer.alloc(cookieSize);
        let offset = 0;

        cookieBuffer.writeUInt32LE(cookieSize, offset); offset += 4;
        cookieBuffer.writeUInt32LE(1, offset); offset += 4;
        cookieBuffer.writeUInt32LE(flags, offset); offset += 4;
        cookieBuffer.writeUInt32LE(0, offset); offset += 4;
        cookieBuffer.writeUInt32LE(domainOffset, offset); offset += 4;
        cookieBuffer.writeUInt32LE(nameOffset, offset); offset += 4;
        cookieBuffer.writeUInt32LE(pathOffset, offset); offset += 4;
        cookieBuffer.writeUInt32LE(valueOffset, offset); offset += 4;
        cookieBuffer.writeUInt32LE(0, offset); offset += 4;
        cookieBuffer.writeUInt32LE(0, offset); offset += 4;
        cookieBuffer.writeDoubleLE(expirationTime, offset); offset += 8;
        cookieBuffer.writeDoubleLE(creationTime, offset); offset += 8;

        domainBytes.copy(cookieBuffer, offset); offset += domainBytes.length;
        nameBytes.copy(cookieBuffer, offset); offset += nameBytes.length;
        pathBytes.copy(cookieBuffer, offset); offset += pathBytes.length;
        valueBytes.copy(cookieBuffer, offset);

        const pageHeader = Buffer.from([0x00, 0x00, 0x01, 0x00]);
        const numCookies = Buffer.alloc(4);
        numCookies.writeUInt32LE(1, 0);
        
        const cookieOffsetInPage = 12;
        const cookieOffsetBuffer = Buffer.alloc(4);
        cookieOffsetBuffer.writeUInt32LE(cookieOffsetInPage, 0);

        const pageData = Buffer.concat([
            pageHeader,
            numCookies,
            cookieOffsetBuffer,
            cookieBuffer
        ]);

        let checksum = 0;
        for (let i = 0; i < pageData.length; i += 4) {
            checksum += pageData[i];
        }

        const fileHeader = Buffer.from([0x63, 0x6F, 0x6F, 0x6B]);
        const fileFooter = Buffer.from([0x07, 0x17, 0x20, 0x05, 0x00, 0x00, 0x00, 0x4B]);
        
        const numPages = Buffer.alloc(4);
        numPages.writeUInt32BE(1, 0);
        
        const pageSize = Buffer.alloc(4);
        pageSize.writeUInt32BE(pageData.length, 0);
        
        const checksumBuffer = Buffer.alloc(4);
        checksumBuffer.writeUInt32BE(checksum, 0);

        return Buffer.concat([
            fileHeader,
            numPages,
            pageSize,
            pageData,
            checksumBuffer,
            fileFooter
        ]);
    }

    async writeRobloxCookie(cookieValue, profileId = 'default') {
        const homeDir = os.homedir();
        const cookieFile = path.join(homeDir, 'Library', 'HTTPStorages', `com.roblox.RobloxPlayer.${profileId}.binarycookies`);

        const cookiesDir = path.dirname(cookieFile);
        if (!fs.existsSync(cookiesDir)) {
            fs.mkdirSync(cookiesDir, { recursive: true });
        }

        const binaryCookies = this.buildBinaryCookies(cookieValue);
        fs.writeFileSync(cookieFile, binaryCookies);

        return cookieFile;
    }

    modifyBundleIdentifier(robloxAppPath, profileId) {
        const plistPath = path.join(robloxAppPath, 'Contents', 'Info.plist');
        if (!fs.existsSync(plistPath)) throw new Error(`Info.plist not found at: ${plistPath}`);

        let plistContent = fs.readFileSync(plistPath, 'utf8');
        const bundleIdRegex = /<key>CFBundleIdentifier<\/key>\s*<string>com\.roblox\.RobloxPlayer(\.\w+)?<\/string>/;
        const newBundleId = `<key>CFBundleIdentifier</key>\n\t<string>com.roblox.RobloxPlayer.${profileId}</string>`;

        if (!bundleIdRegex.test(plistContent)) throw new Error('Could not find CFBundleIdentifier in Info.plist');
        fs.writeFileSync(plistPath, plistContent.replace(bundleIdRegex, newBundleId), 'utf8');
    }

    resetBundleIdentifier(robloxAppPath) {
        const plistPath = path.join(robloxAppPath, 'Contents', 'Info.plist');
        if (!fs.existsSync(plistPath)) return;

        let plistContent = fs.readFileSync(plistPath, 'utf8');
        const bundleIdRegex = /<key>CFBundleIdentifier<\/key>\s*<string>com\.roblox\.RobloxPlayer(\.\w+)?<\/string>/;
        const defaultBundleId = `<key>CFBundleIdentifier</key>\n\t<string>com.roblox.RobloxPlayer</string>`;

        if (bundleIdRegex.test(plistContent)) {
            fs.writeFileSync(plistPath, plistContent.replace(bundleIdRegex, defaultBundleId), 'utf8');
        }
    }

    async getAccounts() {
        const accounts = this.loadAccounts();
        let hasUpdates = false;

        const validatedAccounts = await Promise.all(
            accounts.map(async (account) => {
                try {
                    const userData = await this.getRobloxUserData(account.cookie);
                    if (account.name !== userData.name || account.displayName !== userData.displayName || account.thumbnail !== userData.thumbnail) {
                        hasUpdates = true;
                        return { ...account, ...userData, expired: false };
                    }
                    return { ...account, expired: false };
                } catch {
                    return { ...account, expired: true };
                }
            })
        );

        if (hasUpdates) {
            this.saveAccounts(validatedAccounts.map(({ expired, ...acc }) => acc));
        }
        return validatedAccounts;
    }

    async deleteAccount(userId) {
        const accounts = this.loadAccounts().filter(acc => acc.userId !== userId);
        this.saveAccounts(accounts);
        return accounts;
    }

    async addAccountManually(cookie) {
        if (!cookie || typeof cookie !== 'string') {
            throw new Error('Invalid cookie provided');
        }
        
        cookie = cookie.trim();
        if (cookie.startsWith('_|WARNING:-DO-NOT-SHARE-THIS.--Sharing-this-will-allow-someone-to-log-in-as-you-and-to-steal-your-ROBUX-and-items.|_')) {
            cookie = cookie.substring(cookie.indexOf('_|WARNING:-DO-NOT-SHARE-THIS.--Sharing-this-will-allow-someone-to-log-in-as-you-and-to-steal-your-ROBUX-and-items.|_') + '_|WARNING:-DO-NOT-SHARE-THIS.--Sharing-this-will-allow-someone-to-log-in-as-you-and-to-steal-your-ROBUX-and-items.|_'.length);
        }
        
        let userData;
        try {
            userData = await this.getRobloxUserData(cookie);
        } catch (err) {
            if (err.code === 'FORBIDDEN' || err.statusCode === 403 || err.statusCode === 401) {
                throw new Error('Invalid, expired, or banned account');
            }
            throw new Error('Invalid, expired, or banned account');
        }
        
        const accounts = this.loadAccounts();
        const existingIndex = accounts.findIndex(acc => acc.userId === userData.id);
        
        const newAccount = {
            cookie: cookie,
            userId: userData.id,
            name: userData.name,
            displayName: userData.displayName,
            thumbnail: userData.thumbnail,
            addedAt: new Date().toISOString()
        };
        
        if (existingIndex >= 0) {
            accounts[existingIndex] = newAccount;
        } else {
            accounts.push(newAccount);
        }
        
        this.saveAccounts(accounts);
        return newAccount;
    }

    async exportAccounts() {
        const accounts = this.loadAccounts();
        if (accounts.length === 0) throw new Error('No accounts to export');

        const warningResult = await dialog.showMessageBox(this.mainWindow, {
            type: 'warning',
            title: 'Security Warning',
            message: 'Exported accounts are NOT encrypted!',
            detail: 'The exported file will contain your account cookies in plain text. Anyone with this file can add and use ALL your accounts.\n\nOnly share this file with people you absolutely trust.',
            buttons: ['Cancel', 'I Understand, Export Anyway'],
            defaultId: 0,
            cancelId: 0
        });

        if (warningResult.response === 0) return { cancelled: true };

        const result = await dialog.showSaveDialog(this.mainWindow, {
            title: 'Export Accounts',
            defaultPath: 'jewware-accounts.json',
            filters: [{ name: 'JSON Files', extensions: ['json'] }]
        });

        if (result.canceled) return { cancelled: true };
        
        const exportData = accounts.map(acc => ({
            name: acc.name,
            cookie: acc.cookie
        }));
        fs.writeFileSync(result.filePath, JSON.stringify(exportData, null, 2), 'utf8');
        return { success: true, count: accounts.length };
    }

    async importAccounts() {
        const result = await dialog.showOpenDialog(this.mainWindow, {
            title: 'Import Accounts',
            filters: [{ name: 'JSON Files', extensions: ['json'] }],
            properties: ['openFile']
        });

        if (result.canceled) return { cancelled: true, imported: 0 };

        const importedAccounts = JSON.parse(fs.readFileSync(result.filePaths[0], 'utf8'));
        if (!Array.isArray(importedAccounts)) throw new Error('Invalid file format: expected an array of accounts');

        const existingAccounts = this.loadAccounts();
        const existingUserIds = new Set(existingAccounts.map(acc => acc.userId));
        const existingCookies = new Set(existingAccounts.map(acc => acc.cookie));
        
        let importedCount = 0;
        
        for (const acc of importedAccounts) {
            if (!acc.cookie) continue;
            if (existingCookies.has(acc.cookie)) continue;
            
            if (acc.userId && !existingUserIds.has(acc.userId)) {
                existingAccounts.push(acc);
                existingUserIds.add(acc.userId);
                existingCookies.add(acc.cookie);
                importedCount++;
                continue;
            }
            
            if (!acc.userId) {
                try {
                    const userData = await this.getRobloxUserData(acc.cookie);
                    if (!existingUserIds.has(userData.id)) {
                        existingAccounts.push({
                            cookie: acc.cookie,
                            userId: userData.id,
                            name: userData.name,
                            displayName: userData.displayName,
                            thumbnail: userData.thumbnail,
                            addedAt: new Date().toISOString()
                        });
                        existingUserIds.add(userData.id);
                        existingCookies.add(acc.cookie);
                        importedCount++;
                    }
                } catch (error) {
                    console.error('Failed to validate imported account:', error.message);
                }
            }
        }

        if (importedCount > 0) {
            this.saveAccounts(existingAccounts);
        }
        return { imported: importedCount };
    }

    async killAllRoblox() {
        return new Promise((resolve) => {
            exec('pgrep -x RobloxPlayer', (error, stdout) => {
                if (error || !stdout.trim()) return resolve({ count: 0 });

                const count = stdout.trim().split('\n').filter(p => p).length;
                exec('killall -9 RobloxPlayer 2>/dev/null; killall -9 Roblox 2>/dev/null', () => resolve({ count }));
            });
        });
    }

    async launchAccount(userId) {
        const accounts = this.loadAccounts();
        const account = accounts.find(acc => acc.userId === userId);
        if (!account) throw new Error('Account not found');

        const robloxPaths = ['/Applications/Roblox.app', path.join(process.env.HOME, 'Applications', 'Roblox.app')];
        const robloxPath = robloxPaths.find(p => fs.existsSync(p));
        if (!robloxPath) throw new Error('Roblox not found. Please install Roblox first.');

        await this.writeRobloxCookie(account.cookie, String(userId));

        return new Promise((resolve, reject) => {
            try {
                this.modifyBundleIdentifier(robloxPath, String(userId));
            } catch (err) {
                return reject(new Error(`Failed to modify bundle identifier: ${err.message}`));
            }

            exec(`xattr -cr "${robloxPath}" && codesign --force --deep --sign - "${robloxPath}" 2>/dev/null || true`, () => {
                const execPath = path.join(robloxPath, 'Contents', 'MacOS', 'RobloxPlayer');
                if (!fs.existsSync(execPath)) return reject(new Error('RobloxPlayer executable not found'));

                try {
                    const child = spawn(execPath, [], { detached: true, stdio: 'ignore' });
                    child.unref();
                    setTimeout(() => { try { this.resetBundleIdentifier(robloxPath); } catch {} }, 5000);
                    resolve({ success: true, pid: child.pid });
                } catch (err) {
                    reject(new Error(`Failed to launch Roblox: ${err.message}`));
                }
            });
        });
    }

    async openAccountWebsite(userId) {
        const accounts = this.loadAccounts();
        const account = accounts.find(acc => acc.userId === userId);
        if (!account) throw new Error('Account not found');

        const webSession = session.fromPartition(`website-${userId}`, { cache: true });
        await webSession.cookies.set({
            url: 'https://www.roblox.com',
            name: '.ROBLOSECURITY',
            value: account.cookie,
            domain: '.roblox.com',
            path: '/',
            secure: true,
            httpOnly: true
        });

        const webWindow = new BrowserWindow({
            width: 1200,
            height: 800,
            parent: this.mainWindow,
            webPreferences: { session: webSession, nodeIntegration: false, contextIsolation: true }
        });
        webWindow.loadURL('https://www.roblox.com');
        return { success: true };
    }

    async openLoginWindow() {
        return new Promise((resolve) => {
            const loginSession = session.fromPartition('login-session', { cache: false });

            const loginWindow = new BrowserWindow({
                width: 800,
                height: 700,
                parent: this.mainWindow,
                modal: true,
                webPreferences: { session: loginSession, nodeIntegration: false, contextIsolation: true }
            });

            loginSession.setUserAgent('Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36');
            loginSession.clearStorageData({ storages: ['cookies', 'localstorage', 'sessionstorage', 'cachestorage', 'serviceworkers'] });

            const checkCookie = async () => {
                try {
                    const cookies = await loginSession.cookies.get({ domain: '.roblox.com', name: '.ROBLOSECURITY' });
                    if (cookies.length > 0) {
                        const robloSecurity = cookies[0].value;
                        let userData;
                        try {
                            userData = await this.getRobloxUserData(robloSecurity);
                        } catch (err) {
                            loginWindow.close();
                            resolve({ error: { type: err.code === 'FORBIDDEN' ? 'forbidden' : 'unknown', message: err.message } });
                            return;
                        }

                        const accounts = this.loadAccounts();
                        const existingIndex = accounts.findIndex(acc => acc.userId === userData.id);
                        
                        const newAccount = {
                            cookie: robloSecurity,
                            userId: userData.id,
                            name: userData.name,
                            displayName: userData.displayName,
                            thumbnail: userData.thumbnail,
                            addedAt: new Date().toISOString()
                        };
                        
                        if (existingIndex >= 0) {
                            accounts[existingIndex] = newAccount;
                        } else {
                            accounts.push(newAccount);
                        }
                        
                        this.saveAccounts(accounts);
                        loginWindow.close();
                        resolve(newAccount);
                    }
                } catch {}
            };

            const cookieCheckInterval = setInterval(checkCookie, 500);
            loginWindow.loadURL('https://www.roblox.com/login');

            loginWindow.webContents.on('did-finish-load', () => {
                loginWindow.webContents.executeJavaScript(`
                    document.getElementById('header')?.remove();
                    document.getElementById('footer-container')?.remove();
                    const loginBtn = document.getElementById('login-button');
                    if (loginBtn) loginBtn.textContent = 'Add Account';
                    const header = document.querySelector('.login-header');
                    if (header) header.textContent = 'JewWare';
                    document.addEventListener('keydown', (e) => { if (e.key === 'Escape') window.close(); });
                    new MutationObserver(() => {
                        const btn = document.getElementById('login-button');
                        if (btn && btn.textContent !== 'Add Account') btn.textContent = 'Add Account';
                        const h = document.querySelector('.login-header');
                        if (h && h.textContent !== 'JewWare') h.textContent = 'JewWare';
                        document.getElementById('footer-container')?.remove();
                    }).observe(document.body, { childList: true, subtree: true, characterData: true });
                `).catch(() => {});
            });

            loginWindow.on('closed', () => {
                clearInterval(cookieCheckInterval);
                loginSession.clearStorageData({ storages: ['cookies', 'localstorage', 'sessionstorage', 'cachestorage', 'serviceworkers'] });
                resolve(null);
            });
        });
    }


    startLogMonitoring() {
        try {
            const logDir = path.join(os.homedir(), 'Library/Logs/Roblox');
            
            if (!fs.existsSync(logDir)) {
                this.sendToRenderer('updateConsoleOutput', `Roblox logs directory not found: ${logDir}`);
                return { status: 'error', message: 'Roblox logs directory not found' };
            }

            if (this.logMonitorInterval) {
                this.stopLogMonitoring();
            }

            this.sendToRenderer('updateConsoleOutput', 'Starting log monitoring...');
            
            let currentLogFile = null;
            let fileSize = 0;
            let lastFileCheck = 0;
            const fileCheckInterval = 5000;
            let logBuffer = [];
            let lastUpdateTime = Date.now();
            const updateInterval = 300;
            
            this.logMonitorInterval = setInterval(() => {
                try {
                    const currentTime = Date.now();
                    
                    if (currentTime - lastFileCheck >= fileCheckInterval) {
                        try {
                            const files = fs.readdirSync(logDir)
                                .filter(f => {
                                    const fullPath = path.join(logDir, f);
                                    return fs.statSync(fullPath).isFile() && !f.startsWith('.');
                                });
                            
                            if (files.length === 0) {
                                lastFileCheck = currentTime;
                                return;
                            }
                            
                            files.sort((a, b) => {
                                const aPath = path.join(logDir, a);
                                const bPath = path.join(logDir, b);
                                return fs.statSync(bPath).mtime.getTime() - fs.statSync(aPath).mtime.getTime();
                            });
                            
                            const latestLogFile = path.join(logDir, files[0]);
                            
                            if (latestLogFile !== currentLogFile) {
                                currentLogFile = latestLogFile;
                                fileSize = fs.existsSync(currentLogFile) ? fs.statSync(currentLogFile).size : 0;
                                this.sendToRenderer('updateConsoleOutput', `Monitoring new logs from: ${path.basename(currentLogFile)}`);
                            }
                        } catch (e) {
                            this.sendToRenderer('updateConsoleOutput', `Error checking log files: ${e.message}`);
                            setTimeout(() => {}, 2000);
                        }
                        lastFileCheck = currentTime;
                    }
                    
                    if (currentLogFile && fs.existsSync(currentLogFile)) {
                        try {
                            const currentStats = fs.statSync(currentLogFile);
                            const currentSize = currentStats.size;
                            
                            if (currentSize > fileSize) {
                                const chunkSize = 1024 * 1024;
                                const readSize = currentSize - fileSize > chunkSize ? chunkSize : currentSize - fileSize;
                                
                                const buffer = Buffer.alloc(readSize);
                                const fd = fs.openSync(currentLogFile, 'r');
                                
                                try {
                                    const bytesRead = fs.readSync(fd, buffer, 0, readSize, fileSize);
                                    const newContent = buffer.subarray(0, bytesRead).toString('utf8');
                                    
                                    fileSize = fs.statSync(currentLogFile).size;
                                    
                                    const lines = newContent.split('\n');
                                    for (const line of lines) {
                                        if (line.trim()) {
                                            let message = line;
                                            const match = line.match(/\s{2,}(.*)$/);
                                            if (match && match[1]) {
                                                message = match[1];
                                            }
                                            logBuffer.push(`[Output]: ${message}`);
                                        }
                                    }
                                } finally {
                                    fs.closeSync(fd);
                                }
                            }
                        } catch (e) {
                            logBuffer.push(`Error reading log file: ${e.message}`);
                        }
                    }
                    
                    if (logBuffer.length > 0 && (currentTime - lastUpdateTime >= updateInterval)) {
                        try {
                            let toSend;
                            if (logBuffer.length > 100) {
                                toSend = logBuffer.slice(-100);
                                logBuffer = [];
                            } else {
                                toSend = [...logBuffer];
                                logBuffer = [];
                            }
                            
                            if (toSend.length > 0) {
                                this.sendToRenderer('batchUpdateConsole', toSend);
                            }
                            
                            lastUpdateTime = currentTime;
                        } catch (e) {
                            console.error('Error updating console:', e);
                        }
                    }
                } catch (e) {
                    console.error('Log monitoring error:', e);
                    this.sendToRenderer('updateConsoleOutput', `Log monitoring error: ${e.message}`);
                }
            }, logBuffer.length === 0 ? this.logRefreshRate * 1000 : Math.min(100, (this.logRefreshRate * 1000) / 2));
            
            return { status: 'success', message: 'Log monitoring started' };
        } catch (e) {
            return { status: 'error', message: `Failed to start log monitoring: ${e.message}` };
        }
    }

    stopLogMonitoring() {
        if (this.logMonitorInterval) {
            clearInterval(this.logMonitorInterval);
            this.logMonitorInterval = null;
        }
    }

    setLogRefreshRate(rate) {
        this.logRefreshRate = Math.max(parseFloat(rate) || 0.5, 0.1);
        return { status: 'success', message: `Log refresh rate set to ${this.logRefreshRate}` };
    }

    sendToRenderer(channel, data) {
        if (this.mainWindow?.webContents && !this.mainWindow.isDestroyed()) {
            this.mainWindow.webContents.send(channel, data);
        }
    }

    getAiServiceUrl() {
        const configuredUrl = (process.env.JEWWARE_AI_ENDPOINT || '').trim();
        return configuredUrl || AI_SERVICE_URL_FALLBACK;
    }

    getDiscordIpcCandidates() {
        if (process.platform === 'win32') {
            return Array.from({ length: 10 }, (_, index) => `\\\\?\\pipe\\discord-ipc-${index}`);
        }

        const baseDirs = [
            process.env.XDG_RUNTIME_DIR,
            process.env.TMPDIR,
            process.env.TMP,
            process.env.TEMP,
            os.tmpdir()
        ].filter(Boolean);

        return [...new Set(baseDirs)].flatMap(baseDir =>
            Array.from({ length: 10 }, (_, index) => path.join(baseDir, `discord-ipc-${index}`))
        );
    }

    sendDiscordPresencePacket(opcode, payload) {
        if (!this.discordPresenceSocket || this.discordPresenceSocket.destroyed) {
            return false;
        }

        const message = Buffer.from(JSON.stringify(payload), 'utf8');
        const header = Buffer.alloc(8);
        header.writeInt32LE(opcode, 0);
        header.writeInt32LE(message.length, 4);
        this.discordPresenceSocket.write(Buffer.concat([header, message]));
        return true;
    }

    setDiscordPresence(state = DISCORD_PRESENCE.activeState) {
        if (!this.discordPresenceReady) {
            return false;
        }

        const activity = {
            details: 'JewWare',
            state,
            assets: {
                large_text: DISCORD_PRESENCE.largeImageText
            }
        };

        if (DISCORD_PRESENCE.largeImageKey) {
            activity.assets.large_image = DISCORD_PRESENCE.largeImageKey;
        }

        return this.sendDiscordPresencePacket(1, {
            cmd: 'SET_ACTIVITY',
            args: {
                pid: process.pid,
                activity
            },
            nonce: crypto.randomUUID()
        });
    }

    clearDiscordPresence() {
        if (!this.discordPresenceReady) {
            return false;
        }

        return this.sendDiscordPresencePacket(1, {
            cmd: 'SET_ACTIVITY',
            args: {
                pid: process.pid,
                activity: null
            },
            nonce: crypto.randomUUID()
        });
    }

    scheduleDiscordReconnect() {
        if (this.isQuitting || this.discordReconnectTimeout || !DISCORD_PRESENCE.clientId) {
            return;
        }

        this.discordReconnectTimeout = setTimeout(() => {
            this.discordReconnectTimeout = null;
            this.setupDiscordPresence().catch(error => {
                console.error('Discord presence reconnect failed:', error.message);
            });
        }, 15000);
    }

    handleDiscordPresenceClose() {
        this.discordPresenceReady = false;
        this.discordPresenceBuffer = Buffer.alloc(0);

        if (this.discordPresenceSocket) {
            this.discordPresenceSocket.removeAllListeners();
            this.discordPresenceSocket.destroy();
            this.discordPresenceSocket = null;
        }

        this.scheduleDiscordReconnect();
    }

    handleDiscordPresenceData(chunk) {
        this.discordPresenceBuffer = Buffer.concat([this.discordPresenceBuffer, chunk]);

        while (this.discordPresenceBuffer.length >= 8) {
            const opcode = this.discordPresenceBuffer.readInt32LE(0);
            const length = this.discordPresenceBuffer.readInt32LE(4);

            if (this.discordPresenceBuffer.length < 8 + length) {
                return;
            }

            const payloadBuffer = this.discordPresenceBuffer.subarray(8, 8 + length);
            this.discordPresenceBuffer = this.discordPresenceBuffer.subarray(8 + length);

            let payload = null;
            try {
                payload = JSON.parse(payloadBuffer.toString('utf8'));
            } catch (error) {
                continue;
            }

            if (opcode === 1 && payload?.evt === 'READY') {
                this.discordPresenceReady = true;
                this.setDiscordPresence(DISCORD_PRESENCE.activeState);
            }

            if (opcode === 3) {
                this.sendDiscordPresencePacket(4, payload);
            }

            if (opcode === 2) {
                this.handleDiscordPresenceClose();
                return;
            }
        }
    }

    connectDiscordPresenceSocket(socketPath, clientId) {
        return new Promise((resolve, reject) => {
            const socket = net.createConnection(socketPath);
            let settled = false;

            const fail = (error) => {
                if (settled) return;
                settled = true;
                socket.destroy();
                reject(error);
            };

            socket.once('error', fail);
            socket.once('connect', () => {
                if (settled) return;
                settled = true;
                socket.removeListener('error', fail);

                this.discordPresenceSocket = socket;
                this.discordPresenceReady = false;
                this.discordPresenceBuffer = Buffer.alloc(0);

                socket.on('data', chunk => this.handleDiscordPresenceData(chunk));
                socket.on('close', () => this.handleDiscordPresenceClose());
                socket.on('error', error => {
                    console.error('Discord presence socket error:', error.message);
                });

                this.sendDiscordPresencePacket(0, {
                    v: 1,
                    client_id: clientId
                });

                resolve();
            });
        });
    }

    async setupDiscordPresence() {
        if (!DISCORD_PRESENCE.clientId || this.discordPresenceSocket) {
            return;
        }

        const candidates = this.getDiscordIpcCandidates();
        for (const socketPath of candidates) {
            try {
                await this.connectDiscordPresenceSocket(socketPath, DISCORD_PRESENCE.clientId);
                return;
            } catch (error) {
                continue;
            }
        }
    }

    teardownDiscordPresence() {
        this.isQuitting = true;

        if (this.discordReconnectTimeout) {
            clearTimeout(this.discordReconnectTimeout);
            this.discordReconnectTimeout = null;
        }

        this.clearDiscordPresence();
        this.discordPresenceReady = false;
        this.discordPresenceBuffer = Buffer.alloc(0);

        if (this.discordPresenceSocket) {
            this.discordPresenceSocket.removeAllListeners();
            this.discordPresenceSocket.end();
            this.discordPresenceSocket.destroy();
            this.discordPresenceSocket = null;
        }
    }

    getTrayImage() {
        const iconPath = path.join(__dirname, 'assets', 'icon.png');
        if (!fs.existsSync(iconPath)) {
            return nativeImage.createEmpty();
        }

        const icon = nativeImage.createFromPath(iconPath);
        if (icon.isEmpty()) {
            return nativeImage.createEmpty();
        }

        return icon.resize({
            height: process.platform === 'darwin' ? 18 : 20,
            quality: 'best'
        });
    }

    async runTrayScript(scriptName, scriptContent) {
        try {
            const result = await this.executeScript(scriptContent);
            this.sendToRenderer('script-executed-from-tray', {
                script: scriptName,
                result
            });
            return result;
        } catch (e) {
            const result = {
                status: 'error',
                message: `Error executing "${scriptName}": ${e.message}`
            };
            this.sendToRenderer('script-executed-from-tray', {
                script: scriptName,
                result
            });
            console.error(`Error executing script from tray: ${e.message}`);
            return result;
        }
    }

    setupTray() {
        this.tray = new Tray(this.getTrayImage());
        this.tray.setTitle('');
        this.tray.setToolTip('JewWare Direct');
        this.updateTrayMenu();
    }

    updateTrayMenu() {
        const scripts = [];
        if (fs.existsSync(this.scriptsDirectory)) {
            const scriptFiles = fs.readdirSync(this.scriptsDirectory).filter(file => isSupportedScriptFile(file));
            scripts.push(...scriptFiles);
        }

        const template = [
            {
                label: 'JewWare Direct',
                enabled: false
            },
            {
                label: 'Quick Scripts',
                submenu: QUICK_SCRIPTS.map(({ label, script }) => ({
                    label,
                    click: async () => {
                        await this.runTrayScript(label, script);
                    }
                }))
            },
            { type: 'separator' }
        ];

        if (scripts.length > 0) {
            scripts.sort().forEach(scriptName => {
                template.push({
                    label: scriptName,
                    click: async () => {
                        try {
                            const scriptPath = path.join(this.scriptsDirectory, scriptName);
                            if (fs.existsSync(scriptPath)) {
                                const scriptContent = fs.readFileSync(scriptPath, 'utf8');
                                await this.runTrayScript(scriptName, scriptContent);
                            }
                        } catch (e) {
                            console.error(`Error executing script from tray: ${e.message}`);
                        }
                    }
                });
            });
        } else {
            template.push({
                label: 'No scripts found',
                enabled: false
            });
        }

        template.push(
            { type: 'separator' },
            {
                label: 'Open JewWare',
                click: () => {
                    if (this.mainWindow) {
                        this.mainWindow.show();
                        this.mainWindow.focus();
                        if (this.mainWindow.isMinimized()) {
                            this.mainWindow.restore();
                        }
                    }
                }
            },
            { type: 'separator' },
            {
                label: 'Quit',
                click: () => {
                    app.quit();
                }
            }
        );

        const contextMenu = Menu.buildFromTemplate(template);
        this.tray.setContextMenu(contextMenu);
        this.lastTrayMenu = contextMenu;
    }
}

let jewWareAPI;

function createWindow() {
    const mainWindow = new BrowserWindow({
        title: 'JewWare',
        width: 1280,
        height: 720,
        minWidth: 800,
        minHeight: 680,
        frame: false,
        vibrancy: 'fullscreen-ui',
        visualEffectState: 'active',
        hasShadow: false,
        icon: path.join(__dirname, 'assets', 'icon.png'),
        webPreferences: {
            nodeIntegration: true,
            contextIsolation: false,
            devTools: !app.isPackaged,
            webSecurity: false
        }
    });

    jewWareAPI.mainWindow = mainWindow;
    mainWindow.loadFile('index.html');

    mainWindow.webContents.setWindowOpenHandler(({ url }) => {
        if (url.startsWith('http://') || url.startsWith('https://')) {
            shell.openExternal(url);
        }
        return { action: 'deny' };
    });

    mainWindow.webContents.on('will-navigate', (event, url) => {
        if (!url.startsWith('file://')) {
            event.preventDefault();
            shell.openExternal(url);
        }
    });

    mainWindow.webContents.on('dom-ready', () => {
        mainWindow.webContents.executeJavaScript(`
            const header = document.querySelector('.header');
            if (header) {
                header.style.webkitAppRegion = 'drag';
                
                const buttons = header.querySelectorAll('.window-controls, .window-controls *');
                buttons.forEach(btn => {
                    btn.style.webkitAppRegion = 'no-drag';
                });
            }
        `);
    });

    mainWindow.on('focus', () => {
        jewWareAPI?.setDiscordPresence(DISCORD_PRESENCE.activeState);
    });

    mainWindow.on('show', () => {
        jewWareAPI?.setDiscordPresence(DISCORD_PRESENCE.activeState);
    });

    mainWindow.on('hide', () => {
        jewWareAPI?.setDiscordPresence(DISCORD_PRESENCE.backgroundState);
    });

    mainWindow.on('enter-full-screen', () => {
        mainWindow.webContents.send('fullscreen-changed', true);
    });

    mainWindow.on('leave-full-screen', () => {
        mainWindow.webContents.send('fullscreen-changed', false);
    });

    return mainWindow;
}


app.whenReady().then(async () => {
    app.setName('JewWare');
    if (process.platform === 'darwin' && app.dock) {
        app.dock.setIcon(path.join(__dirname, 'assets', 'icon.png'));
    }

    jewWareAPI = new JewWareAPI();

    const mainWindow = createWindow();
    jewWareAPI.setupTray();
    void jewWareAPI.setupDiscordPresence();

    globalShortcut.register('CommandOrControl+.', () => {
        if (jewWareAPI && jewWareAPI.tray && jewWareAPI.lastTrayMenu) {
            jewWareAPI.tray.popUpContextMenu(jewWareAPI.lastTrayMenu);
        }
    });

    ipcMain.handle('get-version', () => jewWareAPI.getVersion());
    ipcMain.handle('open-scripts-folder', () => jewWareAPI.openScriptsFolder());
    ipcMain.handle('execute-script', (event, scriptContent) => jewWareAPI.executeScript(scriptContent));
    ipcMain.handle('execute-script-on-port', (event, scriptContent, targetPort) => jewWareAPI.executeScriptOnPort(scriptContent, targetPort));
    ipcMain.handle('check-port-status', () => jewWareAPI.checkPortStatus());
    ipcMain.handle('get-game-name', (event, universeId) => jewWareAPI.getGameName(universeId));
    ipcMain.handle('get-scripts', (event, script) => jewWareAPI.getScripts(script));
    ipcMain.handle('open-roblox', () => jewWareAPI.openRoblox());
    ipcMain.handle('join-website', () => jewWareAPI.joinWebsite());
    ipcMain.handle('save-script', (event, name, content, autoExec, options) => jewWareAPI.saveScript(name, content, autoExec, options));
    ipcMain.handle('toggle-autoexec', (event, scriptName, enabled) => jewWareAPI.toggleAutoExec(scriptName, enabled));
    ipcMain.handle('get-local-scripts', () => jewWareAPI.getLocalScripts());
    ipcMain.handle('delete-script', (event, scriptName) => jewWareAPI.deleteScript(scriptName));
    ipcMain.handle('rename-script', (event, oldName, newName) => jewWareAPI.renameScript(oldName, newName));
    ipcMain.handle('import-script-folder', () => jewWareAPI.importScriptFolder());
    ipcMain.handle('send-ai-prompt', (event, prompt, editorContent, history) => jewWareAPI.sendAiPrompt(prompt, editorContent, history));
    ipcMain.handle('quit-app', () => jewWareAPI.quitApp());
    ipcMain.handle('minimize-app', () => jewWareAPI.minimizeApp());
    ipcMain.handle('toggle-fullscreen', () => jewWareAPI.toggleFullscreen());
    ipcMain.handle('get-latest-release-info', () => jewWareAPI.getLatestReleaseInfo());
    ipcMain.handle('start-log-monitoring', () => jewWareAPI.startLogMonitoring());
    ipcMain.handle('set-log-refresh-rate', (event, rate) => jewWareAPI.setLogRefreshRate(rate));
    ipcMain.handle('get-metadata', () => jewWareAPI.getMetadata());
    ipcMain.handle('save-metadata', (event, metadata) => jewWareAPI.saveMetadata(metadata));
    
    ipcMain.handle('get-accounts', () => jewWareAPI.getAccounts());
    ipcMain.handle('delete-account', (event, userId) => jewWareAPI.deleteAccount(userId));
    ipcMain.handle('export-accounts', () => jewWareAPI.exportAccounts());
    ipcMain.handle('import-accounts', () => jewWareAPI.importAccounts());
    ipcMain.handle('kill-all-roblox', () => jewWareAPI.killAllRoblox());
    ipcMain.handle('launch-account', (event, userId) => jewWareAPI.launchAccount(userId));
    ipcMain.handle('open-account-website', (event, userId) => jewWareAPI.openAccountWebsite(userId));
    ipcMain.handle('open-login-window', () => jewWareAPI.openLoginWindow());
    ipcMain.handle('add-account-manually', (event, cookie) => jewWareAPI.addAccountManually(cookie));

    ipcMain.on('window-minimize', () => {
        if (mainWindow) mainWindow.minimize();
    });

    ipcMain.on('window-close', () => {
        app.quit();
    });

    app.on('activate', () => {
        if (BrowserWindow.getAllWindows().length === 0) {
            createWindow();
        } else {
            mainWindow.show();
        }
    });
});


app.on('window-all-closed', () => {
    if (process.platform !== 'darwin') {
        app.quit();
    }
});

app.on('before-quit', () => {
    globalShortcut.unregisterAll();

    if (jewWareAPI) {
        jewWareAPI.teardownDiscordPresence();
    }

    if (jewWareAPI && jewWareAPI.tray) {
        jewWareAPI.tray.destroy();
    }
});
