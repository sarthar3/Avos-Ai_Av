const { app, BrowserWindow, ipcMain } = require('electron');
const path = require('path');
const grpc = require('@grpc/grpc-js');
const protoLoader = require('@grpc/proto-loader');
const isDev = !app.isPackaged;

// Load gRPC Proto
const PROTO_PATH = path.join(__dirname, '../../shared/proto/avos.proto');
const packageDefinition = protoLoader.loadSync(PROTO_PATH, {
    keepCase: true, longs: String, enums: String, defaults: true, oneofs: true
});
const avosProto = grpc.loadPackageDefinition(packageDefinition).avos;

let mainWindow;
let grpcClient;

function createWindow() {
    mainWindow = new BrowserWindow({
        width: 1280, height: 800,
        title: "AVOS — Intelligent Security Platform",
        frame: false,
        backgroundColor: '#f4f5f6',
        webPreferences: {
            preload: path.join(__dirname, 'preload.js'),
            nodeIntegration: false,
            contextIsolation: true,
        },
    });

    const startURL = isDev
        ? 'http://localhost:3000'
        : `file://${path.join(__dirname, '../build/index.html')}`;
    mainWindow.loadURL(startURL);

    // Initialize gRPC Client
    grpcClient = new avosProto.AvosService(
        'localhost:50051',
        grpc.credentials.createInsecure()
    );

    // Start Threat Stream
    startThreatStream();

    // Poll system status every 2 seconds
    setInterval(pollSystemStatus, 2000);

    if (isDev) {
        mainWindow.webContents.openDevTools({ mode: 'detach' });
    }
}

// ─── gRPC Streaming + Polling ────────────────────────────────────────────────

function startThreatStream() {
    const stream = grpcClient.StreamThreatEvents({});
    stream.on('data', (threat) => {
        if (mainWindow) {
            mainWindow.webContents.send('threat-detected', threat);
        }
    });
    stream.on('error', (err) => {
        console.error("gRPC Stream Error:", err.message);
        // Reconnect after 5s
        setTimeout(startThreatStream, 5000);
    });
}

function pollSystemStatus() {
    grpcClient.GetSystemStatus({}, (err, status) => {
        if (!err && mainWindow) {
            mainWindow.webContents.send('status-update', status);
        }
    });
}

// ─── App Lifecycle ────────────────────────────────────────────────────────────

app.whenReady().then(createWindow);
app.on('window-all-closed', () => {
    if (process.platform !== 'darwin') app.quit();
});

// ─── Window Controls ──────────────────────────────────────────────────────────

ipcMain.on('window-minimize', () => mainWindow.minimize());
ipcMain.on('window-maximize', () => mainWindow.isMaximized() ? mainWindow.unmaximize() : mainWindow.maximize());
ipcMain.on('window-close', () => mainWindow.close());

// ─── Mode ─────────────────────────────────────────────────────────────────────

ipcMain.handle('set-mode', async (event, mode) => {
    return new Promise((resolve, reject) => {
        grpcClient.SetMode({ mode }, (err, res) => err ? reject(err) : resolve(res));
    });
});

// ─── Module Config ────────────────────────────────────────────────────────────

ipcMain.handle('set-module-config', async (event, { name, enabled }) => {
    return new Promise((resolve, reject) => {
        grpcClient.SetModuleConfig({ module_name: name, enabled }, (err, res) =>
            err ? reject(err) : resolve(res)
        );
    });
});

// ─── Threats ─────────────────────────────────────────────────────────────────

ipcMain.handle('get-threats', async (event, { limit, offset, filter } = {}) => {
    return new Promise((resolve, reject) => {
        grpcClient.GetThreats(
            { limit: limit || 100, offset: offset || 0, filter: filter || '' },
            (err, res) => err ? reject(err) : resolve(res)
        );
    });
});

ipcMain.handle('quarantine-file', async (event, filePath) => {
    return new Promise((resolve, reject) => {
        grpcClient.QuarantineFile({ path: filePath }, (err, res) =>
            err ? reject(err) : resolve(res)
        );
    });
});

// ─── On-Demand Scan ───────────────────────────────────────────────────────────

ipcMain.handle('scan-file', async (event, filePath) => {
    return new Promise((resolve, reject) => {
        grpcClient.ScanFile({ path: filePath }, (err, res) =>
            err ? reject(err) : resolve(res)
        );
    });
});

// ─── AI Chat ──────────────────────────────────────────────────────────────────

ipcMain.handle('chat', async (event, { question, eventId }) => {
    return new Promise((resolve, reject) => {
        grpcClient.Chat(
            { question, threat_event_id: eventId || '' },
            (err, res) => err ? reject(err) : resolve(res)
        );
    });
});

// ─── Dark Web / Breach Alerts ────────────────────────────────────────────────

ipcMain.handle('get-breach-alerts', async () => {
    return new Promise((resolve, reject) => {
        grpcClient.GetBreachAlerts({}, (err, res) => err ? reject(err) : resolve(res));
    });
});

// ─── Payment Shield ───────────────────────────────────────────────────────────

ipcMain.handle('launch-secure-browser', async (event, url) => {
    return new Promise((resolve, reject) => {
        grpcClient.LaunchSecureBrowser({ url }, (err, res) =>
            err ? reject(err) : resolve(res)
        );
    });
});

ipcMain.handle('tokenize-card-data', async (event, { card, exp, cvv }) => {
    return new Promise((resolve, reject) => {
        grpcClient.TokenizeCardData({ card_number: card, expiry: exp, cvv }, (err, res) =>
            err ? reject(err) : resolve(res)
        );
    });
});

ipcMain.handle('wipe-clipboard', async () => {
    return new Promise((resolve, reject) => {
        grpcClient.WipeClipboard({}, (err, res) => err ? reject(err) : resolve(res));
    });
});

// ─── DNS Audit ────────────────────────────────────────────────────────────────

ipcMain.handle('audit-dns', async (event, domains) => {
    return new Promise((resolve, reject) => {
        grpcClient.AuditDns({ domains: domains || [] }, (err, res) =>
            err ? reject(err) : resolve(res)
        );
    });
});

// ─── Utilities ────────────────────────────────────────────────────────────────

ipcMain.handle('scan-registry', async () => {
    return new Promise((resolve, reject) => {
        grpcClient.ScanRegistry({}, (err, res) => err ? reject(err) : resolve(res));
    });
});

ipcMain.handle('clean-temp', async (event, includeBrowserCache) => {
    return new Promise((resolve, reject) => {
        grpcClient.CleanTemp({ include_browser_cache: includeBrowserCache !== false }, (err, res) =>
            err ? reject(err) : resolve(res)
        );
    });
});

ipcMain.handle('lock-folder', async (event, { folderPath, password }) => {
    return new Promise((resolve, reject) => {
        grpcClient.LockFolder({ path: folderPath, password }, (err, res) =>
            err ? reject(err) : resolve(res)
        );
    });
});

ipcMain.handle('unlock-folder', async (event, { folderPath, password }) => {
    return new Promise((resolve, reject) => {
        grpcClient.UnlockFolder({ path: folderPath, password }, (err, res) =>
            err ? reject(err) : resolve(res)
        );
    });
});

// ─── Firewall ─────────────────────────────────────────────────────────────────

ipcMain.handle('get-firewall-rules', async () => {
    return new Promise((resolve, reject) => {
        grpcClient.GetFirewallRules({}, (err, res) => err ? reject(err) : resolve(res));
    });
});

// ─── EDR Events ──────────────────────────────────────────────────────────────

ipcMain.handle('get-edr-events', async (event, limit) => {
    return new Promise((resolve, reject) => {
        grpcClient.GetEDREvents({ limit: limit || 200 }, (err, res) =>
            err ? reject(err) : resolve(res)
        );
    });
});
