const { app, BrowserWindow, ipcMain, dialog } = require('electron');
const path = require('path');
const { spawn } = require('child_process');

let mainWindow;
let splashWindow;
let pythonProcess;

const isDev = !app.isPackaged;

function createSplashWindow() {
  splashWindow = new BrowserWindow({
    width: 400,
    height: 300,
    transparent: true,
    frame: false,
    alwaysOnTop: true
  });
  
  const splashHTML = `
    <div style="font-family: sans-serif; height: 100vh; display: flex; flex-direction: column; align-items: center; justify-content: center; background: #1e1e2f; color: white; border-radius: 10px;">
      <h2>File Signature Analyzer</h2>
      <p>Starting AI Backend...</p>
    </div>
  `;
  splashWindow.loadURL(`data:text/html;charset=utf-8,${encodeURIComponent(splashHTML)}`);
}

function createWindow() {
  mainWindow = new BrowserWindow({
    width: 1200,
    height: 800,
    minWidth: 1000,
    minHeight: 700,
    title: "File Signature Analyzer — v1.0",
    show: false, // Don't show until app is ready and splashed
    titleBarStyle: 'default', // uses native
    icon: path.join(__dirname, 'assets', 'icon.png'),
    webPreferences: {
      nodeIntegration: true,
      contextIsolation: false, // Allows simple window.require('electron') in renderer
    }
  });

  if (isDev && process.argv.includes('--dev')) {
    // Assuming Vite dev server runs natively
    mainWindow.loadURL('http://localhost:5173');
    mainWindow.webContents.openDevTools(); // Open DevTools only in devmode
  } else {
    mainWindow.loadFile(path.join(__dirname, 'dist', 'index.html'));
  }

  mainWindow.once('ready-to-show', () => {
    if (splashWindow) {
      splashWindow.close();
      splashWindow = null;
    }
    mainWindow.show();
  });
}

function startPythonBackend() {
  return new Promise((resolve, reject) => {
    createSplashWindow();

    let scriptPath;
    let cwd;

    if (isDev) {
      // In Dev, relative to file_signature_recovery/gui/electron
      cwd = path.join(__dirname, '..', '..');
      scriptPath = path.join(cwd, 'gui', 'api', 'start_server.py');
    } else {
      // In Production, extraResources are inside process.resourcesPath
      cwd = process.resourcesPath;
      scriptPath = path.join(cwd, 'api', 'start_server.py');
    }

    pythonProcess = spawn('python', [scriptPath], { cwd: cwd });

    pythonProcess.stdout.on('data', (data) => {
      console.log(`[Python]: ${data}`);
    });

    pythonProcess.stderr.on('data', (data) => {
      console.error(`[Python Err]: ${data}`);
    });

    pythonProcess.on('close', (code) => {
      console.log(`Python process exited with code ${code}`);
    });

    pythonProcess.on('error', (err) => {
      reject(err);
    });

    // Wait exactly 2 seconds for FastAPI to be fully up
    setTimeout(() => {
      resolve();
    }, 2000);
  });
}

app.whenReady().then(async () => {
  try {
    await startPythonBackend();
    createWindow();
  } catch (err) {
    dialog.showErrorBox(
      "Startup Error", 
      "Failed to start Python backend. Make sure Python is installed on your system.\n\nDetails: " + err
    );
    app.quit();
  }

  app.on('activate', () => {
    if (BrowserWindow.getAllWindows().length === 0) {
      createWindow();
    }
  });
});

app.on('window-all-closed', () => {
  if (process.platform !== 'darwin') {
    app.quit();
  }
});

app.on('will-quit', () => {
  if (pythonProcess) {
    // Gracefully clean up deep python process tree
    if (process.platform === 'win32') {
      const { exec } = require('child_process');
      exec(`taskkill /pid ${pythonProcess.pid} /t /f`);
    } else {
      pythonProcess.kill();
    }
  }
});

// ----------------------------------------------------
// IPC Event Handlers
// ----------------------------------------------------

ipcMain.handle('analyze-file', async (event, filePath) => {
  try {
    const FormData = require('form-data');
    const fs = require('fs');
    const axios = require('axios');
    
    // We send multipart form data via axios straight from Node.js backend to local FastAPI
    const form = new FormData();
    form.append('file', fs.createReadStream(filePath));
    
    const response = await axios.post('http://127.0.0.1:7999/analyze', form, {
      headers: form.getHeaders(),
      maxContentLength: Infinity,
      maxBodyLength: Infinity
    });
    
    return response.data;
  } catch (error) {
    console.error("Analysis Request Error:", error);
    throw new Error(error.response?.data?.detail || error.message);
  }
});

ipcMain.handle('get-health', async () => {
  try {
    const axios = require('axios');
    const response = await axios.get('http://127.0.0.1:7999/health');
    return response.data;
  } catch (error) {
    return { status: "error", error: error.message };
  }
});

ipcMain.handle('read-results-json', async () => {
  const fs = require('fs');
  const path = require('path');
  let filePath;
  if (!app.isPackaged) {
    filePath = path.join(__dirname, '..', '..', 'outputs', 'evaluation_results.json');
  } else {
    filePath = path.join(process.resourcesPath, 'outputs', 'evaluation_results.json');
  }
  
  if (fs.existsSync(filePath)) {
    return fs.readFileSync(filePath, 'utf8');
  }
  return null;
});
