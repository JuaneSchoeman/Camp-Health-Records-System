const { app, BrowserWindow, ipcMain } = require('electron');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const { exec } = require('child_process');
const util = require('util');
const execPromise = util.promisify(exec);
require('dotenv').config();

// Imports from project modules
const { openEncryptedDatabase } = require('./database/database');
const { createAuditLogger, ACTION_TYPES } = require('./database/auditLog');
const { insertPatient, logAuditEvent } = require('./services/dbController');
const { verifyPassword, hashPassword } = require('./services/authService');
const { exportOfflineBackup } = require('./services/syncService');
const { importPatientsFromCsv } = require('./services/csvImportService');
const { createPatientProfile } = require('./services/patientProfileService');
const { findPatient } = require('./services/patientQueryService');
const { listUsbDrives } = require('./services/usbDetection');
const { handleIpcSafely } = require('./utils/errorHandler');

let mainWindow;
let dbInstance = null;
let dbFilePath = null;
let auditLog = null;

const DB_ENCRYPTION_KEY = process.env.DB_ENCRYPTION_KEY || 'dev_db_passphrase';
const JWT_SECRET = process.env.JWT_SECRET || 'dev_jwt_secret_key';

function initDatabase() {
  try {
    dbFilePath = path.join(app.getPath('userData'), 'chrs.db');
    console.log(`[Backend DB] Initializing SQLCipher connection at: ${dbFilePath}`);
    dbInstance = openEncryptedDatabase(dbFilePath, DB_ENCRYPTION_KEY);
    auditLog = createAuditLogger(dbInstance);
    console.log('[Backend DB] Encrypted database initialized.');
  } catch (error) {
    console.error('[Backend DB] Database initialization failed:', error.message);
  }
}

const getDb = () => dbInstance;

function createWindow() {
  mainWindow = new BrowserWindow({
    width: 1280,
    height: 800,
    title: 'Camp Health Records System (CHRS)',
    webPreferences: {
      preload: path.join(__dirname, 'preload.js'),
      contextIsolation: true,
      nodeIntegration: false,
      sandbox: false,
    },
  });

  const startUrl = process.env.ELECTRON_START_URL || `file://${path.join(__dirname, '../build/index.html')}`;
  mainWindow.loadURL(startUrl);

  mainWindow.on('closed', () => {
    mainWindow = null;
  });
}

app.whenReady().then(() => {
  initDatabase();
  createWindow();

  app.on('activate', () => {
    if (BrowserWindow.getAllWindows().length === 0) createWindow();
  });
});

app.on('window-all-closed', () => {
  if (process.platform !== 'darwin') app.quit();
});

// ============================================================================
// IPC HANDLERS
// ============================================================================

// 1. Authentication Endpoint
ipcMain.handle('auth:login', async (event, { username, password }) => {
  console.log(`[Backend Auth] Login attempt for user: ${username}`);

  const roleByUsername = {
    admin: 'Admin',
    nurse: 'Nurse',
    physician: 'Physician',
    counselor: 'Counselor',
  };
  const role = roleByUsername[username?.toLowerCase()];

  if (role && password === 'password123') {
    const normalizedUsername = username.toLowerCase();
    const databaseRoleByUsername = {
      admin: 'camp_administrator',
      nurse: 'camp_nurse',
      physician: 'camp_physician',
    };
    const db = getDb();
    if (db && databaseRoleByUsername[normalizedUsername]) {
      const existingUser = db.prepare('SELECT id, is_active FROM users WHERE username = ?').get(normalizedUsername);
      if (existingUser && !existingUser.is_active) {
        return { success: false, message: 'This account is disabled.' };
      }
      if (!existingUser) {
        const passwordHash = await hashPassword(password);
        db.prepare(`
          INSERT INTO users (username, password_hash, role, full_name)
          VALUES (?, ?, ?, ?)
        `).run(normalizedUsername, passwordHash, databaseRoleByUsername[normalizedUsername], normalizedUsername);
      }
    }

    const userId = `usr-${normalizedUsername}-01`;
    const header = Buffer.from(JSON.stringify({ alg: 'HS256', typ: 'JWT' })).toString('base64url');
    const payload = Buffer.from(
      JSON.stringify({
        userId,
        username: normalizedUsername,
        role,
        exp: Math.floor(Date.now() / 1000) + 60 * 60 * 8, // 8 hours
      })
    ).toString('base64url');

    const signature = crypto
      .createHmac('sha256', JWT_SECRET)
      .update(`${header}.${payload}`)
      .digest('base64url');

    const jwtToken = `${header}.${payload}.${signature}`;

    return {
      success: true,
      token: jwtToken,
      user: { userId, username: normalizedUsername, role },
    };
  }

  return { success: false, message: 'Invalid credentials' };
});

// 2. Tamper-Evident Audit Logging
handleIpcSafely(ipcMain, 'audit:log-event', getDb, async (event, logData = {}) => {
  if (!auditLog) throw new Error('Audit log is not available: database failed to initialize.');

  try {
    const entry = auditLog.logEvent({
      userId: logData.userId ?? null,
      action: logData.action ?? null,
      actionType: logData.actionType ?? null,
      targetTable: logData.targetTable ?? 'system',
      targetId: logData.targetId ?? null,
      beforeImage: logData.beforeImage ?? null,
      afterImage: logData.afterImage ?? null,
      viewDurationMs: logData.viewDurationMs ?? null,
      details: logData.details ?? null,
    });

    return { success: true, id: entry.id, hash: entry.entryHash };
  } catch (err) {
    console.warn('[Audit Log Warning] Could not record log event:', err.message);
    return { success: false, error: err.message };
  }
});

// Read audit log entries
handleIpcSafely(ipcMain, 'audit:get-entries', getDb, async (event, filters = {}) => {
  if (!auditLog) throw new Error('Audit log is not available: database failed to initialize.');
  return auditLog.getEntries(filters);
});

// Verify audit chain integrity
handleIpcSafely(ipcMain, 'audit:verify-chain', getDb, async () => {
  if (!auditLog) throw new Error('Audit log is not available: database failed to initialize.');
  return auditLog.verifyChain();
});

// Import a camper roster and audit each patient insert in the same transaction.
handleIpcSafely(ipcMain, 'patient:import-csv', getDb, async (event, importData = {}) => {
  const db = getDb();
  if (!db) throw new Error('Database is not available.');
  return importPatientsFromCsv(db, importData);
});

// Create a patient profile and its audit entry atomically.
handleIpcSafely(ipcMain, 'patient:create', getDb, async (event, profile = {}) => {
  const db = getDb();
  if (!db) throw new Error('Database is not available.');
  return createPatientProfile(db, profile);
});

// 3. Clinical Records Queries
handleIpcSafely(ipcMain, 'patient:get-by-id', getDb, async (event, searchTerm) => {
  const db = getDb();
  if (!db) throw new Error('Database is not available.');
  console.log(`[Backend DB] Searching for patient: ${searchTerm}`);
  return findPatient(db, searchTerm);
});

// 4. USB Backup
handleIpcSafely(ipcMain, 'backup:list-drives', getDb, async () => {
  return listUsbDrives();
});

handleIpcSafely(ipcMain, 'backup:start', getDb, async (event, { driveLetter, folderName, initiatedByUserId } = {}) => {
  const db = getDb();
  if (!db) throw new Error('Database is not available.');
  if (!driveLetter) throw new Error('No drive selected.');

  const result = await exportOfflineBackup(db, dbFilePath, driveLetter, folderName, initiatedByUserId);

  if (auditLog) {
    try {
      auditLog.logEvent({
        userId: initiatedByUserId ?? null,
        actionType: 'EXPORT',
        targetTable: 'backup_log',
        details: `USB backup written to ${driveLetter}${result.folderName}, sha256=${result.hash}`,
      });
    } catch (err) {
      console.warn('[Audit Log Warning] Could not log backup event:', err.message);
    }
  }

  return result;
});