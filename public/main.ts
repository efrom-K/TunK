import { invoke } from '@tauri-apps/api/core';
import { emit } from '@tauri-apps/event';

// Type declarations for Tauri API
declare global {
    interface Window {
        tauri: any;
    }
}

// State management
let isConnected = false;
let pingValue = 0;
let downloadSpeed = 0;
let uploadSpeed = 0;
let serverList: string[] = [];

// DOM Elements
const connectBtn = document.getElementById('connect-btn') as HTMLButtonElement;
const statusIndicator = document.getElementById('status-indicator') as HTMLElement;
const pingValueEl = document.getElementById('ping-value') as HTMLElement;
const downloadValueEl = document.getElementById('download-value') as HTMLElement;
const uploadValueEl = document.getElementById('upload-value') as HTMLElement;
const subscriptionInput = document.getElementById('subscription-input') as HTMLInputElement;
const addSubscriptionBtn = document.getElementById('add-subscription-btn') as HTMLButtonElement;
const serverListEl = document.getElementById('server-list') as HTMLUListElement;
const logContainer = document.getElementById('log-container') as HTMLElement;

// Initialize Tauri API
window.tauri = window.tauri || {};

// Toggle VPN connection
connectBtn.addEventListener('click', async () => {
    try {
        if (isConnected) {
            // Disconnect
            await invoke<void>('toggle_vpn', { enable: false });
            isConnected = false;
            
            updateUI(false);
            logToSniffer('[00:00:00] [INFO] VPN отключен');
        } else {
            // Connect
            await invoke<void>('toggle_vpn', { enable: true });
            isConnected = true;
            
            updateUI(true);
            logToSniffer('[00:00:00] [INFO] Подключение к VPN...');
        }
    } catch (error) {
        console.error('Error toggling VPN:', error);
        logToSniffer(`[ERROR] Ошибка при переключении VPN: ${error}`);
    }
});

// Add subscription
addSubscriptionBtn.addEventListener('click', async () => {
    const url = subscriptionInput.value.trim();
    
    if (!url) {
        logToSniffer('[WARNING] Введите URL подписки');
        return;
    }
    
    try {
        const profiles = await invoke<any[]>('add_subscription', { url });
        
        // Add to server list
        profiles.forEach(profile => {
            if (!serverList.includes(profile.name)) {
                serverList.push(profile.name);
                renderServerItem(profile);
            }
        });
        
        subscriptionInput.value = '';
        logToSniffer(`[INFO] Добавлен сервер: ${profiles[0]?.name || 'Неизвестный'}`);
    } catch (error) {
        console.error('Error adding subscription:', error);
        logToSniffer(`[ERROR] Ошибка при добавлении подписки: ${error}`);
    }
});

// Render server item
function renderServerItem(profile: any): void {
    const li = document.createElement('li');
    li.className = 'server-item';
    
    const nameSpan = document.createElement('span');
    nameSpan.textContent = profile.name;
    nameSpan.title = profile.url;
    
    const statusBadge = document.createElement('span');
    statusBadge.className = 'status-badge';
    statusBadge.style.cssText = `
        padding: 2px 8px;
        border-radius: 10px;
        font-size: 11px;
        background-color: #e5e7eb;
        color: var(--text-secondary);
    `;
    statusBadge.textContent = 'Offline';
    
    li.appendChild(nameSpan);
    li.appendChild(statusBadge);
    serverListEl.appendChild(li);
}

// Update UI based on connection state
function updateUI(connected: boolean): void {
    if (connected) {
        connectBtn.textContent = 'Отключить';
        statusIndicator.textContent = 'Подключено';
        statusIndicator.className = 'status-indicator connected';
        
        // Simulate stats updates
        setInterval(() => {
            pingValue = Math.floor(Math.random() * 50) + 10;
            downloadSpeed = Math.floor(Math.random() * 200) + 50;
            uploadSpeed = Math.floor(Math.random() * 100) + 20;
            
            pingValueEl.textContent = pingValue.toString();
            downloadValueEl.textContent = downloadSpeed.toString();
            uploadValueEl.textContent = uploadSpeed.toString();
        }, 2000);
    } else {
        connectBtn.textContent = 'Подключить';
        statusIndicator.textContent = 'Отключено';
        statusIndicator.className = 'status-indicator disconnected';
        
        pingValueEl.textContent = '--';
        downloadValueEl.textContent = '--';
        uploadValueEl.textContent = '--';
    }
}

// Log to sniffer
function logToSniffer(message: string): void {
    const timestamp = new Date().toLocaleTimeString('ru-RU');
    const entry = document.createElement('div');
    entry.className = 'log-entry';
    entry.textContent = `[${timestamp}] ${message}`;
    
    // Insert at the beginning
    logContainer.insertBefore(entry, logContainer.firstChild);
    
    // Keep only last 100 entries
    while (logContainer.children.length > 100) {
        logContainer.removeChild(logContainer.lastChild as Element);
    }
}

// Listen for status changes from Rust backend
window.addEventListener('load', () => {
    window.tauri?.event?.listen('status-change', (event: any) => {
        const status = event.payload.status;
        
        if (status === 'connected') {
            isConnected = true;
            updateUI(true);
            logToSniffer('[05:24:11] [INFO] Подключение завершено');
        } else if (status === 'disconnected') {
            isConnected = false;
            updateUI(false);
            logToSniffer('[05:24:11] [INFO] Отключено от сети');
        }
    });
    
    window.tauri?.event?.listen('stats-update', (event: any) => {
        const stats = event.payload.stats;
        
        pingValueEl.textContent = stats.ping.toString();
        downloadValueEl.textContent = Math.floor(stats.download_bps / 125000).toString();
        uploadValueEl.textContent = Math.floor(stats.upload_bps / 125000).toString();
    });
    
    window.tauri?.event?.listen('log-entry', (event: any) => {
        logToSniffer(event.payload.message);
    });
});

// Initial UI state
updateUI(false);
