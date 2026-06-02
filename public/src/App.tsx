import { useState, useEffect } from 'react';
import { invoke, listen } from '@tauri-apps/api/core';
import './style.css';

type VpnStatus = 'disconnected' | 'connecting' | 'connected' | 'disconnecting';

interface LogEntry {
  timestamp: string;
  level: string;
  message: string;
}

export default function App() {
  const [status, setStatus] = useState<VpnStatus>('disconnected');
  const [speedBps, setSpeedBps] = useState<number>(0);
  const [logs, setLogs] = useState<LogEntry[]>([]);
  const [subscriptionUrl, setSubscriptionUrl] = useState<string>('');
  const [profiles, setProfiles] = useState<string[]>([]);

  useEffect(() => {
    // Подписка на события из Rust бэкенда
    const statusEvent = listen<VpnStatus>('status_changed', (event) => {
      setStatus(event.payload);
    });
    
    return () => {
      // Cleanup
      statusEvent.then(unlisten);
    };
  }, []);

  useEffect(() => {
    // Подписка на скорость
    const speedEvent = listen<number>('speed_changed', (event) => {
      setSpeedBps(event.payload);
    });
    
    return () => {
      // Cleanup
      speedEvent.then(unlisten);
    };
  }, []);

  useEffect(() => {
    // Подписка на логи
    const logsEvent = listen<LogEntry>('log_entry', (event) => {
      setLogs(prev => [...prev, event.payload]);
    });
    
    return () => {
      // Cleanup
      logsEvent.then(unlisten);
    };
  }, []);

  const handleToggleVpn = async (enable: boolean) => {
    try {
      await invoke<void>('toggle_vpn', { enable });
      
      setStatus(enable ? 'connecting' : 'disconnecting');
      
      setTimeout(() => {
        setStatus(enable ? 'connected' : 'disconnected');
      }, 2000);
    } catch (error) {
      console.error('Error toggling VPN:', error);
    }
  };

  const handleAddSubscription = async () => {
    if (!subscriptionUrl.trim()) return;
    
    try {
      const profiles = await invoke<string[]>('add_subscription', { url: subscriptionUrl });
      setProfiles(profiles);
      setSubscriptionUrl('');
      
      // Добавление лога о добавлении подписки
      addLog('INFO', 'SUBSCRIPTION', `Добавлена подписка: ${subscriptionUrl}`);
    } catch (error) {
      console.error('Error adding subscription:', error);
      addLog('ERROR', 'SUBSCRIPTION', 'Ошибка при добавлении подписки');
    }
  };

  const handleSelectProfile = async (profile: string) => {
    try {
      await invoke<void>('set_profile', { profile });
      
      // Добавление лога о выборе профиля
      addLog('INFO', 'PROFILE', `Выбран профиль: ${profile}`);
    } catch (error) {
      console.error('Error selecting profile:', error);
    }
  };

  const handleClearLogs = () => {
    setLogs([]);
  };

  const formatSpeed = (bps: number): string => {
    if (bps === 0) return '0 B/s';
    
    const mbps = bps / 1_048_576;
    const kbps = bps / 1_024;
    
    if (mbps >= 1) {
      return `${mbps.toFixed(2)} MB/s`;
    } else if (kbps >= 1) {
      return `${kbps.toFixed(2)} KB/s`;
    } else {
      return `${bps} B/s`;
    }
  };

  const getStatusText = (): string => {
    switch (status) {
      case 'disconnected':
        return 'Отключено';
      case 'connecting':
        return 'Подключение...';
      case 'connected':
        return 'Подключено';
      case 'disconnecting':
        return 'Отключение...';
      default:
        return 'Неизвестно';
    }
  };

  const getStatusColor = (): string => {
    switch (status) {
      case 'disconnected':
        return '#6c757d'; // Gray
      case 'connecting':
        return '#ffc107'; // Warning
      case 'connected':
        return '#28a745'; // Success
      case 'disconnecting':
        return '#ffc107'; // Warning
      default:
        return '#6c757d';
    }
  };

  const addLog = (level: string, source: string, message: string) => {
    const timestamp = new Date().toLocaleTimeString('ru-RU');
    
    setLogs(prev => [...prev, {
      timestamp,
      level,
      message,
    }]);
  };

  return (
    <div className="app">
      <header className="app-header">
        <h1>VPN Client</h1>
        <p className="subtitle">Windows 11 Lightweight VPN</p>
      </header>

      <main className="app-main">
        {/* Статус и скорость */}
        <section className="status-section">
          <div className={`status-indicator ${status}`}>
            {getStatusText()}
          </div>
          
          <div className="speed-display">
            <span className="label">Скорость:</span>
            <span className="value">{formatSpeed(speedBps)}</span>
          </div>
        </section>

        {/* Кнопка подключения */}
        <section className="control-section">
          <button 
            className={`btn ${status === 'connected' ? 'btn-danger' : 'btn-success'}`}
            onClick={() => handleToggleVpn(!status.includes('dis'))}
            disabled={status === 'connecting' || status === 'disconnecting'}
          >
            {status === 'connected' ? 'Отключить VPN' : 'Подключить VPN'}
          </button>
        </section>

        {/* Менеджер профилей */}
        <section className="profiles-section">
          <h2>Менеджер профилей</h2>
          
          <div className="input-group">
            <label htmlFor="subscription-url">URL подписки:</label>
            <input
              type="text"
              id="subscription-url"
              value={subscriptionUrl}
              onChange={(e) => setSubscriptionUrl(e.target.value)}
              placeholder="vless://user@server.com:443 или ss://base64data@server.com:8388"
            />
            <button onClick={handleAddSubscription}>Добавить</button>
          </div>

          {profiles.length > 0 && (
            <div className="profiles-list">
              <h3>Доступные профили:</h3>
              {profiles.map((profile, index) => (
                <div key={index} className="profile-item">
                  <span>{profile}</span>
                  <button onClick={() => handleSelectProfile(profile)}>Выбрать</button>
                </div>
              ))}
            </div>
          )}
        </section>

        {/* Логирование */}
        <section className="logs-section">
          <h2>Логи (Sniffer)</h2>
          
          <div className="log-controls">
            <button onClick={handleClearLogs}>Очистить логи</button>
          </div>

          <div className="logs-container">
            {logs.length === 0 ? (
              <p className="no-logs">Нет записей в логах</p>
            ) : (
              logs.map((log, index) => (
                <div key={index} className={`log-entry ${log.level.toLowerCase()}`}>
                  <span className="timestamp">{log.timestamp}</span>
                  <span className={`level-badge ${log.level.toLowerCase()}`}>({log.level})</span>
                  <span className="message">{log.message}</span>
                </div>
              ))
            )}
          </div>
        </section>
      </main>

      <footer className="app-footer">
        <p>&copy; 2024 VPN Client Team. Все права защищены.</p>
      </footer>
    </div>
  );
}
