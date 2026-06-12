import { useEffect, useState } from 'react';
import { invoke } from '@tauri-apps/api/core';
import './style.css';

type VpnStatus = 'Disconnected' | 'Connecting' | 'Connected' | 'Disconnecting';

interface ProxyProfile {
  id: string;
  name: string;
  url: string;
  protocol: 'Vless' | 'Shadowsocks' | 'Trojan';
  server: string;
  port: number;
  username: string | null;
  password: string | null;
}

interface LogEntry {
  timestamp: string;
  level: string;
  message: string;
}

const POLL_INTERVAL_MS = 1000;

export default function App() {
  const [status, setStatus] = useState<VpnStatus>('Disconnected');
  const [speedBps, setSpeedBps] = useState<number>(0);
  const [logs, setLogs] = useState<LogEntry[]>([]);
  const [subscriptionUrl, setSubscriptionUrl] = useState<string>('');
  const [profiles, setProfiles] = useState<ProxyProfile[]>([]);
  const [selectedProfileId, setSelectedProfileId] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  // Опрос статуса, скорости и логов с бэкенда
  useEffect(() => {
    const poll = async () => {
      try {
        const [currentStatus, currentSpeed, currentLogs] = await Promise.all([
          invoke<VpnStatus>('get_vpn_status'),
          invoke<number>('get_speed_bps'),
          invoke<LogEntry[]>('get_logs'),
        ]);

        setStatus(currentStatus);
        setSpeedBps(currentSpeed);
        setLogs(currentLogs);
      } catch (err) {
        console.error('Error polling VPN state:', err);
      }
    };

    poll();
    const interval = setInterval(poll, POLL_INTERVAL_MS);

    return () => clearInterval(interval);
  }, []);

  // Загрузка списка профилей при старте
  useEffect(() => {
    invoke<ProxyProfile[]>('get_profiles')
      .then(setProfiles)
      .catch((err) => console.error('Error loading profiles:', err));
  }, []);

  const handleToggleVpn = async () => {
    setError(null);

    try {
      const newStatus = await invoke<VpnStatus>('toggle_vpn', { enable: status !== 'Connected' });
      setStatus(newStatus);
    } catch (err) {
      setError(String(err));
    }
  };

  const handleAddSubscription = async () => {
    if (!subscriptionUrl.trim()) return;

    setError(null);

    try {
      const newProfiles = await invoke<ProxyProfile[]>('add_subscription', { url: subscriptionUrl });
      setProfiles(newProfiles);
      setSubscriptionUrl('');
    } catch (err) {
      setError(String(err));
    }
  };

  const handleSelectProfile = async (profileId: string) => {
    setError(null);

    try {
      await invoke<void>('set_profile', { profileId });
      setSelectedProfileId(profileId);
    } catch (err) {
      setError(String(err));
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

  const statusText: Record<VpnStatus, string> = {
    Disconnected: 'Отключено',
    Connecting: 'Подключение...',
    Connected: 'Подключено',
    Disconnecting: 'Отключение...',
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
          <div className={`status-indicator ${status.toLowerCase()}`}>
            {statusText[status]}
          </div>

          <div className="speed-display">
            <span className="label">Скорость:</span>
            <span className="value">{formatSpeed(speedBps)}</span>
          </div>
        </section>

        {error && (
          <section className="error-section">
            <p className="error-message">{error}</p>
          </section>
        )}

        {/* Кнопка подключения */}
        <section className="control-section">
          <button
            className={`btn ${status === 'Connected' ? 'btn-danger' : 'btn-success'}`}
            onClick={handleToggleVpn}
            disabled={status === 'Connecting' || status === 'Disconnecting'}
          >
            {status === 'Connected' ? 'Отключить VPN' : 'Подключить VPN'}
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
              placeholder="vless://uuid@server.com:443#name или ss://base64@server.com:8388#name"
            />
            <button onClick={handleAddSubscription}>Добавить</button>
          </div>

          {profiles.length > 0 && (
            <div className="profiles-list">
              <h3>Доступные профили:</h3>
              {profiles.map((profile) => (
                <div key={profile.id} className="profile-item">
                  <span>
                    {profile.name} ({profile.protocol} — {profile.server}:{profile.port})
                  </span>
                  <button
                    onClick={() => handleSelectProfile(profile.id)}
                    disabled={selectedProfileId === profile.id}
                  >
                    {selectedProfileId === profile.id ? 'Выбран' : 'Выбрать'}
                  </button>
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
