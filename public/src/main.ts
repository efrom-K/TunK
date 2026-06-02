import { mount } from '@tauri-apps/api/core';
import App from './App.vue';
import './style.css';

// Инициализация Tauri приложения
mount({
  el: '#app',
  app: window.__TAURI__.createApp(App),
});

console.log('Tauri VPN Client initialized');
