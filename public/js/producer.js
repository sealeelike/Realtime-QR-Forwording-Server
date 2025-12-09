// Auth check and logout
async function checkAuth() {
  try {
    const res = await fetch('/api/auth/me');
    if (!res.ok) {
      window.location.href = '/login.html';
      return false;
    }
    const data = await res.json();
    document.getElementById('currentUser').textContent = `${data.user.username} (${data.user.role})`;
    
    // Inject admin link for admin/owner
    if (data.user.role === 'admin' || data.user.role === 'owner') {
      document.getElementById('admin-nav').innerHTML = '<a href="/admin.html">Admin</a>';
    }
    
    document.body.classList.add('auth-ready');
    return true;
  } catch {
    window.location.href = '/login.html';
    return false;
  }
}

async function logout() {
  await fetch('/api/auth/logout', { method: 'POST' });
  window.location.href = '/login.html';
}

const video = document.getElementById('video');
const canvas = document.getElementById('canvas');
const ctx = canvas.getContext('2d', { willReadFrequently: true });
const statusEl = document.getElementById('status');
const channelInfo = document.getElementById('channel-info');
const channelIdEl = document.getElementById('channel-id');
const consumerCountEl = document.getElementById('consumer-count');
const lastUrlEl = document.getElementById('last-url');
const btnStartCamera = document.getElementById('btn-start-camera');
const shareLinkEl = document.getElementById('share-link');
const btnCopyLink = document.getElementById('btn-copy-link');
const copyStatusEl = document.getElementById('copy-status');

let ws = null;
let lastDetectedUrl = '';
let scanning = false;
let serverDomain = '';

const params = new URLSearchParams(window.location.search);
const customChannelId = params.get('channel') || '';
const channelPassword = params.get('password') || '';

// Fetch server config for domain
fetch('/api/admin/config')
  .then(res => res.json())
  .then(config => { serverDomain = config.domain || ''; })
  .catch(() => {});

function connect() {
  const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
  ws = new WebSocket(`${protocol}//${window.location.host}/ws`);

  ws.onopen = () => {
    updateStatus('connected', 'Connected to server');
    ws.send(JSON.stringify({
      type: 'create_channel',
      channelId: customChannelId || null,
      password: channelPassword || null
    }));
  };

  ws.onmessage = (event) => {
    const data = JSON.parse(event.data);
    
    switch (data.type) {
      case 'channel_created':
        channelIdEl.textContent = data.channelId;
        channelInfo.classList.remove('hidden');
        updateShareLink(data.channelId);
        break;
      
      case 'consumer_count':
        consumerCountEl.textContent = data.count;
        break;
      
      case 'error':
        updateStatus('disconnected', `Error: ${data.message}`);
        break;
    }
  };

  ws.onclose = () => {
    updateStatus('disconnected', 'Disconnected from server');
    setTimeout(connect, 3000);
  };

  ws.onerror = () => {
    updateStatus('disconnected', 'Connection error');
  };
}

function updateStatus(type, message) {
  statusEl.className = `status ${type}`;
  statusEl.textContent = message;
}

async function startCamera() {
  try {
    const stream = await navigator.mediaDevices.getUserMedia({
      video: { facingMode: 'environment' }
    });
    video.srcObject = stream;
    video.play();
    
    video.onloadedmetadata = () => {
      canvas.width = video.videoWidth;
      canvas.height = video.videoHeight;
      scanning = true;
      btnStartCamera.textContent = 'Camera Active';
      btnStartCamera.disabled = true;
      scanQRCode();
    };
  } catch (err) {
    alert('Failed to access camera: ' + err.message);
  }
}

function scanQRCode() {
  if (!scanning) return;

  ctx.drawImage(video, 0, 0, canvas.width, canvas.height);
  const imageData = ctx.getImageData(0, 0, canvas.width, canvas.height);
  
  const code = jsQR(imageData.data, imageData.width, imageData.height, {
    inversionAttempts: 'dontInvert'
  });

  if (code && code.data && code.data !== lastDetectedUrl) {
    lastDetectedUrl = code.data;
    lastUrlEl.innerHTML = `<a href="${escapeHtml(code.data)}" target="_blank">${escapeHtml(code.data)}</a>`;
    
    if (ws && ws.readyState === WebSocket.OPEN) {
      ws.send(JSON.stringify({
        type: 'url_update',
        url: code.data,
        timestamp: Date.now()
      }));
    }
  }

  requestAnimationFrame(scanQRCode);
}

function escapeHtml(text) {
  const div = document.createElement('div');
  div.textContent = text;
  return div.innerHTML;
}

function updateShareLink(channelId) {
  const base = serverDomain || `${window.location.protocol}//${window.location.host}`;
  const linkParams = new URLSearchParams({ channel: channelId });
  if (channelPassword) linkParams.append('password', channelPassword);
  shareLinkEl.value = `${base}/consumer.html?${linkParams.toString()}`;
}

btnCopyLink.addEventListener('click', () => {
  navigator.clipboard.writeText(shareLinkEl.value).then(() => {
    copyStatusEl.textContent = 'Link copied!';
    setTimeout(() => { copyStatusEl.textContent = ''; }, 2000);
  }).catch(() => {
    shareLinkEl.select();
    document.execCommand('copy');
    copyStatusEl.textContent = 'Link copied!';
    setTimeout(() => { copyStatusEl.textContent = ''; }, 2000);
  });
});

btnStartCamera.addEventListener('click', startCamera);

// Initialize
checkAuth().then(ok => {
  if (ok) connect();
});
