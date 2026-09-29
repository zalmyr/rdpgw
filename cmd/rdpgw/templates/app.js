// RDP Gateway Web Interface
'use strict';

const config = {
    progressAnimationDuration: 2000, // ms for progress bar animation
    searchThreshold: 6,              // show the search box above this many hosts
    maxRecentHosts: 5,
    recentHostsKey: 'rdpgw.recentHosts',
};

let userInfo = null;
let servers = [];

// Get user initials for avatar
function getUserInitials(name) {
    return (name || '').split(/[\s@._-]+/).filter(Boolean).map(w => w.charAt(0)).slice(0, 2).join('').toUpperCase() || 'U';
}

function el(tag, className, text) {
    const node = document.createElement(tag);
    if (className) node.className = className;
    if (text !== undefined) node.textContent = text;
    return node;
}

// Redirect to login when the session expired. OIDC answers API calls with
// an HTML redirect to the identity provider instead of JSON.
function handleAuthenticationError(response) {
    const contentType = response.headers.get('content-type') || '';
    if (response.status === 401 || response.status === 403 || contentType.includes('text/html')) {
        window.location.href = '/';
        return true;
    }
    return false;
}

async function getJSON(url) {
    const response = await fetch(url, { credentials: 'same-origin', cache: 'no-store' });
    if (handleAuthenticationError(response)) return null;
    if (!response.ok) throw new Error(`${url}: ${response.status}`);
    return response.json();
}

// Messages
function showError(message) {
    const node = document.getElementById('error');
    node.textContent = message;
    node.style.display = 'block';
    hideSuccess();
}

function hideError() {
    document.getElementById('error').style.display = 'none';
}

function showSuccess(message) {
    const node = document.getElementById('success');
    node.textContent = message;
    node.style.display = 'block';
    hideError();
}

function hideSuccess() {
    document.getElementById('success').style.display = 'none';
}

function showNotice(message) {
    const node = document.getElementById('notice');
    node.textContent = message;
    node.hidden = !message;
}

// Animate progress bar
function animateProgress(duration = config.progressAnimationDuration) {
    const progressFill = document.getElementById('progressFill');
    progressFill.style.width = '0%';

    let startTime = null;
    function animate(currentTime) {
        if (!startTime) startTime = currentTime;
        const progress = Math.min((currentTime - startTime) / duration, 1);
        progressFill.style.width = (progress * 100) + '%';
        if (progress < 1) requestAnimationFrame(animate);
    }
    requestAnimationFrame(animate);
}

// Load user information
async function loadUserInfo() {
    try {
        userInfo = await getJSON('/api/v1/user');
        if (!userInfo) return;
        document.getElementById('username').textContent = userInfo.username;
        document.getElementById('userAvatar').textContent = getUserInitials(userInfo.username);
    } catch (error) {
        showError('Failed to load user information');
    }
}

// Render servers in the grid
function renderServers(list) {
    const grid = document.getElementById('serversGrid');
    grid.replaceChildren();

    list.forEach(server => {
        const card = el('div', 'server-card');
        const content = el('div', 'server-content');

        const icon = el('div', 'server-icon');
        const img = el('img');
        img.src = '/static/connect.svg';
        img.alt = '';
        icon.appendChild(img);

        const info = el('div', 'server-info');
        const name = el('div', 'server-name', server.name);
        if (server.isDefault && list.length > 1) name.appendChild(el('span', 'badge', 'default'));
        info.appendChild(name);
        info.appendChild(el('div', 'server-description', server.description));
        if (server.address && server.address !== server.name) {
            info.appendChild(el('div', 'server-address', server.address));
        }

        content.append(icon, info);

        const button = el('button', 'server-connect-button', `Connect to ${server.name}`);
        button.type = 'button';
        button.addEventListener('click', () => connect(server.connectUrl, button));

        card.append(content, button);
        grid.appendChild(card);
    });
}

function applySearch() {
    const query = document.getElementById('hostSearch').value.trim().toLowerCase();
    if (!query) {
        renderServers(servers);
        return;
    }
    renderServers(servers.filter(s =>
        [s.name, s.description, s.address].some(v => (v || '').toLowerCase().includes(query))));
}

// Load available servers
async function loadServers() {
    try {
        const list = await getJSON('/api/v1/hosts');
        if (!list) return;
        servers = list;
        document.getElementById('toolbar').hidden = servers.length <= config.searchThreshold;
        applySearch();
        return servers;
    } catch (error) {
        showError('Failed to load available servers');
        return [];
    }
}

// Recently used custom hosts, kept in this browser only
function recentHosts() {
    try {
        return JSON.parse(localStorage.getItem(config.recentHostsKey) || '[]').filter(h => typeof h === 'string');
    } catch (e) {
        return [];
    }
}

function rememberHost(host) {
    try {
        const list = [host, ...recentHosts().filter(h => h !== host)].slice(0, config.maxRecentHosts);
        localStorage.setItem(config.recentHostsKey, JSON.stringify(list));
    } catch (e) {
        // storage unavailable (private mode, blocked site data)
    }
    renderRecentHosts();
}

function renderRecentHosts() {
    const container = document.getElementById('recentHosts');
    container.replaceChildren();
    recentHosts().forEach(host => {
        const button = el('button', '', host);
        button.type = 'button';
        button.addEventListener('click', () => {
            document.getElementById('customHostInput').value = host;
        });
        container.appendChild(button);
    });
}

function setupCustomHost(settings) {
    if (!settings.allowCustomHost) return;

    document.getElementById('customHost').hidden = false;
    const hint = document.getElementById('customHostHint');
    if (settings.customHostPatterns && settings.customHostPatterns.length) {
        hint.textContent = 'Allowed: ' + settings.customHostPatterns.join(', ');
    } else if (settings.hostSelection === 'any') {
        hint.textContent = 'Publicly reachable hosts on the allowed ports.';
    }
    renderRecentHosts();

    document.getElementById('customHostForm').addEventListener('submit', async (e) => {
        e.preventDefault();
        const input = document.getElementById('customHostInput');
        const host = input.value.trim();
        if (!host) return;
        const ok = await connect('/connect?host=' + encodeURIComponent(host),
            document.getElementById('customHostButton'));
        if (ok) rememberHost(host);
    });
}

function filenameFromResponse(response) {
    const disposition = response.headers.get('content-disposition') || '';
    const match = disposition.match(/filename="?([^";]+)"?/i);
    return match ? match[1] : 'connection.rdp';
}

// Fetch the RDP file and hand it to the browser as a download. Fetching
// (instead of navigating) lets us show the gateway's error message.
async function connect(url, button) {
    if (!url) return false;
    hideError();
    hideSuccess();

    const originalText = button.textContent;
    const loading = document.getElementById('loading');
    button.disabled = true;
    button.textContent = 'Preparing...';
    loading.style.display = 'block';
    animateProgress();

    try {
        const response = await fetch(url, { credentials: 'same-origin', cache: 'no-store' });
        if (handleAuthenticationError(response)) return false;
        if (!response.ok) {
            const text = (await response.text()).trim();
            throw new Error(text || `Download failed (${response.status})`);
        }

        const blob = await response.blob();
        const objectUrl = URL.createObjectURL(blob);
        const link = document.createElement('a');
        link.href = objectUrl;
        link.download = filenameFromResponse(response);
        document.body.appendChild(link);
        link.click();
        link.remove();
        setTimeout(() => URL.revokeObjectURL(objectUrl), 10000);

        showSuccess('RDP file downloaded. Open it with your Remote Desktop client.');
        return true;
    } catch (error) {
        showError(`Could not prepare the connection: ${error.message}`);
        return false;
    } finally {
        button.disabled = false;
        button.textContent = originalText;
        setTimeout(() => { loading.style.display = 'none'; }, 500);
    }
}

document.addEventListener('DOMContentLoaded', async () => {
    document.getElementById('hostSearch').addEventListener('input', applySearch);

    const [settings] = await Promise.all([
        getJSON('/api/v1/settings').catch(() => null),
        loadUserInfo(),
    ]);
    const effective = settings || { hostSelection: '', allowCustomHost: false };

    const list = await loadServers();
    setupCustomHost(effective);

    if (effective.message) {
        showNotice(effective.message);
    } else if (list && list.length === 0 && !effective.allowCustomHost) {
        showNotice('No servers are available for your account. Contact your administrator.');
    }
});

// Refresh the server list when the tab becomes visible again, keeping any
// search the user typed.
document.addEventListener('visibilitychange', () => {
    if (!document.hidden) loadServers();
});
