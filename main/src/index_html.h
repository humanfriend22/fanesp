#pragma once

static const char *INDEX_HTML = R"rawliteral(<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>FanESP Controller</title>
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/@picocss/pico@2/css/pico.min.css">
    <style>
        body { max-width: 900px; }
        .grid { grid-template-columns: 1fr 1fr; }
        button { cursor: pointer; }
        .error { color: red; }
        .success { color: green; }
    </style>
</head>
<body>
    <main class="container">
        <h1>🌬️ FanESP Controller</h1>

        <section>
            <h2>Devices</h2>
            <button onclick="listDevices()">Refresh Devices</button>
            <button onclick="startDiscovery()">Discover Device</button>
            <div id="devices"></div>
        </section>

        <section>
            <h2>Device Control</h2>
            <label>
                Select Device:
                <select id="deviceSelect" onchange="loadFeatures()">
                    <option value="">-- Choose device --</option>
                </select>
            </label>
            <div id="features"></div>
        </section>

        <div id="status"></div>
    </main>

    <script>
        const API_BASE = '';

        function showStatus(msg, isError = false) {
            const div = document.getElementById('status');
            div.innerHTML = `<div class="${isError ? 'error' : 'success'}">${msg}</div>`;
            setTimeout(() => { div.innerHTML = ''; }, 3000);
        }

        async function listDevices() {
            try {
                const res = await fetch(`${API_BASE}/device`);
                const macs = await res.json();

                const select = document.getElementById('deviceSelect');
                const currentVal = select.value;
                select.innerHTML = '<option value="">-- Choose device --</option>';

                let html = '<table><thead><tr><th>Device MAC</th><th>Action</th></tr></thead><tbody>';
                for (const mac of macs) {
                    html += `<tr><td>${mac}</td><td><button onclick="loadDeviceFeatures('${mac}')">View</button></td></tr>`;
                    const opt = document.createElement('option');
                    opt.value = mac;
                    opt.textContent = mac;
                    select.appendChild(opt);
                }
                html += '</tbody></table>';
                document.getElementById('devices').innerHTML = html || '<p>No devices found</p>';

                if (macs.length > 0) {
                    showStatus(`Found ${macs.length} device(s)`);
                }
            } catch (e) {
                showStatus(`Error: ${e}`, true);
            }
        }

        async function startDiscovery() {
            const btn = event.target;
            btn.disabled = true;
            btn.textContent = 'Discovering...';

            try {
                const res = await fetch(`${API_BASE}/discover`);
                const data = await res.json();

                if (data.status === 'found') {
                    showStatus(`Device found: ${data.mac}`);
                    listDevices();
                } else {
                    showStatus('No device found', true);
                }
            } catch (e) {
                showStatus(`Error: ${e}`, true);
            } finally {
                btn.disabled = false;
                btn.textContent = 'Discover Device';
            }
        }

        async function loadDeviceFeatures(mac) {
            try {
                const res = await fetch(`${API_BASE}/device/${mac}`);
                const data = await res.json();

                let html = `<h3>Features for ${mac}</h3><div class="grid">`;
                for (const feature of data.features) {
                    html += `<div><h4>${feature.name}</h4>`;
                    for (const value of feature.values) {
                        html += `<button onclick="executeFeature('${mac}', '${feature.name}', '${value}')">${value}</button>`;
                    }
                    html += '</div>';
                }
                html += '</div>';
                document.getElementById('features').innerHTML = html;
            } catch (e) {
                showStatus(`Error loading features: ${e}`, true);
            }
        }

        async function loadFeatures() {
            const mac = document.getElementById('deviceSelect').value;
            if (mac) {
                loadDeviceFeatures(mac);
            } else {
                document.getElementById('features').innerHTML = '';
            }
        }

        async function executeFeature(mac, feature, value) {
            try {
                const res = await fetch(`${API_BASE}/device/${mac}/${feature}/${value}`);
                const data = await res.json();

                if (data.status === 'ok') {
                    showStatus(`${feature} ${value} - OK`);
                } else {
                    showStatus(`${feature} ${value} - Error`, true);
                }
            } catch (e) {
                showStatus(`Error: ${e}`, true);
            }
        }

        // Load devices on page load
        listDevices();
    </script>
</body>
</html>)rawliteral";
