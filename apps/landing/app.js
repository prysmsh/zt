// The landing page's live bits.
//
// The numbers and the logs are theatre: they show the shape of what a
// node does. Nothing here talks to the controller.

/** The handshake a node performs, typed out line by line. */
const SCRIPT = [
  ['$', 'zt-agent enroll --network production', 'plain'],
  ['ok', 'node enrolled · address 10.42.0.7 · key ml-dsa-65', 'accent'],
  ['ok', 'credential issued · expires in 24h', 'dim'],
  ['$', 'zt-agent run --interface zt0', 'plain'],
  ['ok', 'listening 0.0.0.0:9994 · udp', 'dim'],
  ['ok', 'handshake peer-02 · x25519 + ml-kem-768', 'plain'],
  ['ok', 'handshake peer-02 · ml-dsa-65 verified', 'accent'],
  ['ok', 'session established · replay window 64', 'dim'],
  ['ok', 'forwarding 10.42.0.0/24 → peers', 'plain'],
  ['ok', 'relay 4 nodes · 1.2k pkt/s', 'dim'],
];

/** The nodes the table shows. */
const NODES = [
  ['peer-01', 'eu-west-1', 'ONLINE', '3.8ms'],
  ['peer-02', 'eu-west-2', 'ONLINE', '4.1ms'],
  ['peer-03', 'us-east-1', 'ONLINE', '4.6ms'],
  ['peer-04', 'us-west-2', 'ONLINE', '4.2ms'],
  ['edge-01', 'ap-south-1', 'SYNCING', '11.3ms'],
];

/** Write the terminal, one line at a time. */
function runTerminal(element) {
  let index = 0;

  const tick = () => {
    if (index >= SCRIPT.length) {
      // Start over, so the panel is never static.
      window.setTimeout(() => {
        element.replaceChildren();
        index = 0;
        tick();
      }, 4000);
      return;
    }

    const [mark, text, kind] = SCRIPT[index];
    const line = document.createElement('div');
    line.className = `terminal-line${kind === 'accent' ? ' accent' : kind === 'dim' ? ' dim' : ''}`;
    line.textContent = `${mark} ${text}`;
    element.append(line);

    while (element.childElementCount > 7) {
      element.firstElementChild.remove();
    }

    index += 1;
    window.setTimeout(tick, 520);
  };

  tick();
}

/** Fill the node table. */
function fillNodes(element) {
  for (const [name, region, status, latency] of NODES) {
    const row = document.createElement('tr');

    for (const [value, className] of [
      [name, ''],
      [region, ''],
      [status, status === 'ONLINE' ? 'status-online' : ''],
      [latency, ''],
    ]) {
      const cell = document.createElement('td');
      cell.textContent = value;
      if (className) {
        cell.className = className;
      }
      row.append(cell);
    }

    element.append(row);
  }
}

/**
 * Draw a mesh of hosts, dithered.
 *
 * The nodes drift, the links between them light up as traffic crosses
 * them, and the whole thing is reduced to a dot grid, the way an
 * isometric render survives a low resolution.
 */
function drawMesh(canvas) {
  const context = canvas.getContext('2d');
  if (!context) {
    return;
  }

  const width = canvas.width;
  const height = canvas.height;
  const cell = 4;

  const nodes = Array.from({ length: 14 }, (_, index) => ({
    x: 20 + ((index * 71) % (width - 40)),
    y: 16 + ((index * 113) % (height - 32)),
    phase: index * 1.7,
  }));

  const frame = (time) => {
    context.clearRect(0, 0, width, height);
    context.fillStyle = '#16150f';
    context.fillRect(0, 0, width, height);

    // The links.
    context.strokeStyle = 'rgba(234, 88, 12, 0.55)';
    context.lineWidth = 1;
    for (let a = 0; a < nodes.length; a += 1) {
      for (let b = a + 1; b < nodes.length; b += 1) {
        const distance = Math.hypot(nodes[a].x - nodes[b].x, nodes[a].y - nodes[b].y);
        if (distance > 96) {
          continue;
        }
        const pulse = Math.sin(time / 700 + a * 0.9 + b * 0.4);
        context.globalAlpha = 0.15 + Math.max(0, pulse) * 0.75;
        context.beginPath();
        context.moveTo(nodes[a].x, nodes[a].y);
        context.lineTo(nodes[b].x, nodes[b].y);
        context.stroke();
      }
    }
    context.globalAlpha = 1;

    // The hosts, on the dot grid.
    for (const node of nodes) {
      const drift = Math.sin(time / 1400 + node.phase) * 3;
      const x = node.x + drift;
      const y = node.y + Math.cos(time / 1700 + node.phase) * 3;

      for (let dx = -6; dx <= 6; dx += cell) {
        for (let dy = -6; dy <= 6; dy += cell) {
          const distance = Math.hypot(dx, dy);
          if (distance > 7) {
            continue;
          }
          const lit = distance < 3.5;
          context.fillStyle = lit ? '#ea580c' : 'rgba(240, 235, 220, 0.35)';
          context.fillRect(Math.round(x + dx), Math.round(y + dy), 2, 2);
        }
      }
    }

    window.requestAnimationFrame(frame);
  };

  window.requestAnimationFrame(frame);
}

/** Count the counters up, and keep them moving. */
function runMetrics() {
  const latency = document.getElementById('metric-latency');
  const packets = document.getElementById('metric-packets');
  const uptime = document.getElementById('metric-uptime');
  const nodes = document.getElementById('metric-nodes');
  const throughput = document.getElementById('throughput');
  const statUptime = document.getElementById('stat-uptime');

  if (!latency || !packets || !uptime || !nodes || !throughput || !statUptime) {
    return;
  }

  const started = Date.now();

  window.setInterval(() => {
    const seconds = Math.floor((Date.now() - started) / 1000);
    const drift = Math.sin(seconds / 3) * 0.8;

    latency.textContent = `${(4.2 + drift).toFixed(1)}ms`;
    packets.textContent = `${(1.2 + Math.sin(seconds / 2) * 0.3).toFixed(1)}K`;
    uptime.textContent = `${(99.98 + Math.sin(seconds / 5) * 0.01).toFixed(2)}%`;
    nodes.textContent = String(147 + Math.round(Math.sin(seconds / 7) * 3)).padStart(3, '0');
    throughput.textContent = (1.2 + Math.sin(seconds / 2) * 0.3).toFixed(1);

    const days = Math.floor(seconds / 86400);
    const hours = Math.floor((seconds % 86400) / 3600);
    const minutes = Math.floor((seconds % 3600) / 60);
    statUptime.textContent = `${days}d ${String(hours).padStart(2, '0')}h ${String(minutes).padStart(2, '0')}m ${String(seconds % 60).padStart(2, '0')}s`;
  }, 1000);
}

const terminal = document.getElementById('terminal');
if (terminal) {
  runTerminal(terminal);
}

const nodeRows = document.getElementById('nodes');
if (nodeRows) {
  fillNodes(nodeRows);
}

const mesh = document.getElementById('mesh');
if (mesh) {
  drawMesh(mesh);
}

runMetrics();
