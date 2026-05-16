const sampleCsv = `timestamp,ip,username,event,service,port,path,status,message
2026-05-13T10:00:00Z,192.168.1.25,admin,LOGIN,ssh,22,/login,FAIL,invalid password
2026-05-13T10:01:00Z,192.168.1.25,admin,LOGIN,ssh,22,/login,FAIL,invalid password
2026-05-13T10:02:00Z,192.168.1.25,admin,LOGIN,ssh,22,/login,FAIL,invalid password
2026-05-13T10:03:00Z,192.168.1.25,admin,LOGIN,ssh,22,/login,FAIL,invalid password
2026-05-13T10:04:00Z,192.168.1.25,admin,LOGIN,ssh,22,/login,FAIL,invalid password
2026-05-13T10:05:00Z,192.168.1.25,admin,LOGIN,ssh,22,/login,SUCCESS,logged in
2026-05-13T10:07:00Z,10.0.0.44,guest,REQUEST,http,80,/index.html,OK,normal request
2026-05-13T10:08:00Z,10.0.0.44,guest,REQUEST,http,80,/../../etc/passwd,FAIL,path traversal attempt
2026-05-13T10:09:00Z,10.0.0.44,guest,REQUEST,http,80,/search?q=union+select+password,FAIL,possible SQL injection
2026-05-13T10:10:00Z,10.0.0.44,guest,REQUEST,http,80,/comment?text=<script>alert(1)</script>,FAIL,possible XSS
2026-05-13T10:12:00Z,172.16.5.9,scanner,CONNECT,tcp,21,/connect,FAIL,connection refused
2026-05-13T10:12:20Z,172.16.5.9,scanner,CONNECT,tcp,22,/connect,FAIL,connection refused
2026-05-13T10:12:40Z,172.16.5.9,scanner,CONNECT,tcp,23,/connect,FAIL,connection refused
2026-05-13T10:13:00Z,172.16.5.9,scanner,CONNECT,tcp,25,/connect,FAIL,connection refused
2026-05-13T10:13:20Z,172.16.5.9,scanner,CONNECT,tcp,53,/connect,FAIL,connection refused
2026-05-13T10:13:40Z,172.16.5.9,scanner,CONNECT,tcp,80,/connect,FAIL,connection refused
2026-05-13T10:14:00Z,172.16.5.9,scanner,CONNECT,tcp,443,/connect,FAIL,connection refused
2026-05-13T10:20:00Z,203.0.113.10,bot,REQUEST,http,80,/wp-login.php,FAIL,wordpress login probe
2026-05-13T10:21:00Z,203.0.113.10,bot,REQUEST,http,80,/admin,FAIL,admin panel probe
2026-05-13T10:22:00Z,203.0.113.10,bot,REQUEST,http,80,/api/users,OK,enumerating users
2026-05-13T10:23:00Z,203.0.113.10,bot,REQUEST,https,443,/api/orders,OK,enumerating orders
2026-05-13T10:24:00Z,203.0.113.10,bot,REQUEST,db,5432,/connect,FAIL,database access attempt
2026-05-13T10:25:00Z,203.0.113.10,bot,REQUEST,cache,6379,/connect,FAIL,redis access attempt`;

const customCsv = `timestamp,ip,username,event,service,port,path,status,message
2026-05-13T11:00:00Z,192.168.10.5,root,LOGIN,ssh,22,/login,FAIL,bad login
2026-05-13T11:01:00Z,192.168.10.5,root,LOGIN,ssh,22,/login,FAIL,bad login
2026-05-13T11:02:00Z,192.168.10.5,root,LOGIN,ssh,22,/login,FAIL,bad login
2026-05-13T11:03:00Z,192.168.10.5,root,LOGIN,ssh,22,/login,FAIL,bad login
2026-05-13T11:04:00Z,192.168.10.5,root,LOGIN,ssh,22,/login,FAIL,bad login
2026-05-13T11:05:00Z,192.168.10.5,root,LOGIN,ssh,22,/login,SUCCESS,login successful
2026-05-13T11:10:00Z,10.10.0.8,visitor,REQUEST,http,80,/index.html,OK,normal page view
2026-05-13T11:11:00Z,10.10.0.8,visitor,REQUEST,http,80,/../../etc/passwd,FAIL,path traversal attempt
2026-05-13T11:12:00Z,10.10.0.8,visitor,REQUEST,http,80,/search?q=union+select+email,FAIL,sql injection attempt
2026-05-13T11:13:00Z,10.10.0.8,visitor,REQUEST,http,80,/comment?text=<script>alert(1)</script>,FAIL,xss attempt
2026-05-13T11:20:00Z,172.20.1.9,unknown,CONNECT,tcp,21,/connect,FAIL,connection refused
2026-05-13T11:20:20Z,172.20.1.9,unknown,CONNECT,tcp,22,/connect,FAIL,connection refused
2026-05-13T11:20:40Z,172.20.1.9,unknown,CONNECT,tcp,23,/connect,FAIL,connection refused
2026-05-13T11:21:00Z,172.20.1.9,unknown,CONNECT,tcp,25,/connect,FAIL,connection refused
2026-05-13T11:21:20Z,172.20.1.9,unknown,CONNECT,tcp,53,/connect,FAIL,connection refused
2026-05-13T11:21:40Z,172.20.1.9,unknown,CONNECT,tcp,80,/connect,FAIL,connection refused
2026-05-13T11:30:00Z,203.0.113.77,bot,REQUEST,http,80,/wp-login.php,FAIL,wordpress probe
2026-05-13T11:31:00Z,203.0.113.77,bot,REQUEST,http,80,/admin,FAIL,admin probe
2026-05-13T11:32:00Z,203.0.113.77,bot,REQUEST,db,5432,/connect,FAIL,database access attempt
2026-05-13T11:33:00Z,203.0.113.77,bot,REQUEST,cache,6379,/connect,FAIL,redis access attempt`;

const indicators = [
  "../",
  "etc/passwd",
  "wp-login",
  "admin",
  "union",
  "select",
  "<script>",
  "redis",
  "database"
];

let activeFilter = "all";
let currentReport = null;

const elements = {
  fileInput: document.querySelector("#fileInput"),
  logInput: document.querySelector("#logInput"),
  loadSampleBtn: document.querySelector("#loadSampleBtn"),
  customSampleBtn: document.querySelector("#customSampleBtn"),
  analyzeBtn: document.querySelector("#analyzeBtn"),
  clearBtn: document.querySelector("#clearBtn"),
  exportBtn: document.querySelector("#exportBtn"),
  eventCount: document.querySelector("#eventCount"),
  alertCount: document.querySelector("#alertCount"),
  highRiskCount: document.querySelector("#highRiskCount"),
  topSource: document.querySelector("#topSource"),
  riskSummary: document.querySelector("#riskSummary"),
  riskList: document.querySelector("#riskList"),
  mapSummary: document.querySelector("#mapSummary"),
  serviceMap: document.querySelector("#serviceMap"),
  traceSummary: document.querySelector("#traceSummary"),
  traceGrid: document.querySelector("#traceGrid"),
  alertsTable: document.querySelector("#alertsTable"),
  filters: document.querySelectorAll(".filter")
};

class TrieNode {
  constructor() {
    this.children = new Map();
    this.word = null;
  }
}

class IocTrie {
  constructor(words) {
    this.root = new TrieNode();
    words.forEach((word) => this.insert(word.toLowerCase()));
  }

  insert(word) {
    let current = this.root;
    for (const char of word) {
      if (!current.children.has(char)) {
        current.children.set(char, new TrieNode());
      }
      current = current.children.get(char);
    }
    current.word = word;
  }

  findMatches(text) {
    const matches = new Set();
    const lower = text.toLowerCase();

    for (let start = 0; start < lower.length; start += 1) {
      let current = this.root;
      for (let i = start; i < lower.length; i += 1) {
        current = current.children.get(lower[i]);
        if (!current) {
          break;
        }
        if (current.word) {
          matches.add(current.word);
        }
      }
    }

    return [...matches];
  }
}

class MaxHeap {
  constructor() {
    this.items = [];
  }

  push(item) {
    this.items.push(item);
    this.bubbleUp(this.items.length - 1);
  }

  pop() {
    if (this.items.length === 0) {
      return null;
    }
    const top = this.items[0];
    const end = this.items.pop();
    if (this.items.length > 0) {
      this.items[0] = end;
      this.sinkDown(0);
    }
    return top;
  }

  bubbleUp(index) {
    while (index > 0) {
      const parent = Math.floor((index - 1) / 2);
      if (this.items[parent].score >= this.items[index].score) {
        break;
      }
      [this.items[parent], this.items[index]] = [this.items[index], this.items[parent]];
      index = parent;
    }
  }

  sinkDown(index) {
    while (true) {
      const left = index * 2 + 1;
      const right = index * 2 + 2;
      let largest = index;

      if (left < this.items.length && this.items[left].score > this.items[largest].score) {
        largest = left;
      }
      if (right < this.items.length && this.items[right].score > this.items[largest].score) {
        largest = right;
      }
      if (largest === index) {
        break;
      }

      [this.items[index], this.items[largest]] = [this.items[largest], this.items[index]];
      index = largest;
    }
  }
}

function parseCsv(text) {
  const rows = text
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter(Boolean)
    .map(parseCsvLine);

  if (rows.length < 2) {
    return [];
  }

  return rows.slice(1).map((row, index) => {
    if (row.length !== 9) {
      throw new Error(`Line ${index + 2} must contain 9 columns.`);
    }

    const timestamp = new Date(row[0].trim());
    if (Number.isNaN(timestamp.getTime())) {
      throw new Error(`Line ${index + 2} has an invalid timestamp.`);
    }

    return {
      timestamp,
      ip: row[1].trim(),
      username: row[2].trim(),
      event: row[3].trim().toUpperCase(),
      service: row[4].trim().toLowerCase(),
      port: Number(row[5].trim()),
      path: row[6].trim(),
      status: row[7].trim().toUpperCase(),
      message: row[8].trim()
    };
  });
}

function parseCsvLine(line) {
  const fields = [];
  let current = "";
  let quoted = false;

  for (let i = 0; i < line.length; i += 1) {
    const char = line[i];
    const next = line[i + 1];

    if (char === '"' && quoted && next === '"') {
      current += '"';
      i += 1;
    } else if (char === '"') {
      quoted = !quoted;
    } else if (char === "," && !quoted) {
      fields.push(current);
      current = "";
    } else {
      current += char;
    }
  }

  fields.push(current);
  return fields;
}

function analyzeLogs(csvText) {
  const events = parseCsv(csvText).sort((a, b) => a.timestamp - b.timestamp);
  const report = {
    events,
    alerts: [],
    riskByIp: new Map(),
    servicesByIp: new Map(),
    dsa: {
      hashGroups: 0,
      dequeWindows: 0,
      trieMatches: 0,
      graphEdges: 0,
      heapPushes: 0
    }
  };

  const addAlert = (alert) => {
    report.alerts.push(alert);
    report.riskByIp.set(alert.sourceIp, (report.riskByIp.get(alert.sourceIp) || 0) + alert.severity);
  };

  detectBruteForce(events, report, addAlert);
  detectPortScans(events, report, addAlert);
  detectIndicators(events, report, addAlert);
  analyzeServiceGraph(events, report, addAlert);

  const heap = new MaxHeap();
  for (const [ip, score] of report.riskByIp.entries()) {
    heap.push({ ip, score });
    report.dsa.heapPushes += 1;
  }

  report.topRisk = [];
  let item = heap.pop();
  while (item) {
    report.topRisk.push(item);
    item = heap.pop();
  }

  report.alerts.sort((a, b) => b.severity - a.severity || a.timestamp - b.timestamp);
  return report;
}

function detectBruteForce(events, report, addAlert) {
  const failuresByIpAndUser = new Map();
  const threshold = 5;
  const windowMs = 10 * 60 * 1000;

  events.forEach((event) => {
    if (!(event.event === "LOGIN" && event.status === "FAIL")) {
      return;
    }

    const key = `${event.ip}|${event.username}`;
    if (!failuresByIpAndUser.has(key)) {
      failuresByIpAndUser.set(key, []);
      report.dsa.hashGroups += 1;
    }

    const failures = failuresByIpAndUser.get(key);
    failures.push(event);
    report.dsa.dequeWindows += 1;

    while (failures.length && event.timestamp - failures[0].timestamp > windowMs) {
      failures.shift();
    }

    if (failures.length === threshold) {
      addAlert({
        timestamp: event.timestamp,
        severity: 9,
        type: "Brute force login pattern",
        category: "login",
        sourceIp: event.ip,
        description: `${threshold} failed login attempts for user '${event.username}' within 10 minutes.`,
        evidence: `first=${toIso(failures[0].timestamp)}, last=${toIso(event.timestamp)}`
      });
    }
  });
}

function detectPortScans(events, report, addAlert) {
  const windowsByIp = new Map();
  const threshold = 6;
  const windowMs = 5 * 60 * 1000;

  events.forEach((event) => {
    if (!windowsByIp.has(event.ip)) {
      windowsByIp.set(event.ip, {
        events: [],
        portCounts: new Map(),
        alerted: false
      });
      report.dsa.hashGroups += 1;
    }

    const window = windowsByIp.get(event.ip);
    window.events.push(event);
    window.portCounts.set(event.port, (window.portCounts.get(event.port) || 0) + 1);
    report.dsa.dequeWindows += 1;

    while (window.events.length && event.timestamp - window.events[0].timestamp > windowMs) {
      const expired = window.events.shift();
      const nextCount = window.portCounts.get(expired.port) - 1;
      if (nextCount === 0) {
        window.portCounts.delete(expired.port);
      } else {
        window.portCounts.set(expired.port, nextCount);
      }
    }

    if (!window.alerted && window.portCounts.size >= threshold) {
      window.alerted = true;
      addAlert({
        timestamp: event.timestamp,
        severity: 8,
        type: "Possible port scan",
        category: "network",
        sourceIp: event.ip,
        description: `Source touched ${window.portCounts.size} unique ports within 5 minutes.`,
        evidence: `ports=[${[...window.portCounts.keys()].join(", ")}]`
      });
    }
  });
}

function detectIndicators(events, report, addAlert) {
  const trie = new IocTrie(indicators);

  events.forEach((event) => {
    const searchable = `${event.path} ${event.message}`;
    const matches = trie.findMatches(searchable);

    if (matches.length > 0) {
      report.dsa.trieMatches += matches.length;
      addAlert({
        timestamp: event.timestamp,
        severity: 6,
        type: "Suspicious indicator match",
        category: "web",
        sourceIp: event.ip,
        description: "Request contained a suspicious keyword or attack pattern.",
        evidence: `matches=[${matches.join(", ")}], path=${event.path}`
      });
    }
  });
}

function analyzeServiceGraph(events, report, addAlert) {
  const lastSeenByIp = new Map();
  const threshold = 5;

  events.forEach((event) => {
    const serviceNode = `${event.service}:${event.port}`;
    if (!report.servicesByIp.has(event.ip)) {
      report.servicesByIp.set(event.ip, new Set());
    }

    const services = report.servicesByIp.get(event.ip);
    const beforeSize = services.size;
    services.add(serviceNode);

    if (services.size > beforeSize) {
      report.dsa.graphEdges += 1;
    }

    const previous = lastSeenByIp.get(event.ip);
    if (!previous || event.timestamp > previous) {
      lastSeenByIp.set(event.ip, event.timestamp);
    }
  });

  for (const [ip, services] of report.servicesByIp.entries()) {
    if (services.size >= threshold) {
      addAlert({
        timestamp: lastSeenByIp.get(ip),
        severity: 5,
        type: "Broad service access",
        category: "recon",
        sourceIp: ip,
        description: "Source IP interacted with many distinct services.",
        evidence: `services=[${[...services].join(", ")}]`
      });
    }
  }
}

function render(report) {
  currentReport = report;
  elements.eventCount.textContent = report.events.length;
  elements.alertCount.textContent = report.alerts.length;
  elements.highRiskCount.textContent = report.alerts.filter((alert) => alert.severity >= 8).length;
  elements.topSource.textContent = report.topRisk[0]?.ip || "None";
  elements.mapSummary.textContent = `${report.dsa.graphEdges} connections`;
  elements.traceSummary.textContent = `${report.dsa.hashGroups} groups tracked`;

  renderRisk(report);
  renderTrace(report);
  renderAlerts(report);
  drawServiceMap(report);
}

function renderRisk(report) {
  elements.riskSummary.textContent = `${report.topRisk.length} sources`;

  if (report.topRisk.length === 0) {
    elements.riskList.innerHTML = `<div class="empty-state">No risky sources found.</div>`;
    return;
  }

  const maxScore = Math.max(...report.topRisk.map((item) => item.score), 1);
  elements.riskList.innerHTML = report.topRisk.slice(0, 6).map((item) => {
    const width = Math.max(8, Math.round((item.score / maxScore) * 100));
    const level = item.score >= 20 ? "high" : item.score >= 10 ? "medium" : "";
    return `
      <div class="risk-item">
        <div class="risk-row">
          <strong>${escapeHtml(item.ip)}</strong>
          <span class="risk-score">${item.score}</span>
        </div>
        <div class="bar ${level}" style="--value: ${width}%"><span></span></div>
      </div>
    `;
  }).join("");
}

function renderTrace(report) {
  const items = [
    ["HashMap groups", report.dsa.hashGroups, "IP, user, and service buckets"],
    ["Deque windows", report.dsa.dequeWindows, "time-based detection windows"],
    ["Trie matches", report.dsa.trieMatches, "indicator keyword hits"],
    ["Graph edges", report.dsa.graphEdges, "IP to service links"],
    ["Heap pushes", report.dsa.heapPushes, "risk ranking entries"]
  ];

  elements.traceGrid.innerHTML = items.map(([label, value, note]) => `
    <div class="trace-item">
      <strong>${value}</strong>
      <span>${escapeHtml(label)}</span>
      <span>${escapeHtml(note)}</span>
    </div>
  `).join("");
}

function renderAlerts(report) {
  const alerts = report.alerts.filter((alert) => activeFilter === "all" || alert.category === activeFilter);

  if (alerts.length === 0) {
    elements.alertsTable.innerHTML = `
      <tr>
        <td colspan="5" class="empty-state">No alerts for this view.</td>
      </tr>
    `;
    return;
  }

  elements.alertsTable.innerHTML = alerts.map((alert) => {
    const severityClass = alert.severity >= 8 ? "sev-high" : alert.severity >= 6 ? "sev-medium" : "sev-low";
    return `
      <tr>
        <td><span class="severity ${severityClass}">${alert.severity}/10</span></td>
        <td>
          <strong>${escapeHtml(alert.type)}</strong><br>
          <span>${escapeHtml(alert.description)}</span>
        </td>
        <td>${escapeHtml(alert.sourceIp)}</td>
        <td>${escapeHtml(toIso(alert.timestamp))}</td>
        <td>${escapeHtml(alert.evidence)}</td>
      </tr>
    `;
  }).join("");
}

function drawServiceMap(report) {
  const canvas = elements.serviceMap;
  const ctx = canvas.getContext("2d");
  const rect = canvas.getBoundingClientRect();
  const ratio = window.devicePixelRatio || 1;

  canvas.width = Math.max(320, Math.floor(rect.width * ratio));
  canvas.height = Math.max(260, Math.floor(rect.height * ratio));
  ctx.setTransform(ratio, 0, 0, ratio, 0, 0);

  const width = canvas.width / ratio;
  const height = canvas.height / ratio;
  ctx.clearRect(0, 0, width, height);
  ctx.fillStyle = "#fbfdfc";
  ctx.fillRect(0, 0, width, height);

  const ipEntries = [...report.servicesByIp.entries()]
    .sort((a, b) => b[1].size - a[1].size)
    .slice(0, 5);
  const serviceNames = [...new Set(ipEntries.flatMap(([, services]) => [...services]))].slice(0, 8);

  if (ipEntries.length === 0 || serviceNames.length === 0) {
    ctx.fillStyle = "#5c6b68";
    ctx.font = "14px Arial";
    ctx.fillText("No service activity", 24, 36);
    return;
  }

  const leftX = 130;
  const rightX = Math.max(width - 150, leftX + 180);
  const nodeRadius = 7;
  const ipPoints = new Map();
  const servicePoints = new Map();

  ipEntries.forEach(([ip], index) => {
    ipPoints.set(ip, {
      x: leftX,
      y: distribute(index, ipEntries.length, height)
    });
  });

  serviceNames.forEach((service, index) => {
    servicePoints.set(service, {
      x: rightX,
      y: distribute(index, serviceNames.length, height)
    });
  });

  ctx.lineWidth = 1.4;
  ipEntries.forEach(([ip, services]) => {
    const from = ipPoints.get(ip);
    services.forEach((service) => {
      const to = servicePoints.get(service);
      if (!to) {
        return;
      }
      ctx.beginPath();
      ctx.moveTo(from.x, from.y);
      ctx.lineTo(to.x, to.y);
      ctx.strokeStyle = "rgba(19, 122, 117, 0.22)";
      ctx.stroke();
    });
  });

  drawNodeGroup(ctx, ipPoints, nodeRadius, "#137a75", "Sources");
  drawNodeGroup(ctx, servicePoints, nodeRadius, "#b96800", "Services");
}

function drawNodeGroup(ctx, points, radius, color, label) {
  ctx.fillStyle = "#5c6b68";
  ctx.font = "700 12px Arial";
  const first = [...points.values()][0];
  ctx.fillText(label, first.x - 42, 24);

  for (const [name, point] of points.entries()) {
    ctx.beginPath();
    ctx.arc(point.x, point.y, radius, 0, Math.PI * 2);
    ctx.fillStyle = color;
    ctx.fill();

    ctx.fillStyle = "#15201f";
    ctx.font = "13px Arial";
    const textX = point.x < 200 ? point.x + 14 : point.x - 112;
    ctx.fillText(trimLabel(name), textX, point.y + 4);
  }
}

function distribute(index, total, height) {
  if (total === 1) {
    return height / 2;
  }
  const top = 52;
  const bottom = height - 44;
  return top + ((bottom - top) * index) / (total - 1);
}

function trimLabel(value) {
  return value.length > 18 ? `${value.slice(0, 15)}...` : value;
}

function runAnalysis() {
  try {
    const report = analyzeLogs(elements.logInput.value);
    render(report);
  } catch (error) {
    elements.alertsTable.innerHTML = `
      <tr>
        <td colspan="5" class="empty-state">${escapeHtml(error.message)}</td>
      </tr>
    `;
  }
}

function exportReport() {
  if (!currentReport) {
    return;
  }

  const lines = [
    "SecureLog Sentinel Report",
    `Events analyzed: ${currentReport.events.length}`,
    `Alerts raised: ${currentReport.alerts.length}`,
    "",
    "Top risky IPs",
    ...currentReport.topRisk.map((item) => `${item.ip}: ${item.score}`),
    "",
    "Alerts",
    ...currentReport.alerts.map((alert) => {
      return `[${alert.severity}/10] ${alert.type} from ${alert.sourceIp} at ${toIso(alert.timestamp)} - ${alert.evidence}`;
    })
  ];

  const blob = new Blob([lines.join("\n")], { type: "text/plain" });
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = "securelog-report.txt";
  link.click();
  URL.revokeObjectURL(url);
}

function escapeHtml(value) {
  return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

function toIso(date) {
  return date instanceof Date ? date.toISOString() : "";
}

elements.loadSampleBtn.addEventListener("click", () => {
  elements.logInput.value = sampleCsv;
  runAnalysis();
});

elements.customSampleBtn.addEventListener("click", () => {
  elements.logInput.value = customCsv;
  runAnalysis();
});

elements.analyzeBtn.addEventListener("click", runAnalysis);

elements.clearBtn.addEventListener("click", () => {
  elements.logInput.value = "";
  runAnalysis();
});

elements.exportBtn.addEventListener("click", exportReport);

elements.fileInput.addEventListener("change", (event) => {
  const file = event.target.files[0];
  if (!file) {
    return;
  }

  const reader = new FileReader();
  reader.addEventListener("load", () => {
    elements.logInput.value = String(reader.result || "");
    runAnalysis();
  });
  reader.readAsText(file);
});

elements.filters.forEach((button) => {
  button.addEventListener("click", () => {
    activeFilter = button.dataset.filter;
    elements.filters.forEach((item) => item.classList.toggle("active", item === button));
    if (currentReport) {
      renderAlerts(currentReport);
    }
  });
});

window.addEventListener("resize", () => {
  if (currentReport) {
    drawServiceMap(currentReport);
  }
});

elements.logInput.value = sampleCsv;
runAnalysis();
