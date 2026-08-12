// zebra-rs Traffic Path Visualizer — Frontend (3D Globe)
//
// Ported from the Graphiant topology viewer. Data comes from the local
// backend, which queries each router over MCP (vtyctl mcp). There is no
// TE telemetry here — the lab carries connectivity, IGP metrics, and
// per-algorithm SPF paths, so that is what the globe shows.

const COLORS = ['#e6194b', '#3cb44b', '#4363d8', '#f58231', '#911eb4', '#42d4f4', '#f032e6', '#bfef45'];

const REGION_COLORS = {
    US: '#3b82f6',
    EU: '#2ecc71',
    AP: '#f59e0b',
};

const BASE_ARC_COLOR = 'rgba(170, 180, 200, 0.35)';
const INACTIVE_COLOR = '#95a5a6';

let map;

// Rendered state
let renderedPaths = [];
let allArcs = [];        // base connectivity arcs + path arcs
let allPoints = [];
let visiblePathIdx = new Set();
let currentNodeMap = {};
let currentEdgeCost = {};
let currentAlgorithm = 0;

// Stale-response guards: selects can be changed faster than the MCP
// round-trips complete, and an older response must never overwrite the
// state a newer selection produced.
let topologySeq = 0;
let algorithmsSeq = 0;

// The camera auto-aims only when the vantage point changes (new source
// or destination) — never on an algorithm flip or refresh, so the view
// the user set up stays put while the arcs re-route under it.
let lastFocusKey = null;

function initMap() {
    const container = document.getElementById('map');
    map = Globe()(container)
        .globeImageUrl('//unpkg.com/three-globe/example/img/earth-blue-marble.jpg')
        .bumpImageUrl('//unpkg.com/three-globe/example/img/earth-topology.png')
        .backgroundImageUrl('//unpkg.com/three-globe/example/img/night-sky.png')
        .atmosphereColor('#3b82f6')
        .atmosphereAltitude(0.18)
        .arcColor('color')
        .arcStroke(d => d.base ? 0.22 : 0.5)
        .arcAltitudeAutoScale(d => d.base ? 0.25 : 0.4)
        .arcDashLength(d => d.base ? 1 : 0.4)
        .arcDashGap(d => d.base ? 0 : 0.15)
        .arcDashAnimateTime(d => d.base ? 0 : 2500)
        .arcLabel('tooltip')
        .onArcClick(d => { if (d && !d.base) populatePathDetail(d.pathIdx); })
        .pointLat('lat')
        .pointLng('lng')
        .pointColor('color')
        .pointAltitude(0.01)
        .pointRadius(0.4)
        .pointLabel('label')
        .pointOfView({ lat: 30, lng: -30, altitude: 2.5 });

    // Auto-rotate gently until the user interacts
    const controls = map.controls();
    controls.autoRotate = true;
    controls.autoRotateSpeed = 0.3;
    map.onGlobeClick(() => { controls.autoRotate = false; });

    // Keep canvas sized to its container on viewport changes
    const resize = () => map.width(container.clientWidth).height(container.clientHeight);
    window.addEventListener('resize', resize);
    resize();

    const panel = document.getElementById('pathDetail');
    if (panel) {
        panel.querySelector('.path-detail-close').addEventListener('click', () => {
            panel.style.display = 'none';
        });
    }
}

function clearMap() {
    if (map) {
        map.arcsData([]).pointsData([]);
    }
    document.getElementById('legend').innerHTML = '';

    renderedPaths = [];
    allArcs = [];
    allPoints = [];
    visiblePathIdx = new Set();
    currentNodeMap = {};
    currentEdgeCost = {};

    const panel = document.getElementById('pathDetail');
    if (panel) panel.style.display = 'none';
}

function setStatus(msg, isError) {
    const el = document.getElementById('status');
    el.textContent = msg;
    el.className = isError ? 'status-bar error' : 'status-bar';
}

async function apiFetch(url) {
    const resp = await fetch(url);
    const body = await resp.text();
    if (!resp.ok) {
        let msg = body;
        try { msg = JSON.parse(body).error || body; } catch (e) { /* raw body */ }
        throw new Error(`API error ${resp.status}: ${msg}`);
    }
    return JSON.parse(body);
}

function escapeHtml(s) {
    return String(s).replace(/[&<>"']/g, c => ({
        '&': '&amp;',
        '<': '&lt;',
        '>': '&gt;',
        '"': '&quot;',
        "'": '&#39;'
    })[c]);
}

// --- Dropdown logic ---

async function loadRouters() {
    try {
        setStatus('Loading routers...');
        const data = await apiFetch('/api/routers');
        const routers = data.routers || [];

        const srcSel = document.getElementById('source');
        srcSel.innerHTML = '';
        routers.forEach(r => {
            const opt = document.createElement('option');
            opt.value = r.name;
            opt.textContent = `${r.name} — ${r.fullName} (${r.region})`;
            srcSel.appendChild(opt);
        });

        const dstSel = document.getElementById('destination');
        dstSel.innerHTML = '<option value="__all__">All destinations</option>';
        routers.forEach(r => {
            const opt = document.createElement('option');
            opt.value = r.name;
            opt.textContent = `${r.name} — ${r.fullName} (${r.region})`;
            dstSel.appendChild(opt);
        });
        dstSel.disabled = false;

        // Tokyo makes the flex-algo detour the most dramatic; default to
        // it when present, otherwise the first router.
        if (routers.some(r => r.name === 'tk')) {
            srcSel.value = 'tk';
        }

        setStatus(`${routers.length} routers loaded.`);
        if (routers.length > 0) {
            await loadAlgorithms(srcSel.value);
            await loadTopology();
        }
    } catch (e) {
        setStatus('Failed to load routers: ' + e.message, true);
    }
}

async function loadAlgorithms(source) {
    const algoSel = document.getElementById('algorithm');
    const seq = ++algorithmsSeq;
    try {
        setStatus('Loading algorithms...');
        const data = await apiFetch('/api/algorithms?source=' + encodeURIComponent(source));
        if (seq !== algorithmsSeq) return;
        const algorithms = data.algorithms || [];
        // Capture the selection at rebuild time — not at call time — so a
        // choice the user made while the fetch was in flight survives.
        const previous = algoSel.value;
        algoSel.innerHTML = '';
        algorithms.forEach(a => {
            const opt = document.createElement('option');
            opt.value = String(a.algo);
            opt.textContent = a.label;
            algoSel.appendChild(opt);
        });
        // Keep the current selection when the new source also runs it.
        if ([...algoSel.options].some(o => o.value === previous)) {
            algoSel.value = previous;
        }
        algoSel.disabled = false;
        setStatus(`${algorithms.length} algorithm(s) available.`);
    } catch (e) {
        if (seq !== algorithmsSeq) return;
        algoSel.innerHTML = '<option value="0">0 — shortest path (unconstrained SPF)</option>';
        algoSel.disabled = false;
        setStatus('Failed to load algorithms (showing algorithm 0 only): ' + e.message, true);
    }
}

async function loadTopology() {
    const source = document.getElementById('source').value;
    const destination = document.getElementById('destination').value;
    const algorithm = document.getElementById('algorithm').value || '0';

    if (!source) return;

    const seq = ++topologySeq;
    // Keep the current view (and the user's camera) on screen while the
    // routers are queried; the map is replaced only when new data lands.
    setStatus('Querying ' + source + ' over MCP...');

    try {
        const url = '/api/topology?source=' + encodeURIComponent(source) +
            '&algorithm=' + encodeURIComponent(algorithm) +
            '&destination=' + encodeURIComponent(destination);
        const data = await apiFetch(url);
        if (seq !== topologySeq) return;
        renderTopology(data, `${source}|${destination}`);
    } catch (e) {
        if (seq !== topologySeq) return;
        setStatus('Failed to load topology: ' + e.message, true);
    }
}

// --- Map rendering ---

function nodeLabel(n) {
    const region = n.region && REGION_COLORS[n.region] ? n.region : (n.region || 'unknown');
    return `<b>${escapeHtml(n.fullName || n.name)}</b> (${escapeHtml(n.name)})<br>` +
        `Region: ${escapeHtml(region)}<br>` +
        `IS-IS: ${n.active ? 'up' : 'not in topology'}`;
}

function renderTopology(data, focusKey) {
    clearMap();

    currentAlgorithm = data.algorithm || 0;

    if (!data.nodes || data.nodes.length === 0) {
        setStatus('No topology data returned.');
        return;
    }

    const nodeMap = {};
    data.nodes.forEach(n => { nodeMap[n.name] = n; });
    currentNodeMap = nodeMap;

    const edges = data.edges || [];
    const edgeCost = {};
    edges.forEach(e => {
        edgeCost[e.source + '|' + e.target] = e.cost;
        edgeCost[e.target + '|' + e.source] = e.cost;
    });
    currentEdgeCost = edgeCost;

    // Base connectivity arcs (the algorithm's own view of the graph —
    // links pruned by a flex-algo constraint are genuinely absent here).
    let plottedEdges = 0;
    edges.forEach(e => {
        const a = nodeMap[e.source];
        const b = nodeMap[e.target];
        if (!a || !b || a.lat == null || b.lat == null) return;
        plottedEdges++;
        allArcs.push({
            base: true,
            startLat: a.lat, startLng: a.lng,
            endLat: b.lat, endLng: b.lng,
            color: BASE_ARC_COLOR,
            pathIdx: -1,
            tooltip: `<b>${escapeHtml(e.source)} &harr; ${escapeHtml(e.target)}</b><br>metric ${e.cost}`
        });
    });

    // Path arcs, one color per path, with a legend toggle each.
    const paths = data.paths || [];
    const legendEl = document.getElementById('legend');
    legendEl.innerHTML = '';
    let allPathBtn = null;

    paths.forEach(path => {
        const idx = path.index;
        const color = COLORS[idx % COLORS.length];
        const hops = (path.hops || []).filter(h => {
            const n = nodeMap[h];
            return n && n.lat != null && n.lng != null;
        });
        if (hops.length < 2) return;

        const title = `${path.hops[0]} → ${path.destination}`;
        for (let i = 0; i < hops.length - 1; i++) {
            const a = nodeMap[hops[i]];
            const b = nodeMap[hops[i + 1]];
            const cost = edgeCost[hops[i] + '|' + hops[i + 1]];
            allArcs.push({
                base: false,
                startLat: a.lat, startLng: a.lng,
                endLat: b.lat, endLng: b.lng,
                color,
                pathIdx: idx,
                tooltip: `<b>${escapeHtml(hops[i])} → ${escapeHtml(hops[i + 1])}</b><br>` +
                    `Path ${idx + 1}: ${escapeHtml(title)}<br>` +
                    `Algorithm ${currentAlgorithm}, path cost ${path.cost}` +
                    (cost != null ? `<br>link metric ${cost}` : '')
            });
        }

        visiblePathIdx.add(idx);

        const btn = document.createElement('button');
        btn.className = 'path-toggle active';
        btn.innerHTML = `<span class="swatch" style="background:${color}"></span>` +
            escapeHtml(`${title} #${idx + 1}`);
        btn.addEventListener('click', () => {
            if (visiblePathIdx.has(idx)) {
                visiblePathIdx.delete(idx);
                btn.classList.remove('active');
            } else {
                visiblePathIdx.add(idx);
                btn.classList.add('active');
                populatePathDetail(idx);
            }
            refreshArcs();
            if (allPathBtn) {
                const allVisible = renderedPaths.every(p => visiblePathIdx.has(p.idx));
                allPathBtn.classList.toggle('active', allVisible);
            }
        });
        legendEl.appendChild(btn);

        renderedPaths.push({ idx, color, path, button: btn });
    });

    if (renderedPaths.length > 1) {
        allPathBtn = document.createElement('button');
        allPathBtn.className = 'path-toggle active';
        allPathBtn.textContent = 'All paths';
        allPathBtn.addEventListener('click', () => {
            const anyHidden = renderedPaths.some(p => !visiblePathIdx.has(p.idx));
            if (anyHidden) {
                renderedPaths.forEach(p => {
                    visiblePathIdx.add(p.idx);
                    p.button.classList.add('active');
                });
                allPathBtn.classList.add('active');
            } else {
                renderedPaths.forEach(p => {
                    visiblePathIdx.delete(p.idx);
                    p.button.classList.remove('active');
                });
                allPathBtn.classList.remove('active');
            }
            refreshArcs();
        });
        legendEl.insertBefore(allPathBtn, legendEl.firstChild);
    }

    // Node points, colored by region, grey when not in the IS-IS topology.
    data.nodes.forEach(n => {
        if (n.lat == null || n.lng == null) return;
        const color = n.active ? (REGION_COLORS[n.region] || INACTIVE_COLOR) : INACTIVE_COLOR;
        allPoints.push({
            lat: n.lat,
            lng: n.lng,
            color,
            label: nodeLabel(n)
        });
    });

    map.pointsData(allPoints);
    refreshArcs();

    // Re-aim the camera only when the vantage point changed (new source
    // or destination). An algorithm flip or a refresh keeps the user's
    // camera where they put it, so the arcs visibly re-route in place.
    if (allPoints.length > 0 && focusKey !== lastFocusKey) {
        focusCamera(allPoints);
        lastFocusKey = focusKey;
    }

    const unplotted = data.nodes.filter(n => n.lat == null || n.lng == null).map(n => n.name);
    const extra = unplotted.length > 0 ? ` (${unplotted.length} node(s) without coordinates: ${unplotted.join(', ')})` : '';
    setStatus(`Algorithm ${currentAlgorithm} from ${data.source}: ` +
        `${paths.length} path(s), ${data.nodes.length} node(s), ${plottedEdges} link(s)${extra}.`);
}

function refreshArcs() {
    if (!map) return;
    map.arcsData(allArcs.filter(a => a.base || visiblePathIdx.has(a.pathIdx)));
}

function focusCamera(points) {
    let minLat = 90, maxLat = -90, minLng = 180, maxLng = -180;
    points.forEach(p => {
        if (p.lat < minLat) minLat = p.lat;
        if (p.lat > maxLat) maxLat = p.lat;
        if (p.lng < minLng) minLng = p.lng;
        if (p.lng > maxLng) maxLng = p.lng;
    });
    const lat = (minLat + maxLat) / 2;
    const lng = (minLng + maxLng) / 2;
    const span = Math.max(maxLat - minLat, maxLng - minLng);
    // Altitude: small span = close zoom, large span = far view
    const altitude = Math.max(0.6, Math.min(2.5, span / 25 + 0.6));
    map.pointOfView({ lat, lng, altitude }, 800);
}

// --- Path detail table ---

function populatePathDetail(idx) {
    const panel = document.getElementById('pathDetail');
    if (!panel) return;
    const entry = renderedPaths.find(p => p.idx === idx);
    if (!entry) return;
    const path = entry.path;

    panel.style.display = '';

    const titleEl = panel.querySelector('.path-detail-title');
    if (titleEl) {
        titleEl.innerHTML = `<span class="swatch" style="background:${entry.color}"></span>` +
            escapeHtml(`Path ${idx + 1}: ${path.hops[0]} → ${path.destination}`);
    }

    const subEl = document.getElementById('pathDetailSub');
    if (subEl) {
        const iface = path.interface ? `egress ${path.interface} · ` : '';
        subEl.textContent = `algorithm ${currentAlgorithm} · ${iface}total cost ${path.cost} · ${path.hops.length - 1} hop(s)`;
    }

    const tbody = panel.querySelector('tbody');
    tbody.innerHTML = '';

    let cumulative = 0;
    path.hops.forEach((name, i) => {
        const node = currentNodeMap[name];
        const fullName = node ? node.fullName : name;
        const region = node ? node.region : '—';

        let link = '—';
        if (i > 0) {
            const cost = currentEdgeCost[path.hops[i - 1] + '|' + name];
            if (cost != null) {
                cumulative += cost;
                link = String(cost);
            } else {
                link = '?';
            }
        }

        const tr = document.createElement('tr');
        tr.innerHTML = `
            <td class="metric">${i}</td>
            <td>${escapeHtml(name)} — ${escapeHtml(fullName)}</td>
            <td>${escapeHtml(region)}</td>
            <td class="metric">${escapeHtml(link)}</td>
            <td class="metric">${i === 0 ? '0' : String(cumulative)}</td>
        `;
        tbody.appendChild(tr);
    });
}

// --- Event listeners ---

document.addEventListener('DOMContentLoaded', () => {
    initMap();
    loadRouters();

    document.getElementById('source').addEventListener('change', async (e) => {
        if (e.target.value) {
            await loadAlgorithms(e.target.value);
            loadTopology();
        }
    });

    document.getElementById('destination').addEventListener('change', () => loadTopology());
    document.getElementById('algorithm').addEventListener('change', () => loadTopology());
    document.getElementById('refresh').addEventListener('click', () => loadTopology());
});
