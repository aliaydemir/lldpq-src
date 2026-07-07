/**
 * Cytoscape.js Network Topology Viewer
 * Converts topology data to Cytoscape.js format
 */

// Register dagre layout
cytoscape.use(cytoscapeDagre);

// Global cytoscape instance
let cy = null;
let currentLayout = 'dagre-tb'; // Default to Vertical layout

const LINK_COLORS = {
    normal: '#aaaaaa',   // Light gray for normal links
    missing: '#FF0000',  // Red for missing (LLDP down)
    fail: '#FFED29',     // Yellow for unexpected
    dead: '#E40039',     // Dark red for dead
    new: '#148D09'       // Green for new
};

// Node colors by icon type
const NODE_COLORS = {
    switch: '#5b9bd5',
    router: '#70ad47', 
    firewall: '#FF9800',
    server: '#7030a0',
    host: '#00BCD4',
    unknown: '#666666'
};

const ICON_CHARS = {
    switch: '\ue618',
    router: '\ue61c',
    firewall: '\ue647',
    server: '\ue61b',
    host: '\ue624',
    unknown: '\ue612'
};


/**
 * Get link color based on status
 */
function getLinkColor(link) {
    if (link.is_dead === 'yes') return LINK_COLORS.dead;
    if (link.is_new === 'yes') return LINK_COLORS.new;
    if (link.is_missing === 'yes') return LINK_COLORS.missing;
    if (link.is_missing === 'fail') return LINK_COLORS.fail;
    return LINK_COLORS.normal;
}

/**
 * Get link style (dashed for dead links)
 */
function getLinkStyle(link) {
    if (link.is_dead === 'yes') return 'dashed';
    return 'solid';
}

function convertToCytoscapeFormat(topologyData) {
    const elements = [];
    
    // Convert nodes
    topologyData.nodes.forEach(node => {
        const iconType = node.icon || 'switch';
        const color = NODE_COLORS[iconType] || NODE_COLORS.switch;
        const iconChar = ICON_CHARS[iconType] || ICON_CHARS.switch;
        const bgChar = ICON_CHARS[iconType + 'bg'] || '';
        
        elements.push({
            data: {
                id: 'n' + node.id,
                label: node.name,
                level: node.layerSortPreference || 5,
                staggerRow: node.staggerRow,
                icon: iconType,
                iconChar: iconChar,
                iconBgChar: bgChar,
                color: color,
                // Store original data
                primaryIP: node.primaryIP || 'N/A',
                model: node.model || 'N/A',
                serial_number: node.serial_number || 'N/A',
                version: node.version || 'N/A',
                dcimDeviceLink: node.dcimDeviceLink || '#'
            }
        });
    });
    
    // Convert edges
    topologyData.links.forEach(link => {
        elements.push({
            data: {
                id: 'e' + link.id,
                source: 'n' + link.source,
                target: 'n' + link.target,
                srcIfName: link.srcIfName,
                tgtIfName: link.tgtIfName,
                srcDevice: link.srcDevice,
                tgtDevice: link.tgtDevice,
                srcPortStatus: link.srcPortStatus,
                tgtPortStatus: link.tgtPortStatus,
                srcPortSpeed: link.srcPortSpeed || 'N/A',
                tgtPortSpeed: link.tgtPortSpeed || 'N/A',
                color: getLinkColor(link),
                lineStyle: getLinkStyle(link),
                is_missing: link.is_missing,
                is_dead: link.is_dead,
                is_new: link.is_new
            }
        });
    });
    
    return elements;
}

/**
 * Re-position staggered endpoint groups (nodes tagged with staggerRow by the
 * generator's `type: stagger` rule) as RACK COLUMNS so individual devices stay
 * legible:
 *   - members are split into racks wherever the sub-row parity flips (rack N and
 *     N+1 always differ in parity, so this delineates racks without parsing names),
 *   - each rack becomes its own vertical column (devices listed top-to-bottom, one
 *     per row, so labels don't overlap),
 *   - even racks are dropped half a column to keep the brick/zigzag offset.
 *
 * Fully config-driven: no device names are hardcoded here. Grouped by level so
 * multiple independent stagger groups stay separate. Runs after the normal TB
 * level layout and only overrides tagged nodes.
 */
function applyStagger(positions, padding, containerWidth) {
    const NODE_VGAP = 26;          // vertical pitch between devices in a rack column
    const MIN_RACK_PITCH = 340;    // horizontal gap between rack columns (spread + label room)
    const SUBCOL_GAP = 50;         // horizontal gap between a rack's two sub-columns
    const groups = {};
    cy.nodes().forEach(n => {
        const sr = n.data('staggerRow');
        if (sr === 0 || sr === 1) {
            const lvl = n.data('level');
            (groups[lvl] = groups[lvl] || []).push(n);
        }
    });
    Object.keys(groups).forEach(lvl => {
        const members = groups[lvl];
        if (members.length < 2) return;
        // Natural order by label: pod -> rack -> compute slot.
        members.sort((a, b) =>
            a.data('label').localeCompare(b.data('label'), undefined, { numeric: true, sensitivity: 'base' }));
        // Split into racks: a new rack begins wherever the sub-row parity flips.
        const racks = [];
        let prev = null;
        members.forEach(n => {
            const row = n.data('staggerRow');
            if (row !== prev) { racks.push([]); prev = row; }
            racks[racks.length - 1].push(n);
        });
        const baseY = (positions[members[0].id()] || {}).y != null ? positions[members[0].id()].y : padding;
        // Median rack size for the brick offset. Each rack renders as TWO sub-columns,
        // so the visible height is ~half; offset by half of that.
        const sizes = racks.map(r => r.length).slice().sort((a, b) => a - b);
        const medianRack = sizes[Math.floor(sizes.length / 2)] || 1;
        const drop = Math.ceil(medianRack / 2) * NODE_VGAP * 0.5;     // even-rack brick offset
        const avail = containerWidth - padding * 2;
        const pitchX = Math.max(avail / racks.length, MIN_RACK_PITCH);
        const bandWidth = racks.length * pitchX;
        // Center the band on the same axis as the other levels (they overspread by 1.3x,
        // so their center is padding + 0.65*avail). Without this the wide band drifts right.
        const startX = (padding + avail * 0.65) - bandWidth / 2;
        racks.forEach((rack, r) => {
            const colX = startX + (r + 0.5) * pitchX;
            const colTopY = baseY + (rack[0].data('staggerRow') === 1 ? drop : 0);
            // Split each rack into two sub-columns (first half left, second half right)
            // so the leaf->rack links fan into two streams instead of one overlapping bar.
            const half = Math.ceil(rack.length / 2);
            rack.forEach((n, k) => {
                const left = k < half;
                n.data('subCol', left ? 'L' : 'R');   // drives label side (style below)
                const row = left ? k : k - half;
                positions[n.id()] = {
                    x: colX + (left ? -SUBCOL_GAP / 2 : SUBCOL_GAP / 2),
                    y: colTopY + row * NODE_VGAP
                };
            });
        });
    });
}

/**
 * Calculate hierarchical positions based on level
 */
function calculateHierarchicalPositions(direction) {
    const levels = {};
    
    // Group nodes by level
    cy.nodes().forEach(node => {
        const level = node.data('level') || 5;
        if (!levels[level]) levels[level] = [];
        levels[level].push(node);
    });
    
    // Sort levels
    const sortedLevels = Object.keys(levels).map(Number).sort((a, b) => a - b);
    
    const positions = {};
    const containerWidth = cy.width();
    const containerHeight = cy.height();
    const padding = 25;
    
    if (direction === 'TB') {
        // Top to Bottom - levels are rows
        // Increase level spacing by 1.2x
        const levelHeight = (containerHeight - padding * 2) / Math.max(sortedLevels.length - 1, 1) * 1.2;
        
        sortedLevels.forEach((level, levelIndex) => {
            const nodes = levels[level];
            // Increase node spacing by 1.3x
            const nodeWidth = (containerWidth - padding * 2) / nodes.length * 1.3;
            
            // Sort nodes by name for consistent ordering
            nodes.sort((a, b) => a.data('label').localeCompare(b.data('label'), undefined, { numeric: true, sensitivity: 'base' }));
            
            nodes.forEach((node, nodeIndex) => {
                positions[node.id()] = {
                    x: padding + nodeWidth * nodeIndex + nodeWidth / 2,
                    y: padding + levelHeight * levelIndex
                };
            });
        });
        applyStagger(positions, padding, containerWidth);
    } else {
        // Left to Right - levels are columns
        // Increase level spacing for horizontal (1.8x)
        const levelWidth = (containerWidth - padding * 2) / Math.max(sortedLevels.length - 1, 1) * 1.8;
        
        sortedLevels.forEach((level, levelIndex) => {
            const nodes = levels[level];
            // Increase node spacing for horizontal (1.8x)
            const nodeHeight = (containerHeight - padding * 2) / nodes.length * 1.8;
            
            // Sort nodes by name for consistent ordering
            nodes.sort((a, b) => a.data('label').localeCompare(b.data('label'), undefined, { numeric: true, sensitivity: 'base' }));
            
            nodes.forEach((node, nodeIndex) => {
                positions[node.id()] = {
                    x: padding + levelWidth * levelIndex,
                    y: padding + nodeHeight * nodeIndex + nodeHeight / 2
                };
            });
        });
    }
    
    return positions;
}

function getLayoutOptions(layoutType) {
    switch (layoutType) {
        case 'dagre-lr':
            return {
                name: 'preset',
                positions: calculateHierarchicalPositions('LR'),
                fit: true,
                padding: 25,
                animate: true,
                animationDuration: 300
            };
        case 'dagre-tb':
            return {
                name: 'preset',
                positions: calculateHierarchicalPositions('TB'),
                fit: true,
                padding: 25,
                animate: true,
                animationDuration: 300
            };
        case 'cose':
        default:
            return {
                name: 'cose',
                idealEdgeLength: 100,
                nodeOverlap: 20,
                refresh: 20,
                fit: true,
                padding: 5,
                randomize: false,
                componentSpacing: 100,
                nodeRepulsion: 400000,
                edgeElasticity: 100,
                nestingFactor: 5,
                gravity: 80,
                numIter: 1000,
                initialTemp: 200,
                coolingFactor: 0.95,
                minTemp: 1.0,
                animate: 'end',
                animationDuration: 500
            };
    }
}

/**
 * Set layout
 */
function setLayout(layoutType) {
    if (!cy) return;
    
    currentLayout = layoutType;
    
    // Update button states
    document.querySelectorAll('.toolbar button').forEach(btn => {
        btn.classList.remove('active');
    });
    
    const btnMap = {
        'dagre-lr': 'btn-hlr',
        'dagre-tb': 'btn-hud',
        'cose': 'btn-force'
    };
    
    const activeBtn = document.getElementById(btnMap[layoutType]);
    if (activeBtn) activeBtn.classList.add('active');
    
    // For hierarchical layouts, calculate positions first
    let layoutOptions;
    if (layoutType === 'dagre-lr') {
        layoutOptions = {
            name: 'preset',
            positions: calculateHierarchicalPositions('LR'),
            fit: true,
            padding: 25,
            animate: true,
            animationDuration: 300
        };
    } else if (layoutType === 'dagre-tb') {
        layoutOptions = {
            name: 'preset',
            positions: calculateHierarchicalPositions('TB'),
            fit: true,
            padding: 25,
            animate: true,
            animationDuration: 300
        };
    } else {
        layoutOptions = getLayoutOptions(layoutType);
    }
    
    // Run layout
    const layout = cy.layout(layoutOptions);
    layout.run();
}

/**
 * Show tooltip using mouse position
 */
function showTooltip(event, content) {
    const tooltip = document.getElementById('tooltip');
    if (!tooltip) return;
    
    // Get mouse position from original event
    const e = event.originalEvent;
    if (!e) return;
    
    tooltip.innerHTML = content;
    tooltip.style.display = 'block';
    tooltip.style.left = (e.clientX + 15) + 'px';
    tooltip.style.top = (e.clientY + 15) + 'px';
}

/**
 * Hide tooltip
 */
function hideTooltip() {
    const tooltip = document.getElementById('tooltip');
    if (tooltip) tooltip.style.display = 'none';
}

/**
 * Highlight a node's neighbors and dim others
 */
function highlightNeighbors(node) {
    // Don't override isolation
    if (isIsolated) return;
    
    const neighborhood = node.closedNeighborhood(); // node + connected edges + neighbor nodes
    
    cy.batch(function() {
        // Dim all elements
        cy.elements().addClass('dimmed');
        
        // Highlight the neighborhood
        neighborhood.removeClass('dimmed');
        neighborhood.addClass('highlighted');
    });
    
    // Dim icon overlays for non-neighbors
    updateOverlayOpacity(neighborhood);
}

/**
 * Reset highlight - restore all elements
 */
function resetHighlight() {
    // Don't reset if isolated (unless explicitly clearing isolation)
    if (isIsolated) return;
    
    cy.batch(function() {
        cy.elements().removeClass('dimmed highlighted');
    });
    
    // Restore all icon overlays
    resetOverlayOpacity();
}

/**
 * Clear isolation and reset highlight
 */
function clearIsolation() {
    isIsolated = false;
    cy.batch(function() {
        cy.elements().removeClass('dimmed highlighted');
    });
    resetOverlayOpacity();
}

/**
 * Update icon overlay opacity for highlighting
 */
function updateOverlayOpacity(neighborhood) {
    const neighborIds = new Set(neighborhood.nodes().map(n => n.id()));
    
    iconOverlays.forEach(overlay => {
        const nodeId = overlay.dataset.nodeId;
        if (neighborIds.has(nodeId)) {
            overlay.style.opacity = '1';
        } else {
            overlay.style.opacity = '0.15';
        }
    });
}

/**
 * Reset icon overlay opacity
 */
function resetOverlayOpacity() {
    iconOverlays.forEach(overlay => {
        overlay.style.opacity = '1';
    });
}

/**
 * Search for a device and show results
 */
function searchDevice(query) {
    const resultsDiv = document.getElementById('searchResults');
    
    if (!query || query.length < 2) {
        resultsDiv.classList.remove('show');
        return;
    }
    
    const lowerQuery = query.toLowerCase();
    const matches = cy.nodes().filter(node => {
        const label = node.data('label') || '';
        return label.toLowerCase().includes(lowerQuery);
    });
    
    if (matches.length === 0) {
        resultsDiv.innerHTML = '<div class="search-result-item" style="color:#888;">No results</div>';
        resultsDiv.classList.add('show');
        return;
    }
    
    // Limit to 10 results
    const limitedMatches = matches.slice(0, 10);
    
    resultsDiv.innerHTML = limitedMatches.map(node => 
        `<div class="search-result-item" onclick="focusNode('${node.id()}')">${node.data('label')}</div>`
    ).join('');
    
    resultsDiv.classList.add('show');
}

/**
 * Focus on a specific node
 */
function focusNode(nodeId) {
    const node = cy.getElementById(nodeId);
    if (!node || node.length === 0) return;
    
    // Hide search results
    document.getElementById('searchResults').classList.remove('show');
    document.getElementById('searchInput').value = node.data('label');
    
    // Animate to the node
    cy.animate({
        center: { eles: node },
        zoom: 1.5
    }, {
        duration: 500
    });
    
    // Highlight the node temporarily
    const originalBorderWidth = node.style('border-width');
    const originalBorderColor = node.style('border-color');
    
    node.style({
        'border-width': 4,
        'border-color': '#76b900'
    });
    
    // Reset after 3 seconds
    setTimeout(() => {
        node.style({
            'border-width': originalBorderWidth,
            'border-color': originalBorderColor
        });
    }, 3000);
}

// Close search results when clicking outside
document.addEventListener('click', function(e) {
    const searchBox = document.querySelector('.search-box');
    if (searchBox && !searchBox.contains(e.target)) {
        document.getElementById('searchResults').classList.remove('show');
    }
    // Hide context menus only if click is outside them
    const contextMenu = document.getElementById('contextMenu');
    const linkContextMenu = document.getElementById('linkContextMenu');
    if (contextMenu && !contextMenu.contains(e.target)) {
        hideContextMenu();
    }
    if (linkContextMenu && !linkContextMenu.contains(e.target)) {
        hideLinkContextMenu();
    }
});

// Context menu state
let contextMenuTarget = null;
let linkContextMenuTarget = null;
let isIsolated = false; // Track if isolation is active

/**
 * Show context menu for a node
 */
function showContextMenu(event, node) {
    const menu = document.getElementById('contextMenu');
    contextMenuTarget = node;
    
    // Set current layer and icon values in dropdowns
    const currentLayer = String(node.data('level') || 5);
    const currentIcon = node.data('icon') || 'switch';
    document.getElementById('node-layer-select').value = currentLayer;
    document.getElementById('node-icon-select').value = currentIcon;
    
    // Get mouse position
    const e = event.originalEvent;
    menu.style.left = e.clientX + 'px';
    menu.style.top = e.clientY + 'px';
    menu.style.display = 'block';
    
    // Prevent menu from going off screen
    const rect = menu.getBoundingClientRect();
    if (rect.right > window.innerWidth) {
        menu.style.left = (e.clientX - rect.width) + 'px';
    }
    if (rect.bottom > window.innerHeight) {
        menu.style.top = (e.clientY - rect.height) + 'px';
    }
}

/**
 * Change node layer
 */
function changeNodeLayer(newLayer) {
    if (!contextMenuTarget || !cy) return;
    
    contextMenuTarget.data('level', parseInt(newLayer));
    hideContextMenu();
    
    // Re-apply layout
    setLayout(currentLayout);
    createIconOverlays();
}

/**
 * Change node icon
 */
function changeNodeIcon(newIcon) {
    if (!contextMenuTarget || !cy) return;
    
    const newColor = NODE_COLORS[newIcon] || NODE_COLORS.switch;
    const newIconChar = ICON_CHARS[newIcon] || ICON_CHARS.switch;
    
    contextMenuTarget.data('icon', newIcon);
    contextMenuTarget.data('color', newColor);
    contextMenuTarget.data('iconChar', newIconChar);
    
    hideContextMenu();
    
    // Update overlays
    createIconOverlays();
}

/**
 * Toggle node label visibility
 */
function toggleNodeLabel() {
    if (!contextMenuTarget || !cy) return;
    
    const isHidden = contextMenuTarget.data('_labelHidden') === true;
    
    if (!isHidden) {
        // Hide the label
        contextMenuTarget.style('text-opacity', 0);
        contextMenuTarget.data('_labelHidden', true);
    } else {
        // Show the label
        contextMenuTarget.style('text-opacity', 1);
        contextMenuTarget.data('_labelHidden', false);
    }
    hideContextMenu();
}

/**
 * Hide node and its connected edges
 */
function hideNode() {
    if (!contextMenuTarget || !cy) return;
    
    contextMenuTarget.style('display', 'none');
    contextMenuTarget.connectedEdges().style('display', 'none');
    hideContextMenu();
    updateIconOverlays();
}

/**
 * Apply layout with current node
 */
function applyLayoutWithNode() {
    hideContextMenu();
    setLayout(currentLayout);
}

/**
 * Show all hidden nodes
 */
function showAllHidden() {
    if (!cy) return;
    
    cy.batch(function() {
        cy.nodes().style('display', 'element');
        cy.edges().style('display', 'element');
    });
    
    // Re-apply endpoint filter if endpoints are hidden
    if (!showEndpoints) {
        toggleEndpoints(false);
    }
    
    updateIconOverlays();
}

/**
 * Hide context menu
 */
function hideContextMenu() {
    document.getElementById('contextMenu').style.display = 'none';
    contextMenuTarget = null;
}

/**
 * Show context menu for a link (edge)
 */
function showLinkContextMenu(event, edge) {
    const menu = document.getElementById('linkContextMenu');
    linkContextMenuTarget = edge;
    
    // Get mouse position
    const e = event.originalEvent;
    menu.style.left = e.clientX + 'px';
    menu.style.top = e.clientY + 'px';
    menu.style.display = 'block';
    
    // Prevent menu from going off screen
    const rect = menu.getBoundingClientRect();
    if (rect.right > window.innerWidth) {
        menu.style.left = (e.clientX - rect.width) + 'px';
    }
    if (rect.bottom > window.innerHeight) {
        menu.style.top = (e.clientY - rect.height) + 'px';
    }
}

/**
 * Hide link context menu
 */
function hideLinkContextMenu() {
    const menu = document.getElementById('linkContextMenu');
    if (menu) menu.style.display = 'none';
    linkContextMenuTarget = null;
}

/**
 * Copy text to clipboard with fallback for HTTP sites
 */
function copyToClipboard(text) {
    // Try modern API first (works on HTTPS/localhost)
    if (navigator.clipboard && navigator.clipboard.writeText) {
        return navigator.clipboard.writeText(text).then(() => true).catch(() => fallbackCopy(text));
    }
    return Promise.resolve(fallbackCopy(text));
}

/**
 * Fallback copy using execCommand (works on HTTP)
 */
function fallbackCopy(text) {
    const textarea = document.createElement('textarea');
    textarea.value = text;
    textarea.style.position = 'fixed';
    textarea.style.left = '-9999px';
    textarea.style.top = '-9999px';
    document.body.appendChild(textarea);
    textarea.focus();
    textarea.select();
    try {
        document.execCommand('copy');
        document.body.removeChild(textarea);
        return true;
    } catch (err) {
        document.body.removeChild(textarea);
        return false;
    }
}

/**
 * Copy link info in topology.dot format
 */
function contextCopyLinkInfo() {
    if (!linkContextMenuTarget) return;
    
    const data = linkContextMenuTarget.data();
    // Format: "srcDevice":"srcIfName" -- "tgtDevice":"tgtIfName"
    const dotFormat = `"${data.srcDevice}":"${data.srcIfName}" -- "${data.tgtDevice}":"${data.tgtIfName}"`;
    
    copyToClipboard(dotFormat).then(() => {
        showNotification('Copied: ' + dotFormat);
    });
    hideLinkContextMenu();
}

/**
 * Copy hostname to clipboard
 */
function contextCopyHostname() {
    if (!contextMenuTarget) return;
    const hostname = contextMenuTarget.data('label');
    copyToClipboard(hostname).then(() => {
        showNotification('Copied: ' + hostname);
    });
    hideContextMenu();
}

/**
 * Copy IP to clipboard
 */
function contextCopyIP() {
    if (!contextMenuTarget) return;
    const ip = contextMenuTarget.data('primaryIP') || 'N/A';
    copyToClipboard(ip).then(() => {
        showNotification('Copied: ' + ip);
    });
    hideContextMenu();
}

/**
 * SSH to device - opens in iTerm2 if available, otherwise default terminal
 */
function contextSSH() {
    if (!contextMenuTarget) return;
    const ip = contextMenuTarget.data('primaryIP');
    const hostname = contextMenuTarget.data('label');
    
    if (!ip || ip === 'N/A') {
        showNotification('No IP address available for ' + hostname);
        hideContextMenu();
        return;
    }
    
    // Use ssh:// URL scheme - macOS will open in default terminal app
    // If iTerm2 is set as default handler, it opens there
    // Otherwise opens in Terminal.app
    window.location.href = 'ssh://' + ip;
    
    showNotification('Opening SSH to ' + ip);
    hideContextMenu();
}

/**
 * Open device page
 */
function contextOpenDevice() {
    if (!contextMenuTarget) return;
    const link = contextMenuTarget.data('dcimDeviceLink');
    if (link && link !== '#') {
        window.open(link, '_blank');
    }
    hideContextMenu();
}

/**
 * Focus on device
 */
function contextFocus() {
    if (!contextMenuTarget) return;
    focusNode(contextMenuTarget.id());
    hideContextMenu();
}

/**
 * Isolate device - show only this device and its neighbors
 */
function contextIsolate() {
    if (!contextMenuTarget) return;
    const neighborhood = contextMenuTarget.closedNeighborhood();
    
    isIsolated = true; // Set isolation flag
    
    cy.batch(function() {
        cy.elements().addClass('dimmed');
        neighborhood.removeClass('dimmed');
        neighborhood.addClass('highlighted');
    });
    
    updateOverlayOpacity(neighborhood);
    showNotification('Isolated: ' + contextMenuTarget.data('label') + '. Click background to reset.');
    hideContextMenu();
}

/**
 * Show device details in modal
 */
function contextDetails() {
    if (!contextMenuTarget) return;
    
    const nodeData = contextMenuTarget.data();
    const nodeId = contextMenuTarget.id();
    
    // Get all connected edges
    const connectedEdges = cy.edges().filter(edge => 
        edge.data('source') === nodeId || edge.data('target') === nodeId
    );
    
    // Build info section
    let html = `
        <div class="modal-info">
            <span class="label">Hostname:</span>
            <span class="value">${nodeData.label || 'N/A'}</span>
            <span class="label">IP Address:</span>
            <span class="value">${nodeData.primaryIP || 'N/A'}</span>
            <span class="label">Serial:</span>
            <span class="value">${nodeData.serial_number || 'N/A'}</span>
            <span class="label">Connections:</span>
            <span class="value">${connectedEdges.length}</span>
        </div>
    `;
    
    // Build connections table
    if (connectedEdges.length > 0) {
        // Sort edges by local port name (natural sort for swp1, swp2, swp10, etc.)
        const sortedEdges = connectedEdges.toArray().sort((a, b) => {
            const aData = a.data();
            const bData = b.data();
            const aIsSource = aData.srcDevice === nodeData.label;
            const bIsSource = bData.srcDevice === nodeData.label;
            const aPort = aIsSource ? aData.srcIfName : aData.tgtIfName;
            const bPort = bIsSource ? bData.srcIfName : bData.tgtIfName;
            return aPort.localeCompare(bPort, undefined, { numeric: true, sensitivity: 'base' });
        });
        
        html += `
            <table class="modal-table">
                <thead>
                    <tr>
                        <th>Local Port</th>
                        <th>Port State</th>
                        <th>Speed</th>
                        <th>Remote Device</th>
                        <th>Remote Port</th>
                        <th>Link Status</th>
                    </tr>
                </thead>
                <tbody>
        `;
        
        // Build port status and speed lookup from all edges
        const portStatusLookup = {};
        const portSpeedLookup = {};
        connectedEdges.forEach(e => {
            const d = e.data();
            if (d.srcDevice === nodeData.label) {
                if (d.srcPortStatus && d.srcPortStatus !== 'N/A') {
                    portStatusLookup[d.srcIfName] = d.srcPortStatus;
                }
                if (d.srcPortSpeed && d.srcPortSpeed !== 'N/A') {
                    portSpeedLookup[d.srcIfName] = d.srcPortSpeed;
                }
            }
            if (d.tgtDevice === nodeData.label) {
                if (d.tgtPortStatus && d.tgtPortStatus !== 'N/A') {
                    portStatusLookup[d.tgtIfName] = d.tgtPortStatus;
                }
                if (d.tgtPortSpeed && d.tgtPortSpeed !== 'N/A') {
                    portSpeedLookup[d.tgtIfName] = d.tgtPortSpeed;
                }
            }
        });
        
        sortedEdges.forEach(edge => {
            const edgeData = edge.data();
            // Use device names for reliable comparison
            const isSource = edgeData.srcDevice === nodeData.label;
            
            // Use srcIfName/tgtIfName from topology data
            const localPort = isSource ? edgeData.srcIfName : edgeData.tgtIfName;
            const remotePort = isSource ? edgeData.tgtIfName : edgeData.srcIfName;
            const remoteDevice = isSource ? edgeData.tgtDevice : edgeData.srcDevice;
            const remoteLabel = remoteDevice || 'N/A';
            
            // Get port status - first try direct, then lookup
            let portStatus = isSource ? edgeData.srcPortStatus : edgeData.tgtPortStatus;
            if (!portStatus || portStatus === 'N/A') {
                portStatus = portStatusLookup[localPort] || 'N/A';
            }
            let portStateClass = 'status-ok';
            let portStateText = portStatus || 'N/A';
            
            if (portStatus === 'DOWN') {
                portStateClass = 'status-missing';  // Red for DOWN
                portStateText = '✗ DOWN';
            } else if (portStatus === 'UNKNOWN' || portStatus === 'N/A' || !portStatus) {
                portStateClass = '';  // No color for unknown/N/A
                portStateText = portStatus || 'N/A';
            } else if (portStatus === 'UP') {
                portStateClass = 'status-ok';
                portStateText = '✓ UP';
            }
            
            // Get port speed - first try direct, then lookup
            let portSpeed = isSource ? edgeData.srcPortSpeed : edgeData.tgtPortSpeed;
            if (!portSpeed || portSpeed === 'N/A') {
                portSpeed = portSpeedLookup[localPort] || 'N/A';
            }
            const speedClass = (portSpeed === 'N/A') ? 'status-missing' : 'status-ok';
            
            // Use is_missing from topology data
            const isMissing = edgeData.is_missing === 'yes';
            const isUnexpected = edgeData.is_missing === 'fail';
            let statusClass = 'status-ok';
            let statusText = '✓ OK';
            
            if (isMissing) {
                statusClass = 'status-missing';
                statusText = '✗ Missing';
            } else if (isUnexpected) {
                statusClass = 'status-unexpected';
                statusText = '⚠ Unexpected';
            }
            
            html += `
                <tr>
                    <td>${localPort || 'N/A'}</td>
                    <td class="${portStateClass}">${portStateText}</td>
                    <td class="${speedClass}">${portSpeed}</td>
                    <td>${remoteLabel}</td>
                    <td>${remotePort || 'N/A'}</td>
                    <td class="${statusClass}">${statusText}</td>
                </tr>
            `;
        });
        
        html += '</tbody></table>';
    } else {
        html += '<p style="color:#888;">No connections found.</p>';
    }
    
    // Update modal
    document.getElementById('modalTitle').textContent = nodeData.label || 'Device Details';
    document.getElementById('modalBody').innerHTML = html;
    document.getElementById('detailsModal').classList.add('show');
    
    hideContextMenu();
}

/**
 * Close details modal
 */
function closeDetailsModal() {
    document.getElementById('detailsModal').classList.remove('show');
}

/**
 * Close modal when clicking overlay
 */
function closeModal(event) {
    if (event.target.id === 'detailsModal') {
        closeDetailsModal();
    }
}

// Prevent default context menu on cy container
document.addEventListener('contextmenu', function(e) {
    const cyContainer = document.getElementById('cy');
    if (cyContainer && cyContainer.contains(e.target)) {
        e.preventDefault();
    }
});

/**
 * Show a brief notification
 */
function showNotification(message) {
    // Create notification element if doesn't exist
    let notif = document.getElementById('notification');
    if (!notif) {
        notif = document.createElement('div');
        notif.id = 'notification';
        notif.style.cssText = 'position:fixed;bottom:20px;left:50%;transform:translateX(-50%);background:#76b900;color:#000;padding:10px 20px;border-radius:6px;font-size:13px;font-weight:bold;z-index:99999;opacity:0;transition:opacity 0.3s;';
        document.body.appendChild(notif);
    }
    
    notif.textContent = message;
    notif.style.opacity = '1';
    
    setTimeout(() => {
        notif.style.opacity = '0';
    }, 2000);
}

/**
 * Toggle fullscreen mode
 */
function toggleFullscreen() {
    const btn = document.getElementById('btn-fullscreen');
    
    if (!document.fullscreenElement) {
        // Enter fullscreen
        document.documentElement.requestFullscreen().then(() => {
            btn.textContent = '⤡ Exit';
            btn.classList.add('active');
        }).catch(err => {
            console.error('Fullscreen error:', err);
        });
    } else {
        // Exit fullscreen
        document.exitFullscreen().then(() => {
            btn.textContent = '⤢ Full';
            btn.classList.remove('active');
        });
    }
}

// Listen for fullscreen change (e.g., user presses Escape)
document.addEventListener('fullscreenchange', function() {
    const btn = document.getElementById('btn-fullscreen');
    if (!document.fullscreenElement) {
        btn.textContent = '⤢ Full';
        btn.classList.remove('active');
    }
});

// Visibility states
let showPorts = false;  // Ports hidden by default
let showHostnames = true;
let showEndpoints = true;  // Endpoints (icon: host) visible by default
let showProblemsOnly = false;

/**
 * Toggle port labels visibility
 */
function togglePorts(show) {
    if (!cy) return;
    showPorts = show;
    
    // Use batch for better performance
    cy.batch(function() {
        cy.edges().style('text-opacity', show ? 1 : 0);
    });
    
    console.log('Ports visibility:', show);
}

/**
 * Toggle hostname labels visibility
 */
function toggleHostnames(show) {
    if (!cy) return;
    showHostnames = show;
    
    // Use batch for better performance
    cy.batch(function() {
        cy.nodes().style('text-opacity', show ? 1 : 0);
    });
    
    console.log('Hostname visibility:', show);
}

/**
 * Toggle endpoint (host) nodes visibility
 * Hides/shows nodes with icon type 'host' or 'server' (from endpoint_hosts in devices.yaml)
 */
function toggleEndpoints(show) {
    if (!cy) return;
    showEndpoints = show;
    
    // Debug: list all icon types
    const iconTypes = {};
    cy.nodes().forEach(node => {
        const t = node.data('icon') || 'undefined';
        iconTypes[t] = (iconTypes[t] || 0) + 1;
    });
    console.log('Icon types in topology:', iconTypes);
    
    let hiddenCount = 0;
    cy.batch(function() {
        cy.nodes().forEach(node => {
            const iconType = node.data('icon');
            // Hide 'host', 'server', 'firewall', 'unknown' types (endpoints)
            if (iconType === 'host' || iconType === 'server' || iconType === 'firewall' || iconType === 'unknown') {
                hiddenCount++;
                node.style('display', show ? 'element' : 'none');
                // Hide connected edges when hiding node
                node.connectedEdges().style('display', show ? 'element' : 'none');
            }
        });
    });
    
    // Update icon overlays
    updateIconOverlays();
    
    console.log('Endpoint visibility:', show, '- affected nodes:', hiddenCount);
}

/**
 * Highlight links by type (normal, missing, unexpected)
 * Click on legend item to highlight all links of that type
 */
let highlightedLinkType = null;

function highlightLinkType(type) {
    if (!cy) return;
    
    // If same type clicked again, clear highlight
    if (highlightedLinkType === type) {
        clearLinkHighlight();
        return;
    }
    
    highlightedLinkType = type;
    
    cy.batch(function() {
        // Dim all elements first
        cy.elements().addClass('dimmed');
        
        // Highlight edges of the selected type
        cy.edges().forEach(edge => {
            const isMissing = edge.data('is_missing') === 'yes';
            const isUnexpected = edge.data('is_missing') === 'fail';
            
            let shouldHighlight = false;
            if (type === 'normal' && !isMissing && !isUnexpected) shouldHighlight = true;
            if (type === 'missing' && isMissing) shouldHighlight = true;
            if (type === 'unexpected' && isUnexpected) shouldHighlight = true;
            
            if (shouldHighlight) {
                edge.removeClass('dimmed').addClass('highlighted');
                // Also highlight connected nodes
                edge.source().removeClass('dimmed').addClass('highlighted');
                edge.target().removeClass('dimmed').addClass('highlighted');
            }
        });
    });
    
    // Update overlay opacity for dimmed nodes
    document.querySelectorAll('.node-overlay').forEach(overlay => {
        const nodeId = overlay.dataset.nodeId;
        const node = cy.getElementById(nodeId);
        if (node && node.hasClass('dimmed')) {
            overlay.style.opacity = '0.2';
        } else {
            overlay.style.opacity = '1';
        }
    });
    
    // Show notification
    const typeLabels = { 'normal': 'Normal', 'missing': 'Missing', 'unexpected': 'Unexpected' };
    showNotification(`Highlighting ${typeLabels[type]} links. Click again to clear.`);
}

function clearLinkHighlight() {
    if (!cy) return;
    highlightedLinkType = null;
    
    cy.batch(function() {
        cy.elements().removeClass('dimmed highlighted');
    });
    
    // Reset overlay opacity
    document.querySelectorAll('.node-overlay').forEach(overlay => {
        overlay.style.opacity = '1';
    });
}

/**
 * Toggle problems only filter - show only missing/unexpected links
 */
function toggleProblems(show) {
    if (!cy) return;
    showProblemsOnly = show;
    
    cy.batch(function() {
        if (show) {
            // Hide normal links and their connected nodes (if isolated)
            cy.edges().forEach(edge => {
                const isMissing = edge.data('is_missing') === 'yes';
                const isUnexpected = edge.data('is_missing') === 'fail';
                const isProblem = isMissing || isUnexpected;
                
                edge.style('display', isProblem ? 'element' : 'none');
            });
            
            // Hide nodes that have no visible edges
            cy.nodes().forEach(node => {
                const visibleEdges = node.connectedEdges().filter(e => e.style('display') !== 'none');
                node.style('display', visibleEdges.length > 0 ? 'element' : 'none');
            });
            
            // Update icon overlays
            updateIconOverlays();
        } else {
            // Show all
            cy.edges().style('display', 'element');
            cy.nodes().style('display', 'element');
            updateIconOverlays();
        }
    });
    
    console.log('Problems only:', show);
}

/**
 * Run LLDP check
 */
const TOPOLOGY_LLDP_JOB_KEY = 'lldpq.activeLldpJobToken';
const TOPOLOGY_LLDP_LEGACY_JOB_KEY = 'lldpq_topology_lldp_job';
let topologyLLDPJobToken = null;
let topologyLLDPPollGeneration = 0;
let topologyLLDPPollTimer = null;
let topologyLLDPStatusNotification = null;
let topologyLLDPNotificationSignature = '';

function setStoredTopologyLLDPJob(token) {
    try {
        if (token) sessionStorage.setItem(TOPOLOGY_LLDP_JOB_KEY, token);
        else sessionStorage.removeItem(TOPOLOGY_LLDP_JOB_KEY);
        sessionStorage.removeItem(TOPOLOGY_LLDP_LEGACY_JOB_KEY);
    } catch (error) {
        // Private-storage restrictions must not break the live poll.
    }
}

function getStoredTopologyLLDPJobs() {
    try {
        return {
            current: sessionStorage.getItem(TOPOLOGY_LLDP_JOB_KEY) || '',
            legacy: sessionStorage.getItem(TOPOLOGY_LLDP_LEGACY_JOB_KEY) || ''
        };
    } catch (error) {
        return { current: '', legacy: '' };
    }
}

function setTopologyLLDPButton(state, enabled) {
    const button = document.getElementById('runLLDPCheck');
    const buttonText = document.getElementById('runLLDPCheckText');
    if (!button || !buttonText) return;

    button.disabled = !enabled;
    const isBusy = state === 'queued' || state === 'running' || state === 'reconnecting';
    button.setAttribute('aria-busy', isBusy ? 'true' : 'false');
    button.style.opacity = enabled ? '1' : '0.7';
    button.style.cursor = enabled ? 'pointer' : 'not-allowed';

    if (state === 'running') {
        buttonText.textContent = 'Running...';
        button.style.background = 'linear-gradient(0deg, #76b900 0%, #5a8c00 100%)';
        button.style.color = '#111';
    } else if (state === 'queued') {
        buttonText.textContent = 'Queued...';
        button.style.background = 'linear-gradient(0deg, #76b900 0%, #5a8c00 100%)';
        button.style.color = '#111';
    } else if (state === 'reconnecting') {
        buttonText.textContent = 'Reconnecting...';
        button.style.background = '#ffb74d';
        button.style.color = '#111';
    } else if (state === 'success') {
        buttonText.textContent = '✓ Complete';
        button.style.background = '#76b900';
        button.style.color = '#111';
    } else if (state === 'failure') {
        buttonText.textContent = '✗ Retry Available';
        button.style.background = '#f44336';
        button.style.color = '#111';
    } else {
        buttonText.textContent = 'Run LLDPq';
        button.style.removeProperty('background');
        button.style.removeProperty('color');
    }
}

function updateTopologyLLDPNotification(kind, title, message, detail = '') {
    const colors = {
        success: '#76b900',
        running: '#76b900',
        queued: '#4fc3f7',
        warning: '#ffb74d',
        failure: '#ff7373'
    };
    const color = colors[kind] || colors.queued;
    const signature = JSON.stringify([kind, title, message, detail]);

    // Polls often return the same state repeatedly. Avoid making an aria-live
    // region announce identical content every two seconds.
    if (signature === topologyLLDPNotificationSignature) return;
    topologyLLDPNotificationSignature = signature;

    if (!topologyLLDPStatusNotification) {
        topologyLLDPStatusNotification = document.createElement('div');
        topologyLLDPStatusNotification.setAttribute('role', 'status');
        topologyLLDPStatusNotification.setAttribute('aria-live', 'polite');
        topologyLLDPStatusNotification.setAttribute('aria-atomic', 'true');
        topologyLLDPStatusNotification.style.cssText = `
            position: fixed;
            top: 60px;
            right: 20px;
            background: #2d2d2d;
            color: #d4d4d4;
            padding: 15px 20px;
            border-radius: 8px;
            box-shadow: 0 4px 12px rgba(0,0,0,0.4);
            z-index: 99999;
            font-size: 13px;
            max-width: 350px;
        `;
        document.body.appendChild(topologyLLDPStatusNotification);
    }

    topologyLLDPStatusNotification.style.borderLeft = `4px solid ${color}`;
    topologyLLDPStatusNotification.replaceChildren();

    const heading = document.createElement('strong');
    heading.style.color = color;
    heading.textContent = title;
    const body = document.createElement('div');
    body.textContent = message;
    topologyLLDPStatusNotification.append(heading, document.createElement('br'), body);

    if (detail) {
        const small = document.createElement('small');
        small.style.color = '#aaa';
        small.textContent = detail;
        topologyLLDPStatusNotification.append(document.createElement('br'), small);
    }
}

function scheduleTopologyLLDPStatusPoll(token, generation, delayMs) {
    if (token !== topologyLLDPJobToken || generation !== topologyLLDPPollGeneration) return;
    if (topologyLLDPPollTimer) clearTimeout(topologyLLDPPollTimer);
    topologyLLDPPollTimer = setTimeout(
        () => pollTopologyLLDPJob(token, generation),
        delayMs
    );
}

async function pollTopologyLLDPJob(token, generation) {
    if (token !== topologyLLDPJobToken || generation !== topologyLLDPPollGeneration) return;
    try {
        const response = await fetch(`/trigger-lldp?token=${encodeURIComponent(token)}`, {
            method: 'GET',
            cache: 'no-store',
            headers: { 'Accept': 'application/json', 'Cache-Control': 'no-cache' }
        });
        const data = await response.json();
        if (token !== topologyLLDPJobToken || generation !== topologyLLDPPollGeneration) {
            return; // Ignore every response belonging to an older request.
        }
        if (data.status === 'error' && data.message === 'LLDP job was not found') {
            setStoredTopologyLLDPJob('');
            topologyLLDPJobToken = null;
            topologyLLDPPollGeneration += 1;
            setTopologyLLDPButton('failure', true);
            updateTopologyLLDPNotification('failure', 'LLDP Job Is No Longer Available',
                data.message, 'Start a new LLDPq run to create a fresh tracked request.');
            return;
        }
        if (!response.ok || data.status === 'error') {
            throw new Error(data.error || data.message || `Status request failed (${response.status})`);
        }
        if (data.token !== token) return;

        const reason = data.reason || 'Waiting for LLDP status';
        if (data.status === 'success') {
            setStoredTopologyLLDPJob('');
            topologyLLDPJobToken = null;
            setTopologyLLDPButton('success', false);
            updateTopologyLLDPNotification('success', '✅ LLDP Check Complete',
                'The matching topology report completed successfully.',
                'Loading the new topology...');
            location.reload();
            return;
        }

        const nowSeconds = Math.floor(Date.now() / 1000);
        const statusAge = data.updated_at ? nowSeconds - data.updated_at : 0;
        const retryOverdue = data.status === 'failure' && data.retry_scheduled &&
            data.next_retry_at && nowSeconds - data.next_retry_at > 300;
        const queueDelayed = data.status === 'queued' && statusAge > 120;
        const runningDelayed = data.status === 'running' && statusAge > 3600;

        if (queueDelayed) {
            setTopologyLLDPButton('queued', false);
            updateTopologyLLDPNotification('queued', 'LLDP Check Still Queued', reason,
                'The worker may be completing an earlier analysis. This request remains tracked.');
            scheduleTopologyLLDPStatusPoll(token, generation, 15000);
            return;
        }
        if (runningDelayed) {
            // The worker does not publish a heartbeat while a collection is in
            // progress. Age alone therefore cannot prove that a large fabric
            // run is stalled, so keep the active request locked and tracked.
            setTopologyLLDPButton('running', false);
            updateTopologyLLDPNotification('running', 'LLDP Check Still Running', reason,
                'This collection is taking longer than usual. The same request remains tracked.');
            scheduleTopologyLLDPStatusPoll(token, generation, 15000);
            return;
        }
        if (retryOverdue) {
            setTopologyLLDPButton('failure', true);
            updateTopologyLLDPNotification('failure', 'LLDP Automatic Retry Is Delayed', reason,
                'The failed attempt remains visible. You may start a newer request.');
            scheduleTopologyLLDPStatusPoll(token, generation, 15000);
            return;
        }
        if (data.status === 'running') {
            setTopologyLLDPButton('running', false);
            updateTopologyLLDPNotification('running', 'LLDP Check Running', reason,
                `Attempt ${data.attempt || 1}; this page refreshes only after confirmed success.`);
            scheduleTopologyLLDPStatusPoll(token, generation, 2000);
            return;
        }
        if (data.status === 'queued') {
            setTopologyLLDPButton('queued', false);
            updateTopologyLLDPNotification('queued', 'LLDP Check Queued', reason,
                'Waiting for the matching request to start.');
            const queuedDelay = data.next_retry_at
                ? Math.max(2000, Math.min(10000, data.next_retry_at * 1000 - Date.now() + 500))
                : 2000;
            scheduleTopologyLLDPStatusPoll(token, generation, queuedDelay);
            return;
        }
        if (data.status === 'failure') {
            setTopologyLLDPButton('failure', true);
            const retryDetail = data.retry_scheduled
                ? `Automatic retry is scheduled (attempt ${data.attempt || 1}). You may start a newer request.`
                : `Request ended after attempt ${data.attempt || 0}.`;
            updateTopologyLLDPNotification('failure', 'LLDP Check Failed', reason, retryDetail);
            if (data.retry_scheduled) {
                const retryDelay = data.next_retry_at
                    ? Math.max(5000, Math.min(30000,
                        data.next_retry_at * 1000 - Date.now() + 1000))
                    : 10000;
                scheduleTopologyLLDPStatusPoll(token, generation, retryDelay);
            } else {
                setStoredTopologyLLDPJob('');
                topologyLLDPJobToken = null;
            }
            return;
        }
        throw new Error(`Unknown LLDP job state: ${data.status}`);
    } catch (error) {
        if (token !== topologyLLDPJobToken || generation !== topologyLLDPPollGeneration) return;
        console.error('LLDP topology status unavailable:', error);
        setTopologyLLDPButton('reconnecting', false);
        updateTopologyLLDPNotification('warning', 'LLDP Status Unavailable', error.message,
            'The topology was not treated as complete; status will be checked again.');
        scheduleTopologyLLDPStatusPoll(token, generation, 5000);
    }
}

function trackTopologyLLDPJob(token) {
    if (!/^[a-f0-9]{32}$/.test(token || '')) return false;
    topologyLLDPJobToken = token;
    topologyLLDPPollGeneration += 1;
    const generation = topologyLLDPPollGeneration;
    setStoredTopologyLLDPJob(token);
    setTopologyLLDPButton('queued', false);
    updateTopologyLLDPNotification('queued', 'LLDP Check Queued',
        'The request was accepted and is waiting for the LLDP worker.',
        'This page refreshes only after confirmed success.');
    scheduleTopologyLLDPStatusPoll(token, generation, 250);
    return true;
}

async function runLLDPCheck() {
    topologyLLDPPollGeneration += 1;
    topologyLLDPJobToken = null;
    if (topologyLLDPPollTimer) clearTimeout(topologyLLDPPollTimer);
    // A user-initiated retry is a new event even when it eventually produces
    // the same message as the preceding attempt.
    topologyLLDPNotificationSignature = '';
    setTopologyLLDPButton('queued', false);
    try {
        const response = await fetch('/trigger-lldp', {
            method: 'POST',
            cache: 'no-store',
            headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-cache' }
        });
        const data = await response.json();
        if (!response.ok || data.status !== 'started' ||
            !/^[a-f0-9]{32}$/.test(data.token || '') ||
            !trackTopologyLLDPJob(data.token)) {
            throw new Error(data.error || data.message || 'LLDP job could not be queued');
        }
    } catch (error) {
        console.error('Could not start LLDP topology refresh:', error);
        setStoredTopologyLLDPJob('');
        setTopologyLLDPButton('failure', true);
        updateTopologyLLDPNotification('failure', 'Could Not Start LLDP Check', error.message,
            'No topology was treated as newly completed.');
    }
}

async function readTopologyLLDPResumeStatus(token) {
    const response = await fetch(`/trigger-lldp?token=${encodeURIComponent(token)}`, {
        method: 'GET',
        cache: 'no-store',
        headers: { 'Accept': 'application/json', 'Cache-Control': 'no-cache' }
    });
    const data = await response.json();
    if (data.status === 'error' && data.message === 'LLDP job was not found') return null;
    if (!response.ok || data.status === 'error' || data.token !== token) {
        throw new Error(data.error || data.message || 'LLDP job status is unavailable');
    }
    return data;
}

function newerTopologyLLDPResumeStatus(left, right) {
    const leftCreated = Number(left.data.created_at) || 0;
    const rightCreated = Number(right.data.created_at) || 0;
    if (leftCreated !== rightCreated) return leftCreated > rightCreated ? left : right;

    const activeRank = data => {
        if (data.status === 'running') return 3;
        if (data.status === 'queued') return 2;
        if (data.status === 'failure' && data.retry_scheduled) return 1;
        return 0;
    };
    const leftActiveRank = activeRank(left.data);
    const rightActiveRank = activeRank(right.data);
    const leftActive = leftActiveRank > 0;
    const rightActive = rightActiveRank > 0;
    if (leftActive && rightActive) return null;
    if (leftActive !== rightActive) return leftActive ? left : right;

    const leftUpdated = Number(left.data.updated_at) || 0;
    const rightUpdated = Number(right.data.updated_at) || 0;
    if (leftUpdated !== rightUpdated) return leftUpdated > rightUpdated ? left : right;

    // The API timestamps have one-second resolution while the daemon orders
    // request files more precisely. Keep both keys until active states diverge
    // rather than guessing and deleting the request the daemon may select.
    return left;
}

async function resumeTopologyLLDPJob() {
    const stored = getStoredTopologyLLDPJobs();
    const currentValid = /^[a-f0-9]{32}$/.test(stored.current);
    const legacyValid = /^[a-f0-9]{32}$/.test(stored.legacy);
    if (!currentValid && !legacyValid) return;

    if (!currentValid || !legacyValid || stored.current === stored.legacy) {
        trackTopologyLLDPJob(currentValid ? stored.current : stored.legacy);
        return;
    }

    // Older versions used separate keys on Results and Topology, so both may
    // contain different legitimate jobs. Resolve them before deleting either.
    const generation = ++topologyLLDPPollGeneration;
    setTopologyLLDPButton('reconnecting', false);
    updateTopologyLLDPNotification('warning', 'Resolving Active LLDP Check',
        'Two saved LLDP requests were found after the upgrade.',
        'Checking which request should remain active...');

    const results = await Promise.allSettled([
        readTopologyLLDPResumeStatus(stored.current),
        readTopologyLLDPResumeStatus(stored.legacy)
    ]);
    if (generation !== topologyLLDPPollGeneration || topologyLLDPJobToken !== null) return;

    if (results.some(result => result.status === 'rejected')) {
        setTopologyLLDPButton('reconnecting', false);
        updateTopologyLLDPNotification('warning', 'LLDP Status Unavailable',
            'Saved LLDP requests could not be compared safely.',
            'Nothing was discarded; status will be checked again.');
        topologyLLDPPollTimer = setTimeout(resumeTopologyLLDPJob, 5000);
        return;
    }

    const candidates = [];
    if (results[0].value) candidates.push({ token: stored.current, data: results[0].value });
    if (results[1].value) candidates.push({ token: stored.legacy, data: results[1].value });
    if (candidates.length === 0) {
        setStoredTopologyLLDPJob('');
        setTopologyLLDPButton('failure', true);
        updateTopologyLLDPNotification('failure', 'Saved LLDP Jobs Are No Longer Available',
            'Neither saved request exists on the server.',
            'Start a new LLDPq run to create a fresh tracked request.');
        return;
    }

    const selected = candidates.length === 1
        ? candidates[0]
        : newerTopologyLLDPResumeStatus(candidates[0], candidates[1]);
    if (!selected) {
        setTopologyLLDPButton('reconnecting', false);
        updateTopologyLLDPNotification('warning', 'Resolving Active LLDP Check',
            'Two saved LLDP requests are still indistinguishable.',
            'Nothing was discarded; status will be checked again.');
        topologyLLDPPollTimer = setTimeout(resumeTopologyLLDPJob, 5000);
        return;
    }
    trackTopologyLLDPJob(selected.token);
}

// CodeMirror editor instances
let configEditorCM = null;
let configEditorRevision = null;

/**
 * Open config editor modal (topology_config.yaml)
 */
function openConfigEditor() {
    const modal = document.getElementById('configEditorModal');
    const status = document.getElementById('configEditorStatus');
    
    modal.classList.add('show');
    status.textContent = 'Loading topology_config.yaml...';
    
    fetch('/edit-config', {
        method: 'GET'
    })
    .then(response => response.json())
    .then(data => {
        if (data.success) {
            if (typeof data.revision !== 'string') {
                configEditorRevision = null;
                status.textContent = 'Error: server revision is unavailable';
                return;
            }
            configEditorRevision = data.revision;
            // Initialize CodeMirror if not already done
            if (!configEditorCM) {
                configEditorCM = CodeMirror(document.getElementById('configEditorContainer'), {
                    value: data.content,
                    mode: 'yaml',
                    theme: 'material-darker',
                    lineNumbers: true,
                    lineWrapping: true,
                    tabSize: 2,
                    autofocus: true
                });
                configEditorCM.setSize('100%', '100%');
            } else {
                configEditorCM.setValue(data.content);
            }
            status.textContent = 'Loaded successfully. Edit and save.';
        } else {
            status.textContent = 'Error: ' + (data.error || 'Unknown');
        }
    })
    .catch(error => {
        status.textContent = 'Network error';
    });
}

/**
 * Close config editor modal
 */
function closeConfigEditor(event) {
    if (event && event.target !== event.currentTarget) return;
    document.getElementById('configEditorModal').classList.remove('show');
}

function closeConfigEditorModal() {
    document.getElementById('configEditorModal').classList.remove('show');
}

/**
 * Save config only (no LLDPq run)
 */
function saveConfigOnly() {
    const status = document.getElementById('configEditorStatus');
    const content = configEditorCM ? configEditorCM.getValue() : '';
    if (typeof configEditorRevision !== 'string') {
        status.textContent = 'Error: reload the current config before saving';
        return;
    }
    
    status.textContent = 'Saving...';
    
    fetch('/edit-config', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ content: content, expected_revision: configEditorRevision })
    })
    .then(response => response.json())
    .then(data => {
        if (data.success) {
            configEditorRevision = data.revision || configEditorRevision;
            status.textContent = 'Saved successfully!';
        } else {
            status.textContent = 'Error: ' + (data.error || 'Save failed');
        }
    })
    .catch(error => {
        status.textContent = 'Network error saving';
    });
}

/**
 * Save config and run LLDPq
 */
function saveConfig() {
    const content = configEditorCM ? configEditorCM.getValue() : '';
    const status = document.getElementById('configEditorStatus');
    if (typeof configEditorRevision !== 'string') {
        status.textContent = 'Error: reload the current config before saving';
        return;
    }
    
    status.textContent = 'Saving...';
    
    fetch('/edit-config', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ content: content, expected_revision: configEditorRevision })
    })
    .then(response => response.json())
    .then(data => {
        if (data.success) {
            configEditorRevision = data.revision || configEditorRevision;
            status.textContent = 'Saved! Running LLDPq...';
            closeConfigEditorModal();
            runLLDPCheck();
        } else {
            status.textContent = 'Error: ' + (data.error || 'Save failed');
        }
    })
    .catch(error => {
        status.textContent = 'Network error saving';
    });
}

/**
 * Initialize Cytoscape
 */
function initCytoscape() {
    if (typeof topologyData === 'undefined') {
        document.getElementById('status').textContent = '❌ No topology data';
        return;
    }
    
    const elements = convertToCytoscapeFormat(topologyData);
    
    cy = cytoscape({
        container: document.getElementById('cy'),
        elements: elements,
        style: [
            // Node style - transparent, icon shown via HTML overlay
            {
                selector: 'node',
                style: {
                    // Hostname label
                    'label': 'data(label)',
                    'text-valign': 'bottom',
                    'text-halign': 'center',
                    'font-size': '10px',
                    'font-family': 'Arial, sans-serif',
                    'color': '#ccc',
                    'text-margin-y': 9,
                    'text-background-color': '#212121',
                    'text-background-opacity': 0.8,
                    'text-background-padding': '2px',
                    // Transparent - icon shown via overlay
                    'background-color': 'transparent',
                    'background-opacity': 0,
                    'width': 40,
                    'height': 40,
                    'shape': 'ellipse',
                    'border-width': 0
                }
            },
            // Staggered endpoint nodes (rack columns): label to the RIGHT so each
            // device reads as its own row in the vertical column without overlap.
            {
                selector: 'node[staggerRow >= 0]',
                style: {
                    'text-halign': 'right',
                    'text-valign': 'center',
                    'text-margin-x': 6,
                    'text-margin-y': 0,
                    'font-size': '8px'
                }
            },
            // Left sub-column of a rack: label on the LEFT so the two sub-columns' labels
            // don't collide (right sub-column keeps the default right-aligned label above).
            {
                selector: "node[subCol = 'L']",
                style: {
                    'text-halign': 'left',
                    'text-margin-x': -6
                }
            },
            // Highlighted node
            {
                selector: 'node:selected',
                style: {
                    'border-width': 4,
                    'border-color': '#fff'
                }
            },
            // Edge style
            {
                selector: 'edge',
                style: {
                    'width': 1,
                    'line-color': 'data(color)',
                    'line-style': 'data(lineStyle)',
                    'curve-style': 'bezier',
                    'opacity': 0.7,
                    'target-arrow-shape': 'none',
                    'source-label': 'data(srcIfName)',
                    'target-label': 'data(tgtIfName)',
                    'source-text-offset': 20,
                    'target-text-offset': 20,
                    'font-size': '8px',
                    'color': '#999',
                    'text-rotation': 'autorotate',
                    'text-background-opacity': 0.85,
                    'text-background-color': '#212121',
                    'text-background-padding': '2px'
                }
            },
            // Highlighted edge
            {
                selector: 'edge:selected',
                style: {
                    'width': 4
                }
            },
            // Dimmed elements (for neighbor highlight)
            {
                selector: '.dimmed',
                style: {
                    'opacity': 0.15
                }
            },
            // Highlighted elements
            {
                selector: '.highlighted',
                style: {
                    'opacity': 1
                }
            },
            // Highlighted node border
            {
                selector: 'node.highlighted',
                style: {
                    'border-width': 2,
                    'border-color': '#76b900'
                }
            },
            // Highlighted edge
            {
                selector: 'edge.highlighted',
                style: {
                    'width': 2,
                    'opacity': 1
                }
            }
        ],
        layout: { name: 'preset' }, // Initial - will switch to vertical after
        wheelSensitivity: 0.3,
        minZoom: 0.1,
        maxZoom: 3
    });
    
    // Update status
    const nodeCount = topologyData.nodes.length;
    const linkCount = topologyData.links.length;
    document.getElementById('status').textContent = `✅ ${nodeCount} nodes, ${linkCount} links`;
    
    // Update timestamp
    if (topologyData.timestamp) {
        document.getElementById('topologyTimestamp').textContent = `◷ ${topologyData.timestamp}`;
    }
    
    // Update legend counts
    let normalCount = 0, missingCount = 0, unexpectedCount = 0;
    topologyData.links.forEach(link => {
        if (link.is_missing === 'yes') missingCount++;
        else if (link.is_missing === 'fail') unexpectedCount++;
        else normalCount++;
    });
    
    document.getElementById('count-normal').textContent = normalCount > 0 ? `[${normalCount}]` : '';
    document.getElementById('count-missing').textContent = missingCount > 0 ? `[${missingCount}]` : '';
    document.getElementById('count-unexpected').textContent = unexpectedCount > 0 ? `[${unexpectedCount}]` : '';
    
    // Node hover - show tooltip and highlight neighbors
    cy.on('mouseover', 'node', function(event) {
        const node = event.target;
        const data = node.data();
        
        // Show tooltip
        const content = `
            <h4>${data.label}</h4>
            <p><span class="label">IP:</span> ${data.primaryIP}</p>
            <p><span class="label">Model:</span> ${data.model}</p>
            <p><span class="label">S/N:</span> ${data.serial_number}</p>
            <p><span class="label">Version:</span> ${data.version}</p>
        `;
        showTooltip(event, content);
        
        // Highlight neighbors
        highlightNeighbors(node);
    });
    
    cy.on('mouseout', 'node', function() {
        hideTooltip();
        resetHighlight();
    });
    
    // Edge hover - show tooltip
    cy.on('mouseover', 'edge', function(event) {
        const edge = event.target;
        const data = edge.data();
        
        let status = 'Normal';
        let statusColor = '#76b900';
        if (data.is_missing === 'yes') { status = 'Missing'; statusColor = '#FF0000'; }
        else if (data.is_missing === 'fail') { status = 'Unexpected'; statusColor = '#FFED29'; }
        else if (data.is_dead === 'yes') { status = 'Dead'; statusColor = '#E40039'; }
        else if (data.is_new === 'yes') { status = 'New'; statusColor = '#76b900'; }
        
        // BW display - N/A in red for missing links
        const speed = data.srcPortSpeed || 'N/A';
        const speedColor = (speed === 'N/A') ? '#FF0000' : statusColor;
        
        const content = `
            <h4 style="color:${statusColor}">Link</h4>
            <p><strong>${data.srcDevice}</strong> : ${data.srcIfName}</p>
            <p>↕</p>
            <p><strong>${data.tgtDevice}</strong> : ${data.tgtIfName}</p>
            <p><span class="label">Status:</span> <span style="color:${statusColor}">${status}</span> &nbsp; <span class="label">BW:</span> <span style="color:${speedColor}">${speed}</span></p>
        `;
        showTooltip(event, content);
    });
    
    cy.on('mouseout', 'edge', hideTooltip);
    
    // Node click - open device page
    cy.on('tap', 'node', function(event) {
        const node = event.target;
        const link = node.data('dcimDeviceLink');
        if (link && link !== '#') {
            window.open(link, '_blank');
        }
    });
    
    // Node right-click - show context menu
    cy.on('cxttap', 'node', function(event) {
        event.originalEvent.preventDefault();
        hideTooltip(); // Hide tooltip first
        hideLinkContextMenu(); // Hide link menu if open
        showContextMenu(event, event.target);
    });
    
    // Edge right-click - show link context menu
    cy.on('cxttap', 'edge', function(event) {
        event.originalEvent.preventDefault();
        hideTooltip(); // Hide tooltip first
        hideContextMenu(); // Hide node menu if open
        showLinkContextMenu(event, event.target);
    });
    
    // Click on background to reset isolation
    cy.on('tap', function(event) {
        if (event.target === cy) {
            // Clicked on background - clear isolation
            clearIsolation();
        }
    });
    
    // Apply Vertical layout as default
    setLayout('dagre-tb');
    
    // Hide port labels by default
    togglePorts(false);
    
    // Create HTML overlays for font icons
    createIconOverlays();
    
    // Update overlays on viewport change
    cy.on('viewport', updateIconOverlays);
    cy.on('position', 'node', updateIconOverlays);
    
    console.log('✅ Cytoscape.js initialized');
    console.log(`   Nodes: ${nodeCount}, Links: ${linkCount}`);
}

// Store overlay elements
let iconOverlays = [];

/**
 * Create HTML overlay elements for font icons
 */
function createIconOverlays() {
    const container = document.getElementById('cy');
    
    // Remove existing overlays
    iconOverlays.forEach(el => el.remove());
    iconOverlays = [];
    
    // Create overlay for each node
    cy.nodes().forEach(node => {
        const overlay = document.createElement('div');
        overlay.className = 'node-icon-overlay';
        overlay.dataset.nodeId = node.id();
        
        // Background layer (dark color)
        const bgChar = node.data('iconBgChar');
        if (bgChar) {
            const bgSpan = document.createElement('span');
            bgSpan.className = 'icon-bg';
            bgSpan.textContent = bgChar;
            overlay.appendChild(bgSpan);
        }
        
        // Foreground layer (colored)
        const fgSpan = document.createElement('span');
        fgSpan.className = 'icon-fg';
        fgSpan.textContent = node.data('iconChar');
        fgSpan.style.color = node.data('color');
        overlay.appendChild(fgSpan);
        
        container.appendChild(overlay);
        iconOverlays.push(overlay);
    });
    
    updateIconOverlays();
}

/**
 * Update overlay positions
 */
function updateIconOverlays() {
    if (!cy) return;
    
    const container = document.getElementById('cy');
    const containerRect = container.getBoundingClientRect();
    
    iconOverlays.forEach(overlay => {
        const node = cy.getElementById(overlay.dataset.nodeId);
        if (!node || node.length === 0) return;
        
        // Get rendered position relative to container
        const renderedPos = node.renderedPosition();
        
        overlay.style.left = renderedPos.x + 'px';
        overlay.style.top = renderedPos.y + 'px';
        overlay.style.fontSize = (24 * cy.zoom()) + 'px';
        
        // Hide overlay if node is hidden or zoom is too low
        const nodeVisible = node.style('display') !== 'none';
        overlay.style.display = (nodeVisible && cy.zoom() > 0.2) ? 'block' : 'none';
    });
}

// Initialize when DOM is ready
document.addEventListener('DOMContentLoaded', initCytoscape);
document.addEventListener('DOMContentLoaded', resumeTopologyLLDPJob);
