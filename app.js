/**
 * app.js - FLAME Frontend Application v2
 *
 * Search-driven discovery interface with card grid, lazy-loaded detail view,
 * heat map, taxonomy toggle, and URL hash routing.
 */

(function () {
    'use strict';

    // -----------------------------------------------------------------------
    // Constants
    // -----------------------------------------------------------------------

    const PHASE_INFO = {
        P1: { label: 'P1', name: 'Recon', color: '#f97316' },
        P2: { label: 'P2', name: 'Initial Access', color: '#ef4444' },
        P3: { label: 'P3', name: 'Positioning', color: '#a855f7' },
        P4: { label: 'P4', name: 'Execution', color: '#3b82f6' },
        P5: { label: 'P5', name: 'Monetization', color: '#22c55e' },
    };

    const PHASE_ORDER = ['P1', 'P2', 'P3', 'P4', 'P5'];

    const GROUPIB_STAGES = [
        'Reconnaissance', 'Resource Development', 'Trust Abuse',
        'End-user Interaction', 'Credential Access', 'Account Access',
        'Defence Evasion', 'Perform Fraud', 'Monetization', 'Laundering'
    ];

    // -----------------------------------------------------------------------
    // State
    // -----------------------------------------------------------------------

    let allSubmissions = [];
    let filteredSubmissions = [];
    const activeFilters = {
        cfpf_phases: new Set(),
        sectors: new Set(),
        fraud_types: new Set(),
    };
    let searchQuery = '';
    let activeTaxonomy = 'cfpf';
    let viewState = 'browse'; // 'browse' | 'detail'

    // -----------------------------------------------------------------------
    // DOM References
    // -----------------------------------------------------------------------

    const dom = {};

    function cacheDom() {
        dom.searchInput = document.getElementById('search-input');
        dom.cardGrid = document.getElementById('card-grid');
        dom.resultsBar = document.getElementById('results-bar');
        dom.browseView = document.getElementById('browse-view');
        dom.detailView = document.getElementById('detail-view');
        dom.detailContent = document.getElementById('detail-content');
        dom.backLink = document.getElementById('back-link');
        dom.statTotal = document.getElementById('stat-total');
        dom.statFraudTypes = document.getElementById('stat-fraud-types');
        dom.statSectors = document.getElementById('stat-sectors');
        dom.filterCfpfPhases = document.getElementById('filter-cfpf-phases');
        dom.filterSectors = document.getElementById('filter-sectors');
        dom.filterFraudTypes = document.getElementById('filter-fraud-types');
        dom.filterActions = document.getElementById('filter-actions');
        dom.clearFiltersBtn = document.getElementById('clear-filters-btn');
        dom.filterCount = document.getElementById('filter-count');
        dom.filterToggle = document.getElementById('filter-toggle');
        dom.filterToggleCount = document.getElementById('filter-toggle-count');
        dom.filterPanel = document.getElementById('filter-panel');
        dom.aboutBtn = document.getElementById('about-btn');
        dom.aboutModal = document.getElementById('about-modal');
        dom.aboutClose = document.getElementById('about-close');
        dom.heatMapBtn = document.getElementById('heat-map-btn');
        dom.heatMapModal = document.getElementById('heat-map-modal');
        dom.heatMapClose = document.getElementById('heat-map-close');
        dom.heatMapBody = document.getElementById('heat-map-body');
    }

    // -----------------------------------------------------------------------
    // Utilities
    // -----------------------------------------------------------------------

    const _ESC_MAP = { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' };
    const _ESC_RE = /[&<>"']/g;

    function escapeHtml(str) {
        if (!str) return '';
        return str.replace(_ESC_RE, function (ch) { return _ESC_MAP[ch]; });
    }

    function formatLabel(str) {
        if (!str) return '';
        return str.replace(/-/g, ' ').replace(/\b\w/g, function (c) { return c.toUpperCase(); });
    }

    function truncate(str, len) {
        if (!str) return '';
        if (str.length <= len) return str;
        return str.substring(0, len).replace(/\s+\S*$/, '') + '…';
    }

    // -----------------------------------------------------------------------
    // Initialization
    // -----------------------------------------------------------------------

    document.addEventListener('DOMContentLoaded', function () {
        cacheDom();
        bindEvents();

        FlameData.load().then(function (data) {
            allSubmissions = data;
            initializeUI();
            handleRoute();
        }).catch(function (err) {
            dom.cardGrid.innerHTML = '<div class="empty-state">Failed to load data. Please try again.</div>';
            console.error(err);
        });
    });

    function initializeUI() {
        // Update stats
        const stats = FlameData.getStats();
        dom.statTotal.textContent = stats.total;
        dom.statFraudTypes.textContent = stats.fraudTypes;
        dom.statSectors.textContent = stats.sectors;

        // Build filter chips
        buildPhaseChips();
        buildFilterChips('sectors', dom.filterSectors);
        buildFilterChips('fraud_types', dom.filterFraudTypes);

        // Initial render
        applyFilters();
    }

    // -----------------------------------------------------------------------
    // Event Binding
    // -----------------------------------------------------------------------

    function bindEvents() {
        // Search
        dom.searchInput.addEventListener('input', debounce(function () {
            searchQuery = dom.searchInput.value.trim().toLowerCase();
            applyFilters();
        }, 200));

        // Clear filters
        dom.clearFiltersBtn.addEventListener('click', clearAllFilters);

        // Back link
        dom.backLink.addEventListener('click', function (e) {
            e.preventDefault();
            navigateTo('browse');
        });

        // Mobile filter toggle
        dom.filterToggle.addEventListener('click', function () {
            dom.filterPanel.classList.toggle('open');
        });

        // About modal
        dom.aboutBtn.addEventListener('click', function () {
            dom.aboutModal.style.display = 'flex';
        });
        dom.aboutClose.addEventListener('click', function () {
            dom.aboutModal.style.display = 'none';
        });
        dom.aboutModal.addEventListener('click', function (e) {
            if (e.target === dom.aboutModal) dom.aboutModal.style.display = 'none';
        });

        // Heat map modal
        dom.heatMapBtn.addEventListener('click', function () {
            renderHeatMap();
            dom.heatMapModal.style.display = 'flex';
        });
        dom.heatMapClose.addEventListener('click', function () {
            dom.heatMapModal.style.display = 'none';
        });
        dom.heatMapModal.addEventListener('click', function (e) {
            if (e.target === dom.heatMapModal) dom.heatMapModal.style.display = 'none';
        });

        // Hash routing
        window.addEventListener('hashchange', handleRoute);
    }

    function debounce(fn, delay) {
        let timer;
        return function () {
            clearTimeout(timer);
            timer = setTimeout(fn, delay);
        };
    }

    // -----------------------------------------------------------------------
    // Routing
    // -----------------------------------------------------------------------

    function handleRoute() {
        const hash = window.location.hash || '#browse';
        if (hash.startsWith('#detail/')) {
            const tpId = hash.replace('#detail/', '');
            showDetailView(tpId);
        } else {
            showBrowseView();
        }
    }

    function navigateTo(target, tpId) {
        if (target === 'browse') {
            window.location.hash = '#browse';
        } else if (target === 'detail' && tpId) {
            window.location.hash = '#detail/' + tpId;
        }
    }

    function showBrowseView() {
        viewState = 'browse';
        dom.browseView.style.display = 'block';
        dom.detailView.style.display = 'none';
        dom.filterPanel.classList.remove('detail-active');
    }

    function showDetailView(tpId) {
        viewState = 'detail';
        dom.browseView.style.display = 'none';
        dom.detailView.style.display = 'block';
        dom.filterPanel.classList.add('detail-active');

        // Show loading skeleton
        dom.detailContent.innerHTML = '<div class="detail-skeleton"><div class="skeleton-line w80"></div><div class="skeleton-line w60"></div><div class="skeleton-line w40"></div><div class="skeleton-block"></div></div>';

        // Lazy load content
        FlameData.loadContent(tpId).then(function (item) {
            renderDetailView(item);
        }).catch(function (err) {
            dom.detailContent.innerHTML = '<div class="empty-state">Failed to load threat path content.</div>';
            console.error(err);
        });
    }

    // -----------------------------------------------------------------------
    // Filter Chips
    // -----------------------------------------------------------------------

    function buildPhaseChips() {
        let html = '';
        PHASE_ORDER.forEach(function (phase) {
            const info = PHASE_INFO[phase];
            html += '<button class="chip phase-chip" data-filter="cfpf_phases" data-value="' + phase + '" style="--chip-color: ' + info.color + '">';
            html += '<span class="chip-dot" style="background: ' + info.color + '"></span>';
            html += info.label + ' ' + info.name;
            html += '</button>';
        });
        dom.filterCfpfPhases.innerHTML = html;

        dom.filterCfpfPhases.querySelectorAll('.chip').forEach(function (btn) {
            btn.addEventListener('click', function () {
                toggleFilter(btn.dataset.filter, btn.dataset.value, btn);
            });
        });
    }

    function buildFilterChips(field, container) {
        const values = FlameData.getUniqueValues(field);
        let html = '';
        values.forEach(function (val) {
            html += '<button class="chip" data-filter="' + field + '" data-value="' + escapeHtml(val) + '">';
            html += formatLabel(val);
            html += '</button>';
        });
        container.innerHTML = html;

        container.querySelectorAll('.chip').forEach(function (btn) {
            btn.addEventListener('click', function () {
                toggleFilter(btn.dataset.filter, btn.dataset.value, btn);
            });
        });
    }

    function toggleFilter(filterType, value, btn) {
        if (activeFilters[filterType].has(value)) {
            activeFilters[filterType].delete(value);
            btn.classList.remove('active');
        } else {
            activeFilters[filterType].add(value);
            btn.classList.add('active');
        }
        updateFilterBadge();
        applyFilters();
    }

    function clearAllFilters() {
        activeFilters.cfpf_phases.clear();
        activeFilters.sectors.clear();
        activeFilters.fraud_types.clear();
        searchQuery = '';
        dom.searchInput.value = '';

        document.querySelectorAll('.chip.active').forEach(function (btn) {
            btn.classList.remove('active');
        });

        updateFilterBadge();
        applyFilters();
    }

    function updateFilterBadge() {
        const count = activeFilters.cfpf_phases.size + activeFilters.sectors.size + activeFilters.fraud_types.size;
        if (count > 0) {
            dom.filterActions.style.display = 'flex';
            dom.filterCount.textContent = count;
            dom.filterToggleCount.textContent = count;
            dom.filterToggleCount.style.display = 'flex';
        } else {
            dom.filterActions.style.display = 'none';
            dom.filterToggleCount.style.display = 'none';
        }
    }

    // -----------------------------------------------------------------------
    // Filtering & Rendering Cards
    // -----------------------------------------------------------------------

    function applyFilters() {
        filteredSubmissions = allSubmissions.filter(function (item) {
            // Search
            if (searchQuery) {
                const haystack = (
                    (item.title || '') + ' ' +
                    (item.summary || '') + ' ' +
                    (item.id || '') + ' ' +
                    (item.tags || []).join(' ') + ' ' +
                    (item.fraud_types || []).join(' ') + ' ' +
                    (item.sectors || []).join(' ')
                ).toLowerCase();
                if (haystack.indexOf(searchQuery) === -1) return false;
            }

            // CFPF phases
            if (activeFilters.cfpf_phases.size > 0) {
                const phases = item.cfpf_phases || [];
                let match = false;
                activeFilters.cfpf_phases.forEach(function (p) {
                    if (phases.indexOf(p) !== -1) match = true;
                });
                if (!match) return false;
            }

            // Sectors
            if (activeFilters.sectors.size > 0) {
                const sectors = item.sectors || [];
                let sMatch = false;
                activeFilters.sectors.forEach(function (s) {
                    if (sectors.indexOf(s) !== -1) sMatch = true;
                });
                if (!sMatch) return false;
            }

            // Fraud types
            if (activeFilters.fraud_types.size > 0) {
                const ft = item.fraud_types || [];
                let ftMatch = false;
                activeFilters.fraud_types.forEach(function (f) {
                    if (ft.indexOf(f) !== -1) ftMatch = true;
                });
                if (!ftMatch) return false;
            }

            return true;
        });

        renderCardGrid();
    }

    function renderCardGrid() {
        dom.resultsBar.textContent = filteredSubmissions.length + ' of ' + allSubmissions.length + ' threat paths';

        if (filteredSubmissions.length === 0) {
            dom.cardGrid.innerHTML = '<div class="empty-state">No matching threat paths found. Try adjusting your filters.</div>';
            return;
        }

        let html = '';
        filteredSubmissions.forEach(function (item, idx) {
            html += renderCard(item, idx);
        });
        dom.cardGrid.innerHTML = html;

        // Bind card clicks
        dom.cardGrid.querySelectorAll('.tp-card').forEach(function (card) {
            card.addEventListener('click', function () {
                navigateTo('detail', card.dataset.id);
            });
            // Keyboard
            card.addEventListener('keydown', function (e) {
                if (e.key === 'Enter' || e.key === ' ') {
                    e.preventDefault();
                    navigateTo('detail', card.dataset.id);
                }
            });
        });
    }

    function renderCard(item, idx) {
        const phases = item.cfpf_phases || [];
        const sectors = item.sectors || [];
        const fraudTypes = item.fraud_types || [];
        const summary = truncate(item.summary || '', 160);

        let html = '<div class="tp-card" data-id="' + escapeHtml(item.id) + '" tabindex="0" role="button" style="--delay: ' + (idx * 0.04) + 's">';

        // Card header
        html += '<div class="card-header">';
        html += '<span class="card-id">' + escapeHtml(item.id) + '</span>';
        html += '<span class="card-date">' + escapeHtml(item.date || '') + '</span>';
        html += '</div>';

        // Title
        html += '<h3 class="card-title">' + escapeHtml(item.title) + '</h3>';

        // Summary
        html += '<p class="card-summary">' + escapeHtml(summary) + '</p>';

        // Phase dots
        html += '<div class="card-phases">';
        PHASE_ORDER.forEach(function (p) {
            var active = phases.indexOf(p) !== -1;
            var info = PHASE_INFO[p];
            html += '<span class="phase-dot' + (active ? ' active' : '') + '" title="' + info.label + ': ' + info.name + '" style="--dot-color: ' + info.color + '">';
            html += info.label;
            html += '</span>';
        });
        html += '</div>';

        // Tags row
        html += '<div class="card-tags">';
        sectors.forEach(function (s) {
            html += '<span class="card-tag sector-tag">' + formatLabel(s) + '</span>';
        });
        fraudTypes.slice(0, 3).forEach(function (ft) {
            html += '<span class="card-tag fraud-tag">' + formatLabel(ft) + '</span>';
        });
        if (fraudTypes.length > 3) {
            html += '<span class="card-tag more-tag">+' + (fraudTypes.length - 3) + '</span>';
        }
        html += '</div>';

        html += '</div>';
        return html;
    }

    // -----------------------------------------------------------------------
    // Detail View
    // -----------------------------------------------------------------------

    function renderDetailView(item) {
        const phases = item.cfpf_phases || [];
        const mitre = item.mitre_attack || [];
        const groupib = item.groupib_stages || [];
        const sectors = item.sectors || [];
        const fraudTypes = item.fraud_types || [];
        const tags = item.tags || [];
        const ft3 = item.ft3_tactics || [];

        let html = '';

        // Header
        html += '<div class="detail-header">';
        html += '<div class="detail-id">' + escapeHtml(item.id) + '</div>';
        html += '<h2 class="detail-title">' + escapeHtml(item.title) + '</h2>';
        html += '<div class="detail-meta">';
        html += '<span><strong>Author:</strong> ' + escapeHtml(item.author || 'Unknown') + '</span>';
        html += '<span><strong>Date:</strong> ' + escapeHtml(item.date || 'N/A') + '</span>';
        html += '<span><strong>TLP:</strong> <span class="tlp-badge">' + escapeHtml(item.tlp || 'WHITE') + '</span></span>';
        html += '</div>';
        if (item.source) {
            html += '<div class="detail-source"><strong>Source:</strong> ';
            if (item.source.startsWith('http')) {
                html += '<a href="' + escapeHtml(item.source) + '" target="_blank" rel="noopener">' + escapeHtml(truncate(item.source, 80)) + '</a>';
            } else {
                html += escapeHtml(item.source);
            }
            html += '</div>';
        }
        html += '</div>';

        // Taxonomy toggle
        html += '<div class="taxonomy-toggle" id="taxonomy-toggle">';
        html += '<button class="tax-btn' + (activeTaxonomy === 'cfpf' ? ' active' : '') + '" data-taxonomy="cfpf">CFPF Phases</button>';
        html += '<button class="tax-btn' + (activeTaxonomy === 'mitre' ? ' active' : '') + '" data-taxonomy="mitre">MITRE ATT&CK</button>';
        html += '<button class="tax-btn' + (activeTaxonomy === 'groupib' ? ' active' : '') + '" data-taxonomy="groupib">Group-IB</button>';
        html += '</div>';

        // Phase timeline / taxonomy view
        if (activeTaxonomy === 'cfpf') {
            html += renderCfpfTimeline(phases);
        } else if (activeTaxonomy === 'mitre') {
            html += renderMitreView(mitre);
        } else if (activeTaxonomy === 'groupib') {
            html += renderGroupibView(groupib);
        }

        // Taxonomy tags
        html += '<div class="detail-taxonomy">';

        if (sectors.length > 0) {
            html += '<div class="tag-group"><h4>Sectors</h4><div class="tag-list">';
            sectors.forEach(function (s) { html += '<span class="detail-tag sector-tag">' + escapeHtml(formatLabel(s)) + '</span>'; });
            html += '</div></div>';
        }
        if (fraudTypes.length > 0) {
            html += '<div class="tag-group"><h4>Fraud Types</h4><div class="tag-list">';
            fraudTypes.forEach(function (ft) { html += '<span class="detail-tag fraud-tag">' + escapeHtml(formatLabel(ft)) + '</span>'; });
            html += '</div></div>';
        }
        if (mitre.length > 0 && activeTaxonomy !== 'mitre') {
            html += '<div class="tag-group"><h4>MITRE ATT&CK</h4><div class="tag-list">';
            mitre.forEach(function (t) { html += '<span class="detail-tag mitre-tag">' + escapeHtml(t) + '</span>'; });
            html += '</div></div>';
        }
        if (groupib.length > 0 && activeTaxonomy !== 'groupib') {
            html += '<div class="tag-group"><h4>Group-IB Stages</h4><div class="tag-list">';
            groupib.forEach(function (s) { html += '<span class="detail-tag groupib-tag">' + escapeHtml(s) + '</span>'; });
            html += '</div></div>';
        }
        if (ft3.length > 0) {
            html += '<div class="tag-group"><h4>Stripe FT3</h4><div class="tag-list">';
            ft3.forEach(function (t) { html += '<span class="detail-tag ft3-tag">' + escapeHtml(t) + '</span>'; });
            html += '</div></div>';
        }
        if (tags.length > 0) {
            html += '<div class="tag-group"><h4>Tags</h4><div class="tag-list">';
            tags.forEach(function (t) { html += '<span class="detail-tag general-tag">' + escapeHtml(t) + '</span>'; });
            html += '</div></div>';
        }

        html += '</div>';

        // Body content (rendered from markdown)
        if (item.body) {
            html += '<div class="detail-body" id="detail-body">';
            html += renderMarkdown(item.body);
            html += '</div>';
        }

        dom.detailContent.innerHTML = html;

        // Post-render hooks
        bindTaxonomyToggle(item);
        addCopyButtons();
        highlightLookLeftRight();

        // Scroll to top
        dom.detailView.scrollTop = 0;
        window.scrollTo(0, 0);
    }

    // -----------------------------------------------------------------------
    // Taxonomy Views
    // -----------------------------------------------------------------------

    function renderCfpfTimeline(phases) {
        let html = '<div class="phase-timeline">';
        PHASE_ORDER.forEach(function (phase, i) {
            const info = PHASE_INFO[phase];
            const active = phases.indexOf(phase) !== -1;
            html += '<div class="timeline-phase' + (active ? ' active' : '') + '">';
            html += '<div class="timeline-dot" style="background: ' + (active ? info.color : 'var(--color-surface-3)') + '"></div>';
            html += '<div class="timeline-label">' + info.label + '</div>';
            html += '<div class="timeline-name">' + info.name + '</div>';
            html += '</div>';
            if (i < PHASE_ORDER.length - 1) {
                html += '<div class="timeline-connector' + (active ? ' active' : '') + '"></div>';
            }
        });
        html += '</div>';
        return html;
    }

    function renderMitreView(techniques) {
        if (techniques.length === 0) {
            return '<div class="taxonomy-empty">No MITRE ATT&CK mappings for this threat path.</div>';
        }
        let html = '<div class="mitre-grid">';
        techniques.forEach(function (t) {
            html += '<a class="mitre-card" href="https://attack.mitre.org/techniques/' + encodeURIComponent(t.replace('.', '/')) + '/" target="_blank" rel="noopener">';
            html += '<span class="mitre-id">' + escapeHtml(t) + '</span>';
            html += '<span class="mitre-link-icon">↗</span>';
            html += '</a>';
        });
        html += '</div>';
        return html;
    }

    function renderGroupibView(stages) {
        if (stages.length === 0) {
            return '<div class="taxonomy-empty">No Group-IB Fraud Matrix mappings for this threat path.</div>';
        }
        let html = '<div class="groupib-stages">';
        GROUPIB_STAGES.forEach(function (stage, i) {
            const active = stages.indexOf(stage) !== -1;
            html += '<div class="groupib-stage' + (active ? ' active' : '') + '">';
            html += '<span class="groupib-num">' + (i + 1) + '</span>';
            html += '<span class="groupib-name">' + escapeHtml(stage) + '</span>';
            html += '</div>';
        });
        html += '</div>';
        return html;
    }

    function bindTaxonomyToggle(item) {
        const toggleEl = document.getElementById('taxonomy-toggle');
        if (!toggleEl) return;
        toggleEl.querySelectorAll('.tax-btn').forEach(function (btn) {
            btn.addEventListener('click', function () {
                activeTaxonomy = btn.dataset.taxonomy;
                renderDetailView(item);
            });
        });
    }

    // -----------------------------------------------------------------------
    // Markdown Rendering & Enhancements
    // -----------------------------------------------------------------------

    function renderMarkdown(text) {
        if (typeof marked !== 'undefined') {
            marked.setOptions({
                breaks: true,
                gfm: true,
                headerIds: false,
            });
            return marked.parse(text);
        }
        return '<pre>' + escapeHtml(text) + '</pre>';
    }

    function addCopyButtons() {
        const codeBlocks = dom.detailContent.querySelectorAll('pre');
        codeBlocks.forEach(function (pre) {
            const wrapper = document.createElement('div');
            wrapper.className = 'code-block-wrapper';
            pre.parentNode.insertBefore(wrapper, pre);
            wrapper.appendChild(pre);

            const btn = document.createElement('button');
            btn.className = 'copy-btn';
            btn.textContent = 'Copy';
            btn.title = 'Copy to clipboard';
            btn.addEventListener('click', function () {
                const code = pre.querySelector('code') || pre;
                navigator.clipboard.writeText(code.textContent).then(function () {
                    btn.textContent = 'Copied!';
                    btn.classList.add('copied');
                    setTimeout(function () {
                        btn.textContent = 'Copy';
                        btn.classList.remove('copied');
                    }, 2000);
                });
            });
            wrapper.appendChild(btn);
        });
    }

    function highlightLookLeftRight() {
        const body = document.getElementById('detail-body');
        if (!body) return;

        // Find the "Look Left / Look Right" heading
        const headings = body.querySelectorAll('h2');
        headings.forEach(function (h) {
            if (h.textContent.indexOf('Look Left') !== -1 || h.textContent.indexOf('Look Right') !== -1) {
                // Wrap the section in a callout
                const section = document.createElement('div');
                section.className = 'look-callout';

                const icon = document.createElement('div');
                icon.className = 'look-callout-icon';
                icon.innerHTML = '<svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/></svg>';

                h.classList.add('look-heading');
                h.parentNode.insertBefore(section, h);
                section.appendChild(icon);
                section.appendChild(h);

                // Move sibling elements until next h2
                let next = section.nextSibling;
                while (next && !(next.nodeType === 1 && next.tagName === 'H2')) {
                    const toMove = next;
                    next = next.nextSibling;
                    section.appendChild(toMove);
                }
            }
        });
    }

    // -----------------------------------------------------------------------
    // Heat Map
    // -----------------------------------------------------------------------

    function renderHeatMap() {
        const stats = FlameData.getStats();
        const matrix = stats.coverageMatrix || [];

        if (matrix.length === 0) {
            dom.heatMapBody.innerHTML = '<p>No coverage data available.</p>';
            return;
        }

        // Find max count for color scaling
        let maxCount = 0;
        matrix.forEach(function (row) {
            PHASE_ORDER.forEach(function (p) {
                const val = row.phases[p] || 0;
                if (val > maxCount) maxCount = val;
            });
        });

        let html = '<div class="heat-map-grid">';

        // Header row
        html += '<div class="hm-cell hm-corner"></div>';
        PHASE_ORDER.forEach(function (p) {
            var info = PHASE_INFO[p];
            html += '<div class="hm-cell hm-header" style="color: ' + info.color + '">' + info.label + '</div>';
        });

        // Data rows
        matrix.forEach(function (row) {
            html += '<div class="hm-cell hm-label" title="' + escapeHtml(row.fraud_type) + '">' + escapeHtml(formatLabel(row.fraud_type)) + '</div>';
            PHASE_ORDER.forEach(function (p) {
                const count = row.phases[p] || 0;
                const intensity = maxCount > 0 ? count / maxCount : 0;
                const alpha = count > 0 ? 0.15 + (intensity * 0.85) : 0;
                html += '<div class="hm-cell hm-data" style="background: rgba(249, 115, 22, ' + alpha.toFixed(2) + ')" title="' + formatLabel(row.fraud_type) + ' × ' + p + ': ' + count + ' TPs">';
                if (count > 0) html += count;
                html += '</div>';
            });
        });

        html += '</div>';
        dom.heatMapBody.innerHTML = html;
    }

    // -----------------------------------------------------------------------
    // End
    // -----------------------------------------------------------------------

})();
