/**
 * app.js - FLAME Frontend Application
 *
 * Handles rendering, filtering, search, detail view,
 * and taxonomy toggle for the FLAME threat path database.
 */

(function () {
    'use strict';

    // -----------------------------------------------------------------------
    // Constants
    // -----------------------------------------------------------------------

    const PHASE_INFO = {
        P1: { label: 'P1', name: 'Recon', color: 'p1' },
        P2: { label: 'P2', name: 'Initial Access', color: 'p2' },
        P3: { label: 'P3', name: 'Positioning', color: 'p3' },
        P4: { label: 'P4', name: 'Execution', color: 'p4' },
        P5: { label: 'P5', name: 'Monetization', color: 'p5' },
    };

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
    let activeFilters = {
        cfpf_phases: new Set(),
        sectors: new Set(),
        fraud_types: new Set(),
    };
    let searchQuery = '';
    let selectedId = null;
    let activeTaxonomy = 'cfpf'; // 'cfpf', 'mitre', 'groupib'

    // -----------------------------------------------------------------------
    // DOM References
    // -----------------------------------------------------------------------

    const dom = {
        searchInput: null,
        submissionList: null,
        resultsBar: null,
        contentArea: null,
        detailEmpty: null,
        detailView: null,
        statTotal: null,
        statFraudTypes: null,
        statSectors: null,
        filterSectors: null,
        filterFraudTypes: null,
    };

    // -----------------------------------------------------------------------
    // Initialization
    // -----------------------------------------------------------------------

    document.addEventListener('DOMContentLoaded', async function () {
        // Cache DOM references
        dom.searchInput = document.getElementById('search-input');
        dom.submissionList = document.getElementById('submission-list');
        dom.resultsBar = document.getElementById('results-bar');
        dom.contentArea = document.getElementById('content-area');
        dom.detailEmpty = document.getElementById('detail-empty');
        dom.detailView = document.getElementById('detail-view');
        dom.statTotal = document.getElementById('stat-total');
        dom.statFraudTypes = document.getElementById('stat-fraud-types');
        dom.statSectors = document.getElementById('stat-sectors');
        dom.filterSectors = document.getElementById('filter-sectors');
        dom.filterFraudTypes = document.getElementById('filter-fraud-types');

        // Bind events
        dom.searchInput.addEventListener('input', debounce(onSearchInput, 200));

        // Bind phase filter chips
        document.querySelectorAll('#filter-phases .filter-chip').forEach(function (chip) {
            chip.addEventListener('click', onFilterChipClick);
        });

        // About modal
        var aboutModal = document.getElementById('about-modal');
        var aboutBtn = document.getElementById('about-btn');
        var aboutClose = document.getElementById('about-close');

        if (aboutBtn && aboutModal) {
            aboutBtn.addEventListener('click', function () {
                aboutModal.classList.add('visible');
            });
            aboutClose.addEventListener('click', function () {
                aboutModal.classList.remove('visible');
            });
            aboutModal.addEventListener('click', function (e) {
                if (e.target === aboutModal) {
                    aboutModal.classList.remove('visible');
                }
            });
            document.addEventListener('keydown', function (e) {
                if (e.key === 'Escape' && aboutModal.classList.contains('visible')) {
                    aboutModal.classList.remove('visible');
                }
            });
        }

        // Load data
        try {
            allSubmissions = await FlameData.load();
            initializeUI();
        } catch (err) {
            dom.submissionList.innerHTML =
                '<div class="loading">Failed to load data. Run build_database.py first.</div>';
            console.error('Failed to load FLAME data:', err);
        }
    });

    function initializeUI() {
        // Update stats
        var stats = FlameData.getStats();
        dom.statTotal.textContent = stats.total;
        dom.statFraudTypes.textContent = stats.fraudTypes;
        dom.statSectors.textContent = stats.sectors;

        // Build dynamic filter chips
        buildFilterChips('sectors', dom.filterSectors, 'sectors');
        buildFilterChips('fraud_types', dom.filterFraudTypes, 'fraud_types');

        // Initial render
        applyFilters();
    }

    // -----------------------------------------------------------------------
    // Filter chips
    // -----------------------------------------------------------------------

    function buildFilterChips(dataField, container, filterKey) {
        var values = FlameData.getUniqueValues(dataField);
        container.innerHTML = '';
        values.forEach(function (value) {
            var chip = document.createElement('button');
            chip.className = 'filter-chip';
            chip.textContent = value;
            chip.dataset.filter = filterKey;
            chip.dataset.value = value;
            chip.addEventListener('click', onFilterChipClick);
            container.appendChild(chip);
        });
    }

    function onFilterChipClick(e) {
        var chip = e.currentTarget;
        var filterKey = chip.dataset.filter;
        var value = chip.dataset.value;

        chip.classList.toggle('active');

        if (activeFilters[filterKey].has(value)) {
            activeFilters[filterKey].delete(value);
        } else {
            activeFilters[filterKey].add(value);
        }

        applyFilters();
    }

    // -----------------------------------------------------------------------
    // Search
    // -----------------------------------------------------------------------

    function onSearchInput(e) {
        searchQuery = e.target.value.trim().toLowerCase();
        applyFilters();
    }

    // -----------------------------------------------------------------------
    // Filtering
    // -----------------------------------------------------------------------

    function applyFilters() {
        filteredSubmissions = allSubmissions.filter(function (item) {
            // Search filter
            if (searchQuery) {
                var haystack = [
                    item.id || '',
                    item.title || '',
                    item.summary || '',
                    (item.tags || []).join(' '),
                    (item.fraud_types || []).join(' '),
                    (item.sectors || []).join(' '),
                ].join(' ').toLowerCase();

                if (haystack.indexOf(searchQuery) === -1) {
                    return false;
                }
            }

            // CFPF phase filter (OR within group)
            if (activeFilters.cfpf_phases.size > 0) {
                var phases = item.cfpf_phases || [];
                var hasPhase = false;
                activeFilters.cfpf_phases.forEach(function (p) {
                    if (phases.indexOf(p) !== -1) hasPhase = true;
                });
                if (!hasPhase) return false;
            }

            // Sector filter (OR within group)
            if (activeFilters.sectors.size > 0) {
                var sectors = item.sectors || [];
                var hasSector = false;
                activeFilters.sectors.forEach(function (s) {
                    if (sectors.indexOf(s) !== -1) hasSector = true;
                });
                if (!hasSector) return false;
            }

            // Fraud type filter (OR within group)
            if (activeFilters.fraud_types.size > 0) {
                var fraudTypes = item.fraud_types || [];
                var hasFraud = false;
                activeFilters.fraud_types.forEach(function (ft) {
                    if (fraudTypes.indexOf(ft) !== -1) hasFraud = true;
                });
                if (!hasFraud) return false;
            }

            return true;
        });

        renderSubmissionList();
    }

    // -----------------------------------------------------------------------
    // Submission list rendering
    // -----------------------------------------------------------------------

    function renderSubmissionList() {
        dom.resultsBar.textContent = filteredSubmissions.length + ' of ' + allSubmissions.length + ' threat paths';

        if (filteredSubmissions.length === 0) {
            dom.submissionList.innerHTML = '<div class="loading">No matching threat paths.</div>';
            return;
        }

        var html = '';
        filteredSubmissions.forEach(function (item) {
            var isActive = item.id === selectedId;
            html += renderSubmissionItem(item, isActive);
        });

        dom.submissionList.innerHTML = html;

        // Bind click events
        dom.submissionList.querySelectorAll('.submission-item').forEach(function (el) {
            el.addEventListener('click', function () {
                selectSubmission(el.dataset.id);
            });
        });
    }

    function renderSubmissionItem(item, isActive) {
        var phases = item.cfpf_phases || [];
        var sectors = item.sectors || [];
        var fraudTypes = item.fraud_types || [];

        // Phase timeline dots
        var timelineDots = '';
        ['P1', 'P2', 'P3', 'P4', 'P5'].forEach(function (p) {
            var activeClass = phases.indexOf(p) !== -1 ? ' active-' + p.toLowerCase() : '';
            timelineDots += '<div class="phase-dot' + activeClass + '"></div>';
        });

        // Tags (show first 2 sectors and first 2 fraud types)
        var tags = '';
        sectors.slice(0, 2).forEach(function (s) {
            tags += '<span class="tag tag-sector">' + escapeHtml(s) + '</span>';
        });
        fraudTypes.slice(0, 2).forEach(function (ft) {
            tags += '<span class="tag tag-fraud">' + escapeHtml(ft) + '</span>';
        });

        return '<div class="submission-item' + (isActive ? ' active' : '') + '" data-id="' + escapeHtml(item.id) + '">' +
            '<div class="submission-id">' + escapeHtml(item.id) + '</div>' +
            '<div class="submission-title">' + escapeHtml(item.title) + '</div>' +
            '<div class="submission-meta">' + tags + '</div>' +
            '<div class="phase-timeline-compact">' + timelineDots + '</div>' +
            '</div>';
    }

    // -----------------------------------------------------------------------
    // Detail view
    // -----------------------------------------------------------------------

    function selectSubmission(id) {
        selectedId = id;
        var item = allSubmissions.find(function (s) { return s.id === id; });
        if (!item) return;

        // Update list selection
        dom.submissionList.querySelectorAll('.submission-item').forEach(function (el) {
            el.classList.toggle('active', el.dataset.id === id);
        });

        // Render detail view
        renderDetailView(item);
    }

    function renderDetailView(item) {
        dom.detailEmpty.style.display = 'none';
        dom.detailView.style.display = 'block';

        var phases = item.cfpf_phases || [];
        var mitre = item.mitre_attack || [];
        var groupib = item.groupib_stages || [];
        var sectors = item.sectors || [];
        var fraudTypes = item.fraud_types || [];
        var tags = item.tags || [];
        var ft3 = item.ft3_tactics || [];

        // Build detail HTML
        var html = '';

        // Header
        html += '<div class="detail-header">';
        html += '<div class="detail-id">' + escapeHtml(item.id) + '</div>';
        html += '<h2>' + escapeHtml(item.title) + '</h2>';

        // Meta row
        html += '<div class="detail-meta-row">';
        html += '<span><span class="label">Author:</span> ' + escapeHtml(item.author || 'Unknown') + '</span>';
        html += '<span><span class="label">Date:</span> ' + escapeHtml(item.date || 'N/A') + '</span>';
        html += '<span><span class="label">TLP:</span> ' + escapeHtml(item.tlp || 'WHITE') + '</span>';
        html += '<span><span class="label">Category:</span> ' + escapeHtml(item.category || 'ThreatPath') + '</span>';
        html += '</div>';

        // Source
        if (item.source) {
            html += '<div class="detail-meta-row">';
            html += '<span><span class="label">Source:</span> ' + escapeHtml(item.source) + '</span>';
            html += '</div>';
        }

        html += '</div>'; // end detail-header

        // Taxonomy toggle
        html += '<div class="taxonomy-toggle" id="taxonomy-toggle">';
        html += '<button class="' + (activeTaxonomy === 'cfpf' ? 'active' : '') + '" data-taxonomy="cfpf">CFPF Phases</button>';
        html += '<button class="' + (activeTaxonomy === 'mitre' ? 'active' : '') + '" data-taxonomy="mitre">MITRE ATT&CK</button>';
        html += '<button class="' + (activeTaxonomy === 'groupib' ? 'active' : '') + '" data-taxonomy="groupib">Group-IB</button>';
        html += '</div>';

        // Phase timeline (CFPF view)
        if (activeTaxonomy === 'cfpf') {
            html += renderCfpfTimeline(phases);
        } else if (activeTaxonomy === 'mitre') {
            html += renderMitreView(mitre);
        } else if (activeTaxonomy === 'groupib') {
            html += renderGroupibView(groupib);
        }

        // Taxonomy tags
        html += '<div class="taxonomy-section">';

        // Sectors
        if (sectors.length > 0) {
            html += '<h3>Sectors</h3>';
            html += '<div class="taxonomy-tags">';
            sectors.forEach(function (s) {
                html += '<span class="taxonomy-tag sector">' + escapeHtml(s) + '</span>';
            });
            html += '</div>';
        }

        // Fraud types
        if (fraudTypes.length > 0) {
            html += '<h3>Fraud Types</h3>';
            html += '<div class="taxonomy-tags">';
            fraudTypes.forEach(function (ft) {
                html += '<span class="taxonomy-tag fraud-type">' + escapeHtml(ft) + '</span>';
            });
            html += '</div>';
        }

        // MITRE ATT&CK
        if (mitre.length > 0) {
            html += '<h3>MITRE ATT&CK Techniques</h3>';
            html += '<div class="taxonomy-tags">';
            mitre.forEach(function (t) {
                html += '<span class="taxonomy-tag mitre">' + escapeHtml(t) + '</span>';
            });
            html += '</div>';
        }

        // Group-IB stages
        if (groupib.length > 0) {
            html += '<h3>Group-IB Fraud Matrix Stages</h3>';
            html += '<div class="taxonomy-tags">';
            groupib.forEach(function (s) {
                html += '<span class="taxonomy-tag groupib">' + escapeHtml(s) + '</span>';
            });
            html += '</div>';
        }

        // FT3 tactics
        if (ft3.length > 0) {
            html += '<h3>Stripe FT3 Tactics</h3>';
            html += '<div class="taxonomy-tags">';
            ft3.forEach(function (t) {
                html += '<span class="taxonomy-tag general">' + escapeHtml(t) + '</span>';
            });
            html += '</div>';
        }

        // Tags
        if (tags.length > 0) {
            html += '<h3>Tags</h3>';
            html += '<div class="taxonomy-tags">';
            tags.forEach(function (t) {
                html += '<span class="taxonomy-tag general">' + escapeHtml(t) + '</span>';
            });
            html += '</div>';
        }

        html += '</div>'; // end taxonomy-section

        // Summary (rendered as markdown)
        if (item.summary) {
            html += '<div class="detail-body">';
            html += '<h2>Summary</h2>';
            html += marked.parse(item.summary);
            html += '</div>';
        }

        dom.detailView.innerHTML = html;

        // Bind taxonomy toggle
        dom.detailView.querySelectorAll('#taxonomy-toggle button').forEach(function (btn) {
            btn.addEventListener('click', function () {
                activeTaxonomy = btn.dataset.taxonomy;
                renderDetailView(item);
            });
        });

        // Scroll to top of detail
        dom.contentArea.scrollTop = 0;
    }

    // -----------------------------------------------------------------------
    // Taxonomy views
    // -----------------------------------------------------------------------

    function renderCfpfTimeline(phases) {
        var html = '<div class="phase-timeline">';
        ['P1', 'P2', 'P3', 'P4', 'P5'].forEach(function (p) {
            var info = PHASE_INFO[p];
            var covered = phases.indexOf(p) !== -1;
            html += '<div class="phase-block ' + info.color + (covered ? ' covered' : '') + '">';
            html += '<div class="phase-label">' + info.label + '</div>';
            html += '<div class="phase-name">' + info.name + '</div>';
            html += '</div>';
        });
        html += '</div>';
        return html;
    }

    function renderMitreView(techniques) {
        if (techniques.length === 0) {
            return '<div class="taxonomy-section"><p style="color: var(--text-tertiary);">No MITRE ATT&CK techniques mapped for this threat path.</p></div>';
        }
        var html = '<div class="taxonomy-section">';
        html += '<h3>MITRE ATT&CK Technique Mapping</h3>';
        html += '<div class="taxonomy-tags" style="margin-top: 8px;">';
        techniques.forEach(function (t) {
            html += '<span class="taxonomy-tag mitre" style="font-size: 0.85rem; padding: 6px 14px;">' + escapeHtml(t) + '</span>';
        });
        html += '</div>';
        html += '</div>';
        return html;
    }

    function renderGroupibView(stages) {
        if (stages.length === 0) {
            return '<div class="taxonomy-section"><p style="color: var(--text-tertiary);">No Group-IB Fraud Matrix stages mapped for this threat path.</p></div>';
        }

        var html = '<div class="phase-timeline">';
        GROUPIB_STAGES.forEach(function (stage) {
            var covered = stages.indexOf(stage) !== -1;
            html += '<div class="phase-block p5' + (covered ? ' covered' : '') + '" style="' + (covered ? 'background: var(--phase-p5-bg); border-bottom: 3px solid var(--phase-p5);' : '') + '">';
            html += '<div class="phase-label" style="font-size: 0.6rem; ' + (covered ? 'color: var(--phase-p5);' : '') + '">' + escapeHtml(stage) + '</div>';
            html += '</div>';
        });
        html += '</div>';
        return html;
    }

    // -----------------------------------------------------------------------
    // Utilities
    // -----------------------------------------------------------------------

    function escapeHtml(str) {
        if (!str) return '';
        var div = document.createElement('div');
        div.textContent = String(str);
        return div.innerHTML;
    }

    function debounce(fn, delay) {
        var timer;
        return function () {
            var context = this;
            var args = arguments;
            clearTimeout(timer);
            timer = setTimeout(function () {
                fn.apply(context, args);
            }, delay);
        };
    }

})();
