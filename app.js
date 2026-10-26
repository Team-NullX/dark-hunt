/**
 * Project Dark Hunt — Core Frontend Application (app.js)
 * High-Assurance Cyber Threat Intelligence Dashboard
 * Team NullX
 *
 * Requirements:
 * - 100% Client-side offline operation (zero remote requests)
 * - Strict DOM text escaping against stored XSS
 * - Strict legal gate enforcement (legal_gate_ok === true)
 * - CSV formula-injection defense
 * - Full 7-view architecture with state preservation
 */

(function () {
  'use strict';

  // Fallback data container if data.js didn't load
  const DATA = window.PROJECT_DARK_HUNT_DATA || {
    metadata: {
      project_name: "Project Dark Hunt",
      organization: "Team NullX",
      deadline: "2026-10-31",
      reporting_date: "2026-10-26"
    },
    kpis: [],
    sources: [],
    evidence: [],
    inventory: []
  };

  // State
  const state = {
    currentView: 'overview',
    kpiSearch: '',
    kpiSector: 'ALL',
    kpiStatus: 'ALL',
    kpiSortCol: 'kpi_id',
    kpiSortAsc: true,

    claimSearch: '',
    claimSector: 'ALL',
    claimThreat: 'ALL',
    claimVerif: 'ALL',
    claimCategory: 'ALL',
    claimSortCol: 'claim_id',
    claimSortAsc: true,
    claimPage: 1,
    claimPageSize: 25,

    sourceSearch: '',
    evidenceSearch: '',
    responseOwner: 'ALL'
  };

  // -----------------------------------------------------------
  // Security & Sanitization Helpers
  // -----------------------------------------------------------
  function escapeHtml(str) {
    if (str === null || str === undefined) return '';
    return String(str)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#39;');
  }

  /**
   * Strictly enforces legal authorization gate.
   * Only genuine boolean TRUE passes. All strings, nulls, undefined, 0, or false fail closed.
   */
  function isLegalGateAuthorized(record) {
    return Boolean(record && record.legal_gate_ok === true);
  }

  /**
   * Sanitizes cells for CSV export against Formula Injection (=, +, -, @, \t, \r).
   */
  function sanitizeCsvCell(val) {
    if (val === null || val === undefined) return '""';
    let s = String(val);
    if (s.length > 0 && (s[0] === '=' || s[0] === '+' || s[0] === '-' || s[0] === '@' || s[0] === '\t' || s[0] === '\r')) {
      s = "'" + s;
    }
    return '"' + s.replace(/"/g, '""') + '"';
  }

  // -----------------------------------------------------------
  // DOM Elements
  // -----------------------------------------------------------
  const navButtons = document.querySelectorAll('.nav-btn');
  const viewSections = document.querySelectorAll('.view-section');

  // KPI elements
  const kpiTableBody = document.getElementById('kpi-table-body');
  const kpiSearchInput = document.getElementById('kpi-search-input');
  const kpiSectorSelect = document.getElementById('kpi-sector-select');
  const kpiStatusSelect = document.getElementById('kpi-status-select');
  const kpiClearBtn = document.getElementById('kpi-clear-btn');
  const kpiTableCount = document.getElementById('kpi-table-count');

  // Claims elements
  const claimsTableBody = document.getElementById('claims-table-body');
  const claimSearchInput = document.getElementById('claim-search-input');
  const claimFilterSector = document.getElementById('claim-filter-sector');
  const claimFilterThreat = document.getElementById('claim-filter-threat');
  const claimFilterVerif = document.getElementById('claim-filter-verif');
  const claimFilterCategory = document.getElementById('claim-filter-category');
  const claimPageSize = document.getElementById('claim-page-size');
  const claimClearBtn = document.getElementById('claim-clear-btn');
  const claimResetAllBtn = document.getElementById('claim-reset-all-btn');
  const claimsTableCount = document.getElementById('claims-table-count');
  const paginationButtons = document.getElementById('pagination-buttons');
  const exportCsvBtn = document.getElementById('export-csv-btn');
  const exportJsonBtn = document.getElementById('export-json-btn');

  // Sources & Evidence elements
  const sourcesTableBody = document.getElementById('sources-table-body');
  const sourceSearchInput = document.getElementById('source-search-input');
  const evidenceTableBody = document.getElementById('evidence-table-body');
  const evidenceSearchInput = document.getElementById('evidence-search-input');

  // Threat & Response elements
  const threatSectorGrid = document.getElementById('threat-sector-grid');
  const responseOwnerFilter = document.getElementById('response-owner-filter');
  const responseTableBody = document.getElementById('response-table-body');

  // Briefing elements
  const briefingKpiSummary = document.getElementById('briefing-kpi-summary');
  const briefingMajorIncidents = document.getElementById('briefing-major-incidents');
  const briefingOnionRegister = document.getElementById('briefing-onion-register');
  const briefingRecommendations = document.getElementById('briefing-recommendations');
  const briefingEvidenceList = document.getElementById('briefing-evidence-list');

  // Modal elements
  const detailModal = document.getElementById('detail-modal');
  const modalTitle = document.getElementById('modal-title');
  const modalContent = document.getElementById('modal-content');
  const modalCloseBtn = document.getElementById('modal-close-btn');
  const modalDismissBtn = document.getElementById('modal-dismiss-btn');

  // -----------------------------------------------------------
  // Navigation Handler
  // -----------------------------------------------------------
  function switchView(viewName) {
    state.currentView = viewName;
    navButtons.forEach(btn => {
      btn.classList.toggle('active', btn.getAttribute('data-view') === viewName);
    });
    viewSections.forEach(sec => {
      sec.classList.toggle('active', sec.id === `view-${viewName}`);
    });

    if (viewName === 'briefing') {
      renderBriefing();
    }
  }

  navButtons.forEach(btn => {
    btn.addEventListener('click', () => {
      const v = btn.getAttribute('data-view');
      switchView(v);
    });
  });

  // -----------------------------------------------------------
  // View 1: Overview & KPI Summary
  // -----------------------------------------------------------
  function populateSectorDropdowns() {
    const sectors = Array.from(new Set(DATA.kpis.map(k => k.sector))).sort();
    sectors.forEach(sec => {
      const opt1 = document.createElement('option');
      opt1.value = sec;
      opt1.textContent = sec;
      kpiSectorSelect.appendChild(opt1);

      const opt2 = document.createElement('option');
      opt2.value = sec;
      opt2.textContent = sec;
      claimFilterSector.appendChild(opt2);
    });
  }

  function getThreatBadgeClass(threat) {
    switch (threat) {
      case 'Critical': return 'badge-critical';
      case 'High': return 'badge-high';
      case 'Medium': return 'badge-medium';
      case 'Low': return 'badge-low';
      default: return 'badge-unassessed';
    }
  }

  function getVerifBadgeClass(verif) {
    if (verif.includes('Verified')) return 'badge-verified';
    if (verif.includes('Corroborated')) return 'badge-corroborated';
    if (verif.includes('Unverified')) return 'badge-unverified';
    return 'badge-unassessed';
  }

  function renderKpiTable() {
    let filtered = DATA.kpis.filter(k => {
      const matchesSearch = !state.kpiSearch || (
        k.kpi_id.toLowerCase().includes(state.kpiSearch.toLowerCase()) ||
        k.kpi_name.toLowerCase().includes(state.kpiSearch.toLowerCase()) ||
        k.sector.toLowerCase().includes(state.kpiSearch.toLowerCase())
      );
      const matchesSector = state.kpiSector === 'ALL' || k.sector === state.kpiSector;
      const matchesStatus = state.kpiStatus === 'ALL' || (
        state.kpiStatus === 'EXPOSED' ? k.claim_count > 0 : k.claim_count === 0
      );
      return matchesSearch && matchesSector && matchesStatus;
    });

    // Sort
    filtered.sort((a, b) => {
      let vA = a[state.kpiSortCol];
      let vB = b[state.kpiSortCol];
      if (typeof vA === 'string') {
        vA = vA.toLowerCase();
        vB = (vB || '').toLowerCase();
      }
      if (vA < vB) return state.kpiSortAsc ? -1 : 1;
      if (vA > vB) return state.kpiSortAsc ? 1 : -1;
      return 0;
    });

    kpiTableBody.innerHTML = '';
    filtered.forEach(k => {
      const tr = document.createElement('tr');
      const claimBadge = k.claim_count > 0
        ? `<span class="badge badge-high">${k.claim_count} Claim(s)</span>`
        : `<span class="badge badge-unassessed">0 Claims</span>`;

      tr.innerHTML = `
        <td class="mono-cell"><strong>${escapeHtml(k.kpi_id)}</strong></td>
        <td><strong>${escapeHtml(k.kpi_name)}</strong></td>
        <td>${escapeHtml(k.sector)}</td>
        <td><span class="badge ${k.criticality === 'Critical' ? 'badge-critical' : 'badge-high'}">${escapeHtml(k.criticality)}</span></td>
        <td>${claimBadge}</td>
        <td><span class="badge ${getThreatBadgeClass(k.highest_threat)}">${escapeHtml(k.highest_threat)}</span></td>
        <td><span class="badge ${getVerifBadgeClass(k.verification_status)}">${escapeHtml(k.verification_status)}</span></td>
        <td class="mono-cell">${escapeHtml(k.latest_source_date)}</td>
        <td><button class="btn btn-secondary btn-sm" data-kpi-id="${escapeHtml(k.kpi_id)}">View Profile</button></td>
      `;
      kpiTableBody.appendChild(tr);
    });

    kpiTableCount.textContent = `Showing ${filtered.length} of ${DATA.kpis.length} Key Point Installations`;
  }

  // -----------------------------------------------------------
  // View 2: Exposure Search
  // -----------------------------------------------------------
  function getFilteredClaims() {
    return DATA.inventory.filter(c => {
      const q = state.claimSearch.toLowerCase();
      const matchesSearch = !q || (
        c.claim_id.toLowerCase().includes(q) ||
        c.kpi_name.toLowerCase().includes(q) ||
        c.kpi_id.toLowerCase().includes(q) ||
        c.source_name.toLowerCase().includes(q) ||
        c.evidence_ref.toLowerCase().includes(q) ||
        c.summary_redacted.toLowerCase().includes(q)
      );
      const matchesSector = state.claimSector === 'ALL' || c.sector === state.claimSector;
      const matchesThreat = state.claimThreat === 'ALL' || c.threat_level === state.claimThreat;
      const matchesVerif = state.claimVerif === 'ALL' || c.verification_status === state.claimVerif;
      const matchesCat = state.claimCategory === 'ALL' || c.data_category.toLowerCase().includes(state.claimCategory.toLowerCase());

      return matchesSearch && matchesSector && matchesThreat && matchesVerif && matchesCat;
    });
  }

  function onionLinkState(url) {
    const raw = String(url || '');
    const host = raw.match(/[a-z2-7]{16,63}\.onion/i);
    if (!host) {
      return { rank: 0, label: 'No onion link', badge: 'badge-unassessed', host: '' };
    }
    return { rank: 1, label: 'Not verified', badge: 'badge-unverified', host: host[0] };
  }

  function renderClaimsTable() {
    let filtered = getFilteredClaims();

    // Sort
    filtered.sort((a, b) => {
      if (state.claimSortCol === 'onion_link_verified') {
        const diff = onionLinkState(a.source_url_or_ref).rank - onionLinkState(b.source_url_or_ref).rank;
        return state.claimSortAsc ? diff : -diff;
      }
      let vA = a[state.claimSortCol] || '';
      let vB = b[state.claimSortCol] || '';
      if (typeof vA === 'string') {
        vA = vA.toLowerCase();
        vB = vB.toLowerCase();
      }
      if (vA < vB) return state.claimSortAsc ? -1 : 1;
      if (vA > vB) return state.claimSortAsc ? 1 : -1;
      return 0;
    });

    // Pagination
    const total = filtered.length;
    let pageSize = state.claimPageSize === 'ALL' ? total : parseInt(state.claimPageSize, 10);
    if (!pageSize || pageSize < 1) pageSize = total || 1;
    const totalPages = Math.ceil(total / pageSize) || 1;
    if (state.claimPage > totalPages) state.claimPage = 1;

    const startIdx = (state.claimPage - 1) * pageSize;
    const pageRecords = filtered.slice(startIdx, startIdx + pageSize);

    claimsTableBody.innerHTML = '';
    if (pageRecords.length === 0) {
      claimsTableBody.innerHTML = `<tr><td colspan="11" style="text-align: center; padding: 2rem; color: var(--text-muted);">No matching exposure claims located under the specified filters.</td></tr>`;
    } else {
      pageRecords.forEach(c => {
        const tr = document.createElement('tr');
        const onion = onionLinkState(c.source_url_or_ref);
        tr.innerHTML = `
          <td class="mono-cell"><strong>${escapeHtml(c.claim_id)}</strong></td>
          <td><strong>${escapeHtml(c.kpi_name)}</strong> <small style="color: #94a3b8;">(${escapeHtml(c.kpi_id)})</small></td>
          <td>${escapeHtml(c.sector)}</td>
          <td><span class="badge ${getThreatBadgeClass(c.threat_level)}">${escapeHtml(c.threat_level)}</span></td>
          <td><span class="badge ${getVerifBadgeClass(c.verification_status)}">${escapeHtml(c.verification_status)}</span></td>
          <td>${escapeHtml(c.source_name)}</td>
          <td class="onion-cell"><span class="badge ${onion.badge}">${escapeHtml(onion.label)}</span>${onion.host ? `<span class="onion-host">${escapeHtml(onion.host)}</span>` : ''}</td>
          <td class="mono-cell">${escapeHtml(c.source_date)}</td>
          <td class="mono-cell" style="font-size: 0.75rem;">${escapeHtml(c.evidence_ref)}</td>
          <td style="max-width: 280px; font-size: 0.78rem;">${escapeHtml(c.summary_redacted.slice(0, 110))}...</td>
          <td><button class="btn btn-secondary btn-sm" data-claim-id="${escapeHtml(c.claim_id)}">View</button></td>
        `;
        claimsTableBody.appendChild(tr);
      });
    }

    claimsTableCount.textContent = `Showing ${Math.min(startIdx + 1, total)} to ${Math.min(startIdx + pageRecords.length, total)} of ${total} records`;

    // Render pagination buttons
    paginationButtons.innerHTML = '';
    if (totalPages > 1) {
      for (let p = 1; p <= totalPages; p++) {
        const btn = document.createElement('button');
        btn.className = `btn btn-secondary btn-sm ${p === state.claimPage ? 'btn-primary' : ''}`;
        btn.textContent = p;
        btn.addEventListener('click', () => {
          state.claimPage = p;
          renderClaimsTable();
        });
        paginationButtons.appendChild(btn);
      }
    }
  }

  // -----------------------------------------------------------
  // View 3: Source Register
  // -----------------------------------------------------------
  function renderSourcesTable() {
    const q = state.sourceSearch.toLowerCase();
    const filtered = DATA.sources.filter(s => {
      return !q || s.source_name.toLowerCase().includes(q) ||
        s.category.toLowerCase().includes(q) ||
        s.notes.toLowerCase().includes(q);
    });

    sourcesTableBody.innerHTML = '';
    filtered.forEach(s => {
      const tr = document.createElement('tr');
      const netTypeBadge = s.is_onion
        ? `<span class="badge badge-unverified">Tor Onion (Passive)</span>`
        : `<span class="badge badge-corroborated">Surface / ClearWeb</span>`;

      tr.innerHTML = `
        <td class="mono-cell"><strong>${escapeHtml(s.source_id)}</strong></td>
        <td><strong>${escapeHtml(s.source_name)}</strong></td>
        <td>${escapeHtml(s.category)}</td>
        <td class="mono-cell" style="word-break: break-all; font-size: 0.75rem;">${escapeHtml(s.url_or_ref)}</td>
        <td>${netTypeBadge}</td>
        <td><span class="badge ${getVerifBadgeClass(s.verification_status)}">${escapeHtml(s.verification_status)}</span></td>
        <td style="font-size: 0.8rem;">${escapeHtml(s.notes)}</td>
      `;
      sourcesTableBody.appendChild(tr);
    });
  }

  // -----------------------------------------------------------
  // View 4: Evidence Registry
  // -----------------------------------------------------------
  function renderEvidenceTable() {
    const q = state.evidenceSearch.toLowerCase();
    const filtered = DATA.evidence.filter(e => {
      return !q || e.evidence_id.toLowerCase().includes(q) ||
        e.originating_document.toLowerCase().includes(q) ||
        e.sha256.toLowerCase().includes(q) ||
        e.ocr_preview.toLowerCase().includes(q);
    });

    evidenceTableBody.innerHTML = '';
    filtered.forEach(e => {
      const tr = document.createElement('tr');
      const imgPath = 'evidence/' + encodeURIComponent(e.filename);
      const shortSha = e.sha256.slice(0, 8) + '...' + e.sha256.slice(-8);
      tr.innerHTML = `
        <td class="mono-cell"><strong>${escapeHtml(e.evidence_id)}</strong></td>
        <td>
          <img src="${imgPath}" class="evidence-thumb" alt="${escapeHtml(e.evidence_id)}" data-evidence-id="${escapeHtml(e.evidence_id)}" title="Click to enlarge" loading="lazy">
        </td>
        <td>${escapeHtml(e.originating_document)}</td>
        <td>
          <span class="sha-text" title="${escapeHtml(e.sha256)} (Click to copy full hash)" data-copy="${escapeHtml(e.sha256)}">
            ${escapeHtml(shortSha)}
          </span>
        </td>
        <td class="mono-cell">${escapeHtml(e.dimensions)}</td>
        <td class="mono-cell">${(e.file_size_bytes / 1024).toFixed(1)} KB</td>
        <td><span class="badge badge-verified">${escapeHtml(e.verification_status)}</span></td>
        <td>
          <div class="ocr-preview-box" title="Extracted OCR text (Click 'View Image' for full text)">${escapeHtml(e.ocr_preview || '[No OCR text available]')}</div>
        </td>
        <td><button class="btn btn-secondary btn-sm" data-evidence-id="${escapeHtml(e.evidence_id)}">View Image</button></td>
      `;
      evidenceTableBody.appendChild(tr);
    });
  }

  // -----------------------------------------------------------
  // View 5: Threat & Impact Matrix
  // -----------------------------------------------------------
  function renderThreatMatrix() {
    const sectors = Array.from(new Set(DATA.kpis.map(k => k.sector))).sort();
    threatSectorGrid.innerHTML = '';

    sectors.forEach(sec => {
      const sectorKpis = DATA.kpis.filter(k => k.sector === sec);
      const exposedCount = sectorKpis.filter(k => k.claim_count > 0).length;

      const card = document.createElement('div');
      card.className = 'sector-card';

      let kpisHtml = sectorKpis.map(k => {
        return `
          <div class="sector-kpi-item">
            <span><strong>${escapeHtml(k.kpi_id)}:</strong> ${escapeHtml(k.kpi_name)}</span>
            <span class="badge ${getThreatBadgeClass(k.highest_threat)}">${escapeHtml(k.highest_threat)}</span>
          </div>
        `;
      }).join('');

      card.innerHTML = `
        <div class="sector-card-header">
          <span class="sector-card-title">${escapeHtml(sec)}</span>
          <span class="badge ${exposedCount > 0 ? 'badge-high' : 'badge-unassessed'}">${exposedCount}/${sectorKpis.length} Impacted</span>
        </div>
        <div class="sector-kpi-list">
          ${kpisHtml}
        </div>
      `;
      threatSectorGrid.appendChild(card);
    });
  }

  // -----------------------------------------------------------
  // View 6: Recommended Response
  // -----------------------------------------------------------
  function renderResponseTable() {
    const filtered = DATA.inventory.filter(c => {
      return state.responseOwner === 'ALL' || c.action_owner === state.responseOwner;
    });

    responseTableBody.innerHTML = '';
    filtered.forEach(c => {
      const tr = document.createElement('tr');
      const ownerBadge = `<span class="badge ${c.action_owner === 'CERT' ? 'badge-critical' : (c.action_owner === 'LEA' ? 'badge-high' : 'badge-corroborated')}">${escapeHtml(c.action_owner)}</span>`;

      tr.innerHTML = `
        <td><strong>${escapeHtml(c.kpi_name)}</strong> <small>(${escapeHtml(c.kpi_id)})</small></td>
        <td>${escapeHtml(c.sector)}</td>
        <td><span class="badge ${getThreatBadgeClass(c.threat_level)}">${escapeHtml(c.threat_level)}</span></td>
        <td>${ownerBadge}</td>
        <td style="font-size: 0.82rem;">${escapeHtml(c.recommended_actions)}</td>
        <td><span class="badge ${getVerifBadgeClass(c.verification_status)}">${escapeHtml(c.verification_status)}</span></td>
      `;
      responseTableBody.appendChild(tr);
    });
  }

  // -----------------------------------------------------------
  // View 7: Print Briefing Dossier
  // -----------------------------------------------------------
  function renderBriefing() {
    // Collect KPIs that have darknet / onion breach claims
    const onionKpiIds = new Set();
    DATA.inventory.forEach(c => {
      if (c.source_url_or_ref && c.source_url_or_ref.includes('.onion') && c.kpi_id) {
        onionKpiIds.add(c.kpi_id);
      }
    });

    // 1. KPI summary table
    let kpiHtml = `
      <div class="dossier-table-container">
        <table class="dossier-table" style="table-layout: fixed; width: 100%;">
          <thead>
            <tr>
              <th style="width: 11%;">KPI ID</th>
              <th style="width: 27%;">Designated Installation / Entity</th>
              <th style="width: 17%;">Sector</th>
              <th style="width: 17%;">Documented Claims</th>
              <th style="width: 12%; text-align: center;">Threat Level</th>
              <th style="width: 16%; text-align: center;">Verification Status</th>
            </tr>
          </thead>
          <tbody>
    `;
    DATA.kpis.forEach(k => {
      const hasOnion = onionKpiIds.has(k.kpi_id);
      const onionIndicator = hasOnion
        ? `<span class="onion-badge" title="Documented onion address">.onion</span>`
        : '';

      kpiHtml += `
        <tr>
          <td><strong>${escapeHtml(k.kpi_id)}</strong></td>
          <td style="font-weight: 600;">${escapeHtml(k.kpi_name)}</td>
          <td>${escapeHtml(k.sector)}</td>
          <td>
            ${k.claim_count > 0 ? k.claim_count + ' incident(s)' : 'No claims located'}
            ${onionIndicator}
          </td>
          <td style="text-align: center; vertical-align: middle;">
            <span class="badge ${getThreatBadgeClass(k.highest_threat)}">${escapeHtml(k.highest_threat)}</span>
          </td>
          <td style="text-align: center; vertical-align: middle;">
            <span class="badge ${getVerifBadgeClass(k.verification_status)}">
              ${escapeHtml(k.verification_status)}
            </span>
          </td>
        </tr>
      `;
    });
    kpiHtml += `</tbody></table></div>`;
    briefingKpiSummary.innerHTML = kpiHtml;

    // 2. Major incidents (Critical / High threat) with available Source / .onion URLs
    const majorClaims = DATA.inventory.filter(c => c.threat_level === 'Critical' || c.threat_level === 'High').slice(0, 15);
    let majHtml = `
      <div class="dossier-table-container">
        <table class="dossier-table" style="table-layout: fixed; width: 100%;">
          <thead>
            <tr>
              <th style="width: 9%;">Claim ID</th>
              <th style="width: 18%;">Target Entity</th>
              <th style="width: 10%; text-align: center;">Threat Level</th>
              <th style="width: 31%;">Platform / Leak Source &amp; URL</th>
              <th style="width: 11%; text-align: center;">Incident Date</th>
              <th style="width: 21%;">Verified Summary</th>
            </tr>
          </thead>
          <tbody>
    `;
    majorClaims.forEach(c => {
      let sourceDisplay = `<div><strong>${escapeHtml(c.source_name)}</strong></div>`;
      if (c.source_url_or_ref) {
        if (c.source_url_or_ref.includes('.onion')) {
          sourceDisplay += `<div class="onion-badge">${escapeHtml(c.source_url_or_ref)}</div>`;
        } else if (c.source_url_or_ref.startsWith('http')) {
          sourceDisplay += `<div class="source-sub-url">${escapeHtml(c.source_url_or_ref)}</div>`;
        }
      }

      majHtml += `
        <tr>
          <td><strong>${escapeHtml(c.claim_id)}</strong></td>
          <td><strong>${escapeHtml(c.kpi_name)}</strong></td>
          <td style="text-align: center; vertical-align: middle;">
            <span class="badge ${getThreatBadgeClass(c.threat_level)}">${escapeHtml(c.threat_level)}</span>
          </td>
          <td>${sourceDisplay}</td>
          <td style="text-align: center; font-family: monospace; font-size: 0.75rem;">${escapeHtml(c.source_date)}</td>
          <td style="font-size: 0.76rem; line-height: 1.45;">${escapeHtml(c.summary_redacted)}</td>
        </tr>
      `;
    });
    majHtml += `</tbody></table></div>`;
    briefingMajorIncidents.innerHTML = majHtml;

    // 3. Dedicated Dark Web (.onion) Threat Sources & Leak Portal Register
    if (briefingOnionRegister) {
      const onionClaims = DATA.inventory.filter(c => c.source_url_or_ref && c.source_url_or_ref.includes('.onion'));
      const onionSources = DATA.sources.filter(s => s.is_onion || (s.url_or_ref && s.url_or_ref.includes('.onion')));

      let onionHtml = `
        <h4 style="font-size: 0.95rem; font-weight: 700; color: #991b1b; margin-top: 1rem; margin-bottom: 0.5rem;">
          5.1 Documented Breach Claims with Available Dark Web (.onion) URLs (${onionClaims.length} Incidents)
        </h4>
        <p style="font-size: 0.85rem; color: #475569; margin-bottom: 0.6rem;">
          Exposures identified on Tor hidden service ransomware blogs, breach forums, and extortion sites directly targeting Bangladeshi public and private infrastructure.
        </p>
        <div class="dossier-table-container">
          <table class="dossier-table" style="table-layout: fixed; width: 100%;">
            <thead>
              <tr>
                <th style="width: 10%;">Claim ID</th>
                <th style="width: 19%;">Target Entity &amp; Sector</th>
                <th style="width: 11%; text-align: center;">Threat Level</th>
                <th style="width: 32%;">Dark Web (.onion) Link / Leak Portal</th>
                <th style="width: 12%; text-align: center;">Incident Date</th>
                <th style="width: 16%; text-align: center;">Evidence Ref</th>
              </tr>
            </thead>
            <tbody>
      `;

      onionClaims.forEach(c => {
        onionHtml += `
          <tr>
            <td><strong>${escapeHtml(c.claim_id)}</strong></td>
            <td>
              <strong>${escapeHtml(c.kpi_name)}</strong>
              <div style="font-size: 0.72rem; color: #64748b;">${escapeHtml(c.sector)}</div>
            </td>
            <td style="text-align: center; vertical-align: middle;">
              <span class="badge ${getThreatBadgeClass(c.threat_level)}">${escapeHtml(c.threat_level)}</span>
            </td>
            <td>
              <div class="onion-badge">${escapeHtml(c.source_url_or_ref)}</div>
              <div style="font-size: 0.72rem; color: #475569; margin-top: 3px;"><em>Source: ${escapeHtml(c.source_name)}</em></div>
              <div style="font-size: 0.74rem; color: #334155; margin-top: 4px; line-height: 1.4;">${escapeHtml(c.summary_redacted)}</div>
            </td>
            <td style="text-align: center; font-family: monospace; font-size: 0.75rem;">${escapeHtml(c.source_date)}</td>
            <td style="text-align: center; vertical-align: middle;">
              <code>${escapeHtml(c.evidence_ref || 'EVD-REG')}</code>
              <div style="font-family: monospace; font-size: 0.68rem; color: #64748b; word-break: break-all; margin-top: 2px;">
                ${escapeHtml(c.artefact_sha256 ? c.artefact_sha256.substring(0, 16) + '...' : 'Verified')}
              </div>
            </td>
          </tr>
        `;
      });
      onionHtml += `</tbody></table></div>`;

      onionHtml += `
        <h4 style="font-size: 0.95rem; font-weight: 700; color: #0f172a; margin-top: 1.5rem; margin-bottom: 0.5rem;">
          5.2 Passive Darknet (.onion) Threat Intelligence Catalogs &amp; Directories (${onionSources.length} Sources)
        </h4>
        <p style="font-size: 0.85rem; color: #475569; margin-bottom: 0.6rem;">
          Public dark web directories and indexes audited passively for breach mentions, ransomware blogs, and paste sites.
        </p>
        <div class="dossier-table-container">
          <table class="dossier-table" style="table-layout: fixed; width: 100%;">
            <thead>
              <tr>
                <th style="width: 11%;">Source ID</th>
                <th style="width: 21%;">Platform / Directory Name</th>
                <th style="width: 16%;">Category</th>
                <th style="width: 32%;">Tor Hidden Service (.onion) Address</th>
                <th style="width: 20%; text-align: center;">Verification Status</th>
              </tr>
            </thead>
            <tbody>
      `;

      onionSources.forEach(s => {
        onionHtml += `
          <tr>
            <td><strong>${escapeHtml(s.source_id)}</strong></td>
            <td><strong>${escapeHtml(s.source_name)}</strong></td>
            <td>${escapeHtml(s.category)}</td>
            <td><span class="onion-badge">${escapeHtml(s.url_or_ref)}</span></td>
            <td style="text-align: center; vertical-align: middle;">
              <span class="badge ${getVerifBadgeClass(s.verification_status)}">${escapeHtml(s.verification_status)}</span>
            </td>
          </tr>
        `;
      });
      onionHtml += `</tbody></table></div>`;

      briefingOnionRegister.innerHTML = onionHtml;
    }

    // 4. Strategic Recommendations
    let recHtml = `
      <div class="dossier-table-container">
        <table class="dossier-table" style="table-layout: fixed; width: 100%;">
          <thead>
            <tr>
              <th style="width: 25%;">Target Category</th>
              <th style="width: 22%;">Designated Responder</th>
              <th style="width: 53%;">Prescribed Defensive Action</th>
            </tr>
          </thead>
          <tbody>
            <tr>
              <td><strong>Critical Infrastructure (KPI Enclaves)</strong></td>
              <td><strong>CERT (BGD e-GOV CIRT)</strong></td>
              <td>Immediate isolation of compromised Exchange/API integration gateways. Perform domain-wide password revocation, revoke inactive API tokens, enforce MFA on all administrative consoles.</td>
            </tr>
            <tr>
              <td><strong>State Defense &amp; Law Enforcement</strong></td>
              <td><strong>LEA &amp; National Security</strong></td>
              <td>Active forensic review of exposed perimeter services. Threat hunting for RemotePE, Babuk, and Medusa implant indicators. Coordinate lawful evidence custody.</td>
            </tr>
            <tr>
              <td><strong>Commercial Sector &amp; Supply Chain</strong></td>
              <td><strong>Infrastructure Operators</strong></td>
              <td>Notification to affected account holders regarding breached databases. Patch exposed Apache/Nginx web instances and deploy Web Application Firewalls (WAF).</td>
            </tr>
          </tbody>
        </table>
      </div>
    `;
    briefingRecommendations.innerHTML = recHtml;

    // 5. Evidence hashes & integrity register
    let evHtml = `
      <div class="dossier-table-container">
        <table class="dossier-table" style="table-layout: fixed; width: 100%;">
          <thead>
            <tr>
              <th style="width: 14%;">Evidence ID</th>
              <th style="width: 32%;">Originating Research Document</th>
              <th style="width: 34%;">Artifact SHA-256 Digest</th>
              <th style="width: 20%; text-align: center;">Verification Status</th>
            </tr>
          </thead>
          <tbody>
    `;
    DATA.evidence.forEach(e => {
      evHtml += `
        <tr>
          <td><strong>${escapeHtml(e.evidence_id)}</strong></td>
          <td style="word-break: break-word; font-size: 0.78rem;">${escapeHtml(e.originating_document)}</td>
          <td style="font-family: monospace; font-size: 0.70rem; word-break: break-all; color: #1e3a8a; background: #f8fafc; padding: 4px 6px; border-radius: 3px;">
            ${escapeHtml(e.sha256)}
          </td>
          <td style="text-align: center; vertical-align: middle;">
            <span class="badge ${getVerifBadgeClass(e.verification_status)}">
              ${escapeHtml(e.verification_status)}
            </span>
          </td>
        </tr>
      `;
    });
    evHtml += `</tbody></table></div>`;
    briefingEvidenceList.innerHTML = evHtml;
  }

  // -----------------------------------------------------------
  // Modal Handlers (State Preservation)
  // -----------------------------------------------------------
  function openModal(title, html) {
    modalTitle.textContent = title;
    modalContent.innerHTML = html;
    detailModal.classList.add('active');
    detailModal.setAttribute('aria-hidden', 'false');
  }

  function closeModal() {
    detailModal.classList.remove('active');
    detailModal.setAttribute('aria-hidden', 'true');
  }

  modalCloseBtn.addEventListener('click', closeModal);
  modalDismissBtn.addEventListener('click', closeModal);
  detailModal.addEventListener('click', (e) => {
    if (e.target === detailModal) closeModal();
  });
  window.addEventListener('keydown', (e) => {
    if (e.key === 'Escape' && detailModal.classList.contains('active')) closeModal();
  });

  // Table action clicks (delegated)
  kpiTableBody.addEventListener('click', (e) => {
    const btn = e.target.closest('button[data-kpi-id]');
    if (!btn) return;
    const kId = btn.getAttribute('data-kpi-id');
    const kpi = DATA.kpis.find(k => k.kpi_id === kId);
    if (!kpi) return;

    const matchedClaims = DATA.inventory.filter(c => c.kpi_id === kId);

    let html = `
      <div class="modal-grid">
        <div><div class="modal-field-label">KPI ID</div><div class="modal-field-val"><strong>${escapeHtml(kpi.kpi_id)}</strong></div></div>
        <div><div class="modal-field-label">Criticality</div><div class="modal-field-val"><span class="badge ${kpi.criticality === 'Critical' ? 'badge-critical' : 'badge-high'}">${escapeHtml(kpi.criticality)}</span></div></div>
        <div><div class="modal-field-label">Installation Name</div><div class="modal-field-val">${escapeHtml(kpi.kpi_name)}</div></div>
        <div><div class="modal-field-label">Sector</div><div class="modal-field-val">${escapeHtml(kpi.sector)}</div></div>
        <div><div class="modal-field-label">Threat Level</div><div class="modal-field-val"><span class="badge ${getThreatBadgeClass(kpi.highest_threat)}">${escapeHtml(kpi.highest_threat)}</span></div></div>
        <div><div class="modal-field-label">Verification Status</div><div class="modal-field-val"><span class="badge ${getVerifBadgeClass(kpi.verification_status)}">${escapeHtml(kpi.verification_status)}</span></div></div>
        <div class="modal-full-field">
          <div class="modal-field-label">Impact Assessment Summary</div>
          <div class="modal-field-val">${escapeHtml(kpi.impact_summary)}</div>
        </div>
      </div>
      <h4 style="margin: 1rem 0 0.5rem 0; color: #ffffff;">Associated Documented Claims (${matchedClaims.length})</h4>
    `;

    if (matchedClaims.length === 0) {
      html += `<p style="color: var(--text-muted); font-style: italic;">No public claim located for this Key Point Installation as of 2026-10-26.</p>`;
    } else {
      html += `<ul style="padding-left: 1.25rem; font-size: 0.82rem; color: var(--text-muted);">`;
      matchedClaims.forEach(c => {
        html += `
          <li style="margin-bottom: 0.5rem;">
            <strong>${escapeHtml(c.claim_id)}:</strong> ${escapeHtml(c.source_name)} (${escapeHtml(c.source_date)}) &bull;
            <span class="badge ${getThreatBadgeClass(c.threat_level)}">${escapeHtml(c.threat_level)}</span>
            <div style="color: var(--text-main); margin-top: 0.2rem;">${escapeHtml(c.summary_redacted)}</div>
          </li>
        `;
      });
      html += `</ul>`;
    }

    openModal(`Key Point Installation Profile — ${kpi.kpi_id}`, html);
  });

  claimsTableBody.addEventListener('click', (e) => {
    const btn = e.target.closest('button[data-claim-id]');
    if (!btn) return;
    const cid = btn.getAttribute('data-claim-id');
    const claim = DATA.inventory.find(c => c.claim_id === cid);
    if (!claim) return;

    // Find associated evidence artifacts
    const evIds = (claim.evidence_ref || '').match(/EVD-[0-9]+/g) || [];
    const matchedEvidence = DATA.evidence.filter(e => evIds.includes(e.evidence_id));

    let galleryHtml = '';
    if (matchedEvidence.length > 0) {
      galleryHtml = `
        <div class="modal-full-field">
          <div class="modal-field-label">Attached Screenshot Artifacts (${matchedEvidence.length})</div>
          <div class="claim-evidence-gallery">
            ${matchedEvidence.map(e => `
              <div class="gallery-item">
                <img src="evidence/${encodeURIComponent(e.filename)}" class="evidence-thumb" alt="${escapeHtml(e.evidence_id)}" data-evidence-id="${escapeHtml(e.evidence_id)}" title="Click to view full screenshot">
                <span><strong>${escapeHtml(e.evidence_id)}</strong> (${escapeHtml(e.dimensions)})</span>
              </div>
            `).join('')}
          </div>
        </div>
      `;
    }

    const html = `
      <div class="modal-grid">
        <div><div class="modal-field-label">Claim ID</div><div class="modal-field-val"><strong>${escapeHtml(claim.claim_id)}</strong></div></div>
        <div><div class="modal-field-label">Target Entity</div><div class="modal-field-val"><strong>${escapeHtml(claim.kpi_name)}</strong> (${escapeHtml(claim.kpi_id)})</div></div>
        <div><div class="modal-field-label">Sector</div><div class="modal-field-val">${escapeHtml(claim.sector)}</div></div>
        <div><div class="modal-field-label">Threat Level</div><div class="modal-field-val"><span class="badge ${getThreatBadgeClass(claim.threat_level)}">${escapeHtml(claim.threat_level)}</span></div></div>
        <div><div class="modal-field-label">Verification Status</div><div class="modal-field-val"><span class="badge ${getVerifBadgeClass(claim.verification_status)}">${escapeHtml(claim.verification_status)}</span></div></div>
        <div><div class="modal-field-label">Credibility</div><div class="modal-field-val">${escapeHtml(claim.credibility)}</div></div>
        <div><div class="modal-field-label">Source Platform / Medium</div><div class="modal-field-val">${escapeHtml(claim.source_name)}</div></div>
        <div><div class="modal-field-label">Recorded Date</div><div class="modal-field-val">${escapeHtml(claim.source_date)}</div></div>
        <div><div class="modal-field-label">Source URL / Passive Ref</div><div class="modal-field-val" style="word-break: break-all; font-family: monospace; font-size: 0.75rem;">${escapeHtml(claim.source_url_or_ref)}</div></div>
        <div><div class="modal-field-label">Evidence Reference</div><div class="modal-field-val mono-cell">${escapeHtml(claim.evidence_ref)}</div></div>
        <div class="modal-full-field">
          <div class="modal-field-label">Breach Nature & Summary (Redacted)</div>
          <div class="modal-field-val">${escapeHtml(claim.summary_redacted)}</div>
        </div>
        <div class="modal-full-field">
          <div class="modal-field-label">Impact Summary</div>
          <div class="modal-field-val">${escapeHtml(claim.impact_summary)}</div>
        </div>
        <div class="modal-full-field">
          <div class="modal-field-label">Recommended Response Protocol (${escapeHtml(claim.action_owner)})</div>
          <div class="modal-field-val">${escapeHtml(claim.recommended_actions)}</div>
        </div>
        ${galleryHtml}
      </div>
    `;

    openModal(`Claim Dossier — ${claim.claim_id}`, html);
  });

  // Evidence table action clicks & modal image preview
  function showEvidenceModal(eid) {
    const ev = DATA.evidence.find(e => e.evidence_id === eid);
    if (!ev) return;

    const imgPath = 'evidence/' + encodeURIComponent(ev.filename);
    const html = `
      <div class="modal-grid">
        <div><div class="modal-field-label">Evidence ID</div><div class="modal-field-val"><strong>${escapeHtml(ev.evidence_id)}</strong></div></div>
        <div><div class="modal-field-label">Verification Status</div><div class="modal-field-val"><span class="badge badge-verified">${escapeHtml(ev.verification_status)}</span></div></div>
        <div><div class="modal-field-label">Originating Document</div><div class="modal-field-val">${escapeHtml(ev.originating_document)}</div></div>
        <div><div class="modal-field-label">Dimensions & Size</div><div class="modal-field-val">${escapeHtml(ev.dimensions)} &bull; ${(ev.file_size_bytes / 1024).toFixed(1)} KB</div></div>
        <div class="modal-full-field">
          <div class="modal-field-label">Artifact SHA-256 Digest</div>
          <div class="modal-field-val" style="font-family: monospace; font-size: 0.8rem; word-break: break-all; color: #93c5fd;">${escapeHtml(ev.sha256)}</div>
        </div>
        <div class="modal-full-field">
          <div class="modal-field-label">Screenshot Visual Artifact</div>
          <a href="${imgPath}" target="_blank" title="Click to open raw full-resolution image in new tab">
            <img src="${imgPath}" class="modal-evidence-preview" alt="${escapeHtml(ev.evidence_id)}">
          </a>
          <small style="color: var(--text-dim);">Click image to open full resolution in new browser tab</small>
        </div>
        <div class="modal-full-field">
          <div class="modal-field-label">Complete Optical Character Recognition (OCR Document Text - Redacted)</div>
          <pre class="modal-ocr-full">${escapeHtml(ev.ocr_full || ev.ocr_preview || '[No OCR text extracted]')}</pre>
        </div>
      </div>
    `;

    openModal(`Evidence Artifact — ${ev.evidence_id}`, html);
  }

  evidenceTableBody.addEventListener('click', (e) => {
    const target = e.target.closest('[data-evidence-id]');
    if (!target) return;
    const eid = target.getAttribute('data-evidence-id');
    showEvidenceModal(eid);
  });

  // Modal delegation for gallery thumbnails
  modalContent.addEventListener('click', (e) => {
    const target = e.target.closest('[data-evidence-id]');
    if (!target) return;
    const eid = target.getAttribute('data-evidence-id');
    showEvidenceModal(eid);
  });

  // Click to copy SHA-256 hash
  document.addEventListener('click', (e) => {
    const shaEl = e.target.closest('.sha-text[data-copy]');
    if (!shaEl) return;
    const textToCopy = shaEl.getAttribute('data-copy');
    if (textToCopy && navigator.clipboard) {
      navigator.clipboard.writeText(textToCopy).then(() => {
        const originalText = shaEl.textContent;
        shaEl.textContent = 'Copied!';
        setTimeout(() => {
          shaEl.textContent = originalText;
        }, 1500);
      }).catch(() => {});
    }
  });

  // -----------------------------------------------------------
  // Export Handlers with Strict Legal Gate and CSV Sanitization
  // -----------------------------------------------------------
  function exportFilteredCSV() {
    const claims = getFilteredClaims();

    // Check legal gate for all records
    const authorizedClaims = claims.filter(isLegalGateAuthorized);
    if (authorizedClaims.length === 0) {
      alert("LEGAL GATE BLOCKED: Zero records satisfied the strict legal export criteria (legal_gate_ok === true). Export aborted.");
      return;
    }

    if (authorizedClaims.length < claims.length) {
      alert(`NOTICE: ${claims.length - authorizedClaims.length} records were blocked by the strict legal export gate. Only approved records will be exported.`);
    }

    const headers = [
      "claim_id", "kpi_id", "kpi_name", "sector", "criticality",
      "threat_level", "verification_status", "source_name", "source_date",
      "evidence_ref", "summary_redacted", "impact_summary", "recommended_actions"
    ];

    let csvContent = headers.join(",") + "\n";
    authorizedClaims.forEach(c => {
      const row = headers.map(h => sanitizeCsvCell(c[h]));
      csvContent += row.join(",") + "\n";
    });

    const blob = new Blob([csvContent], { type: "text/csv;charset=utf-8;" });
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.setAttribute("href", url);
    link.setAttribute("download", `project_dark_hunt_claims_${Date.now()}.csv`);
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    URL.revokeObjectURL(url);
  }

  function exportFilteredJSON() {
    const claims = getFilteredClaims();
    const authorizedClaims = claims.filter(isLegalGateAuthorized);

    if (authorizedClaims.length === 0) {
      alert("LEGAL GATE BLOCKED: Zero records satisfied the strict legal export criteria (legal_gate_ok === true). Export aborted.");
      return;
    }

    const jsonStr = JSON.stringify(authorizedClaims, null, 2);
    const blob = new Blob([jsonStr], { type: "application/json;charset=utf-8;" });
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.setAttribute("href", url);
    link.setAttribute("download", `project_dark_hunt_claims_${Date.now()}.json`);
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    URL.revokeObjectURL(url);
  }

  exportCsvBtn.addEventListener('click', exportFilteredCSV);
  exportJsonBtn.addEventListener('click', exportFilteredJSON);

  // -----------------------------------------------------------
  // Event Listeners for Filters & Search
  // -----------------------------------------------------------
  kpiSearchInput.addEventListener('input', (e) => {
    state.kpiSearch = e.target.value.trim();
    renderKpiTable();
  });

  kpiSectorSelect.addEventListener('change', (e) => {
    state.kpiSector = e.target.value;
    renderKpiTable();
  });

  kpiStatusSelect.addEventListener('change', (e) => {
    state.kpiStatus = e.target.value;
    renderKpiTable();
  });

  kpiClearBtn.addEventListener('click', () => {
    kpiSearchInput.value = '';
    state.kpiSearch = '';
    renderKpiTable();
  });

  claimSearchInput.addEventListener('input', (e) => {
    state.claimSearch = e.target.value.trim();
    state.claimPage = 1;
    renderClaimsTable();
  });

  claimClearBtn.addEventListener('click', () => {
    claimSearchInput.value = '';
    state.claimSearch = '';
    state.claimPage = 1;
    renderClaimsTable();
  });

  claimFilterSector.addEventListener('change', (e) => {
    state.claimSector = e.target.value;
    state.claimPage = 1;
    renderClaimsTable();
  });

  claimFilterThreat.addEventListener('change', (e) => {
    state.claimThreat = e.target.value;
    state.claimPage = 1;
    renderClaimsTable();
  });

  claimFilterVerif.addEventListener('change', (e) => {
    state.claimVerif = e.target.value;
    state.claimPage = 1;
    renderClaimsTable();
  });

  claimFilterCategory.addEventListener('change', (e) => {
    state.claimCategory = e.target.value;
    state.claimPage = 1;
    renderClaimsTable();
  });

  claimPageSize.addEventListener('change', (e) => {
    state.claimPageSize = e.target.value;
    state.claimPage = 1;
    renderClaimsTable();
  });

  claimResetAllBtn.addEventListener('click', () => {
    claimSearchInput.value = '';
    claimFilterSector.value = 'ALL';
    claimFilterThreat.value = 'ALL';
    claimFilterVerif.value = 'ALL';
    claimFilterCategory.value = 'ALL';
    claimPageSize.value = '25';

    state.claimSearch = '';
    state.claimSector = 'ALL';
    state.claimThreat = 'ALL';
    state.claimVerif = 'ALL';
    state.claimCategory = 'ALL';
    state.claimPageSize = '25';
    state.claimPage = 1;

    renderClaimsTable();
  });

  sourceSearchInput.addEventListener('input', (e) => {
    state.sourceSearch = e.target.value.trim();
    renderSourcesTable();
  });

  evidenceSearchInput.addEventListener('input', (e) => {
    state.evidenceSearch = e.target.value.trim();
    renderEvidenceTable();
  });

  responseOwnerFilter.addEventListener('change', (e) => {
    state.responseOwner = e.target.value;
    renderResponseTable();
  });

  // Table Column Sort handlers
  document.querySelectorAll('#kpi-table th[data-sort]').forEach(th => {
    th.addEventListener('click', () => {
      const col = th.getAttribute('data-sort');
      if (state.kpiSortCol === col) {
        state.kpiSortAsc = !state.kpiSortAsc;
      } else {
        state.kpiSortCol = col;
        state.kpiSortAsc = true;
      }
      renderKpiTable();
    });
  });

  document.querySelectorAll('#claims-table th[data-sort]').forEach(th => {
    th.addEventListener('click', () => {
      const col = th.getAttribute('data-sort');
      if (state.claimSortCol === col) {
        state.claimSortAsc = !state.claimSortAsc;
      } else {
        state.claimSortCol = col;
        state.claimSortAsc = true;
      }
      renderClaimsTable();
    });
  });

  document.getElementById('view-overview').appendChild(document.getElementById('view-threat'));
  document.getElementById('view-overview').appendChild(document.getElementById('view-response'));
  document.getElementById('view-search').appendChild(document.getElementById('view-sources'));

  // -----------------------------------------------------------
  // Initialize Application
  // -----------------------------------------------------------
  function applyTheme(theme) {
    document.documentElement.setAttribute('data-theme', theme);
    localStorage.setItem('pdh-theme', theme);
    const light = theme === 'light';
    themeToggle.textContent = light ? 'Dark theme' : 'Light theme';
    themeToggle.setAttribute('aria-pressed', light ? 'true' : 'false');
    themeToggle.setAttribute('aria-label', light ? 'Switch to dark theme' : 'Switch to light theme');
  }

  const themeToggle = document.getElementById('theme-toggle');
  themeToggle.addEventListener('click', () => {
    const next = document.documentElement.getAttribute('data-theme') === 'light' ? 'dark' : 'light';
    applyTheme(next);
  });

  function init() {
    applyTheme(document.documentElement.getAttribute('data-theme') || 'dark');
    populateSectorDropdowns();
    renderKpiTable();
    renderClaimsTable();
    renderSourcesTable();
    renderEvidenceTable();
    renderThreatMatrix();
    renderResponseTable();
    renderBriefing();

    // Update initial summary stat numbers from real data
    document.getElementById('stat-total-kpis').textContent = DATA.kpis.length;
    document.getElementById('stat-kpis-with-claims').textContent = DATA.kpis.filter(k => k.claim_count > 0).length;
    document.getElementById('stat-kpis-unassessed').textContent = DATA.kpis.filter(k => k.claim_count === 0).length;
    document.getElementById('stat-total-claims').textContent = DATA.inventory.length;
    document.getElementById('stat-total-evidence').textContent = DATA.evidence.length;
  }

  // Run on DOM loaded
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }

})();
