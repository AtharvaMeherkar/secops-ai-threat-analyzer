document.addEventListener('DOMContentLoaded', () => {
    const form = document.getElementById('scan-form');
    const input = document.getElementById('target-url');
    const scanBtn = document.getElementById('scan-btn');
    const loader = document.getElementById('loader');
    const loaderText = document.getElementById('loader-text');
    const errorMsg = document.getElementById('error-message');
    const resultsPanel = document.getElementById('results-panel');

    let trafficChartInstance = null;
    let trendChartInstance = null;

    const phases = [
        "Initializing AI Models...",
        "Validating Network Topology...",
        "Dispatching Concurrent Threads...",
        "Analyzing DOM Reflection Trees...",
        "Calculating Risk Matrices...",
        "Compiling Security Report..."
    ];

    form.addEventListener('submit', async (e) => {
        e.preventDefault();
        const url = input.value.trim();
        if (!url) return;

        // Reset UI state
        errorMsg.classList.add('hidden');
        resultsPanel.classList.add('hidden');
        loader.classList.remove('hidden');
        scanBtn.disabled = true;

        // Animate Loader Text
        let phaseIdx = 0;
        const phaseInterval = setInterval(() => {
            phaseIdx = (phaseIdx + 1) % phases.length;
            loaderText.innerText = phases[phaseIdx];
        }, 800);

        try {
            const response = await fetch('/api/scan', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ url: url })
            });

            const data = await response.json();
            clearInterval(phaseInterval);

            if (data.status === 'success') {
                renderResults(data.report);
            } else {
                showError(data.message);
            }
        } catch (err) {
            clearInterval(phaseInterval);
            showError("A network or server error occurred.");
            console.error(err);
        } finally {
            loader.classList.add('hidden');
            scanBtn.disabled = false;
            loaderText.innerText = "Initializing AI Models...";
        }
    });

    function showError(msg) {
        errorMsg.innerText = msg;
        errorMsg.classList.remove('hidden');
    }

    function renderResults(report) {
        const score = report.executive_summary.risk_score;
        const level = report.executive_summary.risk_level;
        
        const scoreVal = document.getElementById('risk-score-value');
        const levelVal = document.getElementById('threat-level-value');
        
        scoreVal.innerText = score;
        levelVal.innerText = level;

        // Map colors
        scoreVal.className = '';
        levelVal.className = 'level-indicator';
        
        let riskClass = 'risk-low';
        if(level === 'CRITICAL') riskClass = 'risk-critical';
        else if(level === 'HIGH') riskClass = 'risk-high';
        else if(level === 'MEDIUM') riskClass = 'risk-medium';
        
        scoreVal.classList.add(riskClass);
        levelVal.classList.add(riskClass);

        // Recommendations
        const recList = document.getElementById('recommendations-list');
        recList.innerHTML = '';
        if(report.advisories.length === 0) {
            recList.innerHTML = '<li>System is optimally configured.</li>';
        } else {
            report.advisories.forEach(adv => {
                const li = document.createElement('li');
                li.innerText = adv;
                recList.appendChild(li);
            });
        }

        // Terminal Logs
        const termBox = document.getElementById('logs-terminal');
        termBox.innerHTML = '';
        report.detailed_logs.forEach(log => {
            const div = document.createElement('div');
            div.className = 'term-line';
            const time = new Date(log.timestamp).toLocaleTimeString();
            const cssClass = "lvl-" + log.classification.replace(/\s+/g, '');
            // Highlight explicit DOM reflections distinctly
            const domFlag = log.detected_flags.includes("XSS_DOM_REFLECTION_VERIFIED") ? " <span style='color:#ef4444'>[XSS REFLECTED]</span>" : "";
            div.innerHTML = `[${time}] <span class="${cssClass}">${log.classification}</span> | Payload: ${log.payload} | Status: ${log.status_code}${domFlag}`;
            termBox.appendChild(div);
        });

        // Feature 2: ChartJS Doughnut drawing
        updateTrafficChart(report.executive_summary.threat_breakdown || {});

        resultsPanel.classList.remove('hidden');
    }

    function updateTrafficChart(breakdown) {
        const chartelem = document.getElementById('trafficChart');
        if (!chartelem) return; // Prevent crash if browser cached older HTML
        
        const ctx = chartelem.getContext('2d');
        if (trafficChartInstance) trafficChartInstance.destroy();
        
        trafficChartInstance = new Chart(ctx, {
            type: 'doughnut',
            data: {
                labels: ['Normal', 'Suspicious', 'High Risk'],
                datasets: [{
                    data: [breakdown['Normal'] || 0, breakdown['Suspicious'] || 0, breakdown['High Risk'] || 0],
                    backgroundColor: ['#10b981', '#facc15', '#ef4444'],
                    borderWidth: 0
                }]
            },
            options: { maintainAspectRatio: false, plugins: { legend: { position: 'bottom', labels: { color: 'white' } } } }
        });
    }

    // SPA Navigation Logic
    const navItems = document.querySelectorAll('.nav-item');
    const viewSections = document.querySelectorAll('.view-section');

    navItems.forEach(item => {
        item.addEventListener('click', () => {
            navItems.forEach(n => n.classList.remove('active'));
            item.classList.add('active');

            const targetId = item.getAttribute('data-target');
            viewSections.forEach(section => {
                if (section.id === targetId) {
                    section.classList.remove('hidden');
                } else {
                    section.classList.add('hidden');
                }
            });

            if (targetId === 'view-reports') loadReports();
            if (targetId === 'view-intelligence') loadIntelligence();
        });
    });

    async function loadReports() {
        try {
            const res = await fetch('/api/reports');
            const data = await res.json();
            const tbody = document.querySelector('#reports-table tbody');
            tbody.innerHTML = '';
            
            data.forEach(rep => {
                const tr = document.createElement('tr');
                tr.innerHTML = `
                    <td>${rep.target}</td>
                    <td>${new Date(rep.scan_time).toLocaleString()}</td>
                    <td>${rep.risk_score}</td>
                    <td><span class="risk-${rep.risk_level.toLowerCase()}">${rep.risk_level}</span></td>
                `;
                tbody.appendChild(tr);
            });

            // Feature 2: ChartJS Trendline Data Generation
            const scores = data.map(r => r.risk_score).reverse();
            const dates = data.map(r => new Date(r.scan_time).toLocaleDateString()).reverse();
            
            const ctx = document.getElementById('trendChart').getContext('2d');
            if (trendChartInstance) trendChartInstance.destroy();
            
            trendChartInstance = new Chart(ctx, {
                type: 'line',
                data: {
                    labels: dates,
                    datasets: [{
                        label: 'Threat Execution Risk Score',
                        data: scores,
                        borderColor: '#00ffcc',
                        backgroundColor: 'rgba(0, 255, 204, 0.1)',
                        tension: 0.3,
                        fill: true
                    }]
                },
                options: {
                    maintainAspectRatio: false,
                    scales: {
                        y: { min: 0, max: 100, ticks: { color: '#ccc' } },
                        x: { ticks: { color: '#ccc' } }
                    },
                    plugins: { legend: { labels: { color: 'white' } } }
                }
            });

        } catch(e) { console.error("Error loading reports", e); }
    }

    async function loadIntelligence() {
        try {
            const res = await fetch('/api/intelligence');
            const data = await res.json();
            const tbody = document.querySelector('#intel-table tbody');
            tbody.innerHTML = '';
            data.forEach(item => {
                const tr = document.createElement('tr');
                tr.innerHTML = `
                    <td>${item.id}</td>
                    <td>${item.threat}</td>
                    <td><span class="risk-${item.severity.toLowerCase()}">${item.severity}</span></td>
                    <td>${item.active ? 'Active Tracking' : 'Mitigated'}</td>
                `;
                tbody.appendChild(tr);
            });
        } catch(e) { console.error("Error loading intel", e); }
    }

    // Feature 1: Export PDF
    document.getElementById('export-pdf-btn').addEventListener('click', () => {
        const element = document.getElementById('pdf-content-wrapper');
        const opt = {
          margin:       0.5,
          filename:     'SecOpsAI_Architectural_Report.pdf',
          image:        { type: 'jpeg', quality: 0.98 },
          html2canvas:  { scale: 2, useCORS: true },
          jsPDF:        { unit: 'in', format: 'letter', orientation: 'portrait' }
        };
        // Use html2pdf local scope provided by CDN
        html2pdf().set(opt).from(element).save();
    });
});
