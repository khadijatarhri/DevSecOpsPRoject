const fs = require('fs');
const path = require('path');
const { exec } = require('child_process');
const util = require('util');

const execPromise = util.promisify(exec);

// ============================================
// CONFIGURATION
// ============================================
const OLLAMA_MODEL = 'llama3.2:3b';
const REPORTS_DIR = path.join(__dirname, '../security-reports');
const OUTPUT_DIR = path.join(__dirname, '../ai-analysis');

// ============================================
// 1. PARSER SAST (CodeQL - JSON/SARIF)
// ============================================
function parseSAST(sarifPath) {
    console.log('📊 Parsing SAST report...');
    
    if (!fs.existsSync(sarifPath)) {
        return { vulnerabilities: [], summary: 'No SAST report found' };
    }

    const sarif = JSON.parse(fs.readFileSync(sarifPath, 'utf8'));
    const results = sarif.runs?.[0]?.results || [];
    
    const vulnerabilities = results.map(result => ({
        type: 'SAST',
        severity: result.level || 'unknown',
        rule: result.ruleId || 'unknown',
        message: result.message?.text || 'No description',
        location: result.locations?.[0]?.physicalLocation?.artifactLocation?.uri || 'unknown',
        line: result.locations?.[0]?.physicalLocation?.region?.startLine || 0
    }));

    const summary = {
        total: vulnerabilities.length,
        critical: vulnerabilities.filter(v => v.severity === 'error').length,
        high: vulnerabilities.filter(v => v.severity === 'warning').length,
        medium: vulnerabilities.filter(v => v.severity === 'note').length
    };

    return { vulnerabilities, summary };
}

// ============================================
// 2. PARSER SCA (npm audit - JSON)
// ============================================
function parseSCA(auditPath) {
    console.log('📦 Parsing SCA report...');
    
    if (!fs.existsSync(auditPath)) {
        return { vulnerabilities: [], summary: 'No SCA report found' };
    }

    const audit = JSON.parse(fs.readFileSync(auditPath, 'utf8'));
    const vulns = audit.vulnerabilities || {};
    
    const vulnerabilities = Object.entries(vulns).map(([pkg, data]) => ({
        type: 'SCA',
        package: pkg,
        severity: data.severity || 'unknown',
        title: data.via?.[0]?.title || 'Dependency vulnerability',
        range: data.range || 'unknown',
        fixAvailable: data.fixAvailable ? 'Yes' : 'No'
    }));

    const summary = {
        total: vulnerabilities.length,
        critical: vulnerabilities.filter(v => v.severity === 'critical').length,
        high: vulnerabilities.filter(v => v.severity === 'high').length,
        moderate: vulnerabilities.filter(v => v.severity === 'moderate').length,
        low: vulnerabilities.filter(v => v.severity === 'low').length
    };

    return { vulnerabilities, summary };
}

// ============================================
// 3. PARSER DAST (OWASP ZAP - JSON)
// ============================================
function parseDAST(zapPath) {
    console.log('🌐 Parsing DAST report...');
    
    if (!fs.existsSync(zapPath)) {
        return { vulnerabilities: [], summary: 'No DAST report found' };
    }

    const zap = JSON.parse(fs.readFileSync(zapPath, 'utf8'));
    const alerts = zap.site?.[0]?.alerts || [];
    
    const vulnerabilities = alerts.map(alert => ({
        type: 'DAST',
        name: alert.name || 'Unknown',
        risk: alert.risk || 'unknown',
        confidence: alert.confidence || 'unknown',
        description: alert.desc || 'No description',
        solution: alert.solution || 'No solution provided',
        instances: alert.instances?.length || 0
    }));

    const summary = {
        total: vulnerabilities.length,
        high: vulnerabilities.filter(v => v.risk === 'High').length,
        medium: vulnerabilities.filter(v => v.risk === 'Medium').length,
        low: vulnerabilities.filter(v => v.risk === 'Low').length,
        info: vulnerabilities.filter(v => v.risk === 'Informational').length
    };

    return { vulnerabilities, summary };
}

// ============================================
// 4. GÉNÉRER LE PROMPT POUR LLAMA
// ============================================
function generatePrompt(sastData, scaData, dastData) {
    const prompt = `You are a cybersecurity expert analyzing security scan results for ISO 27017, ISO 27034, and ISO 27005 compliance.

### SECURITY SCAN RESULTS:

**SAST Analysis (CodeQL):**
- Total Issues: ${sastData.summary.total}
- Critical: ${sastData.summary.critical}
- High: ${sastData.summary.high}
- Medium: ${sastData.summary.medium}

Top 3 SAST Issues:
${sastData.vulnerabilities.slice(0, 3).map((v, i) => 
    `${i + 1}. [${v.severity.toUpperCase()}] ${v.rule}: ${v.message.substring(0, 100)}`
).join('\n')}

**SCA Analysis (npm audit):**
- Total Vulnerabilities: ${scaData.summary.total}
- Critical: ${scaData.summary.critical}
- High: ${scaData.summary.high}
- Moderate: ${scaData.summary.moderate}

Top 3 SCA Issues:
${scaData.vulnerabilities.slice(0, 3).map((v, i) => 
    `${i + 1}. [${v.severity.toUpperCase()}] ${v.package}: ${v.title}`
).join('\n')}

**DAST Analysis (OWASP ZAP):**
- Total Alerts: ${dastData.summary.total}
- High Risk: ${dastData.summary.high}
- Medium Risk: ${dastData.summary.medium}
- Low Risk: ${dastData.summary.low}

Top 3 DAST Issues:
${dastData.vulnerabilities.slice(0, 3).map((v, i) => 
    `${i + 1}. [${v.risk.toUpperCase()}] ${v.name}: ${v.description.substring(0, 100)}`
).join('\n')}

### YOUR TASK:
Provide a **concise security assessment** (max 500 words) covering:

1. **Risk Overview**: Overall security posture
2. **ISO Compliance**: Map findings to ISO 27017/27034/27005 controls
3. **Priority Actions**: Top 5 remediation steps (ordered by risk)
4. **Compliance Score**: Estimated compliance percentage for each ISO standard

Format: Clear bullet points, actionable recommendations.`;

    return prompt;
}

// ============================================
// 5. APPELER LLAMA POUR L'ANALYSE
// ============================================
async function analyzeWithLlama(prompt) {
    console.log('🤖 Analyzing with Llama AI...');
    
    try {
        // Échapper les guillemets dans le prompt
        const escapedPrompt = prompt.replace(/"/g, '\\"').replace(/\n/g, ' ');
        
        const { stdout } = await execPromise(
            `ollama run ${OLLAMA_MODEL} "${escapedPrompt}"`
        );
        
        return stdout.trim();
    } catch (error) {
        console.error('❌ Llama analysis failed:', error.message);
        return 'AI analysis unavailable. Please check Ollama installation.';
    }
}

// ============================================
// 6. GÉNÉRER LE RAPPORT FINAL HTML
// ============================================
function generateHTMLReport(sastData, scaData, dastData, aiAnalysis) {
    console.log('📄 Generating HTML report...');
    
    const html = `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>AI-Powered DevSecOps Security Report</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            padding: 20px;
            line-height: 1.6;
        }
        .container {
            max-width: 1200px;
            margin: 0 auto;
            background: white;
            border-radius: 15px;
            box-shadow: 0 20px 60px rgba(0,0,0,0.3);
            overflow: hidden;
        }
        .header {
            background: linear-gradient(135deg, #1e3c72 0%, #2a5298 100%);
            color: white;
            padding: 40px;
            text-align: center;
        }
        .header h1 {
            font-size: 2.5em;
            margin-bottom: 10px;
            text-shadow: 2px 2px 4px rgba(0,0,0,0.3);
        }
        .header p {
            font-size: 1.2em;
            opacity: 0.9;
        }
        .content {
            padding: 40px;
        }
        .section {
            margin-bottom: 40px;
            border-left: 4px solid #667eea;
            padding-left: 20px;
        }
        .section h2 {
            color: #1e3c72;
            margin-bottom: 20px;
            font-size: 1.8em;
        }
        .stats {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 20px;
            margin: 30px 0;
        }
        .stat-card {
            background: linear-gradient(135deg, #f5f7fa 0%, #c3cfe2 100%);
            padding: 25px;
            border-radius: 10px;
            box-shadow: 0 4px 6px rgba(0,0,0,0.1);
            transition: transform 0.3s;
        }
        .stat-card:hover {
            transform: translateY(-5px);
        }
        .stat-card h3 {
            color: #667eea;
            font-size: 1.2em;
            margin-bottom: 10px;
        }
        .stat-number {
            font-size: 2.5em;
            font-weight: bold;
            color: #1e3c72;
        }
        .severity {
            display: inline-block;
            padding: 5px 15px;
            border-radius: 20px;
            font-weight: bold;
            margin: 5px;
        }
        .critical { background: #ff4757; color: white; }
        .high { background: #ff6348; color: white; }
        .medium { background: #ffa502; color: white; }
        .low { background: #26de81; color: white; }
        .ai-analysis {
            background: linear-gradient(135deg, #e0c3fc 0%, #8ec5fc 100%);
            padding: 30px;
            border-radius: 10px;
            margin: 30px 0;
            white-space: pre-wrap;
            line-height: 1.8;
        }
        .footer {
            background: #f5f7fa;
            padding: 20px;
            text-align: center;
            color: #666;
        }
        table {
            width: 100%;
            border-collapse: collapse;
            margin: 20px 0;
        }
        th, td {
            padding: 12px;
            text-align: left;
            border-bottom: 1px solid #ddd;
        }
        th {
            background: #667eea;
            color: white;
        }
        tr:hover {
            background: #f5f7fa;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🛡️ AI-Powered DevSecOps Security Report</h1>
            <p>Intelligent Security Analysis with ISO Compliance Mapping</p>
            <p style="font-size: 0.9em; margin-top: 10px;">Generated: ${new Date().toLocaleString()}</p>
        </div>

        <div class="content">
            <!-- SUMMARY SECTION -->
            <div class="section">
                <h2>📊 Executive Summary</h2>
                <div class="stats">
                    <div class="stat-card">
                        <h3>SAST Issues</h3>
                        <div class="stat-number">${sastData.summary.total}</div>
                        <div>
                            <span class="severity critical">Critical: ${sastData.summary.critical}</span>
                            <span class="severity high">High: ${sastData.summary.high}</span>
                        </div>
                    </div>
                    <div class="stat-card">
                        <h3>SCA Vulnerabilities</h3>
                        <div class="stat-number">${scaData.summary.total}</div>
                        <div>
                            <span class="severity critical">Critical: ${scaData.summary.critical}</span>
                            <span class="severity high">High: ${scaData.summary.high}</span>
                        </div>
                    </div>
                    <div class="stat-card">
                        <h3>DAST Alerts</h3>
                        <div class="stat-number">${dastData.summary.total}</div>
                        <div>
                            <span class="severity high">High: ${dastData.summary.high}</span>
                            <span class="severity medium">Medium: ${dastData.summary.medium}</span>
                        </div>
                    </div>
                </div>
            </div>

            <!-- AI ANALYSIS SECTION -->
            <div class="section">
                <h2>🤖 AI-Powered Analysis & Recommendations</h2>
                <div class="ai-analysis">
${aiAnalysis}
                </div>
            </div>

            <!-- DETAILED FINDINGS -->
            <div class="section">
                <h2>🔍 Top Security Findings</h2>
                
                <h3 style="color: #667eea; margin-top: 20px;">SAST (Static Analysis)</h3>
                <table>
                    <thead>
                        <tr>
                            <th>Severity</th>
                            <th>Rule</th>
                            <th>Location</th>
                            <th>Description</th>
                        </tr>
                    </thead>
                    <tbody>
                        ${sastData.vulnerabilities.slice(0, 10).map(v => `
                        <tr>
                            <td><span class="severity ${v.severity}">${v.severity.toUpperCase()}</span></td>
                            <td>${v.rule}</td>
                            <td>${v.location}:${v.line}</td>
                            <td>${v.message.substring(0, 100)}...</td>
                        </tr>
                        `).join('')}
                    </tbody>
                </table>

                <h3 style="color: #667eea; margin-top: 30px;">SCA (Dependencies)</h3>
                <table>
                    <thead>
                        <tr>
                            <th>Severity</th>
                            <th>Package</th>
                            <th>Issue</th>
                            <th>Fix Available</th>
                        </tr>
                    </thead>
                    <tbody>
                        ${scaData.vulnerabilities.slice(0, 10).map(v => `
                        <tr>
                            <td><span class="severity ${v.severity}">${v.severity.toUpperCase()}</span></td>
                            <td>${v.package}</td>
                            <td>${v.title.substring(0, 80)}...</td>
                            <td>${v.fixAvailable}</td>
                        </tr>
                        `).join('')}
                    </tbody>
                </table>

                <h3 style="color: #667eea; margin-top: 30px;">DAST (Runtime Analysis)</h3>
                <table>
                    <thead>
                        <tr>
                            <th>Risk</th>
                            <th>Alert</th>
                            <th>Instances</th>
                            <th>Confidence</th>
                        </tr>
                    </thead>
                    <tbody>
                        ${dastData.vulnerabilities.slice(0, 10).map(v => `
                        <tr>
                            <td><span class="severity ${v.risk.toLowerCase()}">${v.risk}</span></td>
                            <td>${v.name}</td>
                            <td>${v.instances}</td>
                            <td>${v.confidence}</td>
                        </tr>
                        `).join('')}
                    </tbody>
                </table>
            </div>
        </div>

        <div class="footer">
            <p><strong>DevSecOps Pipeline</strong> | Powered by AI (Llama 3.2) | ISO 27017/27034/27005 Compliance</p>
        </div>
    </div>
</body>
</html>`;

    return html;
}

// ============================================
// 7. FONCTION PRINCIPALE
// ============================================
async function main() {
    console.log('\n🚀 Starting AI-Powered Security Analysis...\n');
    
    // Créer les dossiers si nécessaire
    if (!fs.existsSync(OUTPUT_DIR)) {
        fs.mkdirSync(OUTPUT_DIR, { recursive: true });
    }

    // Définir les chemins des rapports
    const sastPath = process.argv[2] || path.join(REPORTS_DIR, 'codeql-results.sarif');
    const scaPath = process.argv[3] || path.join(REPORTS_DIR, 'audit-report.json');
    const dastPath = process.argv[4] || path.join(REPORTS_DIR, 'report_json.json');

    // Parser les rapports
    const sastData = parseSAST(sastPath);
    const scaData = parseSCA(scaPath);
    const dastData = parseDAST(dastPath);

    console.log(`✅ SAST: ${sastData.summary.total} issues found`);
    console.log(`✅ SCA: ${scaData.summary.total} vulnerabilities found`);
    console.log(`✅ DAST: ${dastData.summary.total} alerts found\n`);

    // Générer le prompt et analyser avec Llama
    const prompt = generatePrompt(sastData, scaData, dastData);
    const aiAnalysis = await analyzeWithLlama(prompt);

    // Générer le rapport HTML
    const htmlReport = generateHTMLReport(sastData, scaData, dastData, aiAnalysis);
    const reportPath = path.join(OUTPUT_DIR, 'ai-security-report.html');
    fs.writeFileSync(reportPath, htmlReport);

    console.log(`\n✅ AI Analysis Complete!`);
    console.log(`📄 Report generated: ${reportPath}`);
    console.log(`\n🌐 Open the report in your browser to view the results.\n`);
}

// Exécuter
if (require.main === module) {
    main().catch(console.error);
}

module.exports = { parseSAST, parseSCA, parseDAST, generatePrompt, analyzeWithLlama };

