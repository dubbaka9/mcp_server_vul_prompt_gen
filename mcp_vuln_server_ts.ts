/**
 * MCP Server for Interactive Vulnerability Prompt Generation (TypeScript)
 * Coordinates user interaction and integrates with FastAPI service
 */

import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
  Tool,
  TextContent,
  CallToolResult,
  ListToolsResult,
} from '@modelcontextprotocol/sdk/types.js';
import axios, { AxiosInstance } from 'axios';
import * as fs from 'fs';
import * as path from 'path';

// Types for vulnerability data
interface VulnerabilityData {
  issueId?: number;
  issueld?: number; // Handle typo in JSON
  issueName: string;
  filePath: string;
  lineNumber?: number;
  LineNumber?: number; // Handle case inconsistency
  priority: string;
  currentVersion?: string | null;
  upgradeVersion?: string | null;
  recommendation: string;
  analysisTrace: string[];
  status: string;
  code_context?: string; // For storing user-provided code context
}

interface VulnerabilityFile {
  title: string;
  summary: string;
  table: VulnerabilityData[];
}

interface GitLabConfig {
  repo_url: string;
  jira_ticket: string;
  base_branch: string;
  user_id?: string;
}

interface NormalizedVulnerability {
  issueId: number;
  issueName: string;
  filePath: string;
  lineNumber: number;
  priority: string;
  recommendation: string;
  analysisTrace: string[];
  status: string;
  code_context?: string;
}

// Session state management
class SessionState {
  public vulnerabilities: VulnerabilityData[] = [];
  public gitlab_config: GitLabConfig | null = null;
  public selected_vulnerabilities: VulnerabilityData[] = [];
  public api_base_url: string = process.env.API_BASE_URL || 'http://localhost:8000';
  public current_step: string = 'initial';
  public session_id: string;
  private api_client: AxiosInstance;

  constructor() {
    this.session_id = new Date().toISOString().replace(/[-:]/g, '').split('T')[0] + '_' + 
                     new Date().toTimeString().split(' ')[0].replace(/:/g, '');
    
    this.api_client = axios.create({
      baseURL: this.api_base_url,
      timeout: 30000,
      headers: {
        'Content-Type': 'application/json',
        'User-Agent': 'VulnPromptGenerator-MCP/1.0'
      }
    });

    // Setup axios interceptors
    this.api_client.interceptors.request.use(
      (config) => {
        console.log(`🌐 API Request: ${config.method?.toUpperCase()} ${config.url}`);
        return config;
      },
      (error) => {
        console.error('❌ Request Error:', error.message);
        return Promise.reject(error);
      }
    );

    this.api_client.interceptors.response.use(
      (response) => {
        console.log(`✅ API Response: ${response.status} ${response.statusText}`);
        return response;
      },
      (error) => {
        if (error.response) {
          console.error(`❌ API Error: ${error.response.status} - ${JSON.stringify(error.response.data)}`);
        } else if (error.request) {
          console.error('❌ Network Error: No response received');
        } else {
          console.error('❌ Error:', error.message);
        }
        return Promise.reject(error);
      }
    );
  }

  reset(): void {
    const oldSessionId = this.session_id;
    this.vulnerabilities = [];
    this.gitlab_config = null;
    this.selected_vulnerabilities = [];
    this.current_step = 'initial';
    this.session_id = new Date().toISOString().replace(/[-:]/g, '').split('T')[0] + '_' + 
                     new Date().toTimeString().split(' ')[0].replace(/:/g, '');
    console.log(`🔄 Session reset: ${oldSessionId} -> ${this.session_id}`);
  }

  async healthCheck(): Promise<boolean> {
    try {
      const response = await this.api_client.get('/health');
      return response.status === 200;
    } catch (error) {
      return false;
    }
  }

  async callApi(endpoint: string, method: 'GET' | 'POST' = 'POST', data?: any): Promise<any> {
    try {
      if (method === 'GET') {
        const response = await this.api_client.get(endpoint);
        return response.data;
      } else {
        const response = await this.api_client.post(endpoint, data);
        return response.data;
      }
    } catch (error) {
      console.error(`API call failed: ${endpoint}`, error);
      throw error;
    }
  }
}

const session = new SessionState();

// MCP Server setup
const server = new Server(
  {
    name: 'vulnerability-prompt-generator',
    version: '1.0.0',
  },
  {
    capabilities: {
      tools: {},
    },
  }
);

// Tool definitions
const tools: Tool[] = [
  {
    name: 'load_vulnerabilities',
    description: 'Load vulnerabilities from a JSON file',
    inputSchema: {
      type: 'object',
      properties: {
        file_path: {
          type: 'string',
          description: 'Path to the vulnerability JSON file',
        },
      },
      required: ['file_path'],
    },
  },
  {
    name: 'configure_gitlab',
    description: 'Configure GitLab settings for the vulnerability fix workflow',
    inputSchema: {
      type: 'object',
      properties: {
        repo_url: {
          type: 'string',
          description: 'GitLab repository URL',
        },
        jira_ticket: {
          type: 'string',
          description: 'JIRA ticket number (e.g., SEC-2024)',
        },
        base_branch: {
          type: 'string',
          description: 'Base branch name',
          default: 'develop',
        },
        user_id: {
          type: 'string',
          description: 'GitLab user ID for MR assignment (optional)',
        },
      },
      required: ['repo_url', 'jira_ticket'],
    },
  },
  {
    name: 'analyze_vulnerabilities',
    description: 'Analyze loaded vulnerabilities and show summary',
    inputSchema: {
      type: 'object',
      properties: {},
      required: [],
    },
  },
  {
    name: 'select_vulnerability',
    description: 'Select a vulnerability for prompt generation',
    inputSchema: {
      type: 'object',
      properties: {
        issue_id: {
          type: 'integer',
          description: 'Issue ID of the vulnerability to select',
        },
        code_context: {
          type: 'string',
          description: 'Code context around the vulnerability (optional)',
        },
      },
      required: ['issue_id'],
    },
  },
  {
    name: 'generate_single_prompt',
    description: 'Generate an enhanced prompt for a single vulnerability',
    inputSchema: {
      type: 'object',
      properties: {
        issue_id: {
          type: 'integer',
          description: 'Issue ID of the vulnerability',
        },
        enhancement_level: {
          type: 'string',
          enum: ['basic', 'standard', 'advanced'],
          default: 'standard',
          description: 'Level of prompt enhancement',
        },
        use_chain_of_thought: {
          type: 'boolean',
          default: false,
          description: 'Use chain-of-thought prompting',
        },
        code_context: {
          type: 'string',
          description: 'Code context around the vulnerability',
        },
      },
      required: ['issue_id'],
    },
  },
  {
    name: 'generate_batch_prompts',
    description: 'Generate prompts for all selected vulnerabilities',
    inputSchema: {
      type: 'object',
      properties: {
        enhancement_level: {
          type: 'string',
          enum: ['basic', 'standard', 'advanced'],
          default: 'standard',
        },
        use_chain_of_thought: {
          type: 'boolean',
          default: false,
        },
        save_to_files: {
          type: 'boolean',
          default: true,
          description: 'Save prompts to files',
        },
        output_directory: {
          type: 'string',
          default: 'vulnerability_prompts',
          description: 'Output directory for saved prompts',
        },
      },
      required: [],
    },
  },
  {
    name: 'show_session_status',
    description: 'Show current session status and selected vulnerabilities',
    inputSchema: {
      type: 'object',
      properties: {},
      required: [],
    },
  },
  {
    name: 'reset_session',
    description: 'Reset the current session and start over',
    inputSchema: {
      type: 'object',
      properties: {},
      required: [],
    },
  },
];

// Tool handlers
server.setRequestHandler(ListToolsRequestSchema, async (): Promise<ListToolsResult> => {
  return { tools };
});

server.setRequestHandler(CallToolRequestSchema, async (request): Promise<CallToolResult> => {
  const { name, arguments: args } = request.params;

  try {
    switch (name) {
      case 'load_vulnerabilities':
        return { content: await loadVulnerabilities(args.file_path as string) };

      case 'configure_gitlab':
        return { content: await configureGitlab(args as GitLabConfig) };

      case 'analyze_vulnerabilities':
        return { content: await analyzeVulnerabilities() };

      case 'select_vulnerability':
        return { 
          content: await selectVulnerability(
            args.issue_id as number, 
            args.code_context as string || ''
          ) 
        };

      case 'generate_single_prompt':
        return { content: await generateSinglePrompt(args) };

      case 'generate_batch_prompts':
        return { content: await generateBatchPrompts(args) };

      case 'show_session_status':
        return { content: await showSessionStatus() };

      case 'reset_session':
        return { content: await resetSession() };

      default:
        throw new Error(`Unknown tool: ${name}`);
    }
  } catch (error) {
    const errorMessage = error instanceof Error ? error.message : String(error);
    return {
      content: [
        {
          type: 'text',
          text: `❌ Error executing ${name}: ${errorMessage}`,
        },
      ],
    };
  }
});

// Tool implementation functions

async function loadVulnerabilities(filePath: string): Promise<TextContent[]> {
  try {
    if (!fs.existsSync(filePath)) {
      return [
        {
          type: 'text',
          text: `❌ File not found: ${filePath}`,
        },
      ];
    }

    const rawData = fs.readFileSync(filePath, 'utf-8');
    const data: VulnerabilityFile = JSON.parse(rawData);

    session.vulnerabilities = data.table || [];
    session.current_step = 'loaded';

    // Analyze the loaded vulnerabilities via API
    try {
      const analysis = await session.callApi('/analyze-vulnerabilities', 'POST', data);

      let resultText = `✅ Successfully loaded ${session.vulnerabilities.length} vulnerabilities from ${filePath}\n\n`;
      resultText += `📊 **Vulnerability Analysis:**\n`;
      resultText += `- Total vulnerabilities: ${analysis.vulnerability_count}\n\n`;

      resultText += `**By Priority:**\n`;
      for (const [priority, count] of Object.entries(analysis.priorities)) {
        resultText += `  - ${priority}: ${count}\n`;
      }

      resultText += `\n**By Type:**\n`;
      for (const [vulnType, count] of Object.entries(analysis.vulnerability_types)) {
        resultText += `  - ${vulnType}: ${count}\n`;
      }

      resultText += `\n**Files Affected:** ${analysis.files_affected.length}\n\n`;
      resultText += `🔄 **Next Steps:**\n`;
      resultText += `1. Configure GitLab settings using \`configure_gitlab\`\n`;
      resultText += `2. Select vulnerabilities using \`select_vulnerability\`\n`;
      resultText += `3. Generate prompts using \`generate_single_prompt\` or \`generate_batch_prompts\`\n`;

      return [{ type: 'text', text: resultText }];
    } catch (apiError) {
      return [
        {
          type: 'text',
          text: `✅ Loaded ${session.vulnerabilities.length} vulnerabilities, but API analysis failed: ${apiError}`,
        },
      ];
    }
  } catch (error) {
    const errorMessage = error instanceof Error ? error.message : String(error);
    return [
      {
        type: 'text',
        text: `❌ Failed to load vulnerabilities: ${errorMessage}`,
      },
    ];
  }
}

async function configureGitlab(config: GitLabConfig): Promise<TextContent[]> {
  try {
    session.gitlab_config = {
      repo_url: config.repo_url,
      jira_ticket: config.jira_ticket,
      base_branch: config.base_branch || 'develop',
      user_id: config.user_id,
    };
    session.current_step = 'configured';

    let resultText = `✅ **GitLab Configuration Set:**\n\n`;
    resultText += `🔗 **Repository:** ${session.gitlab_config.repo_url}\n`;
    resultText += `🎫 **JIRA Ticket:** ${session.gitlab_config.jira_ticket}\n`;
    resultText += `🌿 **Base Branch:** ${session.gitlab_config.base_branch}\n`;
    resultText += `👤 **User ID:** ${session.gitlab_config.user_id || 'Not specified'}\n\n`;
    resultText += `🔄 **Next Steps:**\n`;
    resultText += `- Select vulnerabilities to fix using \`select_vulnerability\`\n`;
    resultText += `- Or analyze vulnerabilities first with \`analyze_vulnerabilities\`\n`;

    return [{ type: 'text', text: resultText }];
  } catch (error) {
    const errorMessage = error instanceof Error ? error.message : String(error);
    return [
      {
        type: 'text',
        text: `❌ Failed to configure GitLab: ${errorMessage}`,
      },
    ];
  }
}

async function analyzeVulnerabilities(): Promise<TextContent[]> {
  if (session.vulnerabilities.length === 0) {
    return [
      {
        type: 'text',
        text: '❌ No vulnerabilities loaded. Use `load_vulnerabilities` first.',
      },
    ];
  }

  // Group vulnerabilities for display
  const byPriority: Record<string, any[]> = {};
  const byType: Record<string, number> = {};
  const byFile: Record<string, number> = {};

  session.vulnerabilities.forEach((vuln, i) => {
    const issueId = vuln.issueId || vuln.issueld;
    const priority = vuln.priority || 'Unknown';
    const vulnType = vuln.issueName || 'Unknown';
    const filePath = vuln.filePath || 'Unknown';
    const lineNum = vuln.lineNumber || vuln.LineNumber || 'Unknown';
    const status = vuln.status || 'Unknown';

    // Group by priority
    if (!byPriority[priority]) {
      byPriority[priority] = [];
    }
    byPriority[priority].push({
      index: i + 1,
      id: issueId,
      type: vulnType,
      file: filePath,
      line: lineNum,
      status: status,
    });

    // Count by type
    byType[vulnType] = (byType[vulnType] || 0) + 1;

    // Count by file
    byFile[filePath] = (byFile[filePath] || 0) + 1;
  });

  let resultText = `📊 **Detailed Vulnerability Analysis**\n\n`;
  resultText += `🔢 **Total:** ${session.vulnerabilities.length} vulnerabilities\n\n`;

  // Display by priority
  const priorityOrder = ['Critical', 'High', 'Medium', 'Low'];
  for (const priority of priorityOrder) {
    if (byPriority[priority]) {
      resultText += `🔴 **${priority} Priority (${byPriority[priority].length}):**\n`;
      for (const vuln of byPriority[priority]) {
        resultText += `  ${vuln.index}. [ID: ${vuln.id}] ${vuln.type}\n`;
        resultText += `     📁 ${vuln.file}:${vuln.line} | Status: ${vuln.status}\n`;
      }
      resultText += '\n';
    }
  }

  resultText += `📈 **Summary by Type:**\n`;
  for (const [vulnType, count] of Object.entries(byType).sort()) {
    resultText += `  - ${vulnType}: ${count}\n`;
  }

  resultText += `\n📁 **Files Most Affected:**\n`;
  const sortedFiles = Object.entries(byFile)
    .sort(([, a], [, b]) => b - a)
    .slice(0, 5); // Top 5

  for (const [filePath, count] of sortedFiles) {
    resultText += `  - ${filePath}: ${count} vulnerabilities\n`;
  }

  resultText += `\n🔄 **Next Steps:**\n`;
  resultText += `- Use \`select_vulnerability\` with an issue ID to select vulnerabilities\n`;
  resultText += `- Use \`generate_single_prompt\` to create a prompt for one vulnerability\n`;
  resultText += `- Use \`generate_batch_prompts\` to create prompts for all selected vulnerabilities\n`;

  return [{ type: 'text', text: resultText }];
}

async function selectVulnerability(issueId: number, codeContext: string = ''): Promise<TextContent[]> {
  if (session.vulnerabilities.length === 0) {
    return [
      {
        type: 'text',
        text: '❌ No vulnerabilities loaded. Use `load_vulnerabilities` first.',
      },
    ];
  }

  // Find the vulnerability
  let selectedVuln: VulnerabilityData | null = null;
  for (const vuln of session.vulnerabilities) {
    const vulnId = vuln.issueId || vuln.issueld;
    if (vulnId === issueId) {
      selectedVuln = vuln;
      break;
    }
  }

  if (!selectedVuln) {
    return [
      {
        type: 'text',
        text: `❌ Vulnerability with ID ${issueId} not found.`,
      },
    ];
  }

  // Add to selected list if not already there
  const isAlreadySelected = session.selected_vulnerabilities.some(
    (v) => (v.issueId || v.issueld) === issueId
  );

  let action: string;
  if (!isAlreadySelected) {
    if (codeContext) {
      selectedVuln.code_context = codeContext;
    }
    session.selected_vulnerabilities.push(selectedVuln);
    action = 'Added to';
  } else {
    action = 'Already in';
  }

  let resultText = `✅ **${action} selection:**\n\n`;
  resultText += `🔹 **Issue ID:** ${issueId}\n`;
  resultText += `🔹 **Type:** ${selectedVuln.issueName}\n`;
  resultText += `🔹 **Priority:** ${selectedVuln.priority}\n`;
  resultText += `🔹 **File:** ${selectedVuln.filePath}:${selectedVuln.lineNumber || selectedVuln.LineNumber}\n`;
  resultText += `🔹 **Status:** ${selectedVuln.status}\n`;
  resultText += codeContext
    ? `🔹 **Code Context:** Provided\n`
    : `🔹 **Code Context:** Not provided\n`;
  resultText += `\n📋 **Currently Selected:** ${session.selected_vulnerabilities.length} vulnerabilities\n\n`;
  resultText += `🔄 **Next Steps:**\n`;
  resultText += `- Select more vulnerabilities with \`select_vulnerability\`\n`;
  resultText += `- Generate prompt for this vulnerability with \`generate_single_prompt\`\n`;
  resultText += `- Generate prompts for all selected with \`generate_batch_prompts\`\n`;

  return [{ type: 'text', text: resultText }];
}

async function generateSinglePrompt(args: any): Promise<TextContent[]> {
  if (!session.gitlab_config) {
    return [
      {
        type: 'text',
        text: '❌ GitLab configuration required. Use `configure_gitlab` first.',
      },
    ];
  }

  const issueId = args.issue_id as number;

  // Find the vulnerability
  let vulnerability: VulnerabilityData | null = null;
  for (const vuln of session.vulnerabilities) {
    const vulnId = vuln.issueId || vuln.issueld;
    if (vulnId === issueId) {
      vulnerability = vuln;
      break;
    }
  }

  if (!vulnerability) {
    return [
      {
        type: 'text',
        text: `❌ Vulnerability with ID ${issueId} not found.`,
      },
    ];
  }

  try {
    // Prepare request for FastAPI
    const requestData = {
      vulnerability,
      gitlab_config: session.gitlab_config,
      code_context: args.code_context || '',
      use_chain_of_thought: args.use_chain_of_thought || false,
      enhancement_level: args.enhancement_level || 'standard',
    };

    const promptData = await session.callApi('/generate-prompt', 'POST', requestData);

    let resultText = `✅ **Prompt Generated Successfully**\n\n`;
    resultText += `🔹 **Issue ID:** ${issueId}\n`;
    resultText += `🔹 **Enhancement:** ${promptData.enhancement_used}\n`;
    resultText += `🔹 **Generation Time:** ${promptData.generation_time.toFixed(2)}s\n\n`;
    resultText += `📝 **Generated Prompt:**\n\`\`\`\n${promptData.prompt}\n\`\`\`\n\n`;
    resultText += `💾 **To save this prompt to a file, use \`generate_batch_prompts\` with \`save_to_files: true\`**\n`;

    return [{ type: 'text', text: resultText }];
  } catch (error) {
    const errorMessage = error instanceof Error ? error.message : String(error);
    return [
      {
        type: 'text',
        text: `❌ Error generating prompt: ${errorMessage}`,
      },
    ];
  }
}

async function generateBatchPrompts(args: any): Promise<TextContent[]> {
  if (session.selected_vulnerabilities.length === 0) {
    return [
      {
        type: 'text',
        text: '❌ No vulnerabilities selected. Use `select_vulnerability` first.',
      },
    ];
  }

  if (!session.gitlab_config) {
    return [
      {
        type: 'text',
        text: '❌ GitLab configuration required. Use `configure_gitlab` first.',
      },
    ];
  }

  try {
    // Prepare code contexts
    const codeContexts: Record<string, string> = {};
    for (const vuln of session.selected_vulnerabilities) {
      const issueId = String(vuln.issueId || vuln.issueld);
      if (vuln.code_context) {
        codeContexts[issueId] = vuln.code_context;
      }
    }

    // Prepare request for FastAPI
    const requestData = {
      vulnerabilities: session.selected_vulnerabilities,
      gitlab_config: session.gitlab_config,
      code_contexts: codeContexts,
      use_chain_of_thought: args.use_chain_of_thought || false,
      enhancement_level: args.enhancement_level || 'standard',
    };

    if (args.save_to_files !== false) {
      // Use save endpoint
      const saveData = await session.callApi(
        `/save-prompts?output_dir=${args.output_directory || 'vulnerability_prompts'}`,
        'POST',
        requestData
      );

      let resultText = `✅ **Batch Prompts Generated and Saved**\n\n`;
      resultText += `📁 **Output Directory:** ${args.output_directory || 'vulnerability_prompts'}\n`;
      resultText += `🔢 **Prompts Generated:** ${saveData.prompt_count}\n`;
      resultText += `⏱️ **Estimated Completion:** ${saveData.estimated_completion}\n\n`;

      resultText += `📋 **Selected Vulnerabilities:**\n`;
      for (const vuln of session.selected_vulnerabilities) {
        const issueId = vuln.issueId || vuln.issueld;
        resultText += `  - ${issueId}: ${vuln.issueName} (${vuln.priority})\n`;
      }

      resultText += `\n📂 **Files will be created:**\n`;
      for (const vuln of session.selected_vulnerabilities) {
        const issueId = vuln.issueId || vuln.issueld;
        resultText += `  - ${issueId}_prompt.txt\n`;
      }

      resultText += `  - fix_summary.md\n\n`;
      resultText += `🎉 **All prompts have been generated and saved to disk!**\n`;

      return [{ type: 'text', text: resultText }];
    } else {
      // Just generate without saving
      const batchData = await session.callApi('/generate-batch-prompts', 'POST', requestData);

      let resultText = `✅ **Batch Prompts Generated**\n\n`;
      resultText += `🔢 **Total Prompts:** ${Object.keys(batchData.prompts).length}\n`;
      resultText += `⏱️ **Generation Time:** ${batchData.total_generation_time.toFixed(2)}s\n\n`;

      resultText += `📊 **Summary:**\n`;
      for (const [priority, count] of Object.entries(batchData.summary.vulnerabilities_by_priority)) {
        resultText += `  - ${priority}: ${count}\n`;
      }

      resultText += `\n📝 **Generated Prompts:**\n`;
      for (const [issueId, promptData] of Object.entries(batchData.prompts) as [string, any][]) {
        resultText += `\n🔹 **Issue ${issueId}** (${promptData.enhancement_used}):\n`;
        resultText += `\`\`\`\n${promptData.prompt.substring(0, 300)}...\n\`\`\`\n`;
      }

      return [{ type: 'text', text: resultText }];
    }
  } catch (error) {
    const errorMessage = error instanceof Error ? error.message : String(error);
    return [
      {
        type: 'text',
        text: `❌ Error generating batch prompts: ${errorMessage}`,
      },
    ];
  }
}

async function showSessionStatus(): Promise<TextContent[]> {
  let statusText = `📊 **Session Status**\n\n`;
  statusText += `🆔 **Session ID:** ${session.session_id}\n`;
  statusText += `📅 **Current Step:** ${session.current_step}\n\n`;
  statusText += `📋 **Loaded Vulnerabilities:** ${session.vulnerabilities.length}\n`;
  statusText += `✅ **Selected Vulnerabilities:** ${session.selected_vulnerabilities.length}\n\n`;
  statusText += `🔧 **GitLab Configuration:**\n`;

  if (session.gitlab_config) {
    statusText += `  ✅ Configured\n`;
    statusText += `  🔗 Repository: ${session.gitlab_config.repo_url}\n`;
    statusText += `  🎫 JIRA Ticket: ${session.gitlab_config.jira_ticket}\n`;
    statusText += `  🌿 Base Branch: ${session.gitlab_config.base_branch}\n`;
    statusText += `  👤 User ID: ${session.gitlab_config.user_id || 'Not specified'}\n`;
  } else {
    statusText += `  ❌ Not configured\n`;
  }

  if (session.selected_vulnerabilities.length > 0) {
    statusText += `\n🎯 **Selected Vulnerabilities:**\n`;
    for (const vuln of session.selected_vulnerabilities) {
      const issueId = vuln.issueId || vuln.issueld;
      statusText += `  - ${issueId}: ${vuln.issueName} (${vuln.priority})\n`;
    }
  }

  statusText += `\n🔄 **Available Actions:**\n`;
  statusText += `- Load vulnerabilities: \`load_vulnerabilities\`\n`;
  statusText += `- Configure GitLab: \`configure_gitlab\`\n`;
  statusText += `- Analyze vulnerabilities: \`analyze_vulnerabilities\`\n`;
  statusText += `- Select vulnerability: \`select_vulnerability\`\n`;
  statusText += `- Generate single prompt: \`generate_single_prompt\`\n`;
  statusText += `- Generate batch prompts: \`generate_batch_prompts\`\n`;
  statusText += `- Reset session: \`reset_session\`\n`;

  return [{ type: 'text', text: statusText }];
}

async function resetSession(): Promise<TextContent[]> {
  const oldSessionId = session.session_id;
  session.reset();

  const resultText = `🔄 **Session Reset**\n\n` +
    `Previous session: ${oldSessionId}\n` +
    `New session: ${session.session_id}\n\n` +
    `All data cleared:\n` +
    `- Vulnerabilities: Cleared\n` +
    `- GitLab configuration: Cleared\n` +
    `- Selected vulnerabilities: Cleared\n\n` +
    `🚀 **Ready to start fresh!** Use \`load_vulnerabilities\` to begin.\n`;

  return [{ type: 'text', text: resultText }];
}

// Start the server
async function main() {
  const transport = new StdioServerTransport();
  await server.connect(transport);
  console.error('🚀 MCP Vulnerability Prompt Generator Server started');
  console.error(`📊 API Endpoint: ${session.api_base_url}`);
  console.error('🔗 Powered by FastAPI + LangChain');
}

// Handle graceful shutdown
process.on('SIGINT', async () => {
  console.error('\n🛑 Shutting down MCP server...');
  await server.close();
  process.exit(0);
});

process.on('SIGTERM', async () => {
  console.error('\n🛑 Shutting down MCP server...');
  await server.close();
  process.exit(0);
});

// Start the server
main().catch((error) => {
  console.error('❌ Failed to start MCP server:', error);
  process.exit(1);
});

export { server, SessionState };
