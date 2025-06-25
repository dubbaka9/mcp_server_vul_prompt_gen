/**
 * Enhanced Interactive Vulnerability Prompt Generator
 * Integrates with FastAPI service for LangChain-powered prompt generation
 */

import * as fs from 'fs';
import * as path from 'path';
import * as readline from 'readline';
import axios, { AxiosResponse } from 'axios';
import { z } from 'zod';

// API Configuration
const API_BASE_URL = process.env.API_BASE_URL || 'http://localhost:8000';
const API_TIMEOUT = 30000; // 30 seconds

// Zod schemas for validation
const VulnerabilitySchema = z.object({
    issueId: z.number().optional(),
    issueld: z.number().optional(),
    issueName: z.string(),
    filePath: z.string(),
    lineNumber: z.number().optional(),
    LineNumber: z.number().optional(),
    priority: z.string(),
    currentVersion: z.string().nullable(),
    upgradeVersion: z.string().nullable(),
    recommendation: z.string(),
    analysisTrace: z.array(z.string()),
    status: z.string()
});

const VulJsonSchema = z.object({
    title: z.string(),
    summary: z.string(),
    table: z.array(VulnerabilitySchema)
});

// API Response schemas
const PromptResponseSchema = z.object({
    prompt: z.string(),
    metadata: z.object({
        issue_id: z.number(),
        vulnerability_type: z.string(),
        file_path: z.string(),
        line_number: z.number(),
        priority: z.string(),
        gitlab_config: z.any()
    }),
    generation_time: z.number(),
    enhancement_used: z.string()
});

const VulnerabilityAnalysisSchema = z.object({
    vulnerability_count: z.number(),
    priorities: z.record(z.number()),
    vulnerability_types: z.record(z.number()),
    files_affected: z.array(z.string()),
    recommendations: z.array(z.string())
});

// Types
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
}

interface EnhancementOptions {
    enhancement_level: 'basic' | 'standard' | 'advanced';
    use_chain_of_thought: boolean;
    code_context: string;
}

interface ApiClient {
    analyzeVulnerabilities(data: any): Promise<any>;
    generatePrompt(vulnerability: any, config: GitLabConfig, options: EnhancementOptions): Promise<any>;
    generateBatchPrompts(vulnerabilities: any[], config: GitLabConfig, options: EnhancementOptions): Promise<any>;
    saveBatchPrompts(vulnerabilities: any[], config: GitLabConfig, options: EnhancementOptions, outputDir: string): Promise<any>;
}

class EnhancedApiClient implements ApiClient {
    private client = axios.create({
        baseURL: API_BASE_URL,
        timeout: API_TIMEOUT,
        headers: {
            'Content-Type': 'application/json'
        }
    });

    constructor() {
        // Add request interceptor for logging
        this.client.interceptors.request.use(
            (config) => {
                console.log(`🌐 API Request: ${config.method?.toUpperCase()} ${config.url}`);
                return config;
            },
            (error) => {
                console.error('❌ Request Error:', error.message);
                return Promise.reject(error);
            }
        );

        // Add response interceptor for error handling
        this.client.interceptors.response.use(
            (response) => {
                console.log(`✅ API Response: ${response.status} ${response.statusText}`);
                return response;
            },
            (error) => {
                if (error.response) {
                    console.error(`❌ API Error: ${error.response.status} - ${error.response.data}`);
                } else if (error.request) {
                    console.error('❌ Network Error: No response received');
                } else {
                    console.error('❌ Error:', error.message);
                }
                return Promise.reject(error);
            }
        );
    }

    async healthCheck(): Promise<boolean> {
        try {
            const response = await this.client.get('/health');
            return response.status === 200;
        } catch (error) {
            return false;
        }
    }

    async analyzeVulnerabilities(data: any): Promise<any> {
        const response = await this.client.post('/analyze-vulnerabilities', data);
        return VulnerabilityAnalysisSchema.parse(response.data);
    }

    async generatePrompt(vulnerability: any, config: GitLabConfig, options: EnhancementOptions): Promise<any> {
        const requestData = {
            vulnerability,
            gitlab_config: config,
            code_context: options.code_context,
            use_chain_of_thought: options.use_chain_of_thought,
            enhancement_level: options.enhancement_level
        };

        const response = await this.client.post('/generate-prompt', requestData);
        return PromptResponseSchema.parse(response.data);
    }

    async generateBatchPrompts(vulnerabilities: any[], config: GitLabConfig, options: EnhancementOptions): Promise<any> {
        const codeContexts: Record<string, string> = {};
        
        // Extract code contexts from vulnerabilities if they have them
        vulnerabilities.forEach(vuln => {
            const issueId = String(vuln.issueId || vuln.issueld);
            if (vuln.code_context) {
                codeContexts[issueId] = vuln.code_context;
            }
        });

        const requestData = {
            vulnerabilities,
            gitlab_config: config,
            code_contexts: codeContexts,
            use_chain_of_thought: options.use_chain_of_thought,
            enhancement_level: options.enhancement_level
        };

        const response = await this.client.post('/generate-batch-prompts', requestData);
        return response.data;
    }

    async saveBatchPrompts(vulnerabilities: any[], config: GitLabConfig, options: EnhancementOptions, outputDir: string): Promise<any> {
        const codeContexts: Record<string, string> = {};
        
        vulnerabilities.forEach(vuln => {
            const issueId = String(vuln.issueId || vuln.issueld);
            if (vuln.code_context) {
                codeContexts[issueId] = vuln.code_context;
            }
        });

        const requestData = {
            vulnerabilities,
            gitlab_config: config,
            code_contexts: codeContexts,
            use_chain_of_thought: options.use_chain_of_thought,
            enhancement_level: options.enhancement_level
        };

        const response = await this.client.post('/save-prompts', requestData, {
            params: { output_dir: outputDir }
        });
        return response.data;
    }
}

class EnhancedInteractiveVulnerabilityPromptGenerator {
    private rl: readline.Interface;
    private outputDir: string = 'vulnerability_prompts';
    private apiClient: EnhancedApiClient;
    
    constructor() {
        this.rl = readline.createInterface({
            input: process.stdin,
            output: process.stdout
        });
        
        this.apiClient = new EnhancedApiClient();
        
        // Create output directory
        if (!fs.existsSync(this.outputDir)) {
            fs.mkdirSync(this.outputDir, { recursive: true });
        }
    }

    /**
     * Load and parse vulnerability JSON file
     */
    loadVulnerabilities(filePath: string): NormalizedVulnerability[] {
        const rawData = fs.readFileSync(filePath, 'utf-8');
        const parsed = JSON.parse(rawData);
        const validated = VulJsonSchema.parse(parsed);
        
        // Normalize field names
        return validated.table.map(vuln => ({
            issueId: vuln.issueId || vuln.issueld || 0,
            issueName: vuln.issueName,
            filePath: vuln.filePath,
            lineNumber: vuln.lineNumber || vuln.LineNumber || 0,
            priority: vuln.priority,
            recommendation: vuln.recommendation,
            analysisTrace: vuln.analysisTrace,
            status: vuln.status
        }));
    }

    /**
     * Check API service availability
     */
    private async checkApiService(): Promise<boolean> {
        console.log('🔍 Checking API service availability...');
        
        const isHealthy = await this.apiClient.healthCheck();
        if (!isHealthy) {
            console.log('❌ API service is not available at', API_BASE_URL);
            console.log('💡 Please ensure the FastAPI service is running:');
            console.log('   python fastapi_prompt_service.py');
            return false;
        }
        
        console.log('✅ API service is available');
        return true;
    }

    /**
     * Get user input asynchronously
     */
    private async getUserInput(prompt: string): Promise<string> {
        return new Promise((resolve) => {
            this.rl.question(prompt, (answer) => {
                resolve(answer.trim());
            });
        });
    }

    /**
     * Collect GitLab configuration from user
     */
    private async collectGitLabConfig(): Promise<GitLabConfig> {
        console.log('\n🔧 === GitLab Configuration ===\n');
        
        const repoUrl = await this.getUserInput('Enter GitLab repository URL: ');
        const jiraTicket = await this.getUserInput('Enter JIRA ticket (e.g., SEC-2024): ');
        const baseBranch = await this.getUserInput('Enter base branch [develop]: ') || 'develop';
        const userId = await this.getUserInput('Enter GitLab user ID for MR assignment (optional): ');
        
        return {
            repo_url: repoUrl,
            jira_ticket: jiraTicket,
            base_branch: baseBranch,
            user_id: userId || undefined
        };
    }

    /**
     * Collect enhancement options from user
     */
    private async collectEnhancementOptions(): Promise<EnhancementOptions> {
        console.log('\n⚡ === Enhancement Options ===\n');
        
        console.log('Enhancement levels:');
        console.log('  1. Basic - Standard prompt with minimal enhancement');
        console.log('  2. Standard - Enhanced with context analysis (recommended)');
        console.log('  3. Advanced - Full LangChain context enhancement');
        
        const levelInput = await this.getUserInput('Select enhancement level [2]: ') || '2';
        const levelMap: Record<string, EnhancementOptions['enhancement_level']> = {
            '1': 'basic',
            '2': 'standard', 
            '3': 'advanced'
        };
        const enhancement_level = levelMap[levelInput] || 'standard';
        
        const cotInput = await this.getUserInput('Use chain-of-thought prompting? (y/N): ');
        const use_chain_of_thought = cotInput.toLowerCase().startsWith('y');
        
        const code_context = await this.getUserInput('Enter code context (optional): ');
        
        return {
            enhancement_level,
            use_chain_of_thought,
            code_context
        };
    }

    /**
     * Display vulnerabilities with enhanced analysis
     */
    private async displayVulnerabilitiesWithAnalysis(vulnerabilities: NormalizedVulnerability[], rawData: any) {
        console.log('\n📊 === Vulnerability Analysis ===\n');
        
        try {
            // Get analysis from API
            const analysis = await this.apiClient.analyzeVulnerabilities(rawData);
            
            console.log(`📈 Total vulnerabilities: ${analysis.vulnerability_count}`);
            
            console.log('\n🔴 By Priority:');
            Object.entries(analysis.priorities).forEach(([priority, count]) => {
                console.log(`  ${priority}: ${count}`);
            });
            
            console.log('\n🎯 By Type:');
            Object.entries(analysis.vulnerability_types).forEach(([type, count]) => {
                console.log(`  ${type}: ${count}`);
            });
            
            console.log(`\n📁 Files affected: ${analysis.files_affected.length}`);
            
        } catch (error) {
            console.log('⚠️  API analysis failed, showing basic analysis');
        }
        
        console.log('\n📋 === Available Vulnerabilities ===\n');
        
        // Group by priority for better visibility
        const grouped = vulnerabilities.reduce((acc, vuln, index) => {
            const priority = vuln.priority.toLowerCase();
            if (!acc[priority]) acc[priority] = [];
            acc[priority].push({ ...vuln, index });
            return acc;
        }, {} as Record<string, any[]>);
        
        // Display in priority order
        const priorityOrder = ['critical', 'high', 'medium', 'low'];
        
        priorityOrder.forEach(priority => {
            if (grouped[priority]) {
                console.log(`\n🔴 [${priority.toUpperCase()}] Priority:`);
                grouped[priority].forEach((vuln: any) => {
                    console.log(`  ${vuln.index + 1}. [ID: ${vuln.issueId}] ${vuln.issueName}`);
                    console.log(`     📁 ${vuln.filePath}:${vuln.lineNumber}`);
                    console.log(`     📊 Status: ${vuln.status}`);
                });
            }
        });
    }

    /**
     * Enhanced prompt generation for single vulnerability
     */
    private async generateEnhancedPrompt(
        vuln: NormalizedVulnerability, 
        config: GitLabConfig, 
        options: EnhancementOptions
    ): Promise<string> {
        try {
            console.log(`🔄 Generating ${options.enhancement_level} prompt for Issue ${vuln.issueId}...`);
            
            const response = await this.apiClient.generatePrompt(vuln, config, options);
            
            console.log(`✅ Generated using ${response.enhancement_used} (${response.generation_time.toFixed(2)}s)`);
            
            return response.prompt;
            
        } catch (error) {
            console.error('❌ Failed to generate enhanced prompt:', error);
            throw error;
        }
    }

    /**
     * Save enhanced prompt to file
     */
    private saveEnhancedPrompt(
        issueId: number, 
        prompt: string, 
        config: GitLabConfig,
        enhancementUsed: string
    ): string {
        const filename = `${issueId}_enhanced_prompt.txt`;
        const filepath = path.join(this.outputDir, filename);
        
        const fullContent = `# Enhanced Fortify Vulnerability Fix Prompt
# Generated: ${new Date().toISOString()}
# Issue ID: ${issueId}
# JIRA: ${config.jira_ticket}
# Repository: ${config.repo_url}
# Enhancement: ${enhancementUsed}
# Generated via FastAPI + LangChain

${prompt}

---
🚀 Generated with enhanced prompting technology
🔗 API Service: ${API_BASE_URL}
`;
        
        fs.writeFileSync(filepath, fullContent, 'utf-8');
        return filepath;
    }

    /**
     * Main interactive process with API integration
     */
    async processVulnerabilities(jsonFilePath: string) {
        try {
            // Check API service first
            const apiAvailable = await this.checkApiService();
            if (!apiAvailable) {
                console.log('\n🔄 Falling back to local generation...');
                // Could implement fallback logic here
                return;
            }

            // Load vulnerabilities
            const vulnerabilities = this.loadVulnerabilities(jsonFilePath);
            const rawData = JSON.parse(fs.readFileSync(jsonFilePath, 'utf-8'));
            
            console.log(`\n✅ Loaded ${vulnerabilities.length} vulnerabilities from ${jsonFilePath}`);
            
            // Collect GitLab config once
            const gitlabConfig = await this.collectGitLabConfig();
            
            // Collect enhancement options
            const enhancementOptions = await this.collectEnhancementOptions();
            
            // Display vulnerabilities with analysis
            await this.displayVulnerabilitiesWithAnalysis(vulnerabilities, rawData);
            
            // Ask for processing mode
            console.log('\n🎯 === Processing Mode ===\n');
            console.log('1. Interactive selection (select vulnerabilities one by one)');
            console.log('2. Batch processing (process all vulnerabilities)');
            console.log('3. Quick batch (process all with current settings)');
            
            const modeInput = await this.getUserInput('Select mode [1]: ') || '1';
            
            if (modeInput === '2' || modeInput === '3') {
                // Batch processing
                await this.processBatchMode(vulnerabilities, gitlabConfig, enhancementOptions, modeInput === '3');
            } else {
                // Interactive processing
                await this.processInteractiveMode(vulnerabilities, gitlabConfig, enhancementOptions);
            }
            
        } catch (error) {
            console.error('❌ Error:', error);
        } finally {
            this.rl.close();
        }
    }

    /**
     * Process vulnerabilities in batch mode
     */
    private async processBatchMode(
        vulnerabilities: NormalizedVulnerability[],
        gitlabConfig: GitLabConfig,
        enhancementOptions: EnhancementOptions,
        quickMode: boolean = false
    ) {
        try {
            if (!quickMode) {
                const confirm = await this.getUserInput(
                    `Generate prompts for all ${vulnerabilities.length} vulnerabilities? (y/N): `
                );
                if (!confirm.toLowerCase().startsWith('y')) {
                    console.log('❌ Batch processing cancelled');
                    return;
                }
            }

            console.log(`\n🚀 Starting batch processing of ${vulnerabilities.length} vulnerabilities...`);
            console.log(`⚡ Enhancement: ${enhancementOptions.enhancement_level}`);
            console.log(`🧠 Chain-of-thought: ${enhancementOptions.use_chain_of_thought ? 'Yes' : 'No'}`);
            
            // Use API to save batch prompts
            const result = await this.apiClient.saveBatchPrompts(
                vulnerabilities,
                gitlabConfig,
                enhancementOptions,
                this.outputDir
            );
            
            console.log('\n✅ === Batch Processing Complete ===\n');
            console.log(`📁 Output directory: ${this.outputDir}`);
            console.log(`📝 Prompts generated: ${result.prompt_count}`);
            console.log(`⏱️  Estimated completion: ${result.estimated_completion}`);
            
            // Show summary
            console.log('\n📋 Generated files:');
            vulnerabilities.forEach(vuln => {
                console.log(`  - ${vuln.issueId}_prompt.txt (${vuln.priority}: ${vuln.issueName})`);
            });
            console.log('  - fix_summary.md');
            
        } catch (error) {
            console.error('❌ Batch processing failed:', error);
        }
    }

    /**
     * Process vulnerabilities in interactive mode
     */
    private async processInteractiveMode(
        vulnerabilities: NormalizedVulnerability[],
        gitlabConfig: GitLabConfig,
        enhancementOptions: EnhancementOptions
    ) {
        const selectedVulns: (NormalizedVulnerability & { code_context?: string })[] = [];
        let continueSelecting = true;
        
        while (continueSelecting && vulnerabilities.length > 0) {
            // Get user selection
            const selection = await this.getUserInput('\nSelect vulnerability number to fix (or "done" to finish): ');
            
            if (selection.toLowerCase() === 'done') {
                continueSelecting = false;
            } else {
                const index = parseInt(selection) - 1;
                if (index >= 0 && index < vulnerabilities.length) {
                    const selected = vulnerabilities[index];
                    
                    // Ask for code context for this specific vulnerability
                    const codeContext = await this.getUserInput('Enter code context for this vulnerability (optional): ');
                    
                    // Add code context if provided
                    if (codeContext) {
                        selected.code_context = codeContext;
                    }
                    
                    selectedVulns.push(selected);
                    
                    // Generate and save prompt immediately
                    try {
                        const currentOptions = { ...enhancementOptions };
                        if (codeContext) {
                            currentOptions.code_context = codeContext;
                        }
                        
                        const prompt = await this.generateEnhancedPrompt(selected, gitlabConfig, currentOptions);
                        const savedPath = this.saveEnhancedPrompt(
                            selected.issueId, 
                            prompt, 
                            gitlabConfig,
                            enhancementOptions.enhancement_level
                        );
                        
                        console.log(`\n✅ Generated enhanced prompt for Issue ${selected.issueId}: ${savedPath}`);
                        console.log(`🔹 Priority: ${selected.priority}`);
                        console.log(`🔹 Type: ${selected.issueName}`);
                        console.log(`🔹 Enhancement: ${enhancementOptions.enhancement_level}`);
                        
                    } catch (error) {
                        console.error(`❌ Failed to generate prompt for Issue ${selected.issueId}:`, error);
                    }
                    
                    // Remove from available list
                    vulnerabilities.splice(index, 1);
                    
                    if (vulnerabilities.length > 0) {
                        const more = await this.getUserInput('\nSelect another vulnerability? (y/N): ');
                        continueSelecting = more.toLowerCase().startsWith('y');
                    }
                } else {
                    console.log('❌ Invalid selection. Please try again.');
                }
            }
        }
        
        // Summary
        console.log('\n🎉 === Interactive Processing Complete ===');
        console.log(`📝 Generated ${selectedVulns.length} enhanced prompts in ${this.outputDir}/`);
        
        if (selectedVulns.length > 0) {
            console.log('\n📋 Generated prompts for:');
            selectedVulns.forEach(vuln => {
                console.log(`  - ${vuln.issueId}_enhanced_prompt.txt (${vuln.priority}): ${vuln.issueName}`);
            });
            
            // Create summary file
            this.createEnhancedSummaryFile(selectedVulns, gitlabConfig, enhancementOptions);
        }
    }

    /**
     * Create enhanced summary file
     */
    private createEnhancedSummaryFile(
        vulnerabilities: NormalizedVulnerability[], 
        config: GitLabConfig,
        options: EnhancementOptions
    ) {
        const summaryPath = path.join(this.outputDir, 'enhanced_fix_summary.md');
        
        const content = `# Enhanced Vulnerability Fix Summary
Generated: ${new Date().toISOString()}
API Service: ${API_BASE_URL}

## Enhancement Configuration
- **Level**: ${options.enhancement_level}
- **Chain-of-Thought**: ${options.use_chain_of_thought ? 'Enabled' : 'Disabled'}
- **Code Context**: ${options.code_context ? 'Provided' : 'Not provided'}

## GitLab Configuration
- **Repository**: ${config.repo_url}
- **JIRA Ticket**: ${config.jira_ticket}
- **Base Branch**: ${config.base_branch}
- **Feature Branch**: feat/${config.jira_ticket}-enhanced-fixes

## Selected Vulnerabilities (${vulnerabilities.length})

${vulnerabilities.map(vuln => `
### ${vuln.issueId} - ${vuln.issueName}
- **Priority**: ${vuln.priority}
- **File**: ${vuln.filePath}:${vuln.lineNumber}
- **Status**: ${vuln.status}
- **Prompt File**: ${vuln.issueId}_enhanced_prompt.txt
`).join('')}

## Technology Stack
- 🤖 **LangChain**: Enhanced prompt generation
- 🚀 **FastAPI**: RESTful API service
- 🔧 **TypeScript**: Interactive user interface
- 📊 **Zod**: Data validation
- 🔗 **Axios**: API communication

## Next Steps
1. Review each generated enhanced prompt file
2. Execute fixes using your preferred LLM with the enhanced prompts
3. Create feature branch: \`feat/${config.jira_ticket}-enhanced-fixes\`
4. Apply fixes and commit changes
5. Submit merge request with enhanced documentation

## Features Used
✅ Enhanced prompt templates  
✅ Context-aware generation  
✅ GitLab workflow integration  
✅ API-driven processing  
${options.use_chain_of_thought ? '✅ Chain-of-thought reasoning' : '❌ Chain-of-thought reasoning'}  
✅ Batch processing capability  
✅ Real-time API validation  
`;
        
        fs.writeFileSync(summaryPath, content, 'utf-8');
        console.log(`\n✅ Enhanced summary saved to: ${summaryPath}`);
    }
}

// Main execution
if (require.main === module) {
    const generator = new EnhancedInteractiveVulnerabilityPromptGenerator();
    
    // Get JSON file path from command line or use default
    const jsonFile = process.argv[2] || 'vul.json';
    
    console.log('🚀 Enhanced Vulnerability Prompt Generator');
    console.log('🔗 Powered by FastAPI + LangChain');
    console.log(`📊 API Endpoint: ${API_BASE_URL}`);
    console.log('=' * 50);
    
    generator.processVulnerabilities(jsonFile).catch(console.error);
}

export { EnhancedInteractiveVulnerabilityPromptGenerator };
