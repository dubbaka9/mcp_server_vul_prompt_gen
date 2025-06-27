# MCP Server for Vulnerability Prompt Generation (TypeScript)

## 📦 Package Configuration

### package.json
```json
{
  "name": "vulnerability-prompt-mcp-server",
  "version": "1.0.0",
  "description": "MCP Server for Interactive Vulnerability Prompt Generation",
  "main": "dist/mcp-vuln-server.js",
  "type": "module",
  "scripts": {
    "build": "tsc",
    "start": "node dist/mcp-vuln-server.js",
    "dev": "tsx mcp-vuln-server.ts",
    "watch": "tsc --watch",
    "clean": "rm -rf dist",
    "lint": "eslint src/**/*.ts",
    "test": "jest",
    "api": "python ../fastapi_prompt_service.py"
  },
  "dependencies": {
    "@modelcontextprotocol/sdk": "^0.4.0",
    "axios": "^1.6.2",
    "zod": "^3.22.4"
  },
  "devDependencies": {
    "@types/node": "^20.10.0",
    "@typescript-eslint/eslint-plugin": "^6.13.0",
    "@typescript-eslint/parser": "^6.13.0",
    "eslint": "^8.55.0",
    "jest": "^29.7.0",
    "@types/jest": "^29.5.8",
    "tsx": "^4.6.0",
    "typescript": "^5.3.0"
  },
  "keywords": [
    "mcp",
    "vulnerability",
    "security",
    "prompt-generation",
    "langchain",
    "gitlab"
  ],
  "author": "Your Organization",
  "license": "MIT",
  "engines": {
    "node": ">=18.0.0"
  }
}
```

### tsconfig.json
```json
{
  "compilerOptions": {
    "target": "ES2022",
    "module": "ESNext",
    "moduleResolution": "Node",
    "lib": ["ES2022"],
    "outDir": "./dist",
    "rootDir": "./",
    "strict": true,
    "esModuleInterop": true,
    "skipLibCheck": true,
    "forceConsistentCasingInFileNames": true,
    "declaration": true,
    "declarationMap": true,
    "sourceMap": true,
    "removeComments": false,
    "allowSyntheticDefaultImports": true,
    "resolveJsonModule": true,
    "allowImportingTsExtensions": false,
    "noEmit": false,
    "isolatedModules": true
  },
  "include": [
    "mcp-vuln-server.ts",
    "types/**/*"
  ],
  "exclude": [
    "node_modules",
    "dist",
    "**/*.test.ts"
  ]
}
```

### .eslintrc.json
```json
{
  "parser": "@typescript-eslint/parser",
  "plugins": ["@typescript-eslint"],
  "extends": [
    "eslint:recommended",
    "@typescript-eslint/recommended"
  ],
  "parserOptions": {
    "ecmaVersion": 2022,
    "sourceType": "module"
  },
  "rules": {
    "@typescript-eslint/no-unused-vars": "error",
    "@typescript-eslint/no-explicit-any": "warn",
    "@typescript-eslint/explicit-function-return-type": "off",
    "@typescript-eslint/explicit-module-boundary-types": "off",
    "@typescript-eslint/no-inferrable-types": "off",
    "prefer-const": "error",
    "no-var": "error"
  }
}
```

## 🚀 Installation and Setup

### 1. Install Dependencies
```bash
# Install Node.js dependencies
npm install

# Install TypeScript globally (if not already installed)
npm install -g typescript tsx

# Build the project
npm run build
```

### 2. Environment Configuration

Create a `.env` file:
```env
# API Configuration
API_BASE_URL=http://localhost:8000
API_TIMEOUT=30000

# Logging
LOG_LEVEL=INFO
NODE_ENV=development

# Optional: Authentication
API_TOKEN=your-api-token-here
```

### 3. Start Required Services

```bash
# Terminal 1: Start the FastAPI service
npm run api
# or
python ../fastapi_prompt_service.py

# Terminal 2: Start the MCP server
npm run dev
# or for production
npm start
```

## 🎯 Usage Examples

### Basic Usage with Claude Desktop

1. **Add to Claude Desktop Configuration**

Edit your Claude Desktop config file (`~/Library/Application Support/Claude/claude_desktop_config.json` on macOS):

```json
{
  "mcpServers": {
    "vulnerability-prompt-generator": {
      "command": "node",
      "args": ["/path/to/your/dist/mcp-vuln-server.js"],
      "env": {
        "API_BASE_URL": "http://localhost:8000"
      }
    }
  }
}
```

2. **Restart Claude Desktop**

3. **Use the Tools in Claude**

Now you can use the vulnerability tools directly in Claude:

```
Load vulnerabilities from my security scan:
```

Claude will then use the `load_vulnerabilities` tool automatically.

### Command Line Usage

You can also run the MCP server directly:

```bash
# Start the server
npm run dev

# The server will accept MCP protocol messages via stdin/stdout
```

### Programmatic Usage

```typescript
// client-example.ts
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StdioClientTransport } from '@modelcontextprotocol/sdk/client/stdio.js';
import { spawn } from 'child_process';

async function useVulnerabilityMCPServer() {
  // Start the MCP server process
  const serverProcess = spawn('node', ['dist/mcp-vuln-server.js'], {
    stdio: ['pipe', 'pipe', 'inherit']
  });

  // Create MCP client
  const transport = new StdioClientTransport({
    stdin: serverProcess.stdin!,
    stdout: serverProcess.stdout!
  });

  const client = new Client({
    name: 'vulnerability-client',
    version: '1.0.0'
  }, {
    capabilities: {}
  });

  await client.connect(transport);

  try {
    // List available tools
    const tools = await client.listTools();
    console.log('Available tools:', tools.tools.map(t => t.name));

    // Load vulnerabilities
    const loadResult = await client.callTool({
      name: 'load_vulnerabilities',
      arguments: {
        file_path: 'vul.json'
      }
    });
    console.log('Load result:', loadResult.content[0].text);

    // Configure GitLab
    const configResult = await client.callTool({
      name: 'configure_gitlab',
      arguments: {
        repo_url: 'https://gitlab.company.com/project/repo',
        jira_ticket: 'SEC-2024',
        base_branch: 'develop'
      }
    });
    console.log('Config result:', configResult.content[0].text);

    // Analyze vulnerabilities
    const analysisResult = await client.callTool({
      name: 'analyze_vulnerabilities',
      arguments: {}
    });
    console.log('Analysis result:', analysisResult.content[0].text);

    // Select a vulnerability
    const selectResult = await client.callTool({
      name: 'select_vulnerability',
      arguments: {
        issue_id: 27281196,
        code_context: 'const userInput = req.query.redirect; window.location.href = userInput;'
      }
    });
    console.log('Select result:', selectResult.content[0].text);

    // Generate single prompt
    const promptResult = await client.callTool({
      name: 'generate_single_prompt',
      arguments: {
        issue_id: 27281196,
        enhancement_level: 'advanced',
        use_chain_of_thought: true
      }
    });
    console.log('Prompt result:', promptResult.content[0].text);

  } finally {
    await client.close();
    serverProcess.kill();
  }
}

// Run the example
useVulnerabilityMCPServer().catch(console.error);
```

## 🧪 Testing

### Unit Tests

Create `tests/mcp-server.test.ts`:

```typescript
import { describe, it, expect, beforeEach, afterEach } from '@jest/globals';
import { SessionState } from '../mcp-vuln-server.js';
import * as fs from 'fs';

describe('Vulnerability MCP Server', () => {
  let session: SessionState;

  beforeEach(() => {
    session = new SessionState();
  });

  afterEach(() => {
    // Cleanup any test files
  });

  describe('SessionState', () => {
    it('should initialize with default values', () => {
      expect(session.vulnerabilities).toEqual([]);
      expect(session.gitlab_config).toBeNull();
      expect(session.selected_vulnerabilities).toEqual([]);
      expect(session.current_step).toBe('initial');
      expect(session.session_id).toBeDefined();
    });

    it('should reset session correctly', () => {
      session.vulnerabilities = [{ issueName: 'Test' } as any];
      session.current_step = 'loaded';
      
      const oldSessionId = session.session_id;
      session.reset();
      
      expect(session.vulnerabilities).toEqual([]);
      expect(session.current_step).toBe('initial');
      expect(session.session_id).not.toBe(oldSessionId);
    });
  });

  describe('Tool Handlers', () => {
    it('should handle missing vulnerability file', async () => {
      // Test will be implemented based on actual tool functions
      // This is a placeholder showing the testing structure
    });
  });
});
```

### Integration Tests

```bash
# Run integration tests
npm test

# Run with coverage
npm run test:coverage
```

## 🔧 Advanced Configuration

### Custom API Client Configuration

```typescript
// custom-config.ts
interface CustomConfig {
  apiBaseUrl: string;
  timeout: number;
  retryAttempts: number;
  retryDelay: number;
  authentication?: {
    type: 'bearer' | 'apikey';
    token: string;
  };
}

class CustomSessionState extends SessionState {
  constructor(config: CustomConfig) {
    super();
    this.api_base_url = config.apiBaseUrl;
    
    // Configure custom axios instance
    this.api_client.defaults.timeout = config.timeout;
    
    if (config.authentication) {
      if (config.authentication.type === 'bearer') {
        this.api_client.defaults.headers.common['Authorization'] = 
          `Bearer ${config.authentication.token}`;
      } else if (config.authentication.type === 'apikey') {
        this.api_client.defaults.headers.common['X-API-Key'] = 
          config.authentication.token;
      }
    }
    
    // Add retry interceptor
    this.setupRetryInterceptor(config.retryAttempts, config.retryDelay);
  }
  
  private setupRetryInterceptor(maxRetries: number, delay: number) {
    this.api_client.interceptors.response.use(
      (response) => response,
      async (error) => {
        const config = error.config;
        
        if (!config || config.__retryCount >= maxRetries) {
          return Promise.reject(error);
        }
        
        config.__retryCount = config.__retryCount || 0;
        config.__retryCount++;
        
        await new Promise(resolve => setTimeout(resolve, delay * config.__retryCount));
        return this.api_client(config);
      }
    );
  }
}
```

### Docker Configuration

```dockerfile
# Dockerfile.mcp
FROM node:18-alpine

WORKDIR /app

# Copy package files
COPY package*.json ./
RUN npm ci --only=production

# Copy source and build
COPY . .
RUN npm run build

# Create non-root user
RUN addgroup -g 1001 -S nodejs
RUN adduser -S mcp -u 1001
USER mcp

EXPOSE 3001

CMD ["npm", "start"]
```

### Docker Compose Integration

```yaml
# docker-compose.mcp.yml
version: '3.8'

services:
  vulnerability-api:
    build: 
      context: .
      dockerfile: Dockerfile.api
    ports:
      - "8000:8000"
    environment:
      - PYTHONPATH=/app
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:8000/health"]
      interval: 30s
      timeout: 10s
      retries: 3

  mcp-server:
    build:
      context: .
      dockerfile: Dockerfile.mcp
    environment:
      - API_BASE_URL=http://vulnerability-api:8000
      - NODE_ENV=production
    depends_on:
      vulnerability-api:
        condition: service_healthy
    volumes:
      - ./vulnerability_prompts:/app/vulnerability_prompts
    stdin_open: true
    tty: true
```

## 🚀 Production Deployment

### Process Manager (PM2)

```javascript
// ecosystem.config.js
module.exports = {
  apps: [{
    name: 'vulnerability-mcp-server',
    script: 'dist/mcp-vuln-server.js',
    instances: 1,
    exec_mode: 'fork',
    env: {
      NODE_ENV: 'production',
      API_BASE_URL: 'http://localhost:8000'
    },
    error_file: './logs/mcp-server-error.log',
    out_file: './logs/mcp-server-out.log',
    log_file: './logs/mcp-server-combined.log',
    time: true,
    watch: false,
    max_memory_restart: '1G'
  }]
};
```

Start with PM2:
```bash
npm install -g pm2
pm2 start ecosystem.config.js
pm2 save
pm2 startup
```

### Systemd Service

```ini
# /etc/systemd/system/vulnerability-mcp.service
[Unit]
Description=Vulnerability MCP Server
After=network.target

[Service]
Type=simple
User=mcp
WorkingDirectory=/opt/vulnerability-mcp-server
ExecStart=/usr/bin/node dist/mcp-vuln-server.js
Restart=always
RestartSec=10
Environment=NODE_ENV=production
Environment=API_BASE_URL=http://localhost:8000

[Install]
WantedBy=multi-user.target
```

Enable and start:
```bash
sudo systemctl enable vulnerability-mcp
sudo systemctl start vulnerability-mcp
sudo systemctl status vulnerability-mcp
```

## 📊 Monitoring and Logging

### Health Monitoring

```typescript
// health-monitor.ts
import { SessionState } from './mcp-vuln-server.js';

class HealthMonitor {
  private session: SessionState;
  private checkInterval: NodeJS.Timeout;

  constructor(session: SessionState, intervalMs: number = 30000) {
    this.session = session;
    this.checkInterval = setInterval(() => this.performHealthCheck(), intervalMs);
  }

  private async performHealthCheck() {
    try {
      const isHealthy = await this.session.healthCheck();
      if (!isHealthy) {
        console.error('❌ API health check failed');
        // Implement alerting logic here
        this.sendAlert('API health check failed');
      } else {
        console.log('✅ API health check passed');
      }
    } catch (error) {
      console.error('❌ Health check error:', error);
    }
  }

  private sendAlert(message: string) {
    // Implement your alerting mechanism
    // E.g., send to Slack, email, PagerDuty, etc.
    console.error(`🚨 ALERT: ${message}`);
  }

  stop() {
    clearInterval(this.checkInterval);
  }
}
```

### Metrics Collection

```typescript
// metrics.ts
class MetricsCollector {
  private metrics = {
    toolCalls: new Map<string, number>(),
    errors: new Map<string, number>(),
    responseTime: new Map<string, number[]>(),
    sessionCount: 0
  };

  recordToolCall(toolName: string, responseTime: number, success: boolean) {
    // Increment tool call counter
    this.metrics.toolCalls.set(
      toolName, 
      (this.metrics.toolCalls.get(toolName) || 0) + 1
    );

    // Record response time
    if (!this.metrics.responseTime.has(toolName)) {
      this.metrics.responseTime.set(toolName, []);
    }
    this.metrics.responseTime.get(toolName)!.push(responseTime);

    // Record errors
    if (!success) {
      this.metrics.errors.set(
        toolName,
        (this.metrics.errors.get(toolName) || 0) + 1
      );
    }
  }

  getMetrics() {
    return {
      toolCalls: Object.fromEntries(this.metrics.toolCalls),
      errors: Object.fromEntries(this.metrics.errors),
      averageResponseTime: Object.fromEntries(
        Array.from(this.metrics.responseTime.entries()).map(([tool, times]) => [
          tool,
          times.reduce((a, b) => a + b, 0) / times.length
        ])
      ),
      sessionCount: this.metrics.sessionCount
    };
  }
}
```

This TypeScript MCP server provides the same functionality as the Python version with:

1. **Full Type Safety** - Complete TypeScript typing for all interfaces
2. **Modern Node.js** - Uses ES modules and modern JavaScript features  
3. **Robust Error Handling** - Comprehensive error handling and retry logic
4. **Production Ready** - Docker, PM2, and systemd configurations
5. **Monitoring & Metrics** - Built-in health monitoring and metrics collection
6. **Flexible Configuration** - Environment-based configuration with custom options
7. **Easy Integration** - Works seamlessly with Claude Desktop and other MCP clients

The server maintains full compatibility with the FastAPI backend while providing a native TypeScript experience for developers who prefer Node.js over Python for their MCP implementations.
