"""
FastAPI Service for Enhanced Vulnerability Prompt Generation
Exposes LangChain prompt generation functionality via REST API
CORRECTED VERSION - Compatible with SimpleFortifyPromptGenerator
"""

from fastapi import FastAPI, HTTPException, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from typing import Dict, List, Optional, Any
import json
import os
from datetime import datetime
import uvicorn
import asyncio
from pathlib import Path

# Import the CORRECTED enhanced generator
from fixed_prompt_generator import SimpleFortifyPromptGenerator

app = FastAPI(
    title="Vulnerability Prompt Generator API",
    description="Enhanced vulnerability prompt generation using simplified LangChain",
    version="1.0.0"
)

# Enable CORS for TypeScript frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Global generator instance (CORRECTED)
generator = SimpleFortifyPromptGenerator()

# Pydantic models
class GitLabConfig(BaseModel):
    repo_url: str = Field(..., description="GitLab repository URL")
    jira_ticket: str = Field(..., description="JIRA ticket number")
    base_branch: str = Field(default="develop", description="Base branch name")
    user_id: Optional[str] = Field(None, description="GitLab user ID for MR assignment")

class VulnerabilityData(BaseModel):
    issueId: Optional[int] = None
    issueld: Optional[int] = None  # Handle typo in JSON
    issueName: str
    filePath: str
    lineNumber: Optional[int] = None
    LineNumber: Optional[int] = None  # Handle case inconsistency
    priority: str
    currentVersion: Optional[str] = None
    upgradeVersion: Optional[str] = None
    recommendation: str
    analysisTrace: List[str]
    status: str

class VulnerabilityFile(BaseModel):
    title: str
    summary: str
    table: List[VulnerabilityData]

class PromptRequest(BaseModel):
    vulnerability: VulnerabilityData
    gitlab_config: GitLabConfig
    code_context: Optional[str] = Field(default="", description="Code context around the vulnerability")
    use_chain_of_thought: bool = Field(default=False, description="Use chain-of-thought prompting")
    enhancement_level: str = Field(default="standard", description="Enhancement level: basic, standard, advanced")

class BatchPromptRequest(BaseModel):
    vulnerabilities: List[VulnerabilityData]
    gitlab_config: GitLabConfig
    code_contexts: Optional[Dict[str, str]] = Field(default_factory=dict, description="Code contexts by issue ID")
    use_chain_of_thought: bool = Field(default=False)
    enhancement_level: str = Field(default="standard")

class PromptResponse(BaseModel):
    prompt: str
    metadata: Dict[str, Any]
    generation_time: float
    enhancement_used: str

class BatchPromptResponse(BaseModel):
    prompts: Dict[str, PromptResponse]
    summary: Dict[str, Any]
    total_generation_time: float

class VulnerabilityAnalysis(BaseModel):
    vulnerability_count: int
    priorities: Dict[str, int]
    vulnerability_types: Dict[str, int]
    files_affected: List[str]
    recommendations: List[str]

# Utility functions
def normalize_vulnerability(vuln: VulnerabilityData) -> Dict[str, Any]:
    """Normalize vulnerability data for processing"""
    issue_id = vuln.issueId or vuln.issueld or 0
    line_number = vuln.lineNumber or vuln.LineNumber or 0
    
    return {
        'issueId': issue_id,
        'issueName': vuln.issueName,
        'filePath': vuln.filePath,
        'lineNumber': line_number,
        'priority': vuln.priority,
        'recommendation': vuln.recommendation,
        'analysisTrace': vuln.analysisTrace,
        'status': vuln.status
    }

# API Endpoints

@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {
        "status": "healthy",
        "timestamp": datetime.now().isoformat(),
        "service": "vulnerability-prompt-generator",
        "generator": "SimpleFortifyPromptGenerator"
    }

@app.post("/analyze-vulnerabilities", response_model=VulnerabilityAnalysis)
async def analyze_vulnerabilities(file_data: VulnerabilityFile):
    """Analyze vulnerability file and provide insights"""
    try:
        vulnerabilities = file_data.table
        
        # Count by priority
        priorities = {}
        vulnerability_types = {}
        files_affected = set()
        recommendations = []
        
        for vuln in vulnerabilities:
            # Count priorities
            priority = vuln.priority
            priorities[priority] = priorities.get(priority, 0) + 1
            
            # Count vulnerability types
            vuln_type = vuln.issueName
            vulnerability_types[vuln_type] = vulnerability_types.get(vuln_type, 0) + 1
            
            # Collect files
            files_affected.add(vuln.filePath)
            
            # Collect unique recommendations
            if vuln.recommendation not in recommendations:
                recommendations.append(vuln.recommendation)
        
        return VulnerabilityAnalysis(
            vulnerability_count=len(vulnerabilities),
            priorities=priorities,
            vulnerability_types=vulnerability_types,
            files_affected=list(files_affected),
            recommendations=recommendations
        )
        
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Analysis failed: {str(e)}")

@app.post("/generate-prompt", response_model=PromptResponse)
async def generate_prompt(request: PromptRequest):
    """Generate enhanced prompt for a single vulnerability"""
    try:
        start_time = datetime.now()
        
        # Normalize vulnerability data
        vuln_dict = normalize_vulnerability(request.vulnerability)
        
        # Generate prompt based on enhancement level
        if request.use_chain_of_thought:
            prompt = generator.create_chain_of_thought_prompt(
                vuln_dict, 
                request.code_context
            )
            enhancement_used = "chain-of-thought"
        elif request.enhancement_level == "advanced":
            prompt = generator.generate_prompt_with_context_enhancement(
                vuln_dict, 
                request.code_context
            )
            enhancement_used = "context-enhanced"
        else:
            # Use basic enhanced prompt
            prompt = await generate_basic_enhanced_prompt(vuln_dict, request)
            enhancement_used = "basic-enhanced"
        
        # Add GitLab instructions
        gitlab_instructions = generate_gitlab_instructions(
            request.gitlab_config, 
            vuln_dict['filePath'],
            vuln_dict['issueId']
        )
        
        # Combine prompt with GitLab workflow
        full_prompt = f"""{prompt}

{gitlab_instructions}

---
Generated with {enhancement_used} prompting
Generated at: {datetime.now().isoformat()}"""
        
        generation_time = (datetime.now() - start_time).total_seconds()
        
        return PromptResponse(
            prompt=full_prompt,
            metadata={
                "issue_id": vuln_dict['issueId'],
                "vulnerability_type": vuln_dict['issueName'],
                "file_path": vuln_dict['filePath'],
                "line_number": vuln_dict['lineNumber'],
                "priority": vuln_dict['priority'],
                "gitlab_config": request.gitlab_config.dict()
            },
            generation_time=generation_time,
            enhancement_used=enhancement_used
        )
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Prompt generation failed: {str(e)}")

@app.post("/generate-batch-prompts", response_model=BatchPromptResponse)
async def generate_batch_prompts(request: BatchPromptRequest):
    """Generate prompts for multiple vulnerabilities"""
    try:
        start_time = datetime.now()
        prompts = {}
        
        for vuln in request.vulnerabilities:
            vuln_dict = normalize_vulnerability(vuln)
            issue_id = str(vuln_dict['issueId'])
            
            # Get code context for this vulnerability
            code_context = request.code_contexts.get(issue_id, "")
            
            # Create individual prompt request
            individual_request = PromptRequest(
                vulnerability=vuln,
                gitlab_config=request.gitlab_config,
                code_context=code_context,
                use_chain_of_thought=request.use_chain_of_thought,
                enhancement_level=request.enhancement_level
            )
            
            # Generate prompt
            prompt_response = await generate_prompt(individual_request)
            prompts[issue_id] = prompt_response
        
        total_time = (datetime.now() - start_time).total_seconds()
        
        # Generate summary
        summary = {
            "total_vulnerabilities": len(request.vulnerabilities),
            "gitlab_config": request.gitlab_config.dict(),
            "enhancement_level": request.enhancement_level,
            "use_chain_of_thought": request.use_chain_of_thought,
            "vulnerabilities_by_priority": {},
            "files_affected": []
        }
        
        # Analyze the batch
        for vuln in request.vulnerabilities:
            priority = vuln.priority
            summary["vulnerabilities_by_priority"][priority] = \
                summary["vulnerabilities_by_priority"].get(priority, 0) + 1
            
            if vuln.filePath not in summary["files_affected"]:
                summary["files_affected"].append(vuln.filePath)
        
        return BatchPromptResponse(
            prompts=prompts,
            summary=summary,
            total_generation_time=total_time
        )
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Batch generation failed: {str(e)}")

@app.post("/save-prompts")
async def save_prompts(
    request: BatchPromptRequest,
    background_tasks: BackgroundTasks,
    output_dir: str = "vulnerability_prompts"
):
    """Generate and save prompts to files"""
    try:
        # Generate batch prompts
        batch_response = await generate_batch_prompts(request)
        
        # Schedule background task to save files
        background_tasks.add_task(
            save_prompts_to_files,
            batch_response,
            output_dir,
            request.gitlab_config
        )
        
        return {
            "message": "Prompts generated and will be saved",
            "output_directory": output_dir,
            "prompt_count": len(batch_response.prompts),
            "estimated_completion": "30 seconds"
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Save operation failed: {str(e)}")

# Helper functions

async def generate_basic_enhanced_prompt(vuln_dict: Dict, request: PromptRequest) -> str:
    """Generate a basic enhanced prompt without full context analysis"""
    language = detect_language(vuln_dict['filePath'])
    
    template = f"""Fix {vuln_dict['issueName']} vulnerability:

## Vulnerability Details
- Issue ID: {vuln_dict['issueId']}
- File: {vuln_dict['filePath']}:{vuln_dict['lineNumber']}
- Priority: {vuln_dict['priority']}
- Language: {language}

## Fortify Analysis
{vuln_dict['recommendation']}

## Analysis Trace
{format_analysis_trace(vuln_dict['analysisTrace'])}

## Code Context
```{language}
{request.code_context}
```

## Fix Requirements
1. Address the specific vulnerability at line {vuln_dict['lineNumber']}
2. Use {language} security best practices
3. Maintain existing functionality
4. Add appropriate input validation
5. Include error handling

Provide the complete fixed code with explanation."""
    
    return template

def generate_gitlab_instructions(config: GitLabConfig, file_path: str, issue_id: int) -> str:
    """Generate GitLab workflow instructions"""
    branch_name = f"feat/{config.jira_ticket}-fix-{issue_id}"
    file_name = Path(file_path).name
    
    instructions = f"""
## GitLab Workflow
1. Create feature branch "{branch_name}" from "{config.base_branch}"
   Repository: {config.repo_url}
   
2. Apply fix to: {file_path}

3. Commit changes:
   ```bash
   git add {file_path}
   git commit -m "fix: resolve {issue_id} vulnerability in {file_name} [{config.jira_ticket}]"
   ```

4. Push and create Merge Request:
   - Title: "Fix: Vulnerability {issue_id} - {config.jira_ticket}"
   - Target: {config.base_branch}"""
    
    if config.user_id:
        instructions += f"\n   - Assignee: {config.user_id}"
    
    return instructions

def detect_language(file_path: str) -> str:
    """Detect programming language from file path"""
    if '-jsx' in file_path or '.jsx' in file_path:
        return 'javascript'
    if '-tsx' in file_path or '.tsx' in file_path:
        return 'typescript'
    
    ext = Path(file_path).suffix.lower()
    language_map = {
        '.py': 'python',
        '.js': 'javascript',
        '.jsx': 'javascript',
        '.ts': 'typescript',
        '.tsx': 'typescript',
        '.java': 'java',
        '.cs': 'csharp',
        '.cpp': 'cpp',
        '.c': 'c',
        '.rb': 'ruby',
        '.go': 'go',
        '.php': 'php',
        '.rs': 'rust',
        '.swift': 'swift',
        '.kt': 'kotlin'
    }
    
    return language_map.get(ext, 'unknown')

def format_analysis_trace(trace: List[str]) -> str:
    """Format analysis trace for better readability"""
    if not trace:
        return "No analysis trace available"
    
    formatted = []
    for i, step in enumerate(trace, 1):
        if "Read" in step:
            formatted.append(f"{i}. 🔍 Source: {step}")
        elif "Assignment" in step:
            formatted.append(f"{i}. ⚠️  Sink: {step}")
        else:
            formatted.append(f"{i}. → {step}")
    
    return "\n".join(formatted)

async def save_prompts_to_files(
    batch_response: BatchPromptResponse,
    output_dir: str,
    gitlab_config: GitLabConfig
):
    """Background task to save prompts to files"""
    try:
        output_path = Path(output_dir)
        output_path.mkdir(exist_ok=True)
        
        # Save individual prompts
        for issue_id, prompt_response in batch_response.prompts.items():
            filename = f"{issue_id}_prompt.txt"
            filepath = output_path / filename
            
            content = f"""# Enhanced Vulnerability Fix Prompt
# Generated: {datetime.now().isoformat()}
# Issue ID: {issue_id}
# JIRA: {gitlab_config.jira_ticket}
# Repository: {gitlab_config.repo_url}
# Enhancement: {prompt_response.enhancement_used}

{prompt_response.prompt}
"""
            
            with open(filepath, 'w', encoding='utf-8') as f:
                f.write(content)
        
        # Save summary
        summary_content = f"""# Vulnerability Fix Summary
Generated: {datetime.now().isoformat()}

## Configuration
- Repository: {gitlab_config.repo_url}
- JIRA Ticket: {gitlab_config.jira_ticket}
- Base Branch: {gitlab_config.base_branch}
- Total Vulnerabilities: {batch_response.summary['total_vulnerabilities']}
- Generation Time: {batch_response.total_generation_time:.2f}s

## Vulnerabilities by Priority
"""
        
        for priority, count in batch_response.summary['vulnerabilities_by_priority'].items():
            summary_content += f"- {priority}: {count}\n"
        
        summary_content += f"""
## Files Affected
"""
        for file_path in batch_response.summary['files_affected']:
            summary_content += f"- {file_path}\n"
        
        summary_content += f"""
## Generated Prompts
"""
        for issue_id in batch_response.prompts.keys():
            summary_content += f"- {issue_id}_prompt.txt\n"
        
        with open(output_path / "fix_summary.md", 'w', encoding='utf-8') as f:
            f.write(summary_content)
            
        print(f"✓ Saved {len(batch_response.prompts)} prompts to {output_dir}/")
        
    except Exception as e:
        print(f"Error saving prompts: {e}")

# WebSocket endpoint for real-time updates
@app.websocket("/ws/progress")
async def websocket_endpoint(websocket):
    """WebSocket endpoint for real-time progress updates"""
    await websocket.accept()
    try:
        while True:
            # Keep connection alive and send progress updates
            await asyncio.sleep(1)
            await websocket.send_json({
                "type": "ping",
                "timestamp": datetime.now().isoformat()
            })
    except Exception as e:
        print(f"WebSocket error: {e}")

if __name__ == "__main__":
    uvicorn.run(
        "fastapi_prompt_service:app",
        host="0.0.0.0",
        port=8000,
        reload=True,
        log_level="info"
    )
