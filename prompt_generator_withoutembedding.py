"""
Enhanced Prompt Generator using LangChain (Fixed Version)
Generates more accurate prompts for vulnerability fixes
"""

import os
import json
import re
from datetime import datetime
from typing import Dict, List, Optional, Any, Tuple
from pathlib import Path

# Updated LangChain imports for v2 compatibility
try:
    from langchain_core.prompts import (
        PromptTemplate, 
        ChatPromptTemplate,
        FewShotPromptTemplate,
        SystemMessagePromptTemplate,
        HumanMessagePromptTemplate
    )
    from langchain_core.output_parsers import BaseOutputParser
except ImportError:
    # Fallback to older imports if needed
    from langchain.prompts import (
        PromptTemplate, 
        ChatPromptTemplate,
        FewShotPromptTemplate,
        SystemMessagePromptTemplate,
        HumanMessagePromptTemplate
    )
    from langchain.schema import BaseOutputParser

# Updated Pydantic v2 imports
from pydantic import BaseModel, Field


class VulnerabilityFix(BaseModel):
    """Structure for vulnerability fix output"""
    fixed_code: str = Field(description="The secure fixed code")
    explanation: str = Field(description="Explanation of the fix")
    security_considerations: List[str] = Field(description="Security considerations")
    testing_notes: str = Field(description="How to test the fix")


class SimpleFortifyPromptGenerator:
    """Enhanced prompt generator using LangChain (without external dependencies)"""
    
    def __init__(self, output_dir: str = "prompts"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(exist_ok=True)
        
        # Initialize prompt templates
        self.system_template = self._create_system_template()
        self.few_shot_examples = self._load_few_shot_examples()
        
    def _create_system_template(self) -> str:
        """Create the system prompt template"""
        return """You are an expert security engineer specializing in fixing vulnerabilities.
        
Your expertise includes:
- Deep understanding of {vulnerability_type} vulnerabilities
- {language} programming language security best practices
- OWASP security guidelines
- Secure coding patterns

You always:
1. Provide minimal, focused fixes that address the specific vulnerability
2. Maintain existing functionality
3. Follow the principle of least privilege
4. Add appropriate input validation and output encoding
5. Use the most secure methods available in {language}
6. Consider the full context and data flow"""

    def _load_few_shot_examples(self) -> List[Dict[str, str]]:
        """Load few-shot examples for different vulnerability types"""
        return [
            # SQL Injection Example
            {
                "vulnerability_type": "SQL Injection",
                "vulnerable_code": """
const userId = req.params.userId;
const query = `SELECT * FROM users WHERE id = '${userId}'`;
db.query(query, callback);
""",
                "fixed_code": """
const userId = req.params.userId;
const query = 'SELECT * FROM users WHERE id = ?';
db.query(query, [userId], callback);
""",
                "explanation": "Used parameterized queries to prevent SQL injection"
            },
            # XSS Example
            {
                "vulnerability_type": "Cross-Site Scripting: DOM",
                "vulnerable_code": """
const userInput = getUrlParameter('redirect');
window.location.href = userInput;
""",
                "fixed_code": """
const userInput = getUrlParameter('redirect');
const allowedDomains = ['example.com', 'app.example.com'];
try {
    const url = new URL(userInput, window.location.origin);
    if (allowedDomains.includes(url.hostname)) {
        window.location.href = url.toString();
    } else {
        console.error('Invalid redirect URL');
        window.location.href = '/';
    }
} catch (e) {
    console.error('Invalid URL format');
    window.location.href = '/';
}
""",
                "explanation": "Added URL validation with allowlist and error handling to prevent open redirect"
            },
            # Path Traversal Example
            {
                "vulnerability_type": "Path Traversal",
                "vulnerable_code": """
const filename = req.query.file;
const filepath = './uploads/' + filename;
fs.readFile(filepath, callback);
""",
                "fixed_code": """
const path = require('path');
const filename = req.query.file;

// Sanitize filename and prevent directory traversal
const safeFilename = path.basename(filename);
const filepath = path.join(__dirname, 'uploads', safeFilename);

// Ensure the resolved path is within the uploads directory
const uploadsDir = path.resolve(__dirname, 'uploads');
const resolvedPath = path.resolve(filepath);

if (resolvedPath.startsWith(uploadsDir)) {
    fs.readFile(resolvedPath, callback);
} else {
    callback(new Error('Invalid file path'));
}
""",
                "explanation": "Used path.basename() and validated resolved path stays within allowed directory"
            },
            # Command Injection Example
            {
                "vulnerability_type": "Command Injection",
                "vulnerable_code": """
const userInput = req.body.filename;
exec(`ls -la ${userInput}`, callback);
""",
                "fixed_code": """
const { execFile } = require('child_process');
const path = require('path');
const userInput = req.body.filename;

// Validate and sanitize input
const safeFilename = path.basename(userInput);
if (!/^[a-zA-Z0-9._-]+$/.test(safeFilename)) {
    return callback(new Error('Invalid filename format'));
}

// Use execFile with array arguments to prevent injection
execFile('ls', ['-la', safeFilename], { cwd: '/safe/directory' }, callback);
""",
                "explanation": "Used execFile with array arguments and input validation to prevent command injection"
            }
        ]
    
    def _select_relevant_examples(self, vulnerability_type: str) -> List[Dict[str, str]]:
        """Select relevant examples based on vulnerability type (simple matching)"""
        relevant = []
        
        # Exact match first
        for example in self.few_shot_examples:
            if example["vulnerability_type"].lower() == vulnerability_type.lower():
                relevant.append(example)
        
        # If no exact match, look for partial matches
        if not relevant:
            for example in self.few_shot_examples:
                if any(word in vulnerability_type.lower() for word in example["vulnerability_type"].lower().split()):
                    relevant.append(example)
        
        # Return top 2 examples
        return relevant[:2]
    
    def create_enhanced_prompt(self, vulnerability_data: Dict, code_context: str) -> str:
        """Create an enhanced prompt using LangChain templates"""
        
        # Get relevant examples
        relevant_examples = self._select_relevant_examples(vulnerability_data["vulnerability_type"])
        
        # Create few-shot examples text
        examples_text = ""
        if relevant_examples:
            examples_text = "Here are some examples of similar vulnerability fixes:\n\n"
            for i, example in enumerate(relevant_examples, 1):
                examples_text += f"Example {i}:\n"
                examples_text += f"Vulnerability: {example['vulnerability_type']}\n"
                examples_text += f"Vulnerable Code:\n{example['vulnerable_code']}\n"
                examples_text += f"Fixed Code:\n{example['fixed_code']}\n"
                examples_text += f"Explanation: {example['explanation']}\n\n"
            examples_text += "Now fix this vulnerability:\n\n"
        
        # Create the complete prompt
        system_prompt = self.system_template.format(**vulnerability_data)
        human_prompt = self._create_human_template().format(**vulnerability_data)
        
        full_prompt = f"{system_prompt}\n\n{examples_text}{human_prompt}"
        
        return full_prompt
    
    def _create_human_template(self) -> str:
        """Create the human message template"""
        return """Fix this {vulnerability_type} vulnerability:

## Vulnerability Details
- Issue ID: {issue_id}
- File: {file_path}
- Line: {line_number}
- Severity: {severity}
- Scanner: {scanner}

## Fortify Analysis
{recommendation}

## Analysis Trace
{analysis_trace}

## Current Vulnerable Code (Line {line_number})
```{language}
{code_context}
```

## Additional Context
- Framework: {framework}
- Dependencies: {dependencies}
- Security Context: {security_headers}
- Code Complexity: {code_complexity}
- Suggested Libraries: {suggested_libraries}

## Requirements
1. Fix the vulnerability at line {line_number}
2. Use {language} best practices
3. Maintain backward compatibility
4. Add appropriate error handling
5. Include input validation where needed

Provide:
1. The complete fixed code
2. Explanation of the fix
3. Security considerations
4. Testing recommendations"""

    def generate_prompt_with_context_enhancement(self, vulnerability: Dict, code_context: str) -> str:
        """Generate enhanced prompt with additional context"""
        
        # Normalize vulnerability data
        vuln_data = self._normalize_vulnerability_data(vulnerability)
        
        # Enhance with additional context
        enhanced_data = self._enhance_vulnerability_context(vuln_data, code_context)
        
        # Create the prompt
        prompt = self.create_enhanced_prompt(enhanced_data, code_context)
        
        return prompt
    
    def _normalize_vulnerability_data(self, vulnerability: Dict) -> Dict:
        """Normalize and enrich vulnerability data"""
        # Handle field name variations
        issue_id = vulnerability.get('issueId') or vulnerability.get('issueld')
        line_number = vulnerability.get('lineNumber') or vulnerability.get('LineNumber')
        
        normalized = {
            'issue_id': issue_id,
            'vulnerability_type': vulnerability.get('issueName', 'Unknown'),
            'file_path': vulnerability.get('filePath', 'N/A'),
            'line_number': line_number,
            'severity': vulnerability.get('priority', 'Unknown'),
            'recommendation': vulnerability.get('recommendation', 'No recommendation'),
            'analysis_trace': self._format_analysis_trace(vulnerability.get('analysisTrace', [])),
            'scanner': 'Fortify',
            'language': self._detect_language(vulnerability.get('filePath', '')),
            'status': vulnerability.get('status', 'Unknown')
        }
        
        return normalized
    
    def _enhance_vulnerability_context(self, vuln_data: Dict, code_context: str) -> Dict:
        """Enhance vulnerability data with additional context"""
        enhanced = vuln_data.copy()
        
        # Detect framework
        enhanced['framework'] = self._detect_framework(code_context, vuln_data['file_path'])
        
        # Extract dependencies
        enhanced['dependencies'] = self._extract_dependencies(code_context)
        
        # Check for security headers/configurations
        enhanced['security_headers'] = self._analyze_security_context(code_context)
        
        # Add code metrics
        enhanced['code_complexity'] = self._calculate_complexity(code_context)
        
        # Add fix suggestions based on vulnerability type
        enhanced['suggested_libraries'] = self._get_suggested_libraries(
            vuln_data['vulnerability_type'], 
            vuln_data['language']
        )
        
        enhanced['code_context'] = code_context
        
        return enhanced
    
    def _detect_framework(self, code_context: str, file_path: str) -> str:
        """Detect the framework being used"""
        frameworks = {
            'express': ['express', 'app.get', 'app.post', 'req.body', 'res.json'],
            'react': ['useState', 'useEffect', 'Component', 'render()', 'jsx'],
            'angular': ['@Component', '@Injectable', 'ngOnInit'],
            'vue': ['v-model', 'v-if', 'mounted()', 'data()'],
            'django': ['django', 'models.Model', 'views.py', 'urls.py'],
            'spring': ['@RestController', '@Service', '@Autowired'],
            'flask': ['flask', 'Blueprint', '@app.route'],
            'nextjs': ['Next.js', 'getServerSideProps', 'getStaticProps'],
            'nuxt': ['Nuxt', 'asyncData', 'fetch()']
        }
        
        for framework, indicators in frameworks.items():
            if any(indicator in code_context or indicator in file_path for indicator in indicators):
                return framework
                
        return 'unknown'
    
    def _extract_dependencies(self, code_context: str) -> List[str]:
        """Extract dependencies from code"""
        dependencies = []
        
        # JavaScript/TypeScript imports
        import_patterns = [
            r"import .* from ['\"]([^'\"]+)['\"]",
            r"require\(['\"]([^'\"]+)['\"]\)",
            r"from ([^\s]+) import"
        ]
        
        for pattern in import_patterns:
            matches = re.findall(pattern, code_context)
            dependencies.extend(matches)
        
        return list(set(dependencies))
    
    def _analyze_security_context(self, code_context: str) -> Dict[str, bool]:
        """Analyze security-related context"""
        security_checks = {
            'has_input_validation': any(x in code_context for x in ['validate', 'sanitize', 'escape']),
            'has_authentication': any(x in code_context for x in ['auth', 'token', 'session']),
            'has_authorization': any(x in code_context for x in ['authorize', 'permission', 'role']),
            'has_encryption': any(x in code_context for x in ['encrypt', 'hash', 'crypto']),
            'has_error_handling': any(x in code_context for x in ['try', 'catch', 'error'])
        }
        
        return security_checks
    
    def _calculate_complexity(self, code_context: str) -> str:
        """Calculate code complexity indicator"""
        lines = code_context.strip().split('\n')
        
        # Simple complexity metrics
        if len(lines) < 10:
            return 'low'
        elif len(lines) < 50:
            return 'medium'
        else:
            return 'high'
    
    def _get_suggested_libraries(self, vulnerability_type: str, language: str) -> List[str]:
        """Get suggested security libraries for the fix"""
        suggestions = {
            'javascript': {
                'SQL Injection': ['mysql2', 'pg', 'knex', 'sequelize'],
                'Cross-Site Scripting': ['DOMPurify', 'xss', 'sanitize-html'],
                'Path Traversal': ['path', 'fs-extra'],
                'Command Injection': ['child_process.execFile', 'shelljs'],
                'Insecure Deserialization': ['ajv', 'joi']
            },
            'python': {
                'SQL Injection': ['psycopg2', 'SQLAlchemy', 'Django ORM'],
                'Cross-Site Scripting': ['bleach', 'MarkupSafe', 'html.escape'],
                'Path Traversal': ['pathlib', 'os.path'],
                'Command Injection': ['subprocess with shell=False', 'shlex'],
                'Insecure Deserialization': ['json', 'pickle with hmac']
            },
            'java': {
                'SQL Injection': ['PreparedStatement', 'JPA', 'Hibernate'],
                'Cross-Site Scripting': ['OWASP Java Encoder', 'StringEscapeUtils'],
                'Path Traversal': ['java.nio.file.Path', 'FilenameUtils'],
                'Command Injection': ['ProcessBuilder', 'Runtime.exec with array']
            }
        }
        
        lang_suggestions = suggestions.get(language, {})
        vuln_suggestions = lang_suggestions.get(vulnerability_type, [])
        
        return vuln_suggestions
    
    def _format_analysis_trace(self, trace: List[str]) -> str:
        """Format analysis trace with context"""
        if not trace:
            return "No analysis trace available"
        
        formatted = []
        for i, step in enumerate(trace, 1):
            # Add context to each step
            if "Read" in step:
                formatted.append(f"{i}. 🔍 Data Source: {step}")
            elif "Assignment" in step:
                formatted.append(f"{i}. ⚠️  Sink Point: {step}")
            else:
                formatted.append(f"{i}. → Flow: {step}")
        
        return "\n".join(formatted)
    
    def _detect_language(self, file_path: str) -> str:
        """Enhanced language detection"""
        # Handle special cases
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
            '.kt': 'kotlin',
            '.scala': 'scala',
            '.r': 'r',
            '.m': 'objective-c'
        }
        
        return language_map.get(ext, 'unknown')
    
    def create_chain_of_thought_prompt(self, vulnerability: Dict, code_context: str) -> str:
        """Create a chain-of-thought prompt for complex vulnerabilities"""
        vuln_data = self._normalize_vulnerability_data(vulnerability)
        
        cot_template = """Let's fix this {vulnerability_type} vulnerability step by step.

## Step 1: Understand the Vulnerability
The vulnerability is at line {line_number} in {file_path}.
Fortify says: {recommendation}

## Step 2: Analyze the Data Flow
{analysis_trace}

## Step 3: Identify the Root Cause
Looking at the code:
```{language}
{code_context}
```

What makes this code vulnerable?

## Step 4: Design the Fix
Based on {language} best practices for {vulnerability_type}, we should:
1. First, identify what user input needs validation
2. Then, determine the appropriate security control
3. Finally, implement the fix maintaining functionality

## Step 5: Implement the Fix
Provide the complete fixed code with:
- Input validation
- Secure coding patterns
- Error handling
- Comments explaining the security measures

## Step 6: Verify the Fix
Explain how to test that:
1. The vulnerability is fixed
2. The functionality still works
3. No new vulnerabilities are introduced"""
        
        return cot_template.format(**vuln_data, code_context=code_context)
    
    def save_enhanced_prompt(self, json_file_path: str, issue_id: int, 
                           code_context: str = None, use_cot: bool = False):
        """Save enhanced prompt"""
        # Load vulnerability data
        with open(json_file_path, 'r', encoding='utf-8') as f:
            vul_data = json.load(f)
        
        # Find specific vulnerability
        vulnerability = None
        for vuln in vul_data.get('table', []):
            vuln_id = vuln.get('issueId') or vuln.get('issueld')
            if vuln_id == issue_id:
                vulnerability = vuln
                break
        
        if not vulnerability:
            raise ValueError(f"Issue ID {issue_id} not found")
        
        # Generate enhanced prompt
        if use_cot:
            prompt = self.create_chain_of_thought_prompt(vulnerability, code_context or '')
        else:
            prompt = self.generate_prompt_with_context_enhancement(vulnerability, code_context or '')
        
        # Save to file
        timestamp = datetime.now().isoformat()
        content = f"""# ENHANCED FORTIFY PROMPT (Fixed Version)
# Generated: {timestamp}
# Issue ID: {issue_id}
# Enhancement: {'Chain-of-Thought' if use_cot else 'Context-Enhanced'}

{prompt}

---
Generated with simplified LangChain implementation
"""
        
        with open('initialprompt.txt', 'w', encoding='utf-8') as f:
            f.write(content)
        
        print(f"✓ Enhanced prompt saved to initialprompt.txt")
        print(f"  Using: {'Chain-of-Thought' if use_cot else 'Context Enhancement'}")
        
        return prompt


# Example usage
if __name__ == "__main__":
    # Initialize enhanced generator
    generator = SimpleFortifyPromptGenerator()
    
    # Example vulnerability from vul.json
    example_vulnerability = {
        "issueld": 27281196,
        "issueName": "Cross-Site Scripting: DOM",
        "filePath": "src/components/organisms/CollectionsApp/CollectionsApp-jsx",
        "lineNumber": 181,
        "priority": "Critical",
        "recommendation": "The solution to prevent XSS is to ensure that validation occurs in the required places and that relevant properties are set to prevent vulnerabilities.",
        "analysisTrace": [
            "CollectionsApp.jsx:181 - Read window.location",
            "CollectionsApp.jsx:181 - Assignment to window.location.href"
        ],
        "status": "Reviewed"
    }
    
    # Example code context
    code_context = """
const CollectionsApp = () => {
    const handleRedirect = (url) => {
        // Line 181: Vulnerable code
        window.location.href = url;  // Direct assignment without validation
    };
    
    return (
        <div onClick={() => handleRedirect(userInput)}>
            Navigate
        </div>
    );
};
"""
    
    try:
        # Generate enhanced prompt
        enhanced_prompt = generator.generate_prompt_with_context_enhancement(
            example_vulnerability, 
            code_context
        )
        
        print("Enhanced Prompt Preview:")
        print("=" * 50)
        print(enhanced_prompt[:1000] + "...")
        
        # Generate chain-of-thought prompt
        print("\n\nChain-of-Thought Prompt Preview:")
        print("=" * 50)
        cot_prompt = generator.create_chain_of_thought_prompt(
            example_vulnerability,
            code_context
        )
        print(cot_prompt[:1000] + "...")
        
    except Exception as e:
        print(f"Error: {e}")
        print("Please check your dependencies and authentication setup.")
