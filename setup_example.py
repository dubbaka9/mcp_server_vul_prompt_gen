"""
Setup and Usage Example for Vulnerability Analysis System
This file demonstrates how to set up and use the vulnerability analyzer
"""

import os
import json
from vulnerability_analyzer import VulnerabilityAnalyzer
from pathlib import Path

def setup_environment():
    """Setup the environment and directory structure"""
    
    # Create necessary directories
    directories = [
        "knowledge_base",
        "logs",
        "input_samples",
        "output_reports"
    ]
    
    for directory in directories:
        Path(directory).mkdir(exist_ok=True)
        print(f"Created directory: {directory}")
    
    # Create sample environment file
    env_content = """
# Azure OpenAI Configuration
AZURE_OPENAI_API_KEY=your_azure_openai_api_key_here
AZURE_OPENAI_ENDPOINT=https://your-resource-name.openai.azure.com/
AZURE_OPENAI_DEPLOYMENT_NAME=gpt-35-turbo
AZURE_OPENAI_API_VERSION=2023-05-15

# Optional: Additional configuration
LOG_LEVEL=INFO
MAX_VULNERABILITIES_TO_PROCESS=10
"""
    
    with open('.env.example', 'w') as f:
        f.write(env_content)
    print("Created .env.example file - please copy to .env and add your actual keys")

def create_sample_fortify_inputs():
    """Create sample Fortify input files in different formats"""
    
    # JSON format sample
    json_sample = [
        {
            "id": "VULN-001",
            "name": "Cross-Site Scripting (XSS)",
            "severity": "high",
            "language": "JavaScript",
            "category": "Input Validation",
            "description": "User input is not properly sanitized before being rendered in the DOM",
            "file_path": "/src/components/UserProfile.js",
            "line_number": 45,
            "remediation_date": "2025-07-15",
            "recommendations": "Implement proper input sanitization and output encoding. Use textContent instead of innerHTML for user data."
        },
        {
            "id": "VULN-002",
            "name": "SQL Injection",
            "severity": "critical",
            "language": "Python",
            "category": "Database Security",
            "description": "Raw SQL query construction with user input allows for SQL injection attacks",
            "file_path": "/api/user_service.py",
            "line_number": 123,
            "remediation_date": "2025-07-05",
            "recommendations": "Use parameterized queries or ORM. Never concatenate user input directly into SQL strings."
        },
        {
            "id": "VULN-003",
            "name": "Insecure Direct Object References",
            "severity": "high",
            "language": "Java",
            "category": "Access Control",
            "description": "Application allows users to access resources using predictable resource identifiers",
            "file_path": "/src/controllers/DocumentController.java",
            "line_number": 78,
            "remediation_date": "2025-07-20",
            "recommendations": "Implement proper authorization checks. Use indirect object references or UUIDs."
        },
        {
            "id": "VULN-004",
            "name": "Cross-Site Request Forgery",
            "severity": "medium",
            "language": "PHP",
            "category": "Session Management",
            "description": "Application does not validate CSRF tokens for state-changing operations",
            "file_path": "/forms/transfer.php",
            "line_number": 34,
            "remediation_date": "2025-08-01",
            "recommendations": "Implement CSRF token validation for all state-changing forms and AJAX requests."
        },
        {
            "id": "VULN-005",
            "name": "Sensitive Data Exposure",
            "severity": "critical",
            "language": "JavaScript",
            "category": "Data Protection",
            "description": "Sensitive user data is stored in browser localStorage without encryption",
            "file_path": "/src/utils/storage.js",
            "line_number": 12,
            "remediation_date": "2025-07-01",
            "recommendations": "Never store sensitive data in client-side storage. Use secure session management instead."
        }
    ]
    
    with open('input_samples/fortify_sample.json', 'w') as f:
        json.dump(json_sample, f, indent=2)
    
    # CSV format sample
    csv_sample = """id,name,severity,language,category,description,file_path,line_number,remediation_date,recommendations
VULN-006,Buffer Overflow,critical,C++,Memory Management,Stack buffer overflow due to unsafe string operations,/src/utils/string_utils.cpp,89,2025-07-03,"Use safe string functions like strncpy instead of strcpy"
VULN-007,Hardcoded Credentials,high,Python,Authentication,Database password hardcoded in source code,/config/database.py,15,2025-07-10,"Use environment variables or secure configuration management"
VULN-008,XML External Entity,medium,Java,XML Processing,XML parser allows processing of external entities,/src/parsers/XmlProcessor.java,56,2025-08-15,"Disable external entity processing in XML parser configuration"
"""
    
    with open('input_samples/fortify_sample.csv', 'w') as f:
        f.write(csv_sample)
    
    # HTML format sample
    html_sample = """
    <html>
    <head><title>Fortify Scan Results</title></head>
    <body>
        <h1>Vulnerability Report</h1>
        <table border="1">
            <tr>
                <th>ID</th>
                <th>Name</th>
                <th>Severity</th>
                <th>Language</th>
                <th>File Path</th>
                <th>Line</th>
                <th>Remediation Date</th>
                <th>Recommendations</th>
            </tr>
            <tr>
                <td>VULN-009</td>
                <td>Path Traversal</td>
                <td>high</td>
                <td>Node.js</td>
                <td>/api/file-download.js</td>
                <td>23</td>
                <td>2025-07-12</td>
                <td>Validate and sanitize file paths. Use whitelist of allowed directories.</td>
            </tr>
            <tr>
                <td>VULN-010</td>
                <td>Weak Cryptography</td>
                <td>medium</td>
                <td>Python</td>
                <td>/utils/encryption.py</td>
                <td>45</td>
                <td>2025-08-05</td>
                <td>Replace MD5 hashing with SHA-256 or stronger algorithms.</td>
            </tr>
        </table>
    </body>
    </html>
    """
    
    with open('input_samples/fortify_sample.html', 'w') as f:
        f.write(html_sample)
    
    print("Created sample Fortify input files:")
    print("- input_samples/fortify_sample.json")
    print("- input_samples/fortify_sample.csv") 
    print("- input_samples/fortify_sample.html")

def example_usage():
    """Demonstrate how to use the vulnerability analyzer"""
    
    print("\n=== Vulnerability Analysis System Demo ===\n")
    
    # Note: You need to set up your Azure OpenAI credentials first
    print("IMPORTANT: Before running this example:")
    print("1. Copy .env.example to .env")
    print("2. Add your Azure OpenAI credentials to .env")
    print("3. Ensure the knowledge base TOML file is in the knowledge_base/ directory")
    print()
    
    # Example configuration (replace with actual values)
    azure_openai_key = os.getenv("AZURE_OPENAI_API_KEY", "your_key_here")
    azure_openai_endpoint = os.getenv("AZURE_OPENAI_ENDPOINT", "your_endpoint_here")
    
    if azure_openai_key == "your_key_here":
        print("⚠️  Please set up your Azure OpenAI credentials in .env file")
        print("This is just a demo of the structure.")
        return
    
    try:
        # Initialize the analyzer
        print("Initializing Vulnerability Analyzer...")
        analyzer = VulnerabilityAnalyzer(
            azure_openai_key=azure_openai_key,
            azure_openai_endpoint=azure_openai_endpoint
        )
        
        # Example 1: Analyze JSON input
        print("\n--- Example 1: JSON Input Analysis ---")
        with open('input_samples/fortify_sample.json', 'r') as f:
            json_input = f.read()
        
        results = analyzer.analyze_vulnerabilities(json_input, "json")
        print(f"Found {results['total_vulnerabilities']} vulnerabilities")
        print(f"High priority vulnerabilities: {results['high_priority_count']}")
        
        # Save results
        with open('output_reports/json_analysis_results.json', 'w') as f:
            json.dump(results, f, indent=2)
        
        # Example 2: Analyze CSV input
        print("\n--- Example 2: CSV Input Analysis ---")
        with open('input_samples/fortify_sample.csv', 'r') as f:
            csv_input = f.read()
        
        results = analyzer.analyze_vulnerabilities(csv_input, "csv")
        
        # Save results
        with open('output_reports/csv_analysis_results.json', 'w') as f:
            json.dump(results, f, indent=2)
        
        # Example 3: Analyze HTML input
        print("\n--- Example 3: HTML Input Analysis ---")
        with open('input_samples/fortify_sample.html', 'r') as f:
            html_input = f.read()
        
        results = analyzer.analyze_vulnerabilities(html_input, "html")
        
        # Save results
        with open('output_reports/html_analysis_results.json', 'w') as f:
            json.dump(results, f, indent=2)
        
        print("\n✅ Analysis complete! Check the output_reports/ directory for detailed results.")
        
        # Display summary of first result
        if results['analysis_results']:
            first_result = results['analysis_results'][0]
            print(f"\n--- Sample Analysis Result ---")
            print(f"Vulnerability: {first_result['vulnerability']['name']}")
            print(f"Severity: {first_result['vulnerability']['severity']}")
            print(f"Priority Score: {first_result['vulnerability']['priority_score']}")
            print(f"AI Solution Preview: {first_result['ai_solution'][:200]}...")
    
    except Exception as e:
        print(f"Error during analysis: {e}")
        print("Make sure you have:")
        print("1. Valid Azure OpenAI credentials")
        print("2. All required dependencies installed")
        print("3. Knowledge base files in place")

def install_dependencies():
    """Instructions for installing dependencies"""
    
    print("\n=== Installation Instructions ===")
    print("\n1. Create a virtual environment:")
    print("   python -m venv vulnerability_analyzer_env")
    print("   # On Windows:")
    print("   vulnerability_analyzer_env\\Scripts\\activate")
    print("   # On macOS/Linux:")
    print("   source vulnerability_analyzer_env/bin/activate")
    
    print("\n2. Install dependencies:")
    print("   pip install -r requirements.txt")
    
    print("\n3. Set up Azure OpenAI:")
    print("   - Create an Azure OpenAI resource")
    print("   - Deploy a GPT model (e.g., gpt-35-turbo)")
    print("   - Get your API key and endpoint")
    print("   - Copy .env.example to .env and add your credentials")
    
    print("\n4. Set up knowledge base:")
    print("   - Copy the frontend_vulnerabilities.toml file to knowledge_base/")
    print("   - Add additional TOML files for other vulnerability categories")
    
    print("\n5. Run the setup:")
    print("   python setup_example.py")

def create_additional_kb_files():
    """Create additional knowledge base files for different categories"""
    
    # Backend vulnerabilities
    backend_kb = """
[sql_injection]
severity = "critical"
description = "SQL injection vulnerabilities occur when user input is directly incorporated into SQL queries without proper sanitization."
common_causes = [
    "Dynamic SQL query construction",
    "Insufficient input validation",
    "Lack of parameterized queries",
    "Improper use of stored procedures"
]
solutions = [
    "Use parameterized queries/prepared statements",
    "Input validation and sanitization",
    "Use ORM frameworks with built-in protection",
    "Implement least privilege database access"
]
prevention = [
    "Never concatenate user input into SQL queries",
    "Use whitelist input validation",
    "Regular security code reviews",
    "Database security testing"
]
code_examples = '''
// BAD - SQL Injection vulnerable
String query = "SELECT * FROM users WHERE username = '" + username + "'";

// GOOD - Parameterized query
String query = "SELECT * FROM users WHERE username = ?";
PreparedStatement stmt = connection.prepareStatement(query);
stmt.setString(1, username);
'''

[command_injection]
severity = "critical" 
description = "Command injection allows attackers to execute arbitrary system commands on the host operating system."
common_causes = [
    "Unsanitized user input passed to system commands",
    "Use of eval() or similar functions with user input",
    "Improper shell command construction",
    "Insufficient input validation"
]
solutions = [
    "Avoid system calls with user input",
    "Use safe APIs instead of shell commands",
    "Input validation and sanitization",
    "Use parameterized system calls"
]
prevention = [
    "Prefer libraries over system commands",
    "Validate and sanitize all user inputs",
    "Use whitelist-based input validation",
    "Run applications with minimal privileges"
]
code_examples = '''
// BAD - Command injection vulnerable
Runtime.getRuntime().exec("ping " + userInput);

// GOOD - Safe approach
ProcessBuilder pb = new ProcessBuilder("ping", userInput);
Process p = pb.start();
'''
"""
    
    with open('knowledge_base/backend_vulnerabilities.toml', 'w') as f:
        f.write(backend_kb)
    
    # Mobile vulnerabilities  
    mobile_kb = """
[insecure_data_storage]
severity = "high"
description = "Sensitive data stored insecurely on mobile devices can be accessed by malicious apps or attackers."
common_causes = [
    "Storing sensitive data in plain text",
    "Using insecure storage mechanisms",
    "Inadequate file permissions",
    "Storing data in shared locations"
]
solutions = [
    "Use secure storage mechanisms (Keychain/Keystore)",
    "Encrypt sensitive data before storage",
    "Implement proper access controls",
    "Regular data purging"
]
prevention = [
    "Data classification and handling policies",
    "Regular security assessments",
    "Use platform-provided secure storage",
    "Implement data encryption standards"
]
code_examples = '''
// BAD - Insecure storage
SharedPreferences prefs = getSharedPreferences("user_data", MODE_WORLD_READABLE);
prefs.edit().putString("password", password).commit();

// GOOD - Secure storage
// Use Android Keystore or encrypted shared preferences
EncryptedSharedPreferences encryptedPrefs = EncryptedSharedPreferences.create(
    "secure_prefs",
    masterKeyAlias,
    context,
    EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
    EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM
);
'''
"""
    
    with open('knowledge_base/mobile_vulnerabilities.toml', 'w') as f:
        f.write(mobile_kb)
    
    print("Created additional knowledge base files:")
    print("- knowledge_base/backend_vulnerabilities.toml")
    print("- knowledge_base/mobile_vulnerabilities.toml")

if __name__ == "__main__":
    print("Setting up Vulnerability Analysis System...")
    
    # Run setup
    setup_environment()
    create_sample_fortify_inputs()
    create_additional_kb_files()
    
    print("\n" + "="*50)
    install_dependencies()
    
    print("\n" + "="*50)
    print("Setup complete! Next steps:")
    print("1. Install dependencies: pip install -r requirements.txt")
    print("2. Set up your Azure OpenAI credentials in .env")
    print("3. Run: python setup_example.py to test the system")
    
    # Optionally run the example (if credentials are set up)
    run_example = input("\nWould you like to run the example now? (y/n): ").lower().strip()
    if run_example == 'y':
        example_usage()
