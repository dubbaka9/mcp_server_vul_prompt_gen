# Vulnerability Analysis System

An AI-powered vulnerability analysis system that processes Fortify scan results and generates comprehensive remediation solutions using LangChain and Azure OpenAI.

## Features

- **Multi-format Input Support**: Handles JSON, CSV, HTML, and table formats from Fortify scans
- **Intelligent Prioritization**: Automatically prioritizes vulnerabilities based on severity and remediation deadlines
- **AI-Powered Solutions**: Uses Azure OpenAI to generate detailed remediation guidance
- **Knowledge Base Integration**: Leverages TOML-based knowledge base for common vulnerability patterns
- **Comprehensive Analysis**: Provides root cause analysis, step-by-step solutions, and prevention strategies

## Prerequisites

- Python 3.8 or higher
- Azure OpenAI service with a deployed model (GPT-3.5-turbo or GPT-4)
- Fortify scan results in supported formats

## Installation

1. **Clone or download the project files**

2. **Create a virtual environment**:
   ```bash
   python -m venv vulnerability_analyzer_env
   
   # Activate on Windows
   vulnerability_analyzer_env\Scripts\activate
   
   # Activate on macOS/Linux
   source vulnerability_analyzer_env/bin/activate
   ```

3. **Install dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

4. **Set up environment variables**:
   ```bash
   cp .env.example .env
   # Edit .env with your Azure OpenAI credentials
   ```

5. **Run the setup script**:
   ```bash
   python setup_example.py
   ```

## Configuration

### Environment Variables (.env file)

```env
AZURE_OPENAI_API_KEY=your_azure_openai_api_key_here
AZURE_OPENAI_ENDPOINT=https://your-resource-name.openai.azure.com/
AZURE_OPENAI_DEPLOYMENT_NAME=gpt-35-turbo
AZURE_OPENAI_API_VERSION=2023-05-15
LOG_LEVEL=INFO
MAX_VULNERABILITIES_TO_PROCESS=10
```

### Azure OpenAI Setup

1. Create an Azure OpenAI resource in the Azure portal
2. Deploy a model (recommended: gpt-35-turbo or gpt-4)
3. Get your API key and endpoint from the Azure portal
4. Update the .env file with your credentials

**Note**: Azure OpenAI doesn't support Claude models. If you need Claude Sonnet specifically, you would need to modify the code to use Anthropic's API directly.

## Usage

### Basic Usage

```python
from vulnerability_analyzer import VulnerabilityAnalyzer

# Initialize analyzer
analyzer = VulnerabilityAnalyzer(
    azure_openai_key="your_key",
    azure_openai_endpoint="your_endpoint"
)

# Analyze vulnerabilities from Fortify scan
with open('fortify_results.json', 'r') as f:
    fortify_data = f.read()

results = analyzer.analyze_vulnerabilities(fortify_data, "json")

# Process results
print(f"Total vulnerabilities: {results['total_vulnerabilities']}")
for analysis in results['analysis_results']:
    print(f"Vulnerability: {analysis['vulnerability']['name']}")
    print(f"AI Solution: {analysis['ai_solution']}")
```

### Supported Input Formats

#### JSON Format
```json
[
  {
    "id": "VULN-001",
    "name": "Cross-Site Scripting (XSS)",
    "severity": "high",
    "language": "JavaScript",
    "category": "Input Validation",
    "description": "User input not sanitized",
    "file_path": "/src/components/UserProfile.js",
    "line_number": 45,
    "remediation_date": "2025-07-15",
    "recommendations": "Implement proper input sanitization"
  }
]
```

#### CSV Format
```csv
id,name,severity,language,category,description,file_path,line_number,remediation_date,recommendations
VULN-001,XSS,high,JavaScript,Input Validation,User input not sanitized,/src/app.js,45,2025-07-15,Use proper encoding
```

#### HTML Table Format
The system can parse HTML tables with vulnerability data.

### Prioritization Logic

Vulnerabilities are prioritized based on:

1. **Severity Score**:
   - Critical: 100 points
   - High: 75 points
   - Medium: 50 points
   - Low: 25 points

2. **Remediation Date Urgency**:
   - ≤ 7 days: +50 points
   - ≤ 30 days: +30 points
   - ≤ 90 days: +15 points

## Knowledge Base

The system uses TOML files to store vulnerability knowledge:

### Directory Structure
```
knowledge_base/
├── frontend_vulnerabilities.toml
├── backend_vulnerabilities.toml
└── mobile_vulnerabilities.toml
```

### Adding Custom Knowledge

Create new TOML files in the `knowledge_base/` directory:

```toml
[vulnerability_name]
severity = "high"
description = "Description of the vulnerability"
common_causes = [
    "Cause 1",
    "Cause 2"
]
solutions = [
    "Solution 1",
    "Solution 2"
]
prevention = [
    "Prevention method 1",
    "Prevention method 2"
]
code_examples = '''
// Example code here
'''
```

## Output Format

The analyzer returns structured results:

```json
{
  "total_vulnerabilities": 5,
  "high_priority_count": 2,
  "analysis_results": [
    {
      "vulnerability": {
        "id": "VULN-001",
        "name": "Cross-Site Scripting",
        "severity": "high",
        "priority_score": 125,
        "file_path": "/src/app.js",
        "line_number": 45
      },
      "ai_solution": "Detailed AI-generated solution..."
    }
  ]
}
```

## Advanced Features

### Custom Prompts

Modify the prompt template in `VulnerabilityAnalyzer._setup_langchain()` to customize AI responses.

### Batch Processing

Process multiple Fortify files:

```python
import os
results_batch = []

for filename in os.listdir('fortify_scans/'):
    with open(f'fortify_scans/{filename}', 'r') as f:
        data = f.read()
    
    result = analyzer.analyze_vulnerabilities(data, "auto")
    results_batch.append(result)
```

### Integration with CI/CD

Add the analyzer to your CI/CD pipeline:

```bash
# Example Jenkins/GitHub Actions step
python vulnerability_analyzer.py --input fortify_results.json --output security_report.json --threshold high
```

## Troubleshooting

### Common Issues

1. **Import Errors**: Ensure all dependencies are installed: `pip install -r requirements.txt`

2. **Azure OpenAI Connection Issues**: 
   - Verify your API key and endpoint
   - Check that your model deployment is active
   - Ensure you have sufficient quota

3. **Knowledge Base Not Loading**:
   - Verify TOML files are in `knowledge_base/` directory
   - Check TOML syntax is valid

4. **Memory Issues with Large Files**:
   - Process files in smaller batches
   - Increase system memory limits
   - Use file streaming for very large inputs

### Logging

Enable detailed logging:

```python
import logging
logging.basicConfig(level=logging.DEBUG)
```

## Contributing

1. Add new vulnerability types to knowledge base TOML files
2. Extend input format parsers for additional formats
3. Improve prioritization algorithms
4. Add new AI prompt templates

## Security Considerations

- Store API keys securely (use environment variables)
- Don't log sensitive vulnerability details
- Regularly update dependencies
- Review AI-generated solutions before implementation

## License

This project is for educational and internal security use. Ensure compliance with your organization's security policies.

## Support

For issues and questions:
1. Check the troubleshooting section
2. Review Azure OpenAI documentation
3. Validate input file formats
4. Check system logs for detailed error messages

## Version History

- **v1.0**: Initial release with JSON/CSV/HTML support
- **v1.1**: Added knowledge base integration
- **v1.2**: Improved prioritization algorithm
- **v1.3**: Enhanced AI prompt engineering

---

**Note**: This system is designed to assist security teams with vulnerability analysis. Always review and validate AI-generated solutions before implementing fixes in production environments.
