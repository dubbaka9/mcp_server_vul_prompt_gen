"""
Vulnerability Analysis System using LangChain
Analyzes Fortify scan results and generates solutions using AI
"""

import os
import json
import toml
import pandas as pd
from datetime import datetime, timedelta
from typing import List, Dict, Any, Optional
from dataclasses import dataclass
from bs4 import BeautifulSoup
import logging

# LangChain imports
from langchain.llms import AzureOpenAI
from langchain.embeddings import OpenAIEmbeddings
from langchain.vectorstores import FAISS
from langchain.document_loaders import TextLoader
from langchain.text_splitter import CharacterTextSplitter
from langchain.chains import RetrievalQA
from langchain.prompts import PromptTemplate
from langchain.schema import Document

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

@dataclass
class Vulnerability:
    """Data class for vulnerability information"""
    id: str
    name: str
    severity: str
    language: str
    category: str
    description: str
    file_path: str
    line_number: int
    remediation_date: str
    fortify_recommendations: str
    priority_score: int = 0

class VulnerabilityKnowledgeBase:
    """Manages the vulnerability knowledge base"""
    
    def __init__(self, kb_directory: str = "knowledge_base"):
        self.kb_directory = kb_directory
        self.vectorstore = None
        self.embeddings = None
        
    def load_knowledge_base(self):
        """Load knowledge base from TOML files"""
        try:
            # Initialize embeddings
            self.embeddings = OpenAIEmbeddings(
                openai_api_key=os.getenv("AZURE_OPENAI_API_KEY"),
                openai_api_base=os.getenv("AZURE_OPENAI_ENDPOINT"),
                openai_api_type="azure"
            )
            
            documents = []
            
            # Load TOML files from knowledge base directory
            for filename in os.listdir(self.kb_directory):
                if filename.endswith('.toml'):
                    file_path = os.path.join(self.kb_directory, filename)
                    with open(file_path, 'r', encoding='utf-8') as f:
                        kb_data = toml.load(f)
                        
                    # Convert TOML data to documents
                    for vuln_type, vuln_info in kb_data.items():
                        content = f"""
                        Vulnerability Type: {vuln_type}
                        Description: {vuln_info.get('description', '')}
                        Common Causes: {vuln_info.get('common_causes', '')}
                        Solutions: {vuln_info.get('solutions', '')}
                        Prevention: {vuln_info.get('prevention', '')}
                        Code Examples: {vuln_info.get('code_examples', '')}
                        """
                        
                        doc = Document(
                            page_content=content,
                            metadata={
                                'source': filename,
                                'vulnerability_type': vuln_type,
                                'severity': vuln_info.get('severity', 'medium')
                            }
                        )
                        documents.append(doc)
            
            # Create vector store
            if documents:
                self.vectorstore = FAISS.from_documents(documents, self.embeddings)
                logger.info(f"Knowledge base loaded with {len(documents)} documents")
            else:
                logger.warning("No documents found in knowledge base")
                
        except Exception as e:
            logger.error(f"Error loading knowledge base: {e}")

class FortifyInputParser:
    """Parses Fortify input in various formats"""
    
    @staticmethod
    def parse_json(json_data: str) -> List[Dict]:
        """Parse JSON format Fortify data"""
        try:
            data = json.loads(json_data)
            if isinstance(data, list):
                return data
            elif isinstance(data, dict) and 'vulnerabilities' in data:
                return data['vulnerabilities']
            else:
                return [data]
        except json.JSONDecodeError as e:
            logger.error(f"Error parsing JSON: {e}")
            return []
    
    @staticmethod
    def parse_html(html_data: str) -> List[Dict]:
        """Parse HTML format Fortify data"""
        try:
            soup = BeautifulSoup(html_data, 'html.parser')
            vulnerabilities = []
            
            # Look for table rows or specific HTML structures
            tables = soup.find_all('table')
            for table in tables:
                rows = table.find_all('tr')
                headers = [th.get_text().strip() for th in rows[0].find_all(['th', 'td'])]
                
                for row in rows[1:]:
                    cells = [td.get_text().strip() for td in row.find_all(['td', 'th'])]
                    if len(cells) >= len(headers):
                        vuln_dict = dict(zip(headers, cells))
                        vulnerabilities.append(vuln_dict)
            
            return vulnerabilities
        except Exception as e:
            logger.error(f"Error parsing HTML: {e}")
            return []
    
    @staticmethod
    def parse_csv_table(csv_data: str) -> List[Dict]:
        """Parse CSV/table format Fortify data"""
        try:
            import io
            df = pd.read_csv(io.StringIO(csv_data))
            return df.to_dict('records')
        except Exception as e:
            logger.error(f"Error parsing CSV: {e}")
            return []

class VulnerabilityPrioritizer:
    """Prioritizes vulnerabilities based on severity and remediation date"""
    
    @staticmethod
    def calculate_priority_score(vulnerability: Vulnerability) -> int:
        """Calculate priority score for vulnerability"""
        score = 0
        
        # Severity scoring
        severity_scores = {
            'critical': 100,
            'high': 75,
            'medium': 50,
            'low': 25
        }
        score += severity_scores.get(vulnerability.severity.lower(), 25)
        
        # Date proximity scoring
        try:
            if vulnerability.remediation_date:
                remediation_date = datetime.strptime(vulnerability.remediation_date, '%Y-%m-%d')
                days_until_remediation = (remediation_date - datetime.now()).days
                
                if days_until_remediation <= 7:
                    score += 50  # Very urgent
                elif days_until_remediation <= 30:
                    score += 30  # Urgent
                elif days_until_remediation <= 90:
                    score += 15  # Moderate urgency
        except (ValueError, TypeError):
            pass
        
        return score
    
    @staticmethod
    def prioritize_vulnerabilities(vulnerabilities: List[Vulnerability]) -> List[Vulnerability]:
        """Sort vulnerabilities by priority score"""
        for vuln in vulnerabilities:
            vuln.priority_score = VulnerabilityPrioritizer.calculate_priority_score(vuln)
        
        return sorted(vulnerabilities, key=lambda x: x.priority_score, reverse=True)

class VulnerabilityAnalyzer:
    """Main analyzer class that orchestrates the vulnerability analysis"""
    
    def __init__(self, azure_openai_key: str, azure_openai_endpoint: str):
        """Initialize the analyzer with Azure OpenAI credentials"""
        self.azure_openai_key = azure_openai_key
        self.azure_openai_endpoint = azure_openai_endpoint
        
        # Set environment variables
        os.environ["AZURE_OPENAI_API_KEY"] = azure_openai_key
        os.environ["AZURE_OPENAI_ENDPOINT"] = azure_openai_endpoint
        
        # Initialize components
        self.knowledge_base = VulnerabilityKnowledgeBase()
        self.parser = FortifyInputParser()
        self.prioritizer = VulnerabilityPrioritizer()
        
        # Initialize LangChain components
        self.llm = None
        self.qa_chain = None
        
        self._setup_langchain()
    
    def _setup_langchain(self):
        """Setup LangChain components"""
        try:
            # Initialize Azure OpenAI LLM
            self.llm = AzureOpenAI(
                openai_api_key=self.azure_openai_key,
                openai_api_base=self.azure_openai_endpoint,
                openai_api_type="azure",
                deployment_name="gpt-35-turbo",  # Change to your deployment name
                openai_api_version="2023-05-15",
                temperature=0.1
            )
            
            # Load knowledge base
            self.knowledge_base.load_knowledge_base()
            
            # Setup QA chain if knowledge base is available
            if self.knowledge_base.vectorstore:
                # Create custom prompt template
                prompt_template = """
                You are a cybersecurity expert specializing in vulnerability remediation.
                
                Context from knowledge base:
                {context}
                
                Vulnerability Information:
                - Name: {vulnerability_name}
                - Severity: {severity}
                - Language: {language}
                - Description: {description}
                - Fortify Recommendations: {fortify_recommendations}
                
                Question: {question}
                
                Please provide:
                1. Root cause analysis
                2. Step-by-step remediation solution
                3. Secure code examples
                4. Prevention strategies
                5. Testing recommendations
                
                Answer:
                """
                
                PROMPT = PromptTemplate(
                    template=prompt_template,
                    input_variables=["context", "vulnerability_name", "severity", 
                                   "language", "description", "fortify_recommendations", "question"]
                )
                
                self.qa_chain = RetrievalQA.from_chain_type(
                    llm=self.llm,
                    chain_type="stuff",
                    retriever=self.knowledge_base.vectorstore.as_retriever(search_kwargs={"k": 3}),
                    chain_type_kwargs={"prompt": PROMPT}
                )
            
            logger.info("LangChain components initialized successfully")
            
        except Exception as e:
            logger.error(f"Error setting up LangChain: {e}")
    
    def parse_fortify_input(self, input_data: str, input_format: str = "auto") -> List[Vulnerability]:
        """Parse Fortify input and convert to Vulnerability objects"""
        vulnerabilities = []
        
        try:
            # Auto-detect format if not specified
            if input_format == "auto":
                input_data_stripped = input_data.strip()
                if input_data_stripped.startswith('[') or input_data_stripped.startswith('{'):
                    input_format = "json"
                elif input_data_stripped.startswith('<'):
                    input_format = "html"
                else:
                    input_format = "csv"
            
            # Parse based on format
            if input_format == "json":
                parsed_data = self.parser.parse_json(input_data)
            elif input_format == "html":
                parsed_data = self.parser.parse_html(input_data)
            elif input_format == "csv":
                parsed_data = self.parser.parse_csv_table(input_data)
            else:
                logger.error(f"Unsupported input format: {input_format}")
                return []
            
            # Convert to Vulnerability objects
            for item in parsed_data:
                vuln = Vulnerability(
                    id=str(item.get('id', item.get('ID', 'N/A'))),
                    name=str(item.get('name', item.get('Name', item.get('vulnerability_name', 'Unknown')))),
                    severity=str(item.get('severity', item.get('Severity', 'medium'))),
                    language=str(item.get('language', item.get('Language', 'unknown'))),
                    category=str(item.get('category', item.get('Category', 'general'))),
                    description=str(item.get('description', item.get('Description', ''))),
                    file_path=str(item.get('file_path', item.get('File', ''))),
                    line_number=int(item.get('line_number', item.get('Line', 0))),
                    remediation_date=str(item.get('remediation_date', item.get('RemediationDate', ''))),
                    fortify_recommendations=str(item.get('recommendations', item.get('Recommendations', '')))
                )
                vulnerabilities.append(vuln)
            
            logger.info(f"Parsed {len(vulnerabilities)} vulnerabilities")
            
        except Exception as e:
            logger.error(f"Error parsing Fortify input: {e}")
        
        return vulnerabilities
    
    def generate_solution_prompt(self, vulnerability: Vulnerability) -> str:
        """Generate AI prompt for vulnerability solution"""
        if not self.qa_chain:
            # Fallback to direct LLM call if QA chain is not available
            prompt = f"""
            Analyze this security vulnerability and provide a comprehensive solution:
            
            Vulnerability: {vulnerability.name}
            Severity: {vulnerability.severity}
            Language: {vulnerability.language}
            Description: {vulnerability.description}
            File: {vulnerability.file_path}:{vulnerability.line_number}
            Fortify Recommendations: {vulnerability.fortify_recommendations}
            
            Please provide:
            1. Root cause analysis
            2. Step-by-step remediation solution
            3. Secure code examples
            4. Prevention strategies
            5. Testing recommendations
            """
            
            try:
                response = self.llm(prompt)
                return response
            except Exception as e:
                logger.error(f"Error generating solution with LLM: {e}")
                return f"Error generating solution: {e}"
        
        else:
            # Use QA chain with knowledge base
            question = f"How to fix {vulnerability.name} vulnerability in {vulnerability.language}?"
            
            try:
                response = self.qa_chain.run({
                    "query": question,
                    "vulnerability_name": vulnerability.name,
                    "severity": vulnerability.severity,
                    "language": vulnerability.language,
                    "description": vulnerability.description,
                    "fortify_recommendations": vulnerability.fortify_recommendations
                })
                return response
            except Exception as e:
                logger.error(f"Error generating solution with QA chain: {e}")
                return f"Error generating solution: {e}"
    
    def analyze_vulnerabilities(self, fortify_input: str, input_format: str = "auto") -> Dict[str, Any]:
        """Main method to analyze vulnerabilities"""
        # Parse input
        vulnerabilities = self.parse_fortify_input(fortify_input, input_format)
        
        if not vulnerabilities:
            return {"error": "No vulnerabilities found in input"}
        
        # Prioritize vulnerabilities
        prioritized_vulns = self.prioritizer.prioritize_vulnerabilities(vulnerabilities)
        
        # Generate solutions for high-priority vulnerabilities
        results = {
            "total_vulnerabilities": len(vulnerabilities),
            "high_priority_count": len([v for v in prioritized_vulns if v.priority_score >= 75]),
            "analysis_results": []
        }
        
        # Process top 10 highest priority vulnerabilities
        for vuln in prioritized_vulns[:10]:
            solution = self.generate_solution_prompt(vuln)
            
            result = {
                "vulnerability": {
                    "id": vuln.id,
                    "name": vuln.name,
                    "severity": vuln.severity,
                    "language": vuln.language,
                    "priority_score": vuln.priority_score,
                    "file_path": vuln.file_path,
                    "line_number": vuln.line_number,
                    "remediation_date": vuln.remediation_date
                },
                "ai_solution": solution
            }
            
            results["analysis_results"].append(result)
        
        return results

# Example usage
def main():
    """Example usage of the VulnerabilityAnalyzer"""
    
    # Initialize analyzer
    analyzer = VulnerabilityAnalyzer(
        azure_openai_key="your_azure_openai_key",
        azure_openai_endpoint="your_azure_openai_endpoint"
    )
    
    # Example Fortify input (JSON format)
    sample_input = '''
    [
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
            "recommendations": "Implement proper input sanitization and output encoding"
        },
        {
            "id": "VULN-002",
            "name": "SQL Injection",
            "severity": "critical",
            "language": "Python",
            "category": "Database Security",
            "description": "Raw SQL query construction with user input",
            "file_path": "/api/user_service.py",
            "line_number": 123,
            "remediation_date": "2025-07-05",
            "recommendations": "Use parameterized queries or ORM"
        }
    ]
    '''
    
    # Analyze vulnerabilities
    results = analyzer.analyze_vulnerabilities(sample_input, "json")
    
    # Print results
    print(json.dumps(results, indent=2))

if __name__ == "__main__":
    main()
