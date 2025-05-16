import os
import json
import requests
import time
import random
from typing import Dict, List, Optional, Tuple, Any
import openai
from dotenv import load_dotenv
import logging

# Set up logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Load environment variables
load_dotenv()

# Configure Azure OpenAI Service
openai.api_key = os.getenv("AZURE_OPENAI_API_KEY")
openai.api_base = os.getenv("AZURE_OPENAI_ENDPOINT")
openai.api_type = "azure"
openai.api_version = "2024-08-01-preview"

# Base Agent class
class Agent:
    """Base class for all agents in the system"""
    
    def __init__(self, name: str):
        self.name = name
        logger.info(f"Initialized {name} agent")
        
    def process(self, *args, **kwargs):
        """Base process method to be implemented by subclasses"""
        raise NotImplementedError("Subclasses must implement this method")

# Attack phase agents
class DataCollectorAgent(Agent):
    """Agent responsible for collecting target information"""
    
    def __init__(self):
        super().__init__("DataCollector")
        self.target_data = {}
        
    def process(self, target_info: Dict = None) -> Dict:
        """
        Process target information for phishing preparation
        
        Args:
            target_info: Dictionary containing target information
            
        Returns:
            Processed target data dictionary
        """
        logger.info("Collecting and processing target information")
        
        # If target_info is provided, use it; otherwise use a default template
        if not target_info:
            # Default information for demonstration purposes
            self.target_data = {
                "name": "John Smith",
                "email": "john.smith@example.com",
                "position": "IT Manager",
                "company": "Acme Corporation",
                "department": "Information Technology",
                "colleagues": ["Sarah Johnson", "Mike Peters"],
                "recent_projects": ["Cloud Migration", "Security Audit"],
                "interests": ["Cybersecurity", "Cloud Computing"],
                "communication_style": "formal",
                "social_media": {
                    "linkedin": "linkedin.com/in/johnsmith",
                    "twitter": "@johnsmith"
                }
            }
        else:
            # Normalize and process the provided target information
            self.target_data = target_info
            
            # Ensure required fields are present
            required_fields = ["name", "email", "position", "company"]
            for field in required_fields:
                if field not in self.target_data:
                    self.target_data[field] = "Unknown"
                    logger.warning(f"Missing required field: {field}")
        
        logger.info(f"Target data processed: {self.target_data['name']} at {self.target_data['company']}")
        return self.target_data

class EmailGeneratorAgent(Agent):
    """Agent responsible for generating phishing emails using the V-Triad framework and Azure OpenAI"""
    
    def __init__(self):
        super().__init__("EmailGenerator")
        self.model = os.getenv("AZURE_OPENAI_MODEL", "gpt-4")
        
    def process(self, target_data: Dict, difficulty: str = "moderate") -> Dict:
        """
        Generate a phishing email based on target data and difficulty level
        
        Args:
            target_data: Dictionary containing target information
            difficulty: Level of sophistication ("easy", "moderate", "advanced")
            
        Returns:
            Dictionary containing the generated email content
        """
        logger.info(f"Generating {difficulty} phishing email for {target_data.get('name', 'target')}")
        
        # Build prompt based on V-Triad framework and difficulty level
        prompt = self._build_prompt(target_data, difficulty)
        
        try:
            # Call Azure OpenAI to generate email content
            client = openai.AzureOpenAI(
                api_key=os.getenv("AZURE_OPENAI_API_KEY"),
                api_version=os.getenv("AZURE_OPENAI_API_VERSION", "2024-08-01-preview"),
                azure_endpoint=os.getenv("AZURE_OPENAI_ENDPOINT")
            )
            response = client.chat.completions.create(
                model=self.model,
                messages=[
                    {"role": "system", "content": "You are an expert in creating realistic phishing emails for cybersecurity training. Your goal is to create emails that seem legitimate but contain phishing elements."},
                    {"role": "user", "content": prompt}
                ],
                temperature=0.7,
                max_tokens=1000
            )
            email_content = response.choices[0].message.content.strip()
            
            # Process the generated email to extract components
            email_components = self._process_email_content(email_content)
            
            # Add a phishing URL based on difficulty
            email_components["phishing_url"] = self._generate_phishing_url(difficulty, target_data)
            
            logger.info(f"Generated {difficulty} phishing email with subject: {email_components['subject']}")
            return email_components
            
        except Exception as e:
            logger.error(f"Error generating email: {str(e)}")
            # Fallback to template in case of API failure
            return self._generate_fallback_email(target_data, difficulty)
    
    def _build_prompt(self, target_data: Dict, difficulty: str) -> str:
        """Build a prompt for the LLM based on V-Triad and difficulty"""
        
        # V-Triad components: credibility, compatibility, customizability
        credibility_elements = {
            "easy": "Use a generic business context that would be common in any workplace.",
            "moderate": f"Impersonate {target_data.get('company', 'the company')}'s IT department requesting a password reset.",
            "advanced": f"Precisely reference {target_data.get('recent_projects', ['a recent project'])[0]} and impersonate {target_data.get('colleagues', ['a colleague'])[0]}."
        }
        
        compatibility_elements = {
            "easy": "Use generic greetings and formal language.",
            "moderate": f"Match the communication style typical for {target_data.get('department', 'the department')}.",
            "advanced": f"Closely mimic {target_data.get('communication_style', 'professional')} communication style and reference specific work details."
        }
        
        customizability_elements = {
            "easy": "Include generic urgency cues like 'Please respond promptly'.",
            "moderate": f"Reference {target_data.get('position', 'the recipient')} specific responsibilities.",
            "advanced": f"Mention specific interests like {', '.join(target_data.get('interests', ['professional development']))} and create a highly personalized message."
        }
        
        # Red flags based on difficulty (more subtle as difficulty increases)
        red_flags = {
            "easy": "Include obvious red flags: misspellings, generic greeting, unusual request, clear urgency.",
            "moderate": "Include moderate red flags: slight domain misspelling, requesting sensitive information, mild urgency.",
            "advanced": "Include subtle red flags: slight inconsistency in tone, unusual timing for the request, subtle pressure."
        }
        
        # Build the full prompt
        prompt = f"""
        Create a phishing email for cybersecurity awareness training based on the following guidelines:
        
        TARGET INFORMATION:
        - Name: {target_data.get('name', 'Employee')}
        - Position: {target_data.get('position', 'Staff Member')}
        - Company: {target_data.get('company', 'The Company')}
        - Department: {target_data.get('department', 'Department')}
        
        DIFFICULTY LEVEL: {difficulty}
        
        V-TRIAD FRAMEWORK IMPLEMENTATION:
        1. Credibility: {credibility_elements[difficulty]}
        2. Compatibility: {compatibility_elements[difficulty]}
        3. Customizability: {customizability_elements[difficulty]}
        
        RED FLAGS:
        {red_flags[difficulty]}
        
        FORMAT:
        - Include From field, Subject line, and Email body
        - Construct the email to include a link that the recipient would be tempted to click
        - Format the output as From: [sender], Subject: [subject line], Body: [email content]
        - Do not include the actual URL in the output, just indicate where a link would be with [LINK]
        
        The email should appear realistic but contain subtle or obvious phishing elements appropriate for the specified difficulty level.
        """
        
        return prompt
    
    def _process_email_content(self, email_content: str) -> Dict:
        """Extract components from the generated email content"""
        
        components = {
            "from": "",
            "subject": "",
            "body": ""
        }
        
        # Extract the From field
        if "From:" in email_content:
            from_start = email_content.find("From:") + 5
            from_end = email_content.find("\n", from_start)
            components["from"] = email_content[from_start:from_end].strip()
        
        # Extract the Subject field
        if "Subject:" in email_content:
            subject_start = email_content.find("Subject:") + 8
            subject_end = email_content.find("\n", subject_start)
            components["subject"] = email_content[subject_start:subject_end].strip()
        
        # Extract the Body
        if "Body:" in email_content:
            body_start = email_content.find("Body:") + 5
            components["body"] = email_content[body_start:].strip()
        
        # If the extraction failed, use the whole content as body
        if not components["body"]:
            components["body"] = email_content
        
        return components
    
    def _generate_phishing_url(self, difficulty: str, target_data: Dict) -> Dict:
        """Generate a phishing URL appropriate for the difficulty level"""
        
        company = target_data.get('company', 'company').lower()
        company = company.replace(' ', '')
        
        url_components = {
            "easy": {
                "display_url": f"https://secure-{company}-login.com/portal",
                "actual_url": f"https://malicious-site.com/phish?company={company}",
                "type": "obvious_mismatch"
            },
            "moderate": {
                "display_url": f"https://{company}.com/account-verification",
                "actual_url": f"https://{company}-secure.co/login.php",
                "type": "similar_domain"
            },
            "advanced": {
                "display_url": f"https://{company}.com/internal/projects/update",
                "actual_url": f"https://{company}0.com/login",
                "type": "typosquatting"
            }
        }
        
        return url_components[difficulty]
    
    def _generate_fallback_email(self, target_data: Dict, difficulty: str) -> Dict:
        """Generate a fallback email in case the API call fails"""
        
        templates = {
            "easy": {
                "from": "account-services@gmal.com",
                "subject": "Urgent: Your Account Needs Attention",
                "body": f"Dear {target_data.get('name', 'Valued Customer')},\n\nYour account requires immediate verification due to suspicious activity. Please click the link below to secure your account now:\n\n[CLICK HERE TO VERIFY]\n\nRegards,\nAccount Security Team"
            },
            "moderate": {
                "from": f"it-support@{target_data.get('company', 'company').lower().replace(' ', '')}.net",
                "subject": f"Action Required: Update your {target_data.get('company', 'company')} credentials",
                "body": f"Hello {target_data.get('name', 'Colleague')},\n\nAs part of our quarterly security protocol, we require all {target_data.get('department', 'department')} staff to update their passwords. Please follow the link below to complete this process:\n\n[UPDATE PASSWORD]\n\nThis request will expire in 24 hours.\n\nIT Support Team\n{target_data.get('company', 'Company')}"
            },
            "advanced": {
                "from": f"{target_data.get('colleagues', ['A Colleague'])[0].lower().replace(' ', '.')}@{target_data.get('company', 'company').lower().replace(' ', '')}.com",
                "subject": f"Re: {target_data.get('recent_projects', ['Project'])[0]} Update - Action Required",
                "body": f"Hi {target_data.get('name', '').split()[0]},\n\nI've shared an important document regarding the {target_data.get('recent_projects', ['current project'])[0]} that requires your immediate review. The executive team has requested feedback by end of day.\n\n[ACCESS DOCUMENT]\n\nLet me know if you have any questions.\n\nRegards,\n{target_data.get('colleagues', ['A Colleague'])[0]}"
            }
        }
        
        template = templates[difficulty]
        template["phishing_url"] = self._generate_phishing_url(difficulty, target_data)
        
        return template

class FeedbackAgent(Agent):
    """Agent responsible for refining phishing emails based on quality criteria"""
    
    def __init__(self):
        super().__init__("Feedback")
        self.criteria = {
            "credibility": 0.0,
            "compatibility": 0.0,
            "customizability": 0.0,
            "appropriate_red_flags": 0.0
        }
        self.model = os.getenv("AZURE_OPENAI_MODEL", "gpt-4")
    
    def process(self, email_content: Dict, target_data: Dict, difficulty: str) -> Dict:
        """
        Evaluate and refine the phishing email based on V-Triad criteria
        
        Args:
            email_content: Dictionary containing the email components
            target_data: Dictionary containing target information
            difficulty: Level of sophistication
            
        Returns:
            Refined email content dictionary
        """
        logger.info(f"Evaluating and refining phishing email for {difficulty} difficulty")
        
        # First, evaluate the email against criteria
        evaluation = self._evaluate_email(email_content, target_data, difficulty)
        
        # If the evaluation score is below threshold, refine the email
        if evaluation["overall_score"] < 0.7:
            logger.info(f"Email quality below threshold ({evaluation['overall_score']:.2f}), refining content")
            refined_email = self._refine_email(email_content, evaluation, target_data, difficulty)
            refined_email["evaluation"] = evaluation
            return refined_email
        else:
            logger.info(f"Email passed quality check with score: {evaluation['overall_score']:.2f}")
            email_content["evaluation"] = evaluation
            return email_content
    
    def _evaluate_email(self, email_content: Dict, target_data: Dict, difficulty: str) -> Dict:
        """Evaluate the email against V-Triad criteria"""
        
        try:
            # Prepare the evaluation prompt
            prompt = f"""
            Evaluate the following phishing email for cybersecurity training against the V-Triad framework criteria:
            
            EMAIL:
            From: {email_content['from']}
            Subject: {email_content['subject']}
            Body: {email_content['body']}
            
            TARGET INFORMATION:
            {json.dumps(target_data, indent=2)}
            
            DIFFICULTY LEVEL: {difficulty}
            
            CRITERIA TO EVALUATE:
            1. Credibility: Does the email establish appropriate credibility for the {difficulty} level?
            2. Compatibility: Is the email compatible with the target's role and organizational context?
            3. Customizability: Is the email appropriately customized to the target?
            4. Red Flags: Does the email include appropriate red flags for the {difficulty} level?
            
            Provide a score from 0.0 to 1.0 for each criterion and an overall assessment.
            Format your response as JSON: {{"credibility": score, "compatibility": score, "customizability": score, "appropriate_red_flags": score, "overall_score": average, "feedback": "comments"}}
            """
            
            # Call Azure OpenAI for evaluation
            client = openai.AzureOpenAI(
                api_key=os.getenv("AZURE_OPENAI_API_KEY"),
                api_version=os.getenv("AZURE_OPENAI_API_VERSION", "2024-08-01-preview"),
                azure_endpoint=os.getenv("AZURE_OPENAI_ENDPOINT")
            )
            response = client.chat.completions.create(
                model=self.model,
                messages=[
                    {"role": "system", "content": "You are an expert in creating realistic phishing emails for cybersecurity training. Your goal is to create emails that seem legitimate but contain phishing elements."},
                    {"role": "user", "content": prompt}
                ],
                temperature=0.7,
                max_tokens=1000
            )
            # Extract and parse the evaluation
            evaluation_text = response.choices[0].message.content.strip()
            
            # Find JSON in the response (it may contain additional text)
            json_start = evaluation_text.find('{')
            json_end = evaluation_text.rfind('}') + 1
            if json_start >= 0 and json_end > json_start:
                evaluation_json = json.loads(evaluation_text[json_start:json_end])
            else:
                # Fallback if JSON parsing fails
                logger.warning("Failed to parse evaluation JSON, using default values")
                evaluation_json = {
                    "credibility": 0.7,
                    "compatibility": 0.7,
                    "customizability": 0.7,
                    "appropriate_red_flags": 0.7,
                    "overall_score": 0.7,
                    "feedback": "Evaluation parsing failed. This is a default response."
                }
            
            return evaluation_json
            
        except Exception as e:
            logger.error(f"Error during email evaluation: {str(e)}")
            # Return default evaluation on error
            return {
                "credibility": 0.5,
                "compatibility": 0.5,
                "customizability": 0.5,
                "appropriate_red_flags": 0.5,
                "overall_score": 0.5,
                "feedback": f"Evaluation failed due to error: {str(e)}"
            }
    
    def _refine_email(self, email_content: Dict, evaluation: Dict, target_data: Dict, difficulty: str) -> Dict:
        """Refine the email based on evaluation feedback"""
        
        try:
            # Create refinement prompt using evaluation feedback
            prompt = f"""
            Refine the following phishing email based on the evaluation feedback:
            
            ORIGINAL EMAIL:
            From: {email_content['from']}
            Subject: {email_content['subject']}
            Body: {email_content['body']}
            
            TARGET INFORMATION:
            {json.dumps(target_data, indent=2)}
            
            DIFFICULTY LEVEL: {difficulty}
            
            EVALUATION FEEDBACK:
            {evaluation['feedback']}
            
            SCORES:
            - Credibility: {evaluation['credibility']}
            - Compatibility: {evaluation['compatibility']}
            - Customizability: {evaluation['customizability']}
            - Appropriate Red Flags: {evaluation['appropriate_red_flags']}
            
            Please improve the email to address the weaknesses identified in the evaluation.
            Format the output as From: [sender], Subject: [subject line], Body: [email content]
            Do not include the actual URL in the output, just indicate where a link would be with [LINK].
            """
            
            # Call Azure OpenAI for refinement
            client = openai.AzureOpenAI(
                api_key=os.getenv("AZURE_OPENAI_API_KEY"),
                api_version=os.getenv("AZURE_OPENAI_API_VERSION", "2024-08-01-preview"),
                azure_endpoint=os.getenv("AZURE_OPENAI_ENDPOINT")
            )
            response = client.chat.completions.create(
                model=self.model,
                messages=[
                    {"role": "system", "content": "You are an expert in creating realistic phishing emails for cybersecurity training. Your goal is to create emails that seem legitimate but contain phishing elements."},
                    {"role": "user", "content": prompt}
                ],
                temperature=0.7,
                max_tokens=1000
            )
            refined_content = response.choices[0].message.content.strip()
            
            # Process the refined email to extract components
            refined_components = self._process_refined_email(refined_content)
            
            # Keep the original phishing URL
            refined_components["phishing_url"] = email_content["phishing_url"]
            
            logger.info("Email successfully refined based on feedback")
            return refined_components
            
        except Exception as e:
            logger.error(f"Error refining email: {str(e)}")
            # Return original email if refinement fails
            logger.info("Refinement failed, returning original email")
            return email_content
    
    def _process_refined_email(self, email_content: str) -> Dict:
        """Extract components from the refined email content"""
        
        components = {
            "from": "",
            "subject": "",
            "body": ""
        }
        
        # Extract the From field
        if "From:" in email_content:
            from_start = email_content.find("From:") + 5
            from_end = email_content.find("\n", from_start)
            components["from"] = email_content[from_start:from_end].strip()
        
        # Extract the Subject field
        if "Subject:" in email_content:
            subject_start = email_content.find("Subject:") + 8
            subject_end = email_content.find("\n", subject_start)
            components["subject"] = email_content[subject_start:subject_end].strip()
        
        # Extract the Body
        if "Body:" in email_content:
            body_start = email_content.find("Body:") + 5
            components["body"] = email_content[body_start:].strip()
        
        # If the extraction failed, use the whole content as body
        if not components["body"]:
            components["body"] = email_content
        
        return components

# Detection phase agents
class ContentAnalysisAgent(Agent):
    """Agent responsible for analyzing email content to detect phishing attempts"""
    
    def __init__(self):
        super().__init__("ContentAnalysis")
        self.model = os.getenv("AZURE_OPENAI_MODEL", "gpt-4")
        
    def process(self, email_content: Dict) -> Dict:
        """
        Analyze email content for phishing indicators
        
        Args:
            email_content: Dictionary containing email components
            
        Returns:
            Dictionary with analysis results and confidence score
        """
        logger.info("Analyzing email content for phishing indicators")
        
        try:
            # Create analysis prompt
            prompt = f"""
            Analyze the following email for potential phishing indicators:
            
            From: {email_content.get('from', 'Unknown')}
            Subject: {email_content.get('subject', 'No subject')}
            Body: 
            {email_content.get('body', 'No content')}
            
            INSTRUCTIONS:
            1. Identify any suspicious elements that suggest this might be a phishing attempt
            2. Check for urgency cues, requests for sensitive information, or suspicious links
            3. Analyze the sender address for legitimacy
            4. Look for grammatical errors, inconsistent formatting, or unusual tone
            5. Evaluate the overall credibility of the message
            
            Format your response as JSON with the following fields:
            - suspicious_elements: list of specific suspicious elements found
            - urgency_indicators: level of urgency (low, medium, high)
            - sensitive_info_requested: boolean
            - sender_legitimacy: assessment of sender legitimacy (low, medium, high)
            - grammar_spelling_issues: boolean
            - unusual_tone: boolean
            - overall_phishing_probability: score from 0.0 to 1.0
            - reasoning: brief explanation of your assessment
            """
            
            # Call Azure OpenAI for content analysis
            client = openai.AzureOpenAI(
                api_key=os.getenv("AZURE_OPENAI_API_KEY"),
                api_version=os.getenv("AZURE_OPENAI_API_VERSION", "2024-08-01-preview"),
                azure_endpoint=os.getenv("AZURE_OPENAI_ENDPOINT")
            )
            response = client.chat.completions.create(
                model=self.model,
                messages=[
                    {"role": "system", "content": "You are an expert in creating realistic phishing emails for cybersecurity training. Your goal is to create emails that seem legitimate but contain phishing elements."},
                    {"role": "user", "content": prompt}
                ],
                temperature=0.7,
                max_tokens=1000
            )
            analysis_text = response.choices[0].message.content.strip()
            
            # Extract JSON from response
            json_start = analysis_text.find('{')
            json_end = analysis_text.rfind('}') + 1
            if json_start >= 0 and json_end > json_start:
                analysis_result = json.loads(analysis_text[json_start:json_end])
            else:
                # Fallback if JSON parsing fails
                logger.warning("Failed to parse analysis JSON, using default values")
                analysis_result = {
                    "suspicious_elements": ["Parsing failed, using default analysis"],
                    "urgency_indicators": "medium",
                    "sensitive_info_requested": True,
                    "sender_legitimacy": "medium",
                    "grammar_spelling_issues": False,
                    "unusual_tone": False,
                    "overall_phishing_probability": 0.5,
                    "reasoning": "Analysis parsing failed. This is a default response."
                }
            
            logger.info(f"Content analysis complete with phishing probability: {analysis_result['overall_phishing_probability']:.2f}")
            return analysis_result
            
        except Exception as e:
            logger.error(f"Error analyzing email content: {str(e)}")
            # Return default analysis on error
            return {
                "suspicious_elements": [f"Analysis error: {str(e)}"],
                "urgency_indicators": "unknown",
                "sensitive_info_requested": False,
                "sender_legitimacy": "unknown",
                "grammar_spelling_issues": False,
                "unusual_tone": False,
                "overall_phishing_probability": 0.5,
                "reasoning": f"Content analysis failed due to error: {str(e)}"
            }

class URLAnalysisAgent(Agent):
    """Agent responsible for analyzing URLs for phishing indicators"""
    
    def __init__(self):
        super().__init__("URLAnalysis")
        self.api_key = os.getenv("VIRUSTOTAL_API_KEY")
        
    def process(self, url_data: Dict) -> Dict:
        """
        Analyze a URL for phishing indicators
        
        Args:
            url_data: Dictionary containing display_url and actual_url
            
        Returns:
            Dictionary with URL analysis results
        """
        logger.info(f"Analyzing URL: {url_data.get('display_url', 'None provided')}")
        
        display_url = url_data.get('display_url', '')
        actual_url = url_data.get('actual_url', '')
        
        # Basic analysis without API
        basic_analysis = self._perform_basic_analysis(display_url, actual_url)
        
        # Advanced analysis using VirusTotal API if available
        if self.api_key and actual_url:
            try:
                api_analysis = self._check_url_with_virustotal(actual_url)
                # Combine results
                analysis_result = {**basic_analysis, **api_analysis}
                logger.info(f"URL analysis complete: {basic_analysis['url_legitimacy_score']:.2f} (basic), {api_analysis.get('api_threat_score', 0):.2f} (API)")
            except Exception as e:
                logger.error(f"Error in VirusTotal API analysis: {str(e)}")
                analysis_result = basic_analysis
                logger.info(f"URL analysis complete (basic only): {basic_analysis['url_legitimacy_score']:.2f}")
        else:
            analysis_result = basic_analysis
            logger.info(f"URL analysis complete (basic only): {basic_analysis['url_legitimacy_score']:.2f}")
            
        return analysis_result
    
    def _perform_basic_analysis(self, display_url: str, actual_url: str) -> Dict:
        """Perform basic URL analysis without external APIs"""
        
        result = {
            "display_url": display_url,
            "actual_url": actual_url,
            "url_mismatch": display_url != actual_url,
            "suspicious_patterns": [],
            "url_legitimacy_score": 1.0,  # Start with perfect score and deduct based on issues
            "analysis_method": "basic"
        }
        
        # Check for URL mismatch
        if result["url_mismatch"]:
            result["suspicious_patterns"].append("Display URL does not match actual URL")
            result["url_legitimacy_score"] -= 0.3
        
        # Check for suspicious TLDs
        suspicious_tlds = ['.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top', '.club', '.work', '.live', '.online']
        for tld in suspicious_tlds:
            if actual_url.endswith(tld):
                result["suspicious_patterns"].append(f"Suspicious TLD: {tld}")
                result["url_legitimacy_score"] -= 0.2
                break
        
        # Check for IP address in URL
        import re
        ip_pattern = re.compile(r'https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}')
        if ip_pattern.search(actual_url):
            result["suspicious_patterns"].append("IP address used in URL instead of domain name")
            result["url_legitimacy_score"] -= 0.3
        
        # Check for excessive subdomains
        subdomain_count = len(actual_url.split('//')[1].split('/')[0].split('.')) - 2
        if subdomain_count > 3:
            result["suspicious_patterns"].append("Excessive number of subdomains")
            result["url_legitimacy_score"] -= 0.1
        
        # Check for URL shorteners
        shortener_services = ['bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'is.gd', 'cli.gs', 'pic.gd', 'ow.ly']
        for shortener in shortener_services:
            if shortener in actual_url:
                result["suspicious_patterns"].append(f"URL shortener detected: {shortener}")
                result["url_legitimacy_score"] -= 0.2
                break
        
        # Check for typosquatting (simple check)
        common_domains = ['google', 'microsoft', 'apple', 'amazon', 'facebook', 'paypal', 'netflix', 'bank']
        domain = actual_url.split('//')[1].split('/')[0].lower()
        
        for common_domain in common_domains:
            if common_domain in domain and common_domain not in display_url:
                # Check for typos (e.g., gooogle.com, micosoft.com)
                if re.search(f"{common_domain}[a-z]{{1,2}}\.com", domain) or re.search(f"{common_domain[:-1]}\.com", domain):
                    result["suspicious_patterns"].append(f"Possible typosquatting of {common_domain}")
                    result["url_legitimacy_score"] -= 0.25
        
        # Ensure the score is between 0 and 1
        result["url_legitimacy_score"] = max(0.0, min(1.0, result["url_legitimacy_score"]))
        
        return result
    
    def _check_url_with_virustotal(self, url: str) -> Dict:
        """Check a URL using the VirusTotal API"""
        
        if not self.api_key:
            return {"api_error": "VirusTotal API key not configured"}
        
        headers = {
            "x-apikey": self.api_key
        }
        
        # First, get a scan ID by submitting the URL
        try:
            # Endpoint for URL scanning
            scan_url = "https://www.virustotal.com/api/v3/urls"
            
            # Prepare the request data
            scan_data = {"url": url}
            
            # Submit the URL for scanning
            response = requests.post(scan_url, headers=headers, data=scan_data)
            response.raise_for_status()

            # Extract the analysis ID
            result = response.json()
            analysis_id = result.get("data", {}).get("id")
            
            if not analysis_id:
                return {"api_error": "Failed to get analysis ID from VirusTotal"}
            
            # Wait for a moment to allow the analysis to complete
            time.sleep(2)
            
            # Get the analysis results
            analysis_url = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"
            analysis_response = requests.get(analysis_url, headers=headers)
            analysis_response.raise_for_status()
            
            analysis_result = analysis_response.json()
            
            # Process the results
            stats = analysis_result.get("data", {}).get("attributes", {}).get("stats", {})
            malicious = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)
            harmless = stats.get("harmless", 0)
            total = malicious + suspicious + harmless + stats.get("undetected", 0)
            
            # Calculate threat score (0-1)
            api_threat_score = 0.0
            if total > 0:
                api_threat_score = (malicious + (suspicious * 0.5)) / total
            
            return {
                "api_analysis": "VirusTotal",
                "api_malicious_detections": malicious,
                "api_suspicious_detections": suspicious,
                "api_harmless_detections": harmless,
                "api_threat_score": api_threat_score,
                "analysis_method": "virustotal_api"
            }
            
        except requests.exceptions.RequestException as e:
            logger.error(f"VirusTotal API request error: {str(e)}")
            return {"api_error": f"VirusTotal API request failed: {str(e)}"}
        except json.JSONDecodeError as e:
            logger.error(f"VirusTotal API response parsing error: {str(e)}")
            return {"api_error": f"Failed to parse VirusTotal API response: {str(e)}"}
        except Exception as e:
            logger.error(f"Unexpected error in VirusTotal analysis: {str(e)}")
            return {"api_error": f"Unexpected error in VirusTotal analysis: {str(e)}"}

# Main orchestration classes
class AttackPhase:
    """Main class to orchestrate the phishing email generation process"""
    
    def __init__(self):
        """Initialize attack phase with required agents"""
        self.data_collector = DataCollectorAgent()
        self.email_generator = EmailGeneratorAgent()
        self.feedback_agent = FeedbackAgent()
        logger.info("Attack phase initialized with all required agents")
    
    def generate_phishing_email(self, target_info: Dict = None, difficulty: str = "moderate") -> Dict:
        """
        Generate a complete phishing email
        
        Args:
            target_info: Optional dictionary with target information
            difficulty: Email sophistication level ("easy", "moderate", "advanced")
            
        Returns:
            Dictionary containing the complete phishing email
        """
        logger.info(f"Starting phishing email generation process for {difficulty} difficulty")
        
        # Step 1: Collect and process target data
        target_data = self.data_collector.process(target_info)
        
        # Step 2: Generate initial phishing email
        email_content = self.email_generator.process(target_data, difficulty)
        
        # Step 3: Refine the email based on feedback
        refined_email = self.feedback_agent.process(email_content, target_data, difficulty)
        
        # Add metadata
        refined_email["difficulty"] = difficulty
        refined_email["target_data"] = target_data
        refined_email["generation_timestamp"] = time.strftime("%Y-%m-%d %H:%M:%S")
        
        logger.info(f"Phishing email generation complete for {difficulty} difficulty")
        return refined_email

class DetectionPhase:
    """Main class to orchestrate the phishing email detection process"""
    
    def __init__(self):
        """Initialize detection phase with required agents"""
        self.content_analyzer = ContentAnalysisAgent()
        self.url_analyzer = URLAnalysisAgent()
        logger.info("Detection phase initialized with all required agents")
    
    def detect_phishing(self, email_content: Dict) -> Dict:
        """
        Analyze an email to detect phishing attempts
        
        Args:
            email_content: Dictionary containing email components to analyze
            
        Returns:
            Dictionary with detection results and confidence scores
        """
        logger.info("Starting phishing detection process")
        
        # Step 1: Analyze email content
        content_analysis = self.content_analyzer.process(email_content)
        
        # Step 2: Analyze URL if present
        url_analysis = {}
        if "phishing_url" in email_content:
            url_analysis = self.url_analyzer.process(email_content["phishing_url"])
        
        # Step 3: Combine analyses and calculate overall threat score
        overall_score = content_analysis.get("overall_phishing_probability", 0.5)
        
        # Incorporate URL analysis if available
        if url_analysis:
            url_score = url_analysis.get("url_legitimacy_score", 0.5)
            # Invert URL legitimacy score (higher means more suspicious)
            url_phishing_score = 1.0 - url_score
            
            # Weight content analysis more heavily (70%) than URL analysis (30%)
            overall_score = (overall_score * 0.7) + (url_phishing_score * 0.3)
        
        # Determine threat level based on overall score
        threat_level = "Low"
        if overall_score >= 0.7:
            threat_level = "High"
        elif overall_score >= 0.4:
            threat_level = "Medium"
        
        # Compile detection results
        detection_result = {
            "content_analysis": content_analysis,
            "url_analysis": url_analysis,
            "overall_phishing_score": overall_score,
            "threat_level": threat_level,
            "detection_timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "recommendations": self._generate_recommendations(content_analysis, url_analysis, overall_score)
        }
        
        logger.info(f"Phishing detection complete with threat level: {threat_level}")
        return detection_result
    
    def _generate_recommendations(self, content_analysis: Dict, url_analysis: Dict, overall_score: float) -> List[str]:
        """Generate security recommendations based on analysis"""
        
        recommendations = []
        
        # Add general recommendations
        recommendations.append("Always verify the sender's email address by checking the full header information.")
        recommendations.append("Never click on suspicious links in emails; instead, type the URL directly in your browser.")
        
        # Add specific recommendations based on content analysis
        if content_analysis.get("urgency_indicators", "low") != "low":
            recommendations.append("Be cautious of emails that create a sense of urgency or pressure you to act quickly.")
        
        if content_analysis.get("sensitive_info_requested", False):
            recommendations.append("Legitimate organizations rarely request sensitive information via email.")
        
        if content_analysis.get("sender_legitimacy", "high") != "high":
            recommendations.append("Double-check the sender's identity by contacting them through an alternative, verified method.")
        
        # Add specific recommendations based on URL analysis
        if url_analysis:
            if url_analysis.get("url_mismatch", False):
                recommendations.append("Hover over links to preview the actual destination before clicking.")
            
            if url_analysis.get("suspicious_patterns", []):
                recommendations.append("Look for unusual characters or misspellings in URLs that might indicate spoofing.")
        
        # Add recommendation based on overall score
        if overall_score >= 0.7:
            recommendations.append("This appears to be a phishing attempt. Report it to your IT security team immediately.")
        elif overall_score >= 0.4:
            recommendations.append("This email contains suspicious elements. Proceed with caution and verify legitimacy before taking action.")
        
        return recommendations