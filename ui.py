import streamlit as st
import json
import time
import os
from dotenv import load_dotenv
from agent import AttackPhase, DetectionPhase

# Load environment variables
load_dotenv()

# Set page configuration
st.set_page_config(
    page_title="Phishing Simulation & Detection Tool",
    page_icon="🔒",
    layout="wide"
)

# Sidebar for navigation
st.sidebar.title("Navigation")
page = st.sidebar.radio("Go to", ["Home", "Generate Phishing Email", "Detect Phishing", "About"])

# Functions for the application
def display_phishing_email(email_data):
    """Display the generated phishing email in a readable format"""
    
    st.subheader("Generated Phishing Email")
    
    col1, col2 = st.columns([3, 1])
    
    with col1:
        st.markdown("### Email Details")
        st.markdown(f"**From:** {email_data.get('from', 'N/A')}")
        st.markdown(f"**Subject:** {email_data.get('subject', 'N/A')}")
        st.markdown("**Body:**")
        st.markdown(email_data.get('body', 'N/A').replace('[LINK]', f"[Click Here]({email_data.get('phishing_url', {}).get('display_url', '#')})"))
        
        st.divider()
        st.markdown("### Phishing URL Details")
        st.markdown(f"**Display URL:** {email_data.get('phishing_url', {}).get('display_url', 'N/A')}")
        st.markdown(f"**Actual URL:** {email_data.get('phishing_url', {}).get('actual_url', 'N/A')}")
        st.markdown(f"**Type:** {email_data.get('phishing_url', {}).get('type', 'N/A')}")
    
    with col2:
        st.markdown("### Evaluation Scores")
        
        if "evaluation" in email_data:
            eval_data = email_data["evaluation"]
            
            # Create a metrics display
            st.metric("Overall Score", f"{eval_data.get('overall_score', 0):.2f}")
            st.metric("Credibility", f"{eval_data.get('credibility', 0):.2f}")
            st.metric("Compatibility", f"{eval_data.get('compatibility', 0):.2f}")
            st.metric("Customizability", f"{eval_data.get('customizability', 0):.2f}")
            st.metric("Red Flags", f"{eval_data.get('appropriate_red_flags', 0):.2f}")
            
            # Show feedback
            st.markdown("### Feedback")
            st.markdown(eval_data.get('feedback', 'No feedback available'))

def display_detection_results(detection_data):
    """Display the phishing detection results"""
    
    st.subheader("Phishing Detection Results")
    
    # Display threat level with appropriate color
    threat_level = detection_data.get('threat_level', 'Unknown')
    threat_color = {
        "Low": "green",
        "Medium": "orange",
        "High": "red",
        "Unknown": "gray"
    }
    
    st.markdown(f"### Threat Level: <span style='color:{threat_color[threat_level]}'>{threat_level}</span>", unsafe_allow_html=True)
    st.metric("Overall Phishing Score", f"{detection_data.get('overall_phishing_score', 0):.2f}")
    
    # Create tabs for different analysis results
    tab1, tab2, tab3 = st.tabs(["Content Analysis", "URL Analysis", "Recommendations"])
    
    with tab1:
        if "content_analysis" in detection_data:
            content = detection_data["content_analysis"]
            st.markdown("### Content Analysis Results")
            
            # Display suspicious elements as bullets
            st.markdown("#### Suspicious Elements:")
            for element in content.get("suspicious_elements", ["None detected"]):
                st.markdown(f"- {element}")
            
            # Create metrics for content analysis
            col1, col2, col3 = st.columns(3)
            with col1:
                st.metric("Urgency Level", content.get("urgency_indicators", "unknown").title())
            with col2:
                st.metric("Sensitive Info Requested", "Yes" if content.get("sensitive_info_requested", False) else "No")
            with col3:
                st.metric("Sender Legitimacy", content.get("sender_legitimacy", "unknown").title())
            
            col1, col2 = st.columns(2)
            with col1:
                st.metric("Grammar/Spelling Issues", "Yes" if content.get("grammar_spelling_issues", False) else "No")
            with col2:
                st.metric("Unusual Tone", "Yes" if content.get("unusual_tone", False) else "No")
            
            # Display reasoning
            st.markdown("#### Analysis Reasoning:")
            st.markdown(content.get("reasoning", "No reasoning provided"))
    
    with tab2:
        if "url_analysis" in detection_data and detection_data["url_analysis"]:
            url_data = detection_data["url_analysis"]
            st.markdown("### URL Analysis Results")
            
            # Display URL mismatch warning
            if url_data.get("url_mismatch", False):
                st.warning("⚠️ Display URL does not match actual URL - a common phishing indicator!")
            
            # Display URLs
            st.markdown(f"**Display URL:** {url_data.get('display_url', 'N/A')}")
            st.markdown(f"**Actual URL:** {url_data.get('actual_url', 'N/A')}")
            
            # Display suspicious patterns as bullets
            st.markdown("#### Suspicious Patterns:")
            for pattern in url_data.get("suspicious_patterns", ["None detected"]):
                st.markdown(f"- {pattern}")
            
            # Display legitimacy score
            st.metric("URL Legitimacy Score", f"{url_data.get('url_legitimacy_score', 0):.2f}")
            
            # Display VirusTotal results if available
            if "api_analysis" in url_data and url_data["api_analysis"] == "VirusTotal":
                st.markdown("#### VirusTotal Analysis:")
                col1, col2, col3 = st.columns(3)
                with col1:
                    st.metric("Malicious Detections", url_data.get("api_malicious_detections", 0))
                with col2:  
                    st.metric("Suspicious Detections", url_data.get("api_suspicious_detections", 0))
                with col3:
                    st.metric("Harmless Detections", url_data.get("api_harmless_detections", 0))
                
                st.metric("API Threat Score", f"{url_data.get('api_threat_score', 0):.2f}")
        else:
            st.info("No URL analysis data available.")
    
    with tab3:
        st.markdown("### Security Recommendations")
        for recommendation in detection_data.get("recommendations", ["No recommendations available"]):
            st.markdown(f"- {recommendation}")

# Home page
if page == "Home":
    st.title("🔒 Phishing Simulation & Detection Tool")
    
    st.markdown("""
    ## Welcome to the Phishing Simulation & Detection Tool
    
    This application provides capabilities for:
    
    1. **Generating realistic phishing emails** - Create customized phishing emails for security awareness training
    2. **Detecting phishing attempts** - Analyze emails for indicators of phishing attacks
    
    ### Getting Started
    
    - Use the sidebar navigation to access different features
    - Generate sample phishing emails with varying difficulty levels
    - Test the detection capabilities against both generated and real emails
    
    > **Note:** This tool is intended for cybersecurity education and awareness purposes only.
    """)
    
    # Key features section
    st.subheader("Key Features")
    col1, col2 = st.columns(2)
    
    with col1:
        st.markdown("#### Attack Phase")
        st.markdown("- Data collection about targets")
        st.markdown("- Email generation using AI")
        st.markdown("- Quality evaluation and refinement")
        st.markdown("- Customizable difficulty levels")
    
    with col2:
        st.markdown("#### Detection Phase")
        st.markdown("- Content analysis for phishing indicators")
        st.markdown("- URL analysis for suspicious patterns")
        st.markdown("- VirusTotal API integration (optional)")
        st.markdown("- Comprehensive security recommendations")

# Generate Phishing Email page
elif page == "Generate Phishing Email":
    st.title("Generate Phishing Email")
    st.markdown("Create realistic phishing emails using the V-Triad framework with customizable settings")
    
    # Form for target information
    with st.expander("Target Information", expanded=True):
        col1, col2 = st.columns(2)
        
        with col1:
            target_name = st.text_input("Name", "John Smith")
            target_email = st.text_input("Email", "john.smith@example.com")
            target_position = st.text_input("Position", "IT Manager")
            target_company = st.text_input("Company", "Acme Corporation")
        
        with col2:
            target_department = st.text_input("Department", "Information Technology")
            target_colleagues = st.text_input("Colleagues (comma separated)", "Sarah Johnson, Mike Peters")
            target_projects = st.text_input("Recent Projects (comma separated)", "Cloud Migration, Security Audit")
            target_interests = st.text_input("Interests (comma separated)", "Cybersecurity, Cloud Computing")
    
    # Additional settings
    col1, col2 = st.columns(2)
    
    with col1:
        communication_style = st.selectbox("Communication Style", ["formal", "casual", "technical", "friendly"])
        # Add these fields below the communication_style section:
        st.subheader("Custom Phishing URL (Optional)")
        use_custom_url = st.checkbox("Use custom phishing URL")
        if use_custom_url:
            custom_display_url = st.text_input("Display URL (what the user sees)", "https://secure-login.company.com")
            custom_actual_url = st.text_input("Actual URL (where link goes)", "https://malicious-site.com/phish")
            custom_url_type = st.selectbox("URL Type", ["obvious_mismatch", "similar_domain", "typosquatting"])
    
    with col2:
        difficulty = st.select_slider("Difficulty Level", ["easy", "moderate", "advanced"], value="moderate")
    
    # Generate button
    if st.button("Generate Phishing Email"):
        with st.spinner("Generating phishing email..."):
            # Prepare target information
            target_info = {
                "name": target_name,
                "email": target_email,
                "position": target_position,
                "company": target_company,
                "department": target_department,
                "colleagues": [colleague.strip() for colleague in target_colleagues.split(",")],
                "recent_projects": [project.strip() for project in target_projects.split(",")],
                "interests": [interest.strip() for interest in target_interests.split(",")],
                "communication_style": communication_style,
                "social_media": {
                    "linkedin": f"linkedin.com/in/{target_name.lower().replace(' ', '')}"
                }
            }

            attack_phase = AttackPhase()

            # After creating the AttackPhase instance but before generating the email:
            if 'use_custom_url' in locals() and use_custom_url:
                # Add custom URL to overwrite the generated one after email creation
                custom_url_data = {
                    "display_url": custom_display_url,
                    "actual_url": custom_actual_url,
                    "type": custom_url_type
                }
                
                # Generate the email
                email_data = attack_phase.generate_phishing_email(target_info, difficulty)
                
                # Override the URL with custom values
                email_data["phishing_url"] = custom_url_data
            else:
                # Generate normally
                email_data = attack_phase.generate_phishing_email(target_info, difficulty)
            
            # Display the generated email
            display_phishing_email(email_data)
            
            # Allow saving the generated email for detection testing
            st.session_state.last_generated_email = email_data
            
            # Add button to test detection on this email
            if st.button("Test Detection on This Email"):
                st.session_state.page = "Detect Phishing"
                st.session_state.test_generated = True
                st.experimental_rerun()

# Detect Phishing page
elif page == "Detect Phishing":
    st.title("Detect Phishing")
    st.markdown("Analyze emails for phishing indicators using content and URL analysis")
    
    # Check if we should use a previously generated email
    if hasattr(st.session_state, 'test_generated') and st.session_state.test_generated and hasattr(st.session_state, 'last_generated_email'):
        email_data = st.session_state.last_generated_email
        st.info("Using previously generated phishing email for detection testing")
        
        # Display the email to be analyzed
        st.subheader("Email to Analyze")
        st.markdown(f"**From:** {email_data.get('from', 'N/A')}")
        st.markdown(f"**Subject:** {email_data.get('subject', 'N/A')}")
        st.markdown("**Body:**")
        st.markdown(email_data.get('body', 'N/A'))
        
        # Reset the test_generated flag
        st.session_state.test_generated = False
        
        # Run detection automatically
        with st.spinner("Analyzing email for phishing indicators..."):
            detection_phase = DetectionPhase()
            detection_results = detection_phase.detect_phishing(email_data)
            
            # Display detection results
            display_detection_results(detection_results)
    
    else:
        # Input form for manual email analysis
        with st.expander("Email Input", expanded=True):
            email_from = st.text_input("From", "it-support@acmecorp.net")
            email_subject = st.text_input("Subject", "Urgent: Security Alert - Action Required")
            email_body = st.text_area("Email Body", """Dear John,

We have detected unusual sign-in activity on your account. To secure your account, please verify your identity by clicking the link below:

[LINK]

If you don't take action within 24 hours, your account will be temporarily suspended for security reasons.

Thank you,
IT Support Team
Acme Corporation""", height=200)
            
            # URL information
            st.subheader("URL Information (if present)")
            display_url = st.text_input("Display URL", "https://acmecorp.com/account-verification")
            actual_url = st.text_input("Actual URL", "https://acmec0rp-secure.co/login.php")
        
        # Run detection
        if st.button("Analyze Email"):
            with st.spinner("Analyzing email for phishing indicators..."):
                # Prepare email data
                email_data = {
                    "from": email_from,
                    "subject": email_subject,
                    "body": email_body,
                    "phishing_url": {
                        "display_url": display_url,
                        "actual_url": actual_url,
                        "type": "unknown"
                    }
                }
                
                # Create DetectionPhase instance and analyze email
                detection_phase = DetectionPhase()
                detection_results = detection_phase.detect_phishing(email_data)
                
                # Display detection results
                display_detection_results(detection_results)

# About page
elif page == "About":
    st.title("About This Tool")
    
    st.markdown("""
    ## Phishing Simulation & Detection Tool
    
    This application provides cybersecurity professionals and trainers with a powerful platform for creating realistic phishing simulations and detecting potential phishing threats. It uses AI-powered agents to analyze and generate content based on the V-Triad framework.
    
    ### Key Components
    
    #### Attack Phase
    - **Data Collector Agent**: Gathers and normalizes target information
    - **Email Generator Agent**: Creates realistic phishing emails using the V-Triad framework
    - **Feedback Agent**: Analyzes and refines emails based on quality criteria
    
    #### Detection Phase
    - **Content Analysis Agent**: Analyzes email content for phishing indicators
    - **URL Analysis Agent**: Identifies suspicious patterns in URLs
    
    ### V-Triad Framework
    
    The tool implements the V-Triad framework for creating effective phishing simulations:
    
    1. **Credibility**: Establishing trust through impersonation and context
    2. **Compatibility**: Tailoring content to match the target's environment
    3. **Customizability**: Personalizing elements to increase relevance
    
    ### Technologies
    
    - **Python**: Core language for agent implementation
    - **Streamlit**: Web interface framework
    - **Azure OpenAI**: AI-powered text generation and analysis
    - **VirusTotal API**: URL reputation checking (optional)
    
    > **Important**: This tool is intended for educational purposes and security awareness training only. Use responsibly and ethically.
    """)
    
    st.subheader("API Configuration")
    st.markdown("""
    To use all features of this application, configure the following in your `.env` file:
    
    ```
    # Azure OpenAI Configuration
    AZURE_OPENAI_API_KEY=your_azure_openai_key
    AZURE_OPENAI_ENDPOINT=your_azure_endpoint
    AZURE_OPENAI_MODEL=your_model_deployment_name
    
    # VirusTotal API (Optional)
    VIRUSTOTAL_API_KEY=your_virustotal_api_key
    ```
    """)

# Run the app
if __name__ == "__main__":
    # Check if OpenAI API key is available
    if not os.getenv("AZURE_OPENAI_API_KEY"):
        st.warning("⚠️ Azure OpenAI API Key not found. Some functionality may be limited.")