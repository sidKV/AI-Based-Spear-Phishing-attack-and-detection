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
    tab1, tab2, tab3 = st.tabs(["Content Analysis", "Header Analysis", "Recommendations"])
    
    with tab1:
        if "content_analysis" in detection_data:
            content = detection_data["content_analysis"]
            st.markdown("### Content Analysis Results")
            
            # Display found URLs and their analysis
            if "found_urls" in content and "url_analysis" in content:
                st.markdown("#### URLs Found in Email:")
                for url, analysis in zip(content["found_urls"], content["url_analysis"]):
                    st.markdown(f"**URL:** {url['display_url']}")
                    st.markdown(f"**Legitimacy Score:** {analysis.get('url_legitimacy_score', 0):.2f}")
                    if analysis.get("suspicious_patterns"):
                        st.markdown("**Suspicious Patterns:**")
                        for pattern in analysis["suspicious_patterns"]:
                            st.markdown(f"- {pattern}")
                    if "api_analysis" in analysis:
                        st.markdown(f"**VirusTotal Analysis:**")
                        st.markdown(f"- Malicious Detections: {analysis.get('api_malicious_detections', 0)}")
                        st.markdown(f"- Suspicious Detections: {analysis.get('api_suspicious_detections', 0)}")
                    st.divider()
            
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
        if "header_analysis" in detection_data:
            header_data = detection_data["header_analysis"]
            st.markdown("### Email Header Analysis")
            
            # Display authentication results
            st.markdown("#### Email Authentication:")
            auth_status = header_data.get("authentication_status", {})
            col1, col2, col3 = st.columns(3)
            with col1:
                st.metric("SPF", "Pass" if auth_status.get("spf") else "Fail")
            with col2:
                st.metric("DKIM", "Pass" if auth_status.get("dkim") else "Fail")
            with col3:
                st.metric("DMARC", "Pass" if auth_status.get("dmarc") else "Fail")
            
            # Display suspicious patterns
            st.markdown("#### Suspicious Patterns:")
            for pattern in header_data.get("suspicious_patterns", ["None detected"]):
                st.markdown(f"- {pattern}")
            
            # Display legitimacy score
            st.metric("Header Legitimacy Score", 
                     f"{header_data.get('header_legitimacy_score', 0)::.2f}")
        else:
            st.info("No header analysis available.")
    
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
    
    with st.expander("Target Information", expanded=True):
        col1, col2 = st.columns(2)
        
        with col1:
            target_name = st.text_input("Name", "John Smith")
            target_email = st.text_input("Email", "john.smith@example.com")
            target_company = st.text_input("Company", "Acme Corporation")
        
        with col2:
            communication_style = st.selectbox("Communication Style", ["formal", "casual", "technical", "friendly"])
            email_context = st.text_area("Email Context", 
                "Context: Security policy update notification requiring immediate action from IT staff.",
                help="Provide context or scenario for the phishing email")
    
    # Custom URL settings
    with st.expander("Custom URL Settings", expanded=False):
        use_custom_url = st.checkbox("Use Custom URL")
        if use_custom_url:
            custom_display_url = st.text_input("Display URL", "https://company.com/login")
            custom_actual_url = st.text_input("Actual URL", "https://malicious.com/phish")
            custom_url_type = st.selectbox("URL Type", ["obvious_mismatch", "similar_domain", "typosquatting"])
    
    # Difficulty setting
    difficulty = st.select_slider("Difficulty Level", ["easy", "moderate", "advanced"], value="moderate")
    
    # Generate button
    if st.button("Generate Phishing Email"):
        with st.spinner("Generating phishing email..."):
            target_info = {
                "name": target_name,
                "email": target_email,
                "company": target_company,
                "communication_style": communication_style,
                "context": email_context
            }
            
            # Add custom URL if specified
            if use_custom_url:
                target_info["custom_url"] = {
                    "display_url": custom_display_url,
                    "actual_url": custom_actual_url,
                    "type": custom_url_type
                }
            
            attack_phase = AttackPhase()
            email_data = attack_phase.generate_phishing_email(target_info, difficulty)
            display_phishing_email(email_data)
            st.session_state.last_generated_email = email_data
            if st.button("Test Detection on This Email"):
                st.session_state.page = "Detect Phishing"
                st.session_state.test_generated = True
                st.experimental_rerun()

# Detect Phishing page
elif page == "Detect Phishing":
    st.title("Detect Phishing")
    
    # Add file upload section
    uploaded_file = st.file_uploader("Upload Email File (.eml)", type=['eml'])
    
    if uploaded_file:
        with st.spinner("Analyzing email..."):
            # Process .eml file
            import email
            eml_content = uploaded_file.read().decode()
            email_message = email.message_from_string(eml_content)
            
            # Extract headers and body
            headers = dict(email_message.items())
            body = ""
            if email_message.is_multipart():
                for part in email_message.walk():
                    if part.get_content_type() == "text/plain":
                        body = part.get_payload(decode=True).decode()
                        break
            else:
                body = email_message.get_payload(decode=True).decode()
            
            # Prepare email data for analysis
            email_data = {
                "from": headers.get("From", "Unknown"),
                "subject": headers.get("Subject", "No Subject"),
                "body": body,
                "headers": headers
            }
            
            # Run detection
            detection_phase = DetectionPhase()
            detection_results = detection_phase.detect_phishing(email_data)
            display_detection_results(detection_results)
    
    st.markdown("### Or Enter Email Details Manually")
    
    with st.expander("Email Input", expanded=True):
        email_from = st.text_input("From", "it-support@acmecorp.net")
        email_subject = st.text_input("Subject", "Urgent: Security Alert")
        email_body = st.text_area("Email Body", height=200)
        
        if st.button("Analyze Email"):
            with st.spinner("Analyzing email for phishing indicators..."):
                email_data = {
                    "from": email_from,
                    "subject": email_subject,
                    "body": email_body
                }
                detection_phase = DetectionPhase()
                detection_results = detection_phase.detect_phishing(email_data)
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