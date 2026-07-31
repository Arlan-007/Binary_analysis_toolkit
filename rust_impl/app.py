import streamlit as st
import subprocess
import os
import re

st.set_page_config(page_title="Threat Intelligence Dashboard", layout="wide", page_icon="🛡️")

# Customized Styling
st.markdown("""
    <style>
    .metric-box { padding: 20px; border-radius: 10px; background-color: #1E1E1E; border-left: 5px solid #FF4B4B; margin-bottom: 15px;}
    .risk-title { font-weight: bold; color: #FF4B4B; font-size: 24px; }
    </style>
""", unsafe_allow_html=True)

st.title("🛡️ Threat Intelligence & Reverse Engineering Dashboard")
st.caption("A graphical layout for your compiled Rust binary analysis engine output")

target_file = st.text_input("📁 Path to executable target:", value=r"C:\Windows\System32\notepad.exe")

if st.button("Analyze System Binary", type="primary"):
    with st.spinner("Decompiling headers and scanning sections..."):
        binary_path = os.path.abspath("target/debug/rust_impl.exe")
        process = subprocess.run([binary_path, target_file], capture_output=True, text=True)
        
        if process.returncode == 0:
            output = process.stdout
            
            # Extract basic metrics using Regular Expressions
            fmt = re.search(r"Format:\s*(\w+)", output).group(1) if re.search(r"Format:\s*(\w+)", output) else "Unknown"
            arch = re.search(r"Architecture:\s*([\w_-]+)", output).group(1) if re.search(r"Architecture:\s*([\w_-]+)", output) else "Unknown"
            strings_count = re.search(r"Found\s*(\d+)\s*strings", output).group(1) if re.search(r"Found\s*(\d+)\s*strings", output) else "0"
            imports_count = re.search(r"Found\s*(\d+)\s*imports", output).group(1) if re.search(r"Found\s*(\d+)\s*imports", output) else "0"
            
            # Extract Risk Summary Score
            score_match = re.search(r"score:\s*(\d+)", output)
            score = score_match.group(1) if score_match else "0"
            level_match = re.search(r"level:\s*(\w+)", output)
            level = level_match.group(1) if level_match else "Unknown"

            # Layout metrics columns
            col1, col2, col3, col4 = st.columns(4)
            col1.metric("Risk Score", f"{score} / 100", delta=level, delta_color="inverse")
            col2.metric("File Format", fmt)
            col3.metric("Architecture", arch)
            col4.metric("Extracted Strings", strings_count)
            
            # Separate the detailed rules list
            st.write("---")
            
            # FIXED: Specified 2 columns here
            left_pane, right_pane = st.columns(2)
            
            with left_pane:
                st.subheader("⚠️ Capability Detection Logs")
                findings = [line.strip() for line in output.split('\n') if "[Low]" in line or "[Medium]" in line or "[High]" in line]
                for finding in findings:
                    if "[High]" in finding:
                        st.error(finding)
                    elif "[Medium]" in finding:
                        st.warning(finding)
                    else:
                        st.info(finding)
                        
            with right_pane:
                st.subheader("⚙️ Static Features")
                features_match = re.search(r"Code features:\s*(.*)", output)
                if features_match:
                    features_str = features_match.group(1).replace(" ", "\n- ")
                    st.markdown(f"- {features_str}")
                
                st.subheader("📊 Raw Terminal Output Dump")
                st.text_area("Complete Log", output, height=250)
        else:
            st.error(f"Error executing engine:\n{process.stderr}")
