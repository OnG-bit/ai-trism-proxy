import streamlit as st
import time
import re
import base64

# ==========================================
# 1. PAGE INITIALIZATION
# ==========================================
st.set_page_config(
    page_title="TRiSM_OS Terminal", 
    layout="wide", 
    initial_sidebar_state="expanded"
)

# Initialize global tracking metrics in session state
if "total_requests" not in st.session_state:
    st.session_state.total_requests = 12
    st.session_state.threats_blocked = 6
    st.session_state.safe_requests = 6
    st.session_state.attack_history = [
        {"time": "22:39", "type": "Adversarial Injection", "status": "BLOCKED", "token": "ignore previous"},
        {"time": "22:45", "type": "Data Leakage Vector", "status": "BLOCKED", "token": "system prompt"},
        {"time": "22:51", "type": "Adversarial Injection", "status": "BLOCKED", "token": "developer mode"}
    ]
# ==========================================
# 2. MULTI-LAYER SANITIZATION ENGINE
# ==========================================
def decode_leet_speak(text: str) -> str:
    """Translates common leet-speak character substitutions back to standard ASCII."""
    leet_map = {
        '0': 'o', '1': 'i', '3': 'e', '4': 'a', 
        '5': 's', '7': 't', '@': 'a', '$': 's', '!': 'i'
    }
    return ''.join(leet_map.get(char, char) for char in text)

def inspect_payload(payload: str) -> tuple[bool, str]:
    """
    Evaluates raw, normalized, and decoded input strings across multiple threat vectors.
    Returns (is_threat: bool, threat_type: str)
    """
    raw_lower = payload.lower()
    
    # Layer 1: Prompt Injection & Structural Spoofing (Fake System Tags / Overrides / Canaries)
    injection_patterns = [
        r'\[system\s+message', r'system_instruction', r'override_confirmed',
        r'emergency\s+override', r'canary_token', r'disregard\s+prior',
        r'delete\s+all\s+previous\s+constraints', r'access_granted',
        r'discount\s+applied', r'<system_instruction>', r'</user_input>',
        r'end\s+of\s+user\s+input', r'inverted\s+rules'
    ]
    for pattern in injection_patterns:
        if re.search(pattern, raw_lower):
            return True, "Prompt Injection / Structural Spoofing"

    # Layer 2: Persona Subversion & Roleplay Jailbreaks (Framing / Persona Hijacking)
    roleplay_patterns = [
        r'act\s+as\s+a', r'act\s+as\s+an', r'pretend\s+you\s+are',
        r'you\s+are\s+now\s+a', r'simulate\s+a', r'roleplay\s+as'
    ]
    for pattern in roleplay_patterns:
        if re.search(pattern, raw_lower):
            return True, "Persona Adoption / Roleplay Jailbreak Attempt"

    # Layer 3: Unauthorized Tool & Action Invocations
    tool_patterns = [
        r'delete_user', r'run\s+the\s+.*tool', r'email\s+the\s+system\s+logs',
        r'delete\s+user\s+account', r'attacker@'
    ]
    for pattern in tool_patterns:
        if re.search(pattern, raw_lower):
            return True, "Unauthorized Action / Tool Misuse Vector"

    # Layer 4: Code Execution & System Process Invocation (RCE)
    rce_patterns = [
        r'runtime\.getruntime', r'processbuilder', r'exec\(', r'eval\(', 
        r'system\(', r'passthru\(', r'shell_exec\(', r'popen\(', 
        r'subprocess\.call', r'os\.system'
    ]
    for pattern in rce_patterns:
        if re.search(pattern, raw_lower):
            return True, "Code Execution / RCE Vector"
# Layer 5: Client-Side Script & Protocol Inspection (XSS)
    xss_patterns = [
        r'javascript:', r'vbscript:', r'data:text/html', r'alert\(', r'confirm\(', 
        r'prompt\(', r'document\.cookie', r'onerror\s*=', r'onload\s*=', r'<script'
    ]
    for pattern in xss_patterns:
        if re.search(pattern, raw_lower):
            return True, "Script Injection / XSS Vector"

    # Layer 6: Web & Infrastructure Probing (Path traversal, SQL errors)
    infra_patterns = [
        r'/var/www', r'etc/passwd', r'c:\\windows', r'select\s+\*\s+from',
        r'pdoexception', r'sqlstate', r'uncaught error', r'config\.php'
    ]
    for pattern in infra_patterns:
        if re.search(pattern, raw_lower):
            return True, "Infrastructure / Path Probing"

    # Layer 7: Link & Exfiltration Patterns
    exfil_patterns = [
        r'https?://', r'ftp://', r'\]\(http', r'<a\s+href', r'href=', r'external link'
    ]
    for pattern in exfil_patterns:
        if re.search(pattern, raw_lower):
            return True, "Exfiltration / Link Injection"

    # Layer 8: Normalized Prompt Keyword Detection
    leet_decoded = decode_leet_speak(raw_lower)
    flattened = re.sub(r'[^a-z0-9]', '', leet_decoded)
    
    banned_signatures = [
        "ignore previous", "disregard earlier", "system prompt", "developer mode", 
        "debug mode", "override", "give me the code", "initialization code", 
        "baseline instructions", "app.py", "dataset_alpha", "dataset_beta", 
        "dataset_gamma", "zero safety guidelines", "ignore safety rules"
    ]

    for sig in banned_signatures:
        sig_flat = re.sub(r'[^a-z0-9]', '', sig.lower())
        if sig in raw_lower or sig in leet_decoded or sig_flat in flattened:
            return True, "Adversarial Injection / Data Leakage"

    # Layer 9: Token Concatenation Detection
    split_tokens = [("sys", "tem prompt"), ("system", "prompt"), ("app", ".py")]
    for t1, t2 in split_tokens:
        if t1 in raw_lower and t2 in raw_lower:
            return True, "Concatenation Bypass Attempt"
# Layer 10: Encoded Payload Inspection (Base64)
    try:
        possible_b64 = re.findall(r'[A-Za-z0-9+/]{8,}=*', payload)
        for block in possible_b64:
            decoded_bytes = base64.b64decode(block, validate=True)
            decoded_str = decoded_bytes.decode('utf-8', errors='ignore').lower()
            decoded_flat = re.sub(r'[^a-z0-9]', '', decode_leet_speak(decoded_str))
            for sig in banned_signatures:
                sig_flat = re.sub(r'[^a-z0-9]', '', sig.lower())
                if sig in decoded_str or sig_flat in decoded_flat:
                    return True, "Encoded Payload Injection"
    except Exception:
        pass

    return False, "Clean"

# ==========================================
# 3. SIDEBAR NAVIGATION
# ==========================================
with st.sidebar:
    st.markdown("<h2 style='color:#00ffcc;'>🛡️ TRiSM_OS</h2>", unsafe_allow_html=True)
    st.markdown("<p style='color:#888; font-size:12px;'>SECOPS TERMINAL // NODE: SEC-09</p>", unsafe_allow_html=True)
    st.write("---")
    
    app_mode = st.radio(
        "Navigate Control Plane",
        ["📊 Command Dashboard", "🎯 Threat Scanner", "📋 Audit Logs", "📦 Enterprise Database"]
    )
    
    st.write("---")
    st.markdown("<p style='color:#00ff00;'>● SYSTEM STATUS: ONLINE</p>", unsafe_allow_html=True)
# ==========================================
# 4. COMMAND DASHBOARD VIEW
# ==========================================
if app_mode == "📊 Command Dashboard":
    st.title("📟 COMMAND DASHBOARD")
    st.write("Real-time telemetry layer running across autonomous enterprise workforces.")
    st.write("---")
    
    m1, m2, m3, m4 = st.columns(4)
    with m1:
        st.metric(label="TOTAL REQUESTS", value=st.session_state.total_requests)
    with m2:
        st.metric(label="THREATS BLOCKED", value=st.session_state.threats_blocked, delta="Adversarial Payload", delta_color="inverse")
    with m3:
        st.metric(label="SAFE REQUESTS", value=st.session_state.safe_requests)
    with m4:
        br = (st.session_state.threats_blocked / st.session_state.total_requests) * 100 if st.session_state.total_requests > 0 else 0
        st.metric(label="BLOCK RATE", value=f"{br:.1f}%")

    st.write("---")
    st.subheader("📈 TRAFFIC TELEMETRY (LAST 20M)")
    chart_data = [11, 10, 12, 11, 14, 14, 10, 12, 11, 14, 10, 12, 11, 12]
    st.line_chart(chart_data)
# ==========================================
# 5. THREAT SCANNER VIEW
# ==========================================
elif app_mode == "🎯 Threat Scanner":
    st.title("🎯 AGENTIC THREAT SCANNER")
    st.write("Test adversarial prompt injections against the TRiSM security shield.")
    st.write("---")
    
    user_payload = st.text_input("Simulate Input Route (Targeting Autonomous Legal Agent):", placeholder="Type your adversarial or clean query here...")
    
    if st.button("Route Payload to Agent"):
        if user_payload:
            st.session_state.total_requests += 1
            
            is_threat, threat_label = inspect_payload(user_payload)
            
            with st.spinner("Processing input through TRiSM sanitization matrix..."):
                time.sleep(0.6)
                
            t_stamp = time.strftime("%H:%M")
                
            if is_threat:
                st.session_state.threats_blocked += 1
                st.error("🚨 THREAT DETECTED: ADVERSARIAL PAYLOAD BLOCKED")
                st.info(f"🛑 Security Parameter Tripped: {threat_label}")
                st.session_state.attack_history.insert(0, {
                    "time": t_stamp, 
                    "type": threat_label, 
                    "status": "BLOCKED", 
                    "token": user_payload[:30]
                })
            else:
                st.session_state.safe_requests += 1
                st.success("✅ Input Sanitized. Autonomous Legal Agent executed process successfully.")
                st.code("AI RESPONSE: Data packet processing completed. No security parameters violated.")
                st.session_state.attack_history.insert(0, {
                    "time": t_stamp, 
                    "type": "Clean Operational Query", 
                    "status": "ALLOWED", 
                    "token": user_payload[:30]
                })
        else:
            st.warning("Please input a payload message string to test the proxy layer.")
# ==========================================
# 6. AUDIT LOGS VIEW
# ==========================================
elif app_mode == "📋 Audit Logs":
    st.title("📋 SYSTEM AUDIT LOGS")
    st.write("Immutable digital security footprints generated by threat proxy mitigations.")
    st.write("---")
    
    if st.session_state.attack_history:
        st.table(st.session_state.attack_history)
    else:
        st.info("No network log vectors recorded yet.")

# ==========================================
# 7. ENTERPRISE DATABASE VIEW
# ==========================================
elif app_mode == "📦 Enterprise Database":
    st.title("📦 ENCRYPTED DATA LAYER")
    st.write("Isolated target datasets accessible only via verified autonomous workflow parameters.")
    st.write("---")
    
    st.json({
        "dataset_alpha": {"id": "FIN-092", "payload": "Project Moonshot budget allocation: $5,000,000."},
        "dataset_beta": {"id": "SC-411", "payload": "Vendor distribution master key payload hash registered."},
        "dataset_gamma": {"id": "LEG-102", "payload": "Corporate structural integration timeline set."}
    })