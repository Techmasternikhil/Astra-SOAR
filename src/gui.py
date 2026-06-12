import streamlit as st
import time
import json

st.set_page_config(
    page_title="Anti-Gravity Autonomous Defense Console",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom Cyberpunk Styles for an Automated Dashboard
st.markdown("""
    <style>
    .stApp { background-color: #0b0e14; color: #ffffff; }
    div.stButton > button:first-child { background-color: #00ff66; color: black; font-weight: bold; border: none; width: 100%; }
    .status-box { background-color: #161b22; padding: 15px; border-radius: 8px; border-left: 5px solid #00ff66; margin-bottom: 10px; }
    code { color: #00ffbb !important; font-size: 14px; }
    </style>
""", unsafe_allow_html=True)

# --- SYSTEM FIXTURES (The Autonomous Datasets) ---
telemetry_log = {
    "event_id": "EVNT-9901",
    "source_ip": "10.244.0.5",
    "cluster_node": "prod-k8s-worker-02",
    "indicator": "Unauthorized reading of ServiceAccount secrets token namespace.",
    "severity": "CRITICAL"
}

remediation_playbook = {
    "threat_id": "THREAT-201",
    "incident_type": "Kubernetes Pod Privilege Escalation",
    "target_infrastructure": "Production AWS/Azure Cluster",
    "execution_payload": {
        "action": "NETWORK_ISOLATION",
        "command": "kubectl patch networkpolicy dynamic-isolate-pod -p '{\"spec\":{\"podSelector\":{\"matchLabels\":{\"app\":\"compromised-node\"}},\"policyTypes\":[\"Egress\"],\"egress\":[]}}'",
        "token_revoke_action": "kubectl delete secret $(kubectl get serviceaccount compromised-sa -o jsonpath='{.secrets[0].name}')"
    }
}

# --- SIDEBAR CONTROL PANEL ---
st.sidebar.title("🛸 Autonomous Defense Core")
st.sidebar.markdown("---")
st.sidebar.subheader("System Configuration")
st.sidebar.write("🔒 **Guard Mode:** `ENABLED`")
st.sidebar.write("📊 **Telemetry Stream:** `CONNECTED`")
st.sidebar.write("🛰️ **Target Infra:** `Production K8s Cluster`")
st.sidebar.markdown("---")

trigger_breach = st.sidebar.button("💥 Inject Synthetic Cyber Threat")

# --- MAIN DASHBOARD WINDOW ---
st.title("🛡️ Anti-Gravity IDE — Autonomous Active Defense Console")
st.write("Real-time Multi-Agent Threat Detection, Validation, and Self-Healing Infrastructure")
st.markdown("---")

# Layout Baseline State Panels
if not trigger_breach:
    st.info("🟢 **System Nominal.** Monitoring active infrastructure streams... No critical indicators detected.")
    
    col_stat1, col_stat2, col_stat3 = st.columns(3)
    col_stat1.metric("System Uptime", "99.98%", delta="Normal")
    col_stat2.metric("Active AI Sensors", "3 Agents Online", delta="Healthy")
    col_stat3.metric("Last Threat Mitigated", "0 Days Ago", delta="Self-Healed")

# If user triggers the automated response simulation
if trigger_breach:
    st.error(f"⚠️ **ALERT TRIPPED:** Critical security anomaly identified in live infrastructure cluster!")
    
    # 1. Agent 1 Phase
    with st.status("🕵️ [AGENT 1] Telemetry Sensor Processing...", expanded=True) as status:
        st.write(f"**Ingesting Log ID:** `{telemetry_log['event_id']}`")
        st.write(f"**Anomaly Signal:** String matching indicator found: *'{telemetry_log['indicator']}'*")
        st.write(f"**Target Node Context:** {telemetry_log['cluster_node']} (IP: {telemetry_log['source_ip']})")
        time.sleep(1.5)
        status.update(label="✔ Agent 1: Threat successfully detected and mapped.", state="complete")

    # 2. Agent 2 Phase
    with st.status("🧠 [AGENT 2] Policy Auditor Validation...", expanded=True) as status:
        st.write(f"Cross-referencing active threat signature with Foundry Compliance Playbook records...")
        st.write(f"**Match Found:** ID `{remediation_playbook['threat_id']}` — *{remediation_playbook['incident_type']}*")
        st.write("🛡️ **Validation Check:** Mitigations verified safe to execute on production nodes.")
        time.sleep(1.5)
        status.update(label="✔ Agent 2: Containment strategy verified against policy rules.", state="complete")

    # 3. Agent 3 Phase
    with st.status("⚡ [AGENT 3] Automated Remediator Executing Fixes...", expanded=True) as status:
        st.write("Executing terminal shell scripts directly onto target node...")
        st.code(remediation_playbook['execution_payload']['command'], language="bash")
        time.sleep(1)
        st.write("Revoking compromised container authentication tokens...")
        st.code(remediation_playbook['execution_payload']['token_revoke_action'], language="bash")
        time.sleep(1.5)
        status.update(label="✔ Agent 3: All malicious processes isolated and neutralized.", state="complete")

    # Final Autonomous Log Summary Display
    st.markdown("---")
    st.subheader("📋 Autonomous Threat Containment Log Report")
    
    st.markdown(f"""
    <div class="status-box">
        <h4 style="color: #00ff66; margin-top: 0px;">🛸 SYSTEM STATUS: SELF-HEALED / SECURED</h4>
        <p><b>Contained Attack Vector:</b> {remediation_playbook['incident_type']}</p>
        <p><b>Affected Node Domain:</b> {telemetry_log['cluster_node']}</p>
        <p><b>Mitigation Metric speed:</b> <code>42 Milliseconds</code></p>
        <p><b>Data Integrity Protection Factor:</b> <code>100% Retained / Egress Blocked</code></p>
    </div>
    """, unsafe_allow_html=True)
    
    if st.button("Reset Dashboard to Monitoring State"):
        st.rerun()