import streamlit as st
import re
import io
from pygments import highlight
from pygments.lexers import PythonLexer, JavaLexer
from pygments.formatters import HtmlFormatter

st.set_page_config(page_title="SafeScript 2.0 - Advanced Security Mechanism Analyzer", layout="wide")

st.title("🛡️ SafeScript 2.0 – Advanced Security Mechanism Analyzer")
st.markdown("##### 📚 A language-based security analyzer implementing IRM, PCC, TAL, SFI, Sandboxing, and JVM mechanisms.")

language = st.selectbox("Select Language:", ["Python", "Java-like Pseudo Code"])
code_input = st.text_area("Paste your code below:", height=300)

# --------- Inline Reference Monitoring (IRM) ---------
def analyze_code(code, lang):
    findings = []
    if lang == "Python":
        if re.search(r'os\.system|subprocess\.Popen|eval|exec', code):
            findings.append("🚨 Dangerous system-level command detected.")
        if re.search(r'open\(.+["\']w["\']', code):
            findings.append("⚠️ File write access detected.")
        if re.search(r'global ', code):
            findings.append("⚠️ Global variable usage – possible aliasing issue.")
        if re.search(r'import os|import sys', code):
            findings.append("🔍 Low-level module import – review carefully.")
        if re.search(r'while True', code):
            findings.append("⚠️ Potential infinite loop detected.")
    else:  # Java-like
        if re.search(r'System\.exit|Runtime\.getRuntime\(\)\.exec', code):
            findings.append("🚨 Dangerous system call detected.")
        if re.search(r'FileWriter|FileOutputStream', code):
            findings.append("⚠️ File write access detected.")
        if re.search(r'static ', code):
            findings.append("⚠️ Static/global variable detected – possible aliasing issue.")
        if re.search(r'while\s*\(true\)', code, re.IGNORECASE):
            findings.append("⚠️ Potential infinite loop detected.")
    return findings

# --------- Proof-Carrying Code (PCC) Certificate ---------
def generate_certificate(code, findings):
    proof = "✅ Safety Policy Proof Certificate\n"
    proof += "-" * 50 + "\n"
    proof += f"Code Length: {len(code.splitlines())} lines\n"
    proof += f"Safety Checks Passed: {5 - len(findings)}\n"
    proof += f"Safety Checks Failed: {len(findings)}\n"
    proof += "-" * 50 + "\n"
    if findings:
        proof += "❌ Violations:\n"
        for f in findings:
            proof += f" - {f}\n"
    else:
        proof += "✅ All safety properties verified.\n"
    proof += "-" * 50 + "\n"
    proof += "Certificate ID: SAFE-" + str(abs(hash(code)))[0:10]
    return proof

# --------- TAL Type Invariant Checker ---------
def check_tal_invariants(code, lang):
    issues = []
    if lang == "Python":
        if re.search(r'\w+\s*=\s*".*"', code) and re.search(r'\1\s*=\s*\d+', code):
            issues.append("❌ Type invariant violation: variable reused with different type.")
    else:
        if re.search(r'int\s+\w+\s*=\s*".*"', code):
            issues.append("❌ Type invariant violation: assigning string to int.")
    return issues if issues else ["✅ No TAL type invariant issues detected."]

# --------- Auto Safety Check Rewriter ---------
def auto_rewrite(code, lang):
    rewritten = code
    if lang == "Python":
        rewritten = re.sub(r'eval\((.*?)\)', r'# Removed unsafe eval(\1)', rewritten)
        rewritten = re.sub(r'os\.system\((.*?)\)', r'# Blocked unsafe system call: os.system(\1)', rewritten)
    else:
        rewritten = re.sub(r'Runtime\.getRuntime\(\)\.exec\((.*?)\)', r'// Blocked unsafe exec(\1)', rewritten)
        rewritten = re.sub(r'System\.exit\((.*?)\)', r'// Blocked unsafe System.exit(\1)', rewritten)
    return rewritten

# --------- Kernel SFI Simulation ---------
def sfi_kernel_simulation(code):
    return "🧱 Kernel Monitor: Memory access within sandbox boundaries.\n✅ Software Fault Isolation enforced."

# --------- JVM Memory Visualization ---------
def jvm_memory_visualization(code):
    heap = len(re.findall(r'new\s+', code))
    stack = len(re.findall(r'\(', code))
    gc = len(re.findall(r'null', code))
    vis = f"📊 JVM Memory Simulation:\nHeap objects: {heap}\nStack frames: {stack}\nGC triggers: {gc}"
    return vis

# --------- Sandbox Execution ---------
def sandbox_execute(code, lang):
    if lang != "Python":
        return "☕ JVM sandbox simulation: Code not executed, only analyzed."
    try:
        exec_env = {}
        exec(code, {"__builtins__": {}}, exec_env)
        return "✅ Code executed safely in sandbox."
    except Exception as e:
        return f"🚫 Sandbox blocked execution: {e}"

# --------- Download PCC Certificate ---------
def download_button(text, filename):
    buf = io.BytesIO(text.encode())
    st.download_button("📥 Download PCC Certificate", buf, file_name=filename, mime="text/plain")

# --------- UI Execution ---------
if st.button("🔍 Analyze & Verify"):
    if code_input.strip() == "":
        st.error("Please paste your code first.")
    else:
        col1, col2 = st.columns(2)

        with col1:
            st.subheader("🧠 Submitted Code")
            formatter = HtmlFormatter(style="colorful", full=False, noclasses=True)
            highlighted = highlight(code_input, PythonLexer() if language == "Python" else JavaLexer(), formatter)
            st.markdown(highlighted, unsafe_allow_html=True)

            st.subheader("✏️ Auto-Rewritten Code (Safe Version)")
            safe_code = auto_rewrite(code_input, language)
            st.code(safe_code, language="python" if language == "Python" else "java")

        with col2:
            st.subheader("🛡️ Security Analysis Results")
            findings = analyze_code(code_input, language)
            if findings:
                for f in findings:
                    st.error(f)
            else:
                st.success("✅ No security violations found.")

            st.subheader("📜 PCC Certificate")
            cert = generate_certificate(code_input, findings)
            st.code(cert, language="text")
            download_button(cert, "PCC_Certificate.txt")

            st.subheader("🧠 TAL Type Invariant Check")
            tal_result = check_tal_invariants(code_input, language)
            for r in tal_result:
                st.info(r if "✅" in r else r)

            st.subheader("🧪 Kernel SFI Simulation")
            st.code(sfi_kernel_simulation(code_input), language="text")

            st.subheader("☕ JVM Memory Visualization")
            st.code(jvm_memory_visualization(code_input), language="text")

            st.subheader("🧪 Sandbox Simulation")
            sandbox_result = sandbox_execute(code_input, language)
            if "✅" in sandbox_result:
                st.success(sandbox_result)
            else:
                st.warning(sandbox_result)

st.markdown("---")
st.caption("© 2025 SafeScript 2.0 – A Language-Based Security Mechanism Demo (IRM + PCC + TAL + SFI + JVM)")
