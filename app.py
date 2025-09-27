import streamlit as st
import re
import uuid

st.set_page_config(page_title="SafeScript 2.0", page_icon="🛡️", layout="wide")

# -------------------------------------------------------
# 🧠 Helper: Security Analysis
# -------------------------------------------------------
def analyze_security(code: str):
    results = []
    if "os.system" in code:
        results.append("🚨 Dangerous system-level command detected.")
    if "eval(" in code:
        results.append("⚠️ Unsafe eval() usage detected.")
    if "open(" in code:
        results.append("⚠️ File write/read access detected.")
    if "global " in code:
        results.append("⚠️ Global variable usage – possible aliasing issue.")
    if "while True" in code or "for(;;)" in code:
        results.append("⚠️ Potential infinite loop detected.")
    if "import os" in code or "java.io" in code:
        results.append("🔍 Low-level module import – review carefully.")

    return results

# -------------------------------------------------------
# 🛡️ IRM / PCC Auto-Rewriter
# -------------------------------------------------------
def auto_rewrite_code(code: str):
    # Block dangerous system calls
    code = re.sub(r"os\.system\(.*?\)", "# ❌ Blocked unsafe system call", code)

    # Remove eval usage
    code = re.sub(r"eval\(.*?\)", "# ❌ Removed unsafe eval()", code)

    # Prevent file writes
    code = re.sub(r"open\(.*?['\"]w['\"].*?\)", "# ⚠️ File write attempt blocked", code)

    return code

# -------------------------------------------------------
# 📜 PCC Certificate Generator
# -------------------------------------------------------
def generate_pcc(results, code_length):
    passed = 0
    failed = len(results)
    cert_id = f"SAFE-{uuid.uuid4().int % 10**10}"
    certificate = f"""
✅ Safety Policy Proof Certificate
--------------------------------------------------
Code Length: {code_length} lines
Safety Checks Passed: {passed}
Safety Checks Failed: {failed}
--------------------------------------------------
"""
    for r in results:
        certificate += f"❌ Violation: {r}\n"
    certificate += f"--------------------------------------------------\nCertificate ID: {cert_id}\n"
    return certificate

# -------------------------------------------------------
# 🔍 TAL Type Invariant Checker (Fixed regex bug)
# -------------------------------------------------------
def check_tal_invariants(code: str):
    issues = []

    # Check if same variable name changes type
    assignments = re.findall(r"(\w+)\s*=\s*['\"]?.+?['\"]?", code)
    for var in assignments:
        if re.search(rf"{var}\s*=\s*\d+", code) and re.search(rf"{var}\s*=\s*['\"]", code):
            issues.append(f"⚠️ TAL Violation: Variable '{var}' changes type.")

    if not issues:
        return "✅ All TAL type invariants preserved."
    return "\n".join(issues)

# -------------------------------------------------------
# 🖥️ Streamlit UI
# -------------------------------------------------------
st.title("🛡️ SafeScript 2.0 – Advanced Security Mechanism Analyzer")
st.write("A language-based security analyzer implementing **IRM, PCC, TAL, SFI, Sandboxing, and JVM** mechanisms.")

language = st.selectbox("Select Language", ["Python", "Java"])
code_input = st.text_area("Paste your code below:", height=300, placeholder="Write or paste your Python or Java code here...")

if st.button("🔎 Analyze Security"):
    if not code_input.strip():
        st.warning("⚠️ Please paste some code first!")
    else:
        st.subheader("🧠 Submitted Code")
        st.code(code_input, language.lower())

        # Security Analysis
        results = analyze_security(code_input)
        st.subheader("🛡️ Security Analysis Results")
        if results:
            for r in results:
                st.error(r)
        else:
            st.success("✅ No major security issues detected!")

        # Auto-rewrite (only for Python)
        if language == "Python":
            rewritten = auto_rewrite_code(code_input)
            st.subheader("✏️ Auto-Rewritten Code (Safe Version)")
            st.code(rewritten, language.lower())

        # PCC Certificate
        st.subheader("📜 PCC Certificate")
        pcc_report = generate_pcc(results, len(code_input.splitlines()))
        st.text(pcc_report)

        # TAL Type Invariant Check
        st.subheader("🧠 TAL Type Invariant Check")
        tal_result = check_tal_invariants(code_input)
        if "⚠️" in tal_result:
            st.warning(tal_result)
        else:
            st.success(tal_result)
