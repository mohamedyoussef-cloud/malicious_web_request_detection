import streamlit as st
from detector import predict_url

st.set_page_config(
    page_title="Malicious Web Request Detection",
    page_icon="🛡️",
    layout="centered"
)

st.title("🛡️ Malicious Web Request Detection")
st.caption("Simple URL risk detection using lightweight machine learning.")

url = st.text_input(
    "Enter a URL or web request:",
    placeholder="https://example.com/search?q=test"
)

if st.button("Analyze URL", use_container_width=True):
    if not url.strip():
        st.warning("Please enter a URL first.")
    else:
        try:
            result = predict_url(url)

            if result["is_malicious"]:
                st.error("Malicious Request Detected")
            else:
                st.success("Safe Request")

            st.metric("Risk Score", result["confidence"])

            st.write("### Reasons")
            for reason in result["reasons"]:
                st.write(f"- {reason}")

            with st.expander("Technical Features"):
                st.json(result["features"])

        except FileNotFoundError:
            st.error("Model file not found. Run train_model.py first, then upload models/malicious_url_model.joblib.")
        except Exception as e:
            st.error(f"Error: {e}")

st.divider()
st.caption("This tool is a detection aid, not a replacement for a real WAF.")
