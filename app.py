from __future__ import annotations

from pathlib import Path

import joblib
import pandas as pd
import streamlit as st

from src.csp_features import FEATURE_COLUMNS, calculate_security_score, explain_csp, extract_csp_features, label_from_score


MODEL_PATH = Path("models/csp_random_forest.pkl")


@st.cache_resource
def load_model():
    if MODEL_PATH.exists():
        return joblib.load(MODEL_PATH)
    return None


def predict_label(csp_text: str) -> tuple[str, int, list[str]]:
    features = extract_csp_features(csp_text)
    score = calculate_security_score(csp_text)
    model = load_model()

    if model is None:
        predicted_label = label_from_score(score)
    else:
        feature_df = pd.DataFrame([features], columns=FEATURE_COLUMNS)
        predicted_label = str(model.predict(feature_df)[0])

    return predicted_label, score, explain_csp(csp_text)


def main() -> None:
    st.set_page_config(page_title="CSP Security Analyzer", page_icon=":material/security:", layout="centered")

    st.title("CSP Security Analyzer")
    st.caption("Analyze Content Security Policy headers using rule-based scoring and a Random Forest model.")

    csp_input = st.text_area(
        "CSP string",
        height=180,
        placeholder="Example: default-src 'self'; script-src 'self' 'nonce-abc123' 'strict-dynamic'; object-src 'none'; base-uri 'self'",
    )

    analyze = st.button("Analyze CSP", type="primary")

    if analyze:
        predicted_class, risk_score, explanations = predict_label(csp_input)

        st.subheader("Result")
        col1, col2 = st.columns(2)
        col1.metric("Predicted class", predicted_class)
        col2.metric("Security score", f"{risk_score}/100")

        if predicted_class == "Weak":
            st.error("This CSP has important security weaknesses.")
        elif predicted_class == "Medium":
            st.warning("This CSP provides partial protection but can be improved.")
        else:
            st.success("This CSP follows stronger security practices.")

        st.subheader("Explanation")
        for item in explanations:
            st.write(f"- {item}")

        with st.expander("Extracted features"):
            st.dataframe(pd.DataFrame([extract_csp_features(csp_input)]), use_container_width=True)
    else:
        st.info("Paste a CSP header and click Analyze CSP.")


if __name__ == "__main__":
    main()
