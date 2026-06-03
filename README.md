# CSP Security Analyzer using Tranco Top Websites Dataset

This semester project collects Content Security Policy (CSP) headers from popular websites, engineers security features, creates rule-based security labels, trains a machine learning classifier, and provides a Streamlit app for quick CSP analysis.

The project intentionally uses synchronous Python with the `requests` library only. It does not use `aiohttp` or async programming.

## Project Structure

```text
CSP_project/
|-- notebooks/
|   |-- 01_data_collection.ipynb
|   |-- 02_feature_engineering.ipynb
|   |-- 03_model_training.ipynb
|   `-- 04_evaluation.ipynb
|-- src/
|   |-- csp_collection.py
|   |-- csp_features.py
|   `-- model_utils.py
|-- data/
|   |-- tranco.csv
|   |-- tranco_domains_sample.csv
|   |-- csp_dataset.csv
|   `-- csp_features_labeled.csv
|-- models/
|   `-- csp_random_forest.pkl
|-- reports/
|   `-- figures/
|-- app.py
`-- requirements.txt
```

## Setup

```bash
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
```

If you are using Jupyter Notebook, start it from the project folder:

```bash
jupyter notebook
```

Then run the notebooks in order:

1. `notebooks/01_data_collection.ipynb`
2. `notebooks/02_feature_engineering.ipynb`
3. `notebooks/03_model_training.ipynb`
4. `notebooks/04_evaluation.ipynb`

## Running the Streamlit App

```bash
streamlit run app.py
```

Paste a CSP header string, click **Analyze CSP**, and the app will show:

- predicted class: Weak, Medium, or Strong
- risk/security score from 0 to 100
- detected risk explanations

## Dataset Notes

The project now includes your real Tranco file at `data/tranco.csv`. The included generated CSV/model files are starter artifacts so the Streamlit app runs immediately. For final academic submission, run `01_data_collection.ipynb` using `data/tranco.csv` with 1000 to 3000 sites, then rerun the remaining notebooks.

If you want to test quickly, change the collection notebook back to `data/tranco_domains_sample.csv`. For the full project dataset, keep it on `data/tranco.csv`.
