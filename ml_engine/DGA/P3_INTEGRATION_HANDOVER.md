# DGA detector handover

## Files

- Detector wrapper: `dga_detector.py`
- Existing model path: `DGA_XGBoost.pkl`
- Training source: `DGA_detector.ipynb`

The existing model file in this checkout is only 87 bytes and cannot be loaded as a joblib model. Obtain the real artifact from the producing branch or artifact store.

## Inference contract

Input is one normalized domain string at a time. The notebook extracts these features in this order:

`len_full`, `len_sld`, `entropy`, `tld_len`, `high_risk_tld`, `cv_ratio`, `digit_ratio`, `dict_match_ratio`, followed by 15 fitted character bigram TF-IDF columns named `ngram_<bigram>`.

The model was trained with `TfidfVectorizer(analyzer="char", ngram_range=(2, 2), max_features=15, lowercase=True)` fitted on the training SLD values. The fitted vectorizer is required for inference but was not saved by the notebook. The English word set was loaded from NLTK `words`, restricted to lowercase words of length 4 through 15, and is also required to reproduce `dict_match_ratio`.

No rolling calculation, grouping, event window, scaling, or column imputation was implemented. Domain normalization is lowercase and whitespace stripping; the SLD is the text before the first dot.

## Prediction and evidence

`0` means benign and `1` means DGA. Confidence is `predict_proba(...)[0][1]`. The notebook selected a default alert threshold of `0.50` while scanning thresholds from `0.50` to `0.75` for FPR at most 5%; the selected value is not persisted separately and was `0.50` in the shown run.

The wrapper exposes the input domain, prediction, confidence threshold, and confidence. There are no additional model-derived evidence fields in the notebook.

## Handover status

The notebook trained a classifier but did not produce a complete production artifact bundle. Do not integrate this detector until the real classifier, fitted TF-IDF vectorizer, and reproducible English dictionary are supplied. No final commit hash or environment variables were recorded in the notebook.