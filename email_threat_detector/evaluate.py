"""Cross-validated accuracy of the content model (for your report)."""
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import cross_val_predict, StratifiedKFold
from sklearn.pipeline import make_pipeline
from sklearn.metrics import classification_report, confusion_matrix
from dataset import SCAM, LEGIT

X, y = SCAM + LEGIT, [1] * len(SCAM) + [0] * len(LEGIT)
pipe = make_pipeline(TfidfVectorizer(ngram_range=(1, 2), sublinear_tf=True), LogisticRegression(C=5, max_iter=1000))
pred = cross_val_predict(pipe, X, y, cv=StratifiedKFold(5, shuffle=True, random_state=42))
print(classification_report(y, pred, target_names=["legit", "scam"]))
print("Confusion matrix:\n", confusion_matrix(y, pred))
print("\nNOTE: tiny demo dataset. Train on SpamAssassin/Enron/Kaggle phishing data for real numbers.")
