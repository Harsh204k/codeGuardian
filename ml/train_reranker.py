import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.metrics import precision_recall_fscore_support
from sklearn.preprocessing import OneHotEncoder
from sklearn.compose import ColumnTransformer
from sklearn.pipeline import Pipeline
from xgboost import XGBClassifier
import joblib, pathlib

df = pd.read_csv("datasets/ml/train_java.csv")
if df.empty:
    raise SystemExit("No rows in datasets/ml/train_java.csv. Build it first with tools/build_training_table.py")

y = df["y"].astype(int)
X = df.drop(columns=["y"])

cat = ["ruleId","cwe"]
num = [c for c in X.columns if c not in cat]

ct = ColumnTransformer([
    ("cat", OneHotEncoder(handle_unknown="ignore"), cat),
    ("num", "passthrough", num)
])

model = XGBClassifier(
    n_estimators=200, max_depth=6, learning_rate=0.08,
    subsample=0.9, colsample_bytree=0.9, reg_lambda=1.0,
    n_jobs=4, random_state=42, tree_method="hist"
)

pipe = Pipeline([("prep", ct), ("clf", model)])

Xtr, Xte, ytr, yte = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)
pipe.fit(Xtr, ytr)
pred = (pipe.predict_proba(Xte)[:,1] >= 0.35).astype(int)  # threshold can be tuned later
p,r,f,_ = precision_recall_fscore_support(yte, pred, average="binary", zero_division=0)
print({"precision": float(p), "recall": float(r), "f1": float(f)})

pathlib.Path("models").mkdir(exist_ok=True, parents=True)
joblib.dump(pipe, "models/reranker_java.joblib")
print("✅ saved models/reranker_java.joblib")
