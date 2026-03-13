import pandas as pd
from sklearn.ensemble import RandomForestClassifier

# ---------------- TRAINING DATA (Demo Dataset) ----------------

data = {
    "length":[10,45,60,15,70,80],
    "dots":[1,3,4,1,5,6],
    "has_at":[0,1,0,0,1,0],
    "phishing":[0,1,1,0,1,1]
}

df = pd.DataFrame(data)

X = df[["length","dots","has_at"]]
y = df["phishing"]

# ---------------- TRAIN MODEL ----------------

model = RandomForestClassifier()

model.fit(X,y)

# ---------------- PREDICT FUNCTION ----------------

def predict_url(url):

    length = len(url)

    dots = url.count(".")

    has_at = 1 if "@" in url else 0

    features = [[length,dots,has_at]]

    result = model.predict(features)

    if result[0] == 1:
        return "danger"
    else:
        return "safe"