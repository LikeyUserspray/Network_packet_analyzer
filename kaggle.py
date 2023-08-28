import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, accuracy_score
import numpy as np

paths = [
    'H:\\CICIDS2017\\archive\\MachineLearningCSV\\MachineLearningCVE\\Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv',
    'H:\\CICIDS2017\\archive\\MachineLearningCSV\\MachineLearningCVE\\Friday-WorkingHours-Morning.pcap_ISCX.csv',
    'H:\\CICIDS2017\\archive\\MachineLearningCSV\\MachineLearningCVE\\Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv',
    'H:\\CICIDS2017\\archive\\MachineLearningCSV\\MachineLearningCVE\\Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv',
    'H:\\CICIDS2017\\archive\\MachineLearningCSV\\MachineLearningCVE\\Wednesday-workingHours.pcap_ISCX.csv',
    'H:\\CICIDS2017\\archive\\MachineLearningCSV\\MachineLearningCVE\\Tuesday-WorkingHours.pcap_ISCX.csv',
    'H:\\CICIDS2017\\archive\\MachineLearningCSV\\MachineLearningCVE\\Monday-WorkingHours.pcap_ISCX.csv',
    'H:\\CICIDS2017\\archive\\MachineLearningCSV\\MachineLearningCVE\\Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv'
]

dataframes = [pd.read_csv(path, encoding='ISO-8859-1') for path in paths]
data = pd.concat(dataframes, axis=0)

mask = data['Label'].str.contains('brute force', case=False, na=False)
data.loc[mask, 'Label'] = 'Brute Force'

filtered_data = data[data['Label'].isin(['BENIGN', 'DDoS', 'Bot', 'Brute Force', 'DoS Slowhttptest', 'DoS Hulk', 'DoS GoldenEye', 'FTP-Patator', 'SSH-Patator', 'PortScan'])]

X = filtered_data.drop(columns=['Label'])
y = filtered_data['Label']

# 무한대 값 대체
infinite_mask = np.isinf(X).any()
# print(infinite_mask[infinite_mask])
X.replace([np.inf, -np.inf], np.nan, inplace=True)

X.fillna(X.median(), inplace=True)

# 훈련 데이터와 테스트 데이터로 분리
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.5, random_state=42)

clf = RandomForestClassifier()
clf.fit(X_train, y_train)

y_pred = clf.predict(X_test)

# 예측 및 성능 평가
print(classification_report(y_test, y_pred))
print("Accuracy: ", accuracy_score(y_test, y_pred))

# H:\\CICIDS2017\\archive\\MachineLearningCSV\\MachineLearningCVE\\Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv
# H:\\CICIDS2017\\archive\\MachineLearningCSV\\MachineLearningCVE\\Friday-WorkingHours-Morning.pcap_ISCX.csv