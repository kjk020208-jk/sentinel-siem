import numpy as np
from sklearn.ensemble import IsolationForest


class AnomalyDetector:
    def __init__(self):
        self.model = IsolationForest(
            n_estimators=100,
            contamination=0.05,
            random_state=42
        )

        self.is_trained = False
        self.train_model()

    def train_model(self):
        np.random.seed(42)

        # 정상 사용자의 행동 패턴을 임시로 생성
        # [로그인 실패 횟수, 파일 접근 횟수, USB 연결 여부, 시간대]

        normal_data = []

        for _ in range(500):
            login_fail_count = np.random.choice(
                [0, 0, 0, 0, 1, 1, 2]
            )

            file_access_count = int(
                np.clip(
                    np.random.normal(5, 2),
                    0,
                    12
                )
            )

            usb_connected = np.random.choice(
                [0, 0, 0, 0, 0, 1]
            )

            # 정상 근무시간 08~19시를 중심으로 생성
            hour = int(
                np.clip(
                    np.random.normal(13, 3),
                    8,
                    19
                )
            )

            normal_data.append([
                login_fail_count,
                file_access_count,
                usb_connected,
                hour
            ])

        normal_data = np.array(normal_data)

        self.model.fit(normal_data)
        self.is_trained = True

    def analyze(
        self,
        login_fail_count,
        file_access_count,
        usb_connected,
        hour
    ):
        features = np.array([[
            login_fail_count,
            file_access_count,
            usb_connected,
            hour
        ]])

        prediction = self.model.predict(features)[0]

        raw_score = self.model.decision_function(features)[0]

        # decision_function:
        # 정상일수록 양수
        # 이상할수록 음수
        #
        # 화면에서 이해하기 쉽게 0~100 이상점수로 변환
        anomaly_score = (0.15 - raw_score) / 0.30 * 100

        anomaly_score = max(0, min(100, anomaly_score))

        is_anomaly = prediction == -1

        return round(float(anomaly_score), 2), bool(is_anomaly)


detector = AnomalyDetector()