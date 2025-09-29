#!/usr/bin/env python3
"""
DID 위협 탐지 시스템 - MSL 기반 탐지 엔진 (수정 버전)
컨텍스트 매니저 지원 및 의존성 문제 해결
"""

import os
import sys
import time
import logging
import warnings
from pathlib import Path
from datetime import datetime, timedelta
from collections import defaultdict, Counter
from typing import Dict, List, Tuple, Any, Optional, Union
from functools import wraps, lru_cache
from concurrent.futures import ProcessPoolExecutor, ThreadPoolExecutor, as_completed
from contextlib import contextmanager
import json
import ast
import multiprocessing as mp

# 필수 imports
import pandas as pd
import numpy as np
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.model_selection import train_test_split, StratifiedKFold, GridSearchCV
from sklearn.metrics import roc_auc_score
from sklearn.svm import SVC

# 로깅 설정
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# 경고 무시
warnings.filterwarnings('ignore')

class Config:
    """설정 클래스"""
    MAX_WORKERS = min(32, (os.cpu_count() or 1) + 4)
    CHUNK_SIZE = 1000
    DETECTION_THRESHOLD = 0.5
    MODEL_UPDATE_INTERVAL = 3600  # 1시간
    
    @classmethod
    def validate(cls):
        """설정 검증"""
        pass

class DetectionError(Exception):
    """탐지 관련 예외"""
    pass

class DataFormatError(DetectionError):
    """데이터 형식 오류"""
    pass

class ModelError(DetectionError):
    """모델 관련 오류"""
    pass

class PerformanceMonitor:
    """성능 모니터링"""
    def __init__(self):
        self.metrics = defaultdict(list)
    
    def record(self, metric_name: str, value: float):
        """메트릭 기록"""
        self.metrics[metric_name].append(value)
    
    def get_summary(self) -> Dict[str, Dict[str, float]]:
        """성능 요약"""
        summary = {}
        for metric, values in self.metrics.items():
            if values:
                summary[metric] = {
                    'mean': np.mean(values),
                    'std': np.std(values),
                    'min': np.min(values),
                    'max': np.max(values)
                }
        return summary

class MSLRulesEngine:
    """MSL 규칙 기반 탐지 엔진"""
    def __init__(self, config):
        self.config = config
        self.rules = self._initialize_rules()
    
    def _initialize_rules(self):
        """규칙 초기화"""
        return {
            'vc_reuse': self._check_vc_reuse,
            'issuer_impersonation': self._check_issuer_impersonation,
            'time_anomaly': self._check_time_anomaly,
            'rapid_events': self._check_rapid_events
        }
    
    def _check_vc_reuse(self, df: pd.DataFrame) -> pd.Series:
        """VC 재사용 탐지"""
        vc_counts = df['vc_hash'].value_counts()
        return df['vc_hash'].map(vc_counts) > 1
    
    def _check_issuer_impersonation(self, df: pd.DataFrame) -> pd.Series:
        """발급자 위장 탐지"""
        suspicious_issuers = ['fake-issuer', 'untrusted', 'malicious']
        return df['issuer_did'].str.contains('|'.join(suspicious_issuers), na=False)
    
    def _check_time_anomaly(self, df: pd.DataFrame) -> pd.Series:
        """시간 이상 탐지"""
        df['timestamp'] = pd.to_datetime(df['timestamp'])
        time_diffs = df.groupby('holder_did')['timestamp'].diff()
        return time_diffs < pd.Timedelta(seconds=1)
    
    def _check_rapid_events(self, df: pd.DataFrame) -> pd.Series:
        """빠른 이벤트 탐지"""
        df['timestamp'] = pd.to_datetime(df['timestamp'])
        event_counts = df.groupby(['holder_did', df['timestamp'].dt.floor('min')]).size()
        return df['holder_did'].map(event_counts) > 10
    
    def detect(self, df: pd.DataFrame) -> pd.DataFrame:
        """규칙 기반 탐지 실행"""
        results = pd.DataFrame(index=df.index)
        
        for rule_name, rule_func in self.rules.items():
            try:
                results[f'rule_{rule_name}'] = rule_func(df)
            except Exception as e:
                logger.warning(f"규칙 {rule_name} 실행 실패: {e}")
                results[f'rule_{rule_name}'] = False
        
        # 전체 위협 점수 계산
        threat_columns = [col for col in results.columns if col.startswith('rule_')]
        results['threat_score'] = results[threat_columns].sum(axis=1) / len(threat_columns)
        results['threat_level'] = results['threat_score'].apply(
            lambda x: 'high' if x > 0.7 else 'medium' if x > 0.3 else 'low' if x > 0 else 'benign'
        )
        
        return results

class MSLModelEngine:
    """MSL 모델 기반 탐지 엔진"""
    def __init__(self, config):
        self.config = config
        self.model = None
        self.scaler = StandardScaler()
        self.label_encoder = LabelEncoder()
        self.is_trained = False
    
    def _prepare_features(self, df: pd.DataFrame) -> pd.DataFrame:
        """특성 준비"""
        features = df.copy()
        
        # 범주형 변수 인코딩
        categorical_columns = ['event_type', 'holder_did', 'verifier_id', 'vc_hash']
        for col in categorical_columns:
            if col in features.columns:
                features[col] = features[col].astype('category').cat.codes
        
        # 시간 특성 추출
        if 'timestamp' in features.columns:
            features['timestamp'] = pd.to_datetime(features['timestamp'])
            features['hour'] = features['timestamp'].dt.hour
            features['day_of_week'] = features['timestamp'].dt.dayofweek
        
        return features
    
    def train(self, df: pd.DataFrame):
        """모델 훈련"""
        try:
            features = self._prepare_features(df)
            X = features.drop(columns=['label'] if 'label' in features.columns else [])
            y = features['label'] if 'label' in features.columns else pd.Series(['benign'] * len(features))
            
            # 레이블 인코딩
            y_encoded = self.label_encoder.fit_transform(y)
            
            # 특성 스케일링
            X_scaled = self.scaler.fit_transform(X.select_dtypes(include=[np.number]))
            
            # 모델 훈련
            self.model = RandomForestClassifier(n_estimators=100, random_state=42)
            self.model.fit(X_scaled, y_encoded)
            self.is_trained = True
            
            logger.info("모델 훈련 완료")
            
        except Exception as e:
            logger.error(f"모델 훈련 실패: {e}")
            self.is_trained = False
    
    def predict(self, df: pd.DataFrame) -> pd.DataFrame:
        """모델 예측"""
        if not self.is_trained:
            logger.warning("모델이 훈련되지 않았습니다. 규칙 기반 탐지만 사용합니다.")
            return pd.DataFrame(index=df.index)
        
        try:
            features = self._prepare_features(df)
            X = features.drop(columns=['label'] if 'label' in features.columns else [])
            X_scaled = self.scaler.transform(X.select_dtypes(include=[np.number]))
            
            # 예측
            predictions = self.model.predict(X_scaled)
            probabilities = self.model.predict_proba(X_scaled)
            
            results = pd.DataFrame(index=df.index)
            results['model_prediction'] = self.label_encoder.inverse_transform(predictions)
            results['model_confidence'] = np.max(probabilities, axis=1)
            
            return results
            
        except Exception as e:
            logger.error(f"모델 예측 실패: {e}")
            return pd.DataFrame(index=df.index)

class MSLDetectionEngine:
    """MSL 기반 DID 위협 탐지 엔진 (수정 버전)"""
    
    def __init__(self, use_lstm=False, config=None):
        # 설정 초기화
        self.config = config or Config()
        if isinstance(self.config, Config):
            Config.validate()
        
        # 엔진 컴포넌트 초기화
        self.rules_engine = MSLRulesEngine(self.config)
        self.model_engine = MSLModelEngine(self.config)
        self.detection_results = []
        self.is_optimized = False
        self.performance_monitor = PerformanceMonitor()
        
        # 멀티프로세싱 초기화
        self.executor = ProcessPoolExecutor(max_workers=getattr(self.config, 'MAX_WORKERS', Config.MAX_WORKERS))
        self._is_closed = False
        
        logger.info("MSL 탐지 엔진 초기화 완료")
    
    def __enter__(self):
        """컨텍스트 매니저 진입"""
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """컨텍스트 매니저 종료"""
        self.close()
    
    def close(self):
        """리소스 정리"""
        if not self._is_closed:
            self.executor.shutdown(wait=True)
            self._is_closed = True
            logger.info("MSL 탐지 엔진 리소스 정리 완료")
    
    def _validate_data(self, df: pd.DataFrame):
        """데이터 검증"""
        required_columns = ['event_id', 'timestamp', 'event_type']
        missing_columns = [col for col in required_columns if col not in df.columns]
        
        if missing_columns:
            raise DataFormatError(f"필수 컬럼이 없습니다: {missing_columns}")
        
        if len(df) == 0:
            raise DataFormatError("데이터가 비어있습니다")
    
    def detect_threats(self, df: pd.DataFrame) -> pd.DataFrame:
        """Hybrid 탐지 실행"""
        try:
            # 데이터 검증
            self._validate_data(df)
            
            logger.info(f"위협 탐지 시작: {len(df)}개 이벤트")
            start_time = time.time()
            
            # 규칙 기반 탐지
            rules_results = self.rules_engine.detect(df)
            
            # 모델 기반 탐지 (레이블이 있는 경우)
            model_results = pd.DataFrame(index=df.index)
            if 'label' in df.columns:
                # 모델 훈련
                self.model_engine.train(df)
                # 모델 예측
                model_results = self.model_engine.predict(df)
            
            # 결과 통합
            results = pd.concat([df, rules_results, model_results], axis=1)
            
            # 최종 위협 레벨 결정
            if 'threat_score' in results.columns:
                results['final_threat_level'] = results['threat_score'].apply(
                    lambda x: 'high' if x > 0.7 else 'medium' if x > 0.3 else 'low' if x > 0 else 'benign'
                )
            else:
                results['final_threat_level'] = 'benign'
            
            # 성능 기록
            end_time = time.time()
            self.performance_monitor.record('detection_time', end_time - start_time)
            
            logger.info(f"위협 탐지 완료: {end_time - start_time:.2f}초")
            
            return results
            
        except Exception as e:
            logger.error(f"위협 탐지 실패: {e}")
            raise DetectionError(f"위협 탐지 중 오류 발생: {e}")
    
    def get_performance_summary(self) -> Dict[str, Dict[str, float]]:
        """성능 요약 반환"""
        return self.performance_monitor.get_summary()

def main():
    """메인 실행 함수"""
    print("MSL 기반 DID 위협 탐지 엔진 테스트 (수정 버전)")
    print("=" * 60)
    
    # 샘플 데이터 생성
    sample_data = pd.DataFrame({
        "event_id": [f"event_{i}" for i in range(100)],
        "timestamp": pd.date_range("2024-01-01", periods=100, freq="min"),
        "event_type": np.random.choice(["ISSUANCE", "PRESENTATION", "VERIFICATION"], 100),
        "holder_did": [f"did:example:holder_{i}" for i in range(100)],
        "verifier_id": [f"did:example:verifier_{i}" for i in range(100)],
        "vc_hash": [f"vc_{i}" for i in range(100)],
        "issuer_did": [f"did:example:issuer_{i}" for i in range(100)],
        "label": np.random.choice(["benign", "malicious"], 100, p=[0.8, 0.2])
    })
    
    print(f"샘플 데이터: {len(sample_data)}개 이벤트")
    
    # 탐지 엔진 테스트
    try:
        with MSLDetectionEngine() as engine:
            print(f"\n1. 탐지 실행...")
            results = engine.detect_threats(sample_data)
            
            print(f"\n2. 탐지 결과:")
            if 'final_threat_level' in results.columns:
                threat_counts = results['final_threat_level'].value_counts()
                for level, count in threat_counts.items():
                    print(f"    {level}: {count}개")
            
            print(f"\n3. 성능 요약:")
            perf_summary = engine.get_performance_summary()
            for metric, stats in perf_summary.items():
                if stats:
                    print(f"  - {metric}: 평균 {stats['mean']:.3f}초")
        
        print(f"\n=== 테스트 완료 ===")
        
    except Exception as e:
        logger.error(f"테스트 실행 오류: {e}")
        print(f"실행 중 오류가 발생했습니다: {e}")

if __name__ == "__main__":
    main()
