#!/usr/bin/env python3
"""
MSL 탐지 엔진 핵심 모듈
각 DID 플랫폼에서 공통으로 사용할 수 있는 MSL 기반 위협 탐지 핵심 기능
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

# 필수 imports만 먼저 로드
import pandas as pd
import numpy as np
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.model_selection import train_test_split, StratifiedKFold, GridSearchCV
from sklearn.metrics import roc_auc_score
from sklearn.svm import SVC
from sklearn.linear_model import LogisticRegression
import xgboost as xgb

warnings.filterwarnings('ignore')

# 로깅 설정
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class MSLDetectionCore:
    """MSL 탐지 엔진 핵심 클래스 - 플랫폼 독립적"""
    
    def __init__(self, config: Dict[str, Any] = None):
        self.config = config or {}
        self.rules_engine = MSLRulesEngine(self.config)
        self.model_engine = MSLModelEngine(self.config)
        self.performance_monitor = PerformanceMonitor()
        self.is_trained = False
        
        logger.info("MSL 탐지 엔진 핵심 모듈 초기화 완료")
    
    def train(self, data: Union[pd.DataFrame, List[Dict]]) -> bool:
        """모델 훈련"""
        try:
            if isinstance(data, list):
                df = pd.DataFrame(data)
            else:
                df = data
            
            if df.empty:
                logger.warning("훈련 데이터가 비어있습니다.")
                return False
            
            # 모델 훈련
            self.model_engine.train(df)
            self.is_trained = True
            
            logger.info("MSL 탐지 엔진 훈련 완료")
            return True
            
        except Exception as e:
            logger.error(f"모델 훈련 중 오류: {e}")
            return False
    
    def detect_threats(self, data: Union[pd.DataFrame, List[Dict]]) -> Dict[str, Any]:
        """위협 탐지 실행"""
        try:
            if isinstance(data, list):
                df = pd.DataFrame(data)
            else:
                df = data
            
            if df.empty:
                return {"threats": [], "summary": {"total_events": 0, "threats_detected": 0}}
            
            # 규칙 기반 탐지
            rule_results = self.rules_engine.detect(df)
            
            # 모델 기반 탐지
            model_results = {}
            if self.is_trained:
                model_results = self.model_engine.detect(df)
            
            # 결과 통합
            combined_results = self._combine_results(df, rule_results, model_results)
            
            # 결과 요약
            summary = self._generate_summary(combined_results)
            
            return {
                "threats": combined_results,
                "summary": summary,
                "rule_results": rule_results,
                "model_results": model_results
            }
            
        except Exception as e:
            logger.error(f"위협 탐지 중 오류: {e}")
            return {"threats": [], "summary": {"total_events": 0, "threats_detected": 0, "error": str(e)}}
    
    def _combine_results(self, df: pd.DataFrame, rule_results: Dict, model_results: Dict) -> List[Dict]:
        """규칙 기반과 모델 기반 결과 통합"""
        combined = []
        
        for idx, row in df.iterrows():
            event_id = row.get('event_id', f"event_{idx}")
            
            # 규칙 기반 결과
            rule_detected = event_id in rule_results
            rule_confidence = rule_results.get(event_id, {}).get('confidence', 0.0)
            rule_threat_type = rule_results.get(event_id, {}).get('threat_type', 'none')
            
            # 모델 기반 결과
            model_detected = event_id in model_results
            model_score = model_results.get(event_id, {}).get('anomaly_score', 0.0)
            
            # 통합 탐지 결정
            final_detection = rule_detected or (model_detected and model_score > 0.5)
            final_confidence = max(rule_confidence, model_score)
            
            threat_info = {
                "event_id": event_id,
                "timestamp": row.get('timestamp', datetime.now().isoformat()),
                "event_type": row.get('event_type', 'UNKNOWN'),
                "threat_detected": final_detection,
                "threat_type": rule_threat_type if rule_detected else ('model_anomaly' if model_detected else 'none'),
                "confidence": final_confidence,
                "rule_detection": rule_detected,
                "model_detection": model_detected,
                "details": {
                    "rule_confidence": rule_confidence,
                    "model_score": model_score,
                    "rule_explanation": rule_results.get(event_id, {}).get('explanation', ''),
                    "raw_data": row.to_dict()
                }
            }
            
            combined.append(threat_info)
        
        return combined
    
    def _generate_summary(self, results: List[Dict]) -> Dict[str, Any]:
        """결과 요약 생성"""
        total_events = len(results)
        threats_detected = sum(1 for r in results if r['threat_detected'])
        
        threat_types = Counter(r['threat_type'] for r in results if r['threat_detected'])
        
        return {
            "total_events": total_events,
            "threats_detected": threats_detected,
            "detection_rate": threats_detected / total_events if total_events > 0 else 0,
            "threat_types": dict(threat_types),
            "timestamp": datetime.now().isoformat()
        }
    
    def get_performance_summary(self) -> Dict[str, Any]:
        """성능 요약 반환"""
        return self.performance_monitor.get_performance_summary()


class MSLRulesEngine:
    """MSL 기반 규칙 탐지 엔진"""
    
    def __init__(self, config: Dict[str, Any] = None):
        self.config = config or {}
        self.detection_rules = self._init_detection_rules()
    
    def _init_detection_rules(self) -> Dict:
        """탐지 규칙 초기화"""
        return {
            'vc_reuse_attack': {
                'description': '동일 VC가 짧은 시간 내 여러 검증자에게 제시',
                'threshold_minutes': 30,
                'min_verifiers': 2
            },
            'issuer_impersonation': {
                'description': '신뢰할 수 없는 발급자로 생성된 VC',
                'untrusted_issuers': ['did:web:issuer3.untrusted.com', 'did:web:fake-issuer.com']
            },
            'time_anomaly': {
                'description': '비정상적인 시간 패턴',
                'max_simultaneous': 3,
                'time_window_minutes': 5
            },
            'rapid_events': {
                'description': '빠른 연속 이벤트 패턴',
                'time_window_minutes': 1,
                'max_events': 5
            }
        }
    
    def detect(self, df: pd.DataFrame) -> Dict:
        """규칙 기반 탐지 실행"""
        results = {}
        
        # VC 재사용 공격 탐지
        vc_reuse_results = self._detect_vc_reuse(df)
        results.update(vc_reuse_results)
        
        # 발급자 위장 탐지
        impersonation_results = self._detect_issuer_impersonation(df)
        results.update(impersonation_results)
        
        # 시간 이상 탐지
        time_anomaly_results = self._detect_time_anomaly(df)
        results.update(time_anomaly_results)
        
        # 빠른 연속 이벤트 탐지
        rapid_events_results = self._detect_rapid_events(df)
        results.update(rapid_events_results)
        
        return results
    
    def _detect_vc_reuse(self, df: pd.DataFrame) -> Dict:
        """VC 재사용 공격 탐지"""
        results = {}
        
        presentations = df[df['event_type'] == 'PRESENTATION'].copy()
        if presentations.empty:
            return results
        
        presentations['timestamp'] = pd.to_datetime(presentations['timestamp'])
        vc_groups = presentations.groupby('vc_hash')
        
        for vc_hash, group in vc_groups:
            if len(group) < 2:
                continue
            
            group = group.sort_values('timestamp')
            
            for i in range(len(group)):
                current_time = group.iloc[i]['timestamp']
                current_verifier = group.iloc[i]['verifier_id']
                
                time_window = current_time + timedelta(minutes=30)
                recent_presentations = group[
                    (group['timestamp'] <= time_window) & 
                    (group['verifier_id'] != current_verifier)
                ]
                
                if len(recent_presentations) >= 1:
                    event_id = group.iloc[i]['event_id']
                    results[event_id] = {
                        'threat_type': 'vc_reuse_attack',
                        'confidence': 0.9,
                        'explanation': f'VC {vc_hash[:16]}...가 30분 내 {len(recent_presentations)+1}개 검증자에게 제시됨'
                    }
        
        return results
    
    def _detect_issuer_impersonation(self, df: pd.DataFrame) -> Dict:
        """발급자 위장 탐지"""
        results = {}
        
        untrusted_issuers = self.detection_rules['issuer_impersonation']['untrusted_issuers']
        
        for idx, row in df.iterrows():
            issuer_did = row.get('optional', {}).get('issuer_did', '')
            if isinstance(issuer_did, str) and any(untrusted in issuer_did for untrusted in untrusted_issuers):
                results[row['event_id']] = {
                    'threat_type': 'issuer_impersonation',
                    'confidence': 0.95,
                    'explanation': f'신뢰할 수 없는 발급자 {issuer_did}로 생성된 VC 사용'
                }
        
        return results
    
    def _detect_time_anomaly(self, df: pd.DataFrame) -> Dict:
        """시간 이상 탐지"""
        results = {}
        
        presentations = df[df['event_type'] == 'PRESENTATION'].copy()
        if presentations.empty:
            return results
        
        presentations['timestamp'] = pd.to_datetime(presentations['timestamp'])
        holder_groups = presentations.groupby('holder_did')
        
        for holder_did, group in holder_groups:
            if len(group) < 3:
                continue
            
            group = group.sort_values('timestamp')
            
            for i in range(len(group) - 2):
                current_time = group.iloc[i]['timestamp']
                time_window = current_time + timedelta(minutes=5)
                
                simultaneous_presentations = group[
                    (group['timestamp'] >= current_time) & 
                    (group['timestamp'] <= time_window)
                ]
                
                if len(simultaneous_presentations) >= 3:
                    for idx, row in simultaneous_presentations.iterrows():
                        results[row['event_id']] = {
                            'threat_type': 'time_anomaly',
                            'confidence': 0.8,
                            'explanation': f'동일 사용자가 5분 내 {len(simultaneous_presentations)}개 VC 제시'
                        }
        
        return results
    
    def _detect_rapid_events(self, df: pd.DataFrame) -> Dict:
        """빠른 연속 이벤트 패턴 탐지"""
        results = {}
        
        time_window_minutes = self.detection_rules['rapid_events']['time_window_minutes']
        max_events = self.detection_rules['rapid_events']['max_events']
        
        df_sorted = df.copy()
        df_sorted['timestamp'] = pd.to_datetime(df_sorted['timestamp'])
        df_sorted = df_sorted.sort_values(['holder_did', 'timestamp'])
        
        for holder_did in df_sorted['holder_did'].unique():
            holder_events = df_sorted[df_sorted['holder_did'] == holder_did]
            
            for i in range(len(holder_events)):
                current_time = holder_events.iloc[i]['timestamp']
                time_window = current_time + timedelta(minutes=time_window_minutes)
                
                rapid_events = holder_events[
                    (holder_events['timestamp'] >= current_time) & 
                    (holder_events['timestamp'] <= time_window)
                ]
                
                if len(rapid_events) > max_events:
                    event_id = holder_events.iloc[i]['event_id']
                    results[event_id] = {
                        'threat_type': 'rapid_events',
                        'confidence': 0.7,
                        'explanation': f'Holder가 {time_window_minutes}분 내 {len(rapid_events)}개 이벤트 발생'
                    }
        
        return results


class MSLModelEngine:
    """MSL 기반 모델 탐지 엔진"""
    
    def __init__(self, config: Dict[str, Any] = None):
        self.config = config or {}
        self.isolation_forest = None
        self.random_forest = None
        self.scaler = StandardScaler()
        self.is_trained = False
    
    def train(self, df: pd.DataFrame):
        """모델 훈련"""
        try:
            features = self._extract_features(df)
            
            if features.empty:
                logger.warning("추출된 특징이 없어 모델 훈련을 건너뜁니다.")
                return
            
            # 특징 정규화
            features_scaled = self.scaler.fit_transform(features)
            
            # 라벨 인코딩
            labels = (df['label'] == 'malicious').astype(int).values
            
            # Random Forest 훈련
            self.random_forest = RandomForestClassifier(
                n_estimators=100,
                max_depth=10,
                random_state=42
            )
            self.random_forest.fit(features_scaled, labels)
            
            # Isolation Forest 훈련 (정상 데이터만)
            normal_data = df[df['label'] == 'benign']
            if len(normal_data) > 0:
                normal_features = self._extract_features(normal_data)
                normal_features_scaled = self.scaler.transform(normal_features)
                
                self.isolation_forest = IsolationForest(
                    contamination=0.1,
                    random_state=42
                )
                self.isolation_forest.fit(normal_features_scaled)
            
            self.is_trained = True
            logger.info("모델 훈련 완료")
            
        except Exception as e:
            logger.error(f"모델 훈련 중 오류: {e}")
    
    def detect(self, df: pd.DataFrame) -> Dict:
        """모델 기반 탐지 실행"""
        if not self.is_trained:
            return {}
        
        try:
            features = self._extract_features(df)
            
            if features.empty:
                return {}
            
            features_scaled = self.scaler.transform(features)
            
            results = {}
            
            # Random Forest 예측
            if self.random_forest is not None:
                rf_probs = self.random_forest.predict_proba(features_scaled)
                rf_threat_probs = rf_probs[:, 1:].max(axis=1)
            else:
                rf_threat_probs = np.zeros(len(features_scaled))
            
            # Isolation Forest 예측
            if self.isolation_forest is not None:
                iso_scores = self.isolation_forest.decision_function(features_scaled)
                iso_anomalies = self.isolation_forest.predict(features_scaled) == -1
                
                # 이상 점수를 0-1 범위로 정규화
                if len(iso_scores) > 1:
                    iso_scores = (iso_scores - iso_scores.min()) / (iso_scores.max() - iso_scores.min())
            else:
                iso_scores = np.zeros(len(features_scaled))
                iso_anomalies = np.zeros(len(features_scaled), dtype=bool)
            
            # 앙상블 점수 계산
            for idx, (_, row) in enumerate(df.iterrows()):
                ensemble_score = 0.6 * rf_threat_probs[idx] + 0.4 * iso_scores[idx]
                ensemble_anomaly = ensemble_score > 0.5
                
                results[row['event_id']] = {
                    'anomaly_score': float(ensemble_score),
                    'is_anomaly': bool(ensemble_anomaly),
                    'rf_threat_prob': float(rf_threat_probs[idx]),
                    'iso_anomaly_score': float(iso_scores[idx])
                }
            
            return results
            
        except Exception as e:
            logger.error(f"모델 탐지 중 오류: {e}")
            return {}
    
    def _extract_features(self, df: pd.DataFrame) -> pd.DataFrame:
        """특징 추출"""
        features = pd.DataFrame()
        
        # 시간 기반 특징
        df['timestamp'] = pd.to_datetime(df['timestamp'])
        features['hour'] = df['timestamp'].dt.hour
        features['is_weekend'] = (df['timestamp'].dt.dayofweek >= 5).astype(int)
        features['is_business_hours'] = ((df['timestamp'].dt.hour >= 9) & (df['timestamp'].dt.hour <= 17)).astype(int)
        
        # 이벤트 유형 인코딩
        event_type_map = {'ISSUANCE': 0, 'PRESENTATION': 1, 'VERIFICATION': 2, 'REVOCATION': 3}
        features['event_type_encoded'] = df['event_type'].map(event_type_map).fillna(0)
        
        # 빈도 기반 특징
        holder_counts = df['holder_did'].value_counts()
        features['holder_frequency'] = df['holder_did'].map(holder_counts) / len(df)
        
        vc_counts = df['vc_hash'].value_counts()
        features['vc_frequency'] = df['vc_hash'].map(vc_counts) / len(df)
        
        # NaN 값 처리
        features = features.fillna(0)
        
        return features


class PerformanceMonitor:
    """성능 모니터링 시스템"""
    
    def __init__(self):
        self.metrics_history = {
            'precision': [],
            'recall': [],
            'f1_score': [],
            'accuracy': [],
            'processing_time': []
        }
        self.detection_counts = {
            'total_events': 0,
            'threats_detected': 0,
            'false_positives': 0,
            'false_negatives': 0
        }
    
    def record_metrics(self, precision: float, recall: float, f1_score: float, 
                      accuracy: float, processing_time: float):
        """성능 지표 기록"""
        self.metrics_history['precision'].append(precision)
        self.metrics_history['recall'].append(recall)
        self.metrics_history['f1_score'].append(f1_score)
        self.metrics_history['accuracy'].append(accuracy)
        self.metrics_history['processing_time'].append(processing_time)
    
    def record_detection(self, total_events: int, threats_detected: int, 
                        false_positives: int, false_negatives: int):
        """탐지 결과 기록"""
        self.detection_counts['total_events'] += total_events
        self.detection_counts['threats_detected'] += threats_detected
        self.detection_counts['false_positives'] += false_positives
        self.detection_counts['false_negatives'] += false_negatives
    
    def get_performance_summary(self) -> Dict[str, Any]:
        """성능 요약 반환"""
        if not self.metrics_history['precision']:
            return {"status": "no_data"}
        
        summary = {}
        for metric, values in self.metrics_history.items():
            if values:
                summary[metric] = {
                    'current': values[-1],
                    'average': np.mean(values),
                    'min': np.min(values),
                    'max': np.max(values)
                }
        
        summary['detection_stats'] = self.detection_counts.copy()
        
        return summary