#!/usr/bin/env python3
"""
DID 위협 탐지 시스템 - 고급 특징 엔지니어링
DID 특화 특징 추출 및 고급 분석 기능
"""

import pandas as pd
import numpy as np
from typing import Dict, List, Tuple, Any, Optional
from datetime import datetime, timedelta
import logging
from utils import handle_errors, log_execution_time

logger = logging.getLogger(__name__)

class MSLFeatureEngineer:
    """MSL 기반 고급 특징 엔지니어링 클래스"""
    
    def __init__(self):
        self.feature_cache = {}
        self.statistics_cache = {}
        
    @handle_errors(default_return=pd.DataFrame())
    @log_execution_time
    def extract_advanced_features(self, df: pd.DataFrame) -> pd.DataFrame:
        """고급 특징 추출"""
        logger.info("고급 특징 추출 시작...")
        
        features_df = df.copy()
        
        # 1. 기본 시간 특징
        features_df = self._extract_temporal_features(features_df)
        
        # 2. DID 특화 특징
        features_df = self._extract_did_specific_features(features_df)
        
        # 3. 행동 패턴 특징
        features_df = self._extract_behavioral_features(features_df)
        
        # 4. 네트워크 특징
        features_df = self._extract_network_features(features_df)
        
        # 5. 위험도 특징
        features_df = self._extract_risk_features(features_df)
        
        # 6. 통계적 특징
        features_df = self._extract_statistical_features(features_df)
        
        logger.info(f"고급 특징 추출 완료: {features_df.shape[1]}개 특징")
        return features_df
    
    def _extract_temporal_features(self, df: pd.DataFrame) -> pd.DataFrame:
        """시간 관련 특징 추출"""
        logger.info("시간 특징 추출 중...")
        
        df['timestamp'] = pd.to_datetime(df['timestamp'])
        
        # 기본 시간 특징
        df['hour'] = df['timestamp'].dt.hour
        df['day_of_week'] = df['timestamp'].dt.dayofweek
        df['day_of_month'] = df['timestamp'].dt.day
        df['month'] = df['timestamp'].dt.month
        df['is_weekend'] = (df['timestamp'].dt.dayofweek >= 5).astype(int)
        df['is_business_hours'] = ((df['hour'] >= 9) & (df['hour'] <= 17)).astype(int)
        df['is_night_time'] = ((df['hour'] >= 22) | (df['hour'] <= 6)).astype(int)
        
        # 시간대별 위험도
        df['hour_risk_score'] = df['hour'].apply(self._calculate_hour_risk_score)
        df['day_risk_score'] = df['day_of_week'].apply(self._calculate_day_risk_score)
        
        # 시간 간격 특징
        df = df.sort_values(['holder_did', 'timestamp'])
        df['time_since_last_event'] = df.groupby('holder_did')['timestamp'].diff().dt.total_seconds() / 3600  # 시간 단위
        df['time_since_last_event'] = df['time_since_last_event'].fillna(0)
        
        # 시간 간격 이상도
        df['time_interval_anomaly'] = df.groupby('holder_did')['time_since_last_event'].transform(
            lambda x: (x - x.mean()) / (x.std() + 1e-8)
        )
        
        return df
    
    def _extract_did_specific_features(self, df: pd.DataFrame) -> pd.DataFrame:
        """DID 특화 특징 추출"""
        logger.info("DID 특화 특징 추출 중...")
        
        # VC 생명주기 특징
        df = self._extract_vc_lifecycle_features(df)
        
        # 발급자 신뢰도 특징
        df = self._extract_issuer_trust_features(df)
        
        # 검증자 패턴 특징
        df = self._extract_verifier_pattern_features(df)
        
        # Holder 행동 특징
        df = self._extract_holder_behavior_features(df)
        
        return df
    
    def _extract_vc_lifecycle_features(self, df: pd.DataFrame) -> pd.DataFrame:
        """VC 생명주기 특징"""
        # VC별 이벤트 시퀀스 분석
        vc_events = df.groupby('vc_hash').agg({
            'timestamp': ['min', 'max', 'count'],
            'event_type': lambda x: list(x),
            'holder_did': 'nunique',
            'verifier_id': 'nunique'
        }).reset_index()
        
        vc_events.columns = ['vc_hash', 'vc_created_at', 'vc_last_used', 'vc_event_count', 
                           'vc_event_sequence', 'vc_holder_count', 'vc_verifier_count']
        
        # VC 생명주기 길이
        vc_events['vc_lifecycle_duration'] = (
            pd.to_datetime(vc_events['vc_last_used']) - 
            pd.to_datetime(vc_events['vc_created_at'])
        ).dt.total_seconds() / 3600  # 시간 단위
        
        # VC 재사용 패턴
        vc_events['vc_reuse_frequency'] = vc_events['vc_event_count'] / (vc_events['vc_lifecycle_duration'] + 1)
        vc_events['vc_multi_holder'] = (vc_events['vc_holder_count'] > 1).astype(int)
        vc_events['vc_multi_verifier'] = (vc_events['vc_verifier_count'] > 1).astype(int)
        
        # 원본 데이터와 병합
        df = df.merge(vc_events[['vc_hash', 'vc_lifecycle_duration', 'vc_reuse_frequency', 
                                'vc_multi_holder', 'vc_multi_verifier']], on='vc_hash', how='left')
        
        return df
    
    def _extract_issuer_trust_features(self, df: pd.DataFrame) -> pd.DataFrame:
        """발급자 신뢰도 특징"""
        # 발급자별 통계
        issuer_stats = df.groupby('issuer_did').agg({
            'event_id': 'count',
            'holder_did': 'nunique',
            'vc_hash': 'nunique',
            'label': lambda x: (x != 'benign').sum()
        }).reset_index()
        
        issuer_stats.columns = ['issuer_did', 'issuer_total_events', 'issuer_unique_holders', 
                              'issuer_unique_vcs', 'issuer_threat_events']
        
        # 발급자 신뢰도 점수
        issuer_stats['issuer_trust_score'] = 1.0 - (issuer_stats['issuer_threat_events'] / issuer_stats['issuer_total_events'])
        issuer_stats['issuer_activity_score'] = issuer_stats['issuer_total_events'] / issuer_stats['issuer_total_events'].max()
        issuer_stats['issuer_diversity_score'] = issuer_stats['issuer_unique_holders'] / issuer_stats['issuer_unique_holders'].max()
        
        # 원본 데이터와 병합
        df = df.merge(issuer_stats[['issuer_did', 'issuer_trust_score', 'issuer_activity_score', 
                                   'issuer_diversity_score']], on='issuer_did', how='left')
        
        return df
    
    def _extract_verifier_pattern_features(self, df: pd.DataFrame) -> pd.DataFrame:
        """검증자 패턴 특징"""
        # 검증자별 통계
        verifier_stats = df.groupby('verifier_id').agg({
            'event_id': 'count',
            'holder_did': 'nunique',
            'vc_hash': 'nunique',
            'timestamp': ['min', 'max']
        }).reset_index()
        
        verifier_stats.columns = ['verifier_id', 'verifier_total_events', 'verifier_unique_holders', 
                                'verifier_unique_vcs', 'verifier_first_seen', 'verifier_last_seen']
        
        # 검증자 활동 기간
        verifier_stats['verifier_activity_duration'] = (
            pd.to_datetime(verifier_stats['verifier_last_seen']) - 
            pd.to_datetime(verifier_stats['verifier_first_seen'])
        ).dt.total_seconds() / 3600
        
        # 검증자 다양성 점수
        verifier_stats['verifier_diversity_score'] = verifier_stats['verifier_unique_holders'] / verifier_stats['verifier_unique_holders'].max()
        verifier_stats['verifier_activity_score'] = verifier_stats['verifier_total_events'] / verifier_stats['verifier_total_events'].max()
        
        # 원본 데이터와 병합
        df = df.merge(verifier_stats[['verifier_id', 'verifier_diversity_score', 'verifier_activity_score', 
                                     'verifier_activity_duration']], on='verifier_id', how='left')
        
        return df
    
    def _extract_holder_behavior_features(self, df: pd.DataFrame) -> pd.DataFrame:
        """Holder 행동 특징"""
        # Holder별 통계
        holder_stats = df.groupby('holder_did').agg({
            'event_id': 'count',
            'vc_hash': 'nunique',
            'verifier_id': 'nunique',
            'issuer_did': 'nunique',
            'timestamp': ['min', 'max'],
            'label': lambda x: (x != 'benign').sum()
        }).reset_index()
        
        holder_stats.columns = ['holder_did', 'holder_total_events', 'holder_unique_vcs', 
                              'holder_unique_verifiers', 'holder_unique_issuers', 
                              'holder_first_seen', 'holder_last_seen', 'holder_threat_events']
        
        # Holder 활동 기간
        holder_stats['holder_activity_duration'] = (
            pd.to_datetime(holder_stats['holder_last_seen']) - 
            pd.to_datetime(holder_stats['holder_first_seen'])
        ).dt.total_seconds() / 3600
        
        # Holder 행동 점수
        holder_stats['holder_activity_score'] = holder_stats['holder_total_events'] / holder_stats['holder_total_events'].max()
        holder_stats['holder_diversity_score'] = holder_stats['holder_unique_verifiers'] / holder_stats['holder_unique_verifiers'].max()
        holder_stats['holder_risk_score'] = holder_stats['holder_threat_events'] / holder_stats['holder_total_events']
        
        # 원본 데이터와 병합
        df = df.merge(holder_stats[['holder_did', 'holder_activity_score', 'holder_diversity_score', 
                                   'holder_risk_score', 'holder_activity_duration']], on='holder_did', how='left')
        
        return df
    
    def _extract_behavioral_features(self, df: pd.DataFrame) -> pd.DataFrame:
        """행동 패턴 특징 추출"""
        logger.info("행동 패턴 특징 추출 중...")
        
        # 이벤트 시퀀스 패턴
        df = self._extract_event_sequence_features(df)
        
        # 시간 패턴 특징
        df = self._extract_temporal_pattern_features(df)
        
        # 빈도 패턴 특징
        df = self._extract_frequency_pattern_features(df)
        
        return df
    
    def _extract_event_sequence_features(self, df: pd.DataFrame) -> pd.DataFrame:
        """이벤트 시퀀스 패턴 특징"""
        # Holder별 이벤트 시퀀스
        holder_sequences = df.groupby('holder_did')['event_type'].apply(list).reset_index()
        holder_sequences.columns = ['holder_did', 'event_sequence']
        
        # 시퀀스 길이
        holder_sequences['sequence_length'] = holder_sequences['event_sequence'].apply(len)
        
        # 시퀀스 다양성 (고유 이벤트 유형 수)
        holder_sequences['sequence_diversity'] = holder_sequences['event_sequence'].apply(lambda x: len(set(x)))
        
        # 시퀀스 복잡도 (이벤트 유형 전환 횟수)
        holder_sequences['sequence_complexity'] = holder_sequences['event_sequence'].apply(
            lambda x: sum(1 for i in range(1, len(x)) if x[i] != x[i-1])
        )
        
        # 원본 데이터와 병합
        df = df.merge(holder_sequences[['holder_did', 'sequence_length', 'sequence_diversity', 
                                       'sequence_complexity']], on='holder_did', how='left')
        
        return df
    
    def _extract_temporal_pattern_features(self, df: pd.DataFrame) -> pd.DataFrame:
        """시간 패턴 특징"""
        # Holder별 시간 패턴
        holder_temporal = df.groupby('holder_did').agg({
            'hour': ['mean', 'std', 'min', 'max'],
            'day_of_week': ['mean', 'std'],
            'time_since_last_event': ['mean', 'std', 'min', 'max']
        }).reset_index()
        
        holder_temporal.columns = ['holder_did', 'avg_hour', 'hour_std', 'min_hour', 'max_hour',
                                 'avg_day_of_week', 'day_std', 'avg_time_interval', 'time_interval_std',
                                 'min_time_interval', 'max_time_interval']
        
        # 시간 패턴 일관성
        holder_temporal['hour_consistency'] = 1.0 / (holder_temporal['hour_std'] + 1)
        holder_temporal['day_consistency'] = 1.0 / (holder_temporal['day_std'] + 1)
        holder_temporal['interval_consistency'] = 1.0 / (holder_temporal['time_interval_std'] + 1)
        
        # 원본 데이터와 병합
        df = df.merge(holder_temporal[['holder_did', 'hour_consistency', 'day_consistency', 
                                      'interval_consistency']], on='holder_did', how='left')
        
        return df
    
    def _extract_frequency_pattern_features(self, df: pd.DataFrame) -> pd.DataFrame:
        """빈도 패턴 특징"""
        # Holder별 이벤트 빈도
        holder_freq = df.groupby(['holder_did', 'event_type']).size().unstack(fill_value=0)
        holder_freq['total_events'] = holder_freq.sum(axis=1)
        
        # 이벤트 유형별 비율
        for event_type in ['ISSUANCE', 'PRESENTATION', 'VERIFICATION', 'REVOCATION']:
            if event_type in holder_freq.columns:
                holder_freq[f'{event_type.lower()}_ratio'] = holder_freq[event_type] / holder_freq['total_events']
            else:
                holder_freq[f'{event_type.lower()}_ratio'] = 0.0
        
        # 빈도 패턴 정규화
        holder_freq = holder_freq.reset_index()
        
        # 원본 데이터와 병합
        df = df.merge(holder_freq[['holder_did', 'issuance_ratio', 'presentation_ratio', 
                                  'verification_ratio', 'revocation_ratio']], on='holder_did', how='left')
        
        return df
    
    def _extract_network_features(self, df: pd.DataFrame) -> pd.DataFrame:
        """네트워크 특징 추출"""
        logger.info("네트워크 특징 추출 중...")
        
        # Holder-Verifier 네트워크
        df = self._extract_holder_verifier_network_features(df)
        
        # Holder-Issuer 네트워크
        df = self._extract_holder_issuer_network_features(df)
        
        # VC 네트워크
        df = self._extract_vc_network_features(df)
        
        return df
    
    def _extract_holder_verifier_network_features(self, df: pd.DataFrame) -> pd.DataFrame:
        """Holder-Verifier 네트워크 특징"""
        # Holder별 Verifier 다양성
        holder_verifier = df.groupby('holder_did')['verifier_id'].nunique().reset_index()
        holder_verifier.columns = ['holder_did', 'verifier_diversity']
        
        # Verifier별 Holder 다양성
        verifier_holder = df.groupby('verifier_id')['holder_did'].nunique().reset_index()
        verifier_holder.columns = ['verifier_id', 'holder_diversity']
        
        # 원본 데이터와 병합
        df = df.merge(holder_verifier, on='holder_did', how='left')
        df = df.merge(verifier_holder, on='verifier_id', how='left')
        
        return df
    
    def _extract_holder_issuer_network_features(self, df: pd.DataFrame) -> pd.DataFrame:
        """Holder-Issuer 네트워크 특징"""
        # Holder별 Issuer 다양성
        holder_issuer = df.groupby('holder_did')['issuer_did'].nunique().reset_index()
        holder_issuer.columns = ['holder_did', 'issuer_diversity']
        
        # Issuer별 Holder 다양성
        issuer_holder = df.groupby('issuer_did')['holder_did'].nunique().reset_index()
        issuer_holder.columns = ['issuer_did', 'holder_diversity']
        
        # 원본 데이터와 병합
        df = df.merge(holder_issuer, on='holder_did', how='left')
        df = df.merge(issuer_holder, on='issuer_did', how='left')
        
        return df
    
    def _extract_vc_network_features(self, df: pd.DataFrame) -> pd.DataFrame:
        """VC 네트워크 특징"""
        # VC별 사용자 다양성
        vc_users = df.groupby('vc_hash')['holder_did'].nunique().reset_index()
        vc_users.columns = ['vc_hash', 'vc_user_diversity']
        
        # VC별 검증자 다양성
        vc_verifiers = df.groupby('vc_hash')['verifier_id'].nunique().reset_index()
        vc_verifiers.columns = ['vc_hash', 'vc_verifier_diversity']
        
        # 원본 데이터와 병합
        df = df.merge(vc_users, on='vc_hash', how='left')
        df = df.merge(vc_verifiers, on='vc_hash', how='left')
        
        return df
    
    def _extract_risk_features(self, df: pd.DataFrame) -> pd.DataFrame:
        """위험도 특징 추출"""
        logger.info("위험도 특징 추출 중...")
        
        # 종합 위험도 점수 계산
        df['comprehensive_risk_score'] = self._calculate_comprehensive_risk_score(df)
        
        # 위험도 등급
        df['risk_level'] = pd.cut(df['comprehensive_risk_score'], 
                                 bins=[0, 0.3, 0.6, 0.8, 1.0], 
                                 labels=['Low', 'Medium', 'High', 'Critical'])
        
        return df
    
    def _extract_statistical_features(self, df: pd.DataFrame) -> pd.DataFrame:
        """통계적 특징 추출"""
        logger.info("통계적 특징 추출 중...")
        
        # Holder별 통계적 특징
        holder_stats = df.groupby('holder_did').agg({
            'time_since_last_event': ['mean', 'std', 'min', 'max'],
            'hour': ['mean', 'std'],
            'day_of_week': ['mean', 'std']
        }).reset_index()
        
        holder_stats.columns = ['holder_did', 'avg_time_interval', 'std_time_interval', 
                              'min_time_interval', 'max_time_interval', 'avg_hour', 'std_hour',
                              'avg_day_of_week', 'std_day_of_week']
        
        # 이상도 점수
        holder_stats['time_interval_anomaly_score'] = holder_stats['std_time_interval'] / (holder_stats['avg_time_interval'] + 1e-8)
        holder_stats['hour_anomaly_score'] = holder_stats['std_hour'] / 12.0  # 표준화
        holder_stats['day_anomaly_score'] = holder_stats['std_day_of_week'] / 3.5  # 표준화
        
        # 원본 데이터와 병합
        df = df.merge(holder_stats[['holder_did', 'time_interval_anomaly_score', 
                                   'hour_anomaly_score', 'day_anomaly_score']], on='holder_did', how='left')
        
        return df
    
    def _calculate_hour_risk_score(self, hour: int) -> float:
        """시간대별 위험도 점수"""
        # 야간 시간대가 더 위험
        if 22 <= hour or hour <= 6:
            return 0.8
        elif 7 <= hour <= 9 or 18 <= hour <= 21:
            return 0.6
        else:
            return 0.4
    
    def _calculate_day_risk_score(self, day_of_week: int) -> float:
        """요일별 위험도 점수"""
        # 주말이 더 위험
        if day_of_week >= 5:  # 토요일, 일요일
            return 0.7
        else:
            return 0.5
    
    def _calculate_comprehensive_risk_score(self, df: pd.DataFrame) -> pd.Series:
        """종합 위험도 점수 계산"""
        risk_factors = []
        
        # 시간 위험도
        risk_factors.append(df['hour_risk_score'] * 0.2)
        
        # 요일 위험도
        risk_factors.append(df['day_risk_score'] * 0.1)
        
        # Holder 위험도
        risk_factors.append(df.get('holder_risk_score', 0.5) * 0.3)
        
        # 발급자 신뢰도 (낮을수록 위험)
        risk_factors.append((1.0 - df.get('issuer_trust_score', 0.5)) * 0.2)
        
        # 시간 간격 이상도
        risk_factors.append(df.get('time_interval_anomaly', 0) * 0.1)
        
        # VC 재사용 빈도
        risk_factors.append(df.get('vc_reuse_frequency', 0) * 0.1)
        
        # 종합 점수 계산
        comprehensive_score = sum(risk_factors)
        
        # 0-1 범위로 정규화
        return np.clip(comprehensive_score, 0, 1)
    
    def get_feature_importance(self, df: pd.DataFrame, target_column: str = 'label') -> Dict[str, float]:
        """특징 중요도 분석"""
        from sklearn.ensemble import RandomForestClassifier
        from sklearn.preprocessing import LabelEncoder
        
        # 수치형 특징만 선택
        numeric_features = df.select_dtypes(include=[np.number]).columns.tolist()
        if target_column in numeric_features:
            numeric_features.remove(target_column)
        
        if len(numeric_features) == 0:
            logger.warning("수치형 특징이 없습니다.")
            return {}
        
        # 타겟 변수 인코딩
        le = LabelEncoder()
        y = le.fit_transform(df[target_column])
        X = df[numeric_features].fillna(0)
        
        # 랜덤 포레스트로 특징 중요도 계산
        rf = RandomForestClassifier(n_estimators=100, random_state=42)
        rf.fit(X, y)
        
        # 특징 중요도 반환
        feature_importance = dict(zip(numeric_features, rf.feature_importances_))
        
        # 중요도 순으로 정렬
        sorted_importance = dict(sorted(feature_importance.items(), key=lambda x: x[1], reverse=True))
        
        logger.info(f"특징 중요도 분석 완료: {len(sorted_importance)}개 특징")
        return sorted_importance
    
    def select_top_features(self, df: pd.DataFrame, target_column: str = 'label', 
                           top_k: int = 20) -> List[str]:
        """상위 K개 특징 선택"""
        feature_importance = self.get_feature_importance(df, target_column)
        top_features = list(feature_importance.keys())[:top_k]
        
        logger.info(f"상위 {top_k}개 특징 선택: {top_features}")
        return top_features