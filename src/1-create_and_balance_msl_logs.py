#!/usr/bin/env python3
"""
DID 위협 탐지 시스템 - 통합 MSL 로그 생성 및 밸런싱
MSL 로그 생성부터 데이터 밸런싱까지 통합된 데이터 파이프라인
"""

from datetime import datetime, timedelta
import uuid
import random
import hashlib
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.utils.class_weight import compute_class_weight
from imblearn.over_sampling import SMOTE, RandomOverSampler
from imblearn.under_sampling import RandomUnderSampler
from imblearn.combine import SMOTEENN, SMOTETomek
import numpy as np
import json
import asyncio
import logging
from pathlib import Path
from typing import Dict, List, Any, Optional

# 시드 고정
random.seed(42)
np.random.seed(42)

# 로깅 설정
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# ===== MSL 상수 정의 =====
EVENT_TYPES = ["ISSUANCE", "PRESENTATION", "VERIFICATION", "REVOCATION"]

# DID 및 서비스 식별자 풀
HOLDER_DIDS = [f"did:web:holder{i:04d}.identity.com" for i in range(1, 1001)]
VERIFIER_IDS = [
    "svc:bank-app-001", "svc:university-portal", "svc:hospital-system", 
    "svc:gov-service", "svc:insurance-portal", "svc:retail-app",
    "svc:travel-booking", "svc:enterprise-hr", "svc:fintech-app"
]
ISSUER_DIDS = [
    "did:web:issuer1.trusted.com", "did:web:university.edu", "did:web:gov.id",
    "did:web:issuer2.trusted.com", "did:web:hospital.org", "did:web:bank.com",
    "did:web:issuer3.untrusted.com", "did:web:fake-issuer.com"  # 악성 발급자
]

# 위협 시나리오 정의
THREAT_SCENARIOS = {
    "vc_reuse_attack": {
        "description": "동일 VC를 여러 검증자에게 재사용",
        "frequency": 0.05,
        "severity": "high"
    },
    "issuer_impersonation": {
        "description": "가짜 발급자로 위조된 VC 생성",
        "frequency": 0.03,
        "severity": "critical"
    },
    "revocation_ignore": {
        "description": "폐기된 VC를 계속 사용",
        "frequency": 0.02,
        "severity": "high"
    },
    "time_anomaly": {
        "description": "비정상적인 시간 패턴 (동시 다중 제시)",
        "frequency": 0.04,
        "severity": "medium"
    }
}

# ===== 통합 MSL 데이터 파이프라인 =====
class IntegratedMSLPipeline:
    """통합 MSL 데이터 생성 및 밸런싱 파이프라인"""
    
    def __init__(self):
        self.vc_registry = {}
        self.issued_vcs = set()
        self.revoked_vcs = set()
        self.original_distribution = {}
        self.balanced_distribution = {}
        
    def generate_vc_hash(self, holder_did, issuer_did, credential_type="degree"):
        """VC 해시 생성 (일관성을 위해 결정적)"""
        content = f"{holder_did}:{issuer_did}:{credential_type}:{uuid.uuid4().hex}"
        return f"blake3:{hashlib.blake2b(content.encode()).hexdigest()}"
    
    def generate_msl_event(self, event_type, threat_type="benign", base_time=None):
        """MSL 표준 이벤트 생성"""
        if base_time is None:
            base_time = datetime.now()
            
        # 시간 변동 (±30일 범위)
        timestamp = base_time + timedelta(
            days=random.randint(-30, 30),
            hours=random.randint(0, 23),
            minutes=random.randint(0, 59),
            seconds=random.randint(0, 59)
        )
        
        # 기본 MSL 필드
        holder_did = random.choice(HOLDER_DIDS)
        verifier_id = random.choice(VERIFIER_IDS)
        
        # 이벤트 유형별 처리
        if event_type == "ISSUANCE":
            issuer_did = random.choice(ISSUER_DIDS)
            vc_hash = self.generate_vc_hash(holder_did, issuer_did)
            self.issued_vcs.add(vc_hash)
            self.vc_registry[vc_hash] = {
                "holder_did": holder_did,
                "issuer_did": issuer_did,
                "issued_at": timestamp,
                "status": "active"
            }
            
        elif event_type == "PRESENTATION":
            if threat_type == "vc_reuse_attack":
                vc_hash = random.choice(list(self.issued_vcs))
            elif threat_type == "revocation_ignore":
                vc_hash = random.choice(list(self.revoked_vcs)) if self.revoked_vcs else random.choice(list(self.issued_vcs))
            else:
                vc_hash = random.choice(list(self.issued_vcs)) if self.issued_vcs else self.generate_vc_hash(holder_did, random.choice(ISSUER_DIDS))
                
        elif event_type == "VERIFICATION":
            if threat_type == "issuer_impersonation":
                fake_issuer = random.choice([d for d in ISSUER_DIDS if "untrusted" in d or "fake" in d])
                vc_hash = self.generate_vc_hash(holder_did, fake_issuer)
            else:
                vc_hash = random.choice(list(self.issued_vcs)) if self.issued_vcs else self.generate_vc_hash(holder_did, random.choice(ISSUER_DIDS))
                
        elif event_type == "REVOCATION":
            if self.issued_vcs:
                vc_hash = random.choice(list(self.issued_vcs))
                self.issued_vcs.remove(vc_hash)
                self.revoked_vcs.add(vc_hash)
                if vc_hash in self.vc_registry:
                    self.vc_registry[vc_hash]["status"] = "revoked"
                    self.vc_registry[vc_hash]["revoked_at"] = timestamp
            else:
                vc_hash = self.generate_vc_hash(holder_did, random.choice(ISSUER_DIDS))
        
        # MSL Canonical Schema 구조
        msl_event = {
            "event_id": str(uuid.uuid4()),
            "event_type": event_type,
            "vc_hash": vc_hash,
            "holder_did": holder_did,
            "verifier_id": verifier_id,
            "timestamp": timestamp.isoformat() + "Z",
            "optional": {
                "issuer_did": self.vc_registry.get(vc_hash, {}).get("issuer_did", random.choice(ISSUER_DIDS)),
                "anchor_status": self.vc_registry.get(vc_hash, {}).get("status", "unknown"),
                "device_id": f"tok:dev-{uuid.uuid4().hex[:8]}",
                "geo_token": f"tok:geo-{random.choice(['kr-seoul', 'us-ny', 'jp-tokyo', 'de-berlin'])}"
            },
            "label": threat_type,
            "threat_type": threat_type
        }
        
        return msl_event
    
    async def generate_threat_campaign(self, campaign_type, event_count, base_time):
        """위협 캠페인 이벤트 생성"""
        events = []
        campaign_id = f"campaign-{uuid.uuid4().hex[:8]}"
        
        if campaign_type == "vc_reuse_campaign":
            issuance_event = self.generate_msl_event("ISSUANCE", "benign", base_time)
            vc_hash = issuance_event["vc_hash"]
            events.append(issuance_event)
            
            for i in range(event_count - 1):
                event_time = base_time + timedelta(minutes=i*5)
                presentation_event = self.generate_msl_event("PRESENTATION", "vc_reuse_attack", event_time)
                presentation_event["vc_hash"] = vc_hash
                presentation_event["campaign_id"] = campaign_id
                events.append(presentation_event)
                
        elif campaign_type == "issuer_impersonation_campaign":
            for i in range(event_count):
                event_time = base_time + timedelta(minutes=i*10)
                if i == 0:
                    event = self.generate_msl_event("ISSUANCE", "issuer_impersonation", event_time)
                else:
                    event = self.generate_msl_event("PRESENTATION", "issuer_impersonation", event_time)
                event["campaign_id"] = campaign_id
                events.append(event)
                
        elif campaign_type == "revocation_ignore_campaign":
            issuance_event = self.generate_msl_event("ISSUANCE", "benign", base_time)
            vc_hash = issuance_event["vc_hash"]
            events.append(issuance_event)
            
            revocation_event = self.generate_msl_event("REVOCATION", "benign", base_time + timedelta(hours=1))
            revocation_event["vc_hash"] = vc_hash
            events.append(revocation_event)
            
            for i in range(event_count - 2):
                event_time = base_time + timedelta(hours=2, minutes=i*15)
                presentation_event = self.generate_msl_event("PRESENTATION", "revocation_ignore", event_time)
                presentation_event["vc_hash"] = vc_hash
                presentation_event["campaign_id"] = campaign_id
                events.append(presentation_event)
        
        return events
    
    async def generate_msl_dataset(self) -> List[Dict]:
        """MSL 기반 포괄적 데이터셋 생성"""
        logger.info("MSL 기반 DID 위협 탐지 데이터셋 생성 시작...")
        
        base_time = datetime(2025, 1, 15, 12, 0, 0)
        all_events = []
        
        # 1. 정상 이벤트 생성
        logger.info("정상 이벤트 생성 중...")
        for event_type in EVENT_TYPES:
            for _ in range(2000):
                event = self.generate_msl_event(event_type, "benign", base_time)
                all_events.append(event)
        
        # 2. 개별 위협 시나리오 생성
        logger.info("위협 시나리오 생성 중...")
        for threat_type in THREAT_SCENARIOS.keys():
            logger.info(f"  - {threat_type}: 1000개")
            for event_type in EVENT_TYPES:
                for _ in range(250):
                    event = self.generate_msl_event(event_type, threat_type, base_time)
                    all_events.append(event)
        
        # 3. 위협 캠페인 생성
        logger.info("위협 캠페인 생성 중...")
        campaigns = [
            ("vc_reuse_campaign", 500),
            ("issuer_impersonation_campaign", 300),
            ("revocation_ignore_campaign", 400)
        ]
        
        for campaign_name, count in campaigns:
            logger.info(f"  - {campaign_name}: {count}개")
            campaign_events = await self.generate_threat_campaign(campaign_name, count, base_time)
            all_events.extend(campaign_events)
        
        # 4. 데이터 밸런스 조정
        logger.info("⚖️ 데이터 밸런스 조정 중...")
        current_threat_count = sum(1 for e in all_events if e["label"] != "benign")
        additional_benign = int(current_threat_count * 1.5)
        
        for _ in range(additional_benign):
            event_type = random.choice(EVENT_TYPES)
            event = self.generate_msl_event(event_type, "benign", base_time)
            all_events.append(event)
        
        return all_events
    
    def analyze_imbalance(self, df: pd.DataFrame) -> Dict[str, Any]:
        """데이터 불균형 분석"""
        label_counts = df['label'].value_counts()
        total_samples = len(df)
        
        analysis = {
            'total_samples': total_samples,
            'class_distribution': label_counts.to_dict(),
            'class_percentages': (label_counts / total_samples * 100).to_dict(),
            'imbalance_ratio': label_counts.max() / label_counts.min(),
            'class_weights': compute_class_weight('balanced', classes=np.array(label_counts.index), y=df['label']).tolist()
        }
        
        return analysis
    
    def _encode_categorical_features(self, X: pd.DataFrame) -> pd.DataFrame:
        """범주형 변수 인코딩"""
        X_encoded = X.copy()
        categorical_columns = ['event_type', 'vc_hash', 'holder_did', 'verifier_id']
        
        for col in categorical_columns:
            if col in X_encoded.columns:
                X_encoded[col] = pd.Categorical(X_encoded[col]).codes
        
        return X_encoded
    
    def _reconstruct_dataframe(self, original_df: pd.DataFrame, X_resampled: np.ndarray, y_resampled: np.ndarray) -> pd.DataFrame:
        """리샘플링된 데이터를 원본 DataFrame 형태로 재구성"""
        balanced_data = []
        
        for i in range(len(X_resampled)):
            original_idx = i % len(original_df)
            original_row = original_df.iloc[original_idx].copy()
            
            original_row['event_id'] = f"balanced_{i}_{original_row['event_id']}"
            original_row['label'] = y_resampled[i]
            original_row['threat_type'] = y_resampled[i]
            
            balanced_data.append(original_row)
        
        return pd.DataFrame(balanced_data)
    
    def balance_with_smote(self, df: pd.DataFrame, target_column='label') -> pd.DataFrame:
        """SMOTE를 사용한 오버샘플링"""
        logger.info("SMOTE를 사용한 데이터 밸런싱 시작...")
        
        X = df.drop(columns=[target_column, 'event_id', 'timestamp', 'optional', 'optional_json'])
        y = df[target_column]
        
        X_encoded = self._encode_categorical_features(X)
        
        smote = SMOTE(random_state=42, k_neighbors=3)
        X_resampled, y_resampled = smote.fit_resample(X_encoded, y)
        
        balanced_df = self._reconstruct_dataframe(df, X_resampled, y_resampled)
        
        logger.info(f"SMOTE 완료: {len(df)} → {len(balanced_df)} 샘플")
        return balanced_df
    
    def balance_with_random_oversampling(self, df: pd.DataFrame, target_column='label') -> pd.DataFrame:
        """랜덤 오버샘플링"""
        logger.info("랜덤 오버샘플링 시작...")
        
        X = df.drop(columns=[target_column, 'event_id', 'timestamp', 'optional', 'optional_json'])
        y = df[target_column]
        
        X_encoded = self._encode_categorical_features(X)
        
        ros = RandomOverSampler(random_state=42)
        X_resampled, y_resampled = ros.fit_resample(X_encoded, y)
        
        balanced_df = self._reconstruct_dataframe(df, X_resampled, y_resampled)
        
        logger.info(f"랜덤 오버샘플링 완료: {len(df)} → {len(balanced_df)} 샘플")
        return balanced_df
    
    def balance_with_undersampling(self, df: pd.DataFrame, target_column='label') -> pd.DataFrame:
        """언더샘플링"""
        logger.info("언더샘플링 시작...")
        
        X = df.drop(columns=[target_column, 'event_id', 'timestamp', 'optional', 'optional_json'])
        y = df[target_column]
        
        X_encoded = self._encode_categorical_features(X)
        
        rus = RandomUnderSampler(random_state=42)
        X_resampled, y_resampled = rus.fit_resample(X_encoded, y)
        
        balanced_df = self._reconstruct_dataframe(df, X_resampled, y_resampled)
        
        logger.info(f"언더샘플링 완료: {len(df)} → {len(balanced_df)} 샘플")
        return balanced_df
    
    def balance_with_hybrid(self, df: pd.DataFrame, target_column='label') -> pd.DataFrame:
        """SMOTE + ENN 하이브리드 방법"""
        logger.info("SMOTE + ENN 하이브리드 밸런싱 시작...")
        
        X = df.drop(columns=[target_column, 'event_id', 'timestamp', 'optional', 'optional_json'])
        y = df[target_column]
        
        X_encoded = self._encode_categorical_features(X)
        
        smote_enn = SMOTEENN(random_state=42)
        X_resampled, y_resampled = smote_enn.fit_resample(X_encoded, y)
        
        balanced_df = self._reconstruct_dataframe(df, X_resampled, y_resampled)
        
        logger.info(f"SMOTE + ENN 완료: {len(df)} → {len(balanced_df)} 샘플")
        return balanced_df
    
    def create_balanced_dataset(self, df: pd.DataFrame, method='smote') -> pd.DataFrame:
        """선택된 방법으로 데이터셋 밸런싱"""
        logger.info(f"{method} 방법으로 데이터셋 밸런싱 시작...")
        
        if method == 'smote':
            return self.balance_with_smote(df)
        elif method == 'random_oversampling':
            return self.balance_with_random_oversampling(df)
        elif method == 'undersampling':
            return self.balance_with_undersampling(df)
        elif method == 'hybrid':
            return self.balance_with_hybrid(df)
        else:
            raise ValueError(f"지원하지 않는 방법: {method}")
    
    def split_and_save_data(self, df: pd.DataFrame, output_prefix: str = "msl_logs") -> Dict[str, str]:
        """데이터 분할 및 저장"""
        logger.info("데이터 분할 및 저장 중...")
        
        # Train/Test 분할
        train_df, test_df = train_test_split(
            df, test_size=0.2, stratify=df["label"], random_state=42
        )
        
        # 파일 경로
        train_path = f"../data/train_{output_prefix}.csv"
        test_path = f"../data/test_{output_prefix}.csv"
        
        # 저장
        train_df.to_csv(train_path, index=False)
        test_df.to_csv(test_path, index=False)
        
        logger.info(f"Train 데이터: {len(train_df):,}개 → {train_path}")
        logger.info(f"Test 데이터: {len(test_df):,}개 → {test_path}")
        
        # Inference 데이터 생성
        inference_dfs = []
        for label in df['label'].unique():
            label_data = df[df['label'] == label]
            sample_size = min(200, len(label_data))
            sample = label_data.sample(n=sample_size, random_state=42)
            inference_dfs.append(sample)
        
        inference_df = pd.concat(inference_dfs, ignore_index=True)
        inference_path = f"../data/inference_{output_prefix}.csv"
        inference_df.to_csv(inference_path, index=False)
        logger.info(f"Inference 데이터: {len(inference_df)}개 → {inference_path}")
        
        return {
            'train': train_path,
            'test': test_path,
            'inference': inference_path
        }
    
    def save_metadata(self, df: pd.DataFrame, analysis: Dict[str, Any], 
                     balancing_method: str = None, file_prefix: str = "msl_dataset") -> str:
        """메타데이터 저장"""
        metadata = {
            "생성일시": datetime.now().isoformat(),
            "데이터셋_유형": "MSL_DID_위협_탐지",
            "MSL_필드": ['vc_hash', 'holder_did', 'verifier_id', 'timestamp'],
            "이벤트_유형": EVENT_TYPES,
            "위협_시나리오": list(THREAT_SCENARIOS.keys()),
            "전체_이벤트수": len(df),
            "레이블별_분포": analysis['class_distribution'],
            "이벤트유형별_분포": df['event_type'].value_counts().to_dict(),
            "불균형_분석": analysis,
            "데이터품질": {
                "null_값": int(df.isnull().sum().sum()),
                "중복_이벤트": int(df.duplicated(subset=['event_id']).sum()),
                "고유_VC해시": int(df['vc_hash'].nunique()),
                "고유_Holder_DID": int(df['holder_did'].nunique()),
                "고유_Verifier_ID": int(df['verifier_id'].nunique())
            }
        }
        
        if balancing_method:
            metadata["밸런싱_방법"] = balancing_method
        
        metadata_path = f"../data/{file_prefix}_metadata.json"
        with open(metadata_path, "w", encoding="utf-8") as f:
            json.dump(metadata, f, ensure_ascii=False, indent=2)
        
        logger.info(f"메타데이터 저장: {metadata_path}")
        return metadata_path
    
    async def run_full_pipeline(self, enable_balancing: bool = True, 
                               balancing_method: str = 'random_oversampling') -> Dict[str, Any]:
        """전체 파이프라인 실행"""
        logger.info("=== 통합 MSL 데이터 파이프라인 시작 ===")
        
        # 데이터 디렉토리 생성
        Path("../data").mkdir(exist_ok=True)
        
        # 1. MSL 데이터셋 생성
        events = await self.generate_msl_dataset()
        
        # 2. DataFrame 생성 및 정리
        logger.info("데이터 후처리 중...")
        df_full = pd.DataFrame(events)
        df_full = df_full.drop_duplicates(subset=['event_id'])
        df_full = df_full.dropna(subset=['timestamp', 'vc_hash', 'holder_did'])
        df_full['optional_json'] = df_full['optional'].apply(json.dumps)
        
        logger.info(f"전체 데이터 생성 완료: {len(df_full):,}개")
        
        # 3. 원본 데이터 불균형 분석
        original_analysis = self.analyze_imbalance(df_full)
        logger.info(f"원본 불균형 비율: {original_analysis['imbalance_ratio']:.1f}:1")
        
        # 4. 데이터 밸런싱 (선택적)
        if enable_balancing:
            logger.info(f"데이터 밸런싱 적용: {balancing_method}")
            
            # 다양한 밸런싱 방법 시도
            methods = ['smote', 'random_oversampling', 'undersampling', 'hybrid']
            balanced_datasets = {}
            
            for method in methods:
                try:
                    balanced_df = self.create_balanced_dataset(df_full, method)
                    balanced_analysis = self.analyze_imbalance(balanced_df)
                    balanced_datasets[method] = {
                        'data': balanced_df,
                        'analysis': balanced_analysis
                    }
                except Exception as e:
                    logger.error(f"{method} 밸런싱 실패: {str(e)}")
            
            # 최적의 밸런싱 방법 선택
            if balanced_datasets:
                best_method = min(balanced_datasets.keys(), 
                                 key=lambda m: balanced_datasets[m]['analysis']['imbalance_ratio'])
                
                logger.info(f"최적 밸런싱 방법: {best_method}")
                best_df = balanced_datasets[best_method]['data']
                best_analysis = balanced_datasets[best_method]['analysis']
                
                # 밸런싱된 데이터 분할 및 저장
                balanced_paths = self.split_and_save_data(best_df, f"msl_logs_balanced_{best_method}")
                
                # 밸런싱 메타데이터 저장
                balancing_metadata = {
                    "밸런싱_방법": best_method,
                    "원본_불균형_비율": original_analysis['imbalance_ratio'],
                    "밸런싱_후_불균형_비율": best_analysis['imbalance_ratio'],
                    "개선_정도": original_analysis['imbalance_ratio'] / best_analysis['imbalance_ratio'],
                    "원본_샘플_수": original_analysis['total_samples'],
                    "밸런싱_후_샘플_수": best_analysis['total_samples']
                }
                
                balancing_metadata_path = f"../data/balancing_metadata_{best_method}.json"
                with open(balancing_metadata_path, "w", encoding="utf-8") as f:
                    json.dump(balancing_metadata, f, ensure_ascii=False, indent=2)
                
                final_df = best_df
                final_analysis = best_analysis
                final_prefix = f"msl_logs_balanced_{best_method}"
            else:
                logger.warning("밸런싱 실패, 원본 데이터 사용")
                final_df = df_full
                final_analysis = original_analysis
                final_prefix = "msl_logs"
        else:
            logger.info("데이터 밸런싱 건너뜀")
            final_df = df_full
            final_analysis = original_analysis
            final_prefix = "msl_logs"
        
        # 5. 최종 데이터 분할 및 저장
        final_paths = self.split_and_save_data(final_df, final_prefix)
        
        # 6. 메타데이터 저장
        metadata_path = self.save_metadata(final_df, final_analysis, 
                                         balancing_method if enable_balancing else None, 
                                         final_prefix)
        
        # 7. 결과 요약
        logger.info("=== 파이프라인 완료 ===")
        logger.info(f"최종 데이터: {len(final_df):,}개")
        logger.info(f"불균형 비율: {final_analysis['imbalance_ratio']:.1f}:1")
        
        return {
            'final_data': final_df,
            'final_analysis': final_analysis,
            'file_paths': final_paths,
            'metadata_path': metadata_path,
            'balancing_applied': enable_balancing,
            'balancing_method': balancing_method if enable_balancing else None
        }

def main():
    """메인 실행 함수"""
    print("🚀 통합 MSL 데이터 생성 및 밸런싱 파이프라인")
    print("=" * 60)
    
    # 파이프라인 초기화
    pipeline = IntegratedMSLPipeline()
    
    # 전체 파이프라인 실행
    results = asyncio.run(pipeline.run_full_pipeline(
        enable_balancing=True,
        balancing_method='random_oversampling'
    ))
    
    # 결과 출력
    print(f"\n✅ 파이프라인 완료!")
    print(f"📊 최종 데이터: {len(results['final_data']):,}개")
    print(f"⚖️ 불균형 비율: {results['final_analysis']['imbalance_ratio']:.1f}:1")
    
    if results['balancing_applied']:
        print(f"🔄 밸런싱 방법: {results['balancing_method']}")
    
    print(f"📁 생성된 파일:")
    for file_type, path in results['file_paths'].items():
        print(f"  - {file_type}: {path}")
    
    print(f"📋 메타데이터: {results['metadata_path']}")

if __name__ == "__main__":
    main()