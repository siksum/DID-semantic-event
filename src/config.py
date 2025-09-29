#!/usr/bin/env python3
"""
DID 위협 탐지 시스템 - 설정 관리
중앙화된 설정 관리 시스템
"""

import os
from dataclasses import dataclass
from typing import Dict, List, Any
import json
import logging

logger = logging.getLogger(__name__)

@dataclass
class DetectionConfig:
    """탐지 설정"""
    # 임계값 설정
    thresholds: Dict[str, float]
    # 앙상블 가중치
    ensemble_weights: Dict[str, float]
    # 탐지 규칙 설정
    rule_config: Dict[str, Any]
    # 모델 설정
    model_config: Dict[str, Any]
    # LSTM 설정
    lstm_config: Dict[str, Any]

@dataclass
class DataConfig:
    """데이터 설정"""
    # 데이터 경로
    data_paths: Dict[str, str]
    # 데이터 분할 비율
    split_ratios: Dict[str, float]
    # 밸런싱 설정
    balancing_config: Dict[str, Any]

@dataclass
class SystemConfig:
    """시스템 설정"""
    # 로깅 설정
    logging_level: str
    # 시드 설정
    random_seed: int
    # GPU 설정
    use_gpu: bool
    # 병렬 처리 설정
    n_jobs: int

class ConfigManager:
    """설정 관리자"""
    
    def __init__(self, config_file: str = None):
        self.config_file = config_file or "./config.json"
        self.detection_config = self._load_detection_config()
        self.data_config = self._load_data_config()
        self.system_config = self._load_system_config()
        
    def _load_detection_config(self) -> DetectionConfig:
        """탐지 설정 로드"""
        return DetectionConfig(
            thresholds={
                'rule': 0.5,
                'model': 0.7,
                'lstm': 0.7,
                'ensemble': 0.6
            },
            ensemble_weights={
                'rule': 0.4,  # LSTM 비활성화로 가중치 재분배
                'model': 0.6,  # 모델 기반 가중치 증가
                'lstm': 0.0   # LSTM 비활성화
            },
            rule_config={
                'vc_reuse_attack': {
                    'threshold_minutes': 30,
                    'min_verifiers': 2
                },
                'issuer_impersonation': {
                    'untrusted_issuers': [
                        'did:web:issuer3.untrusted.com',
                        'did:web:fake-issuer.com'
                    ]
                },
                'revocation_ignore': {
                    'check_revocation': True
                },
                'time_anomaly': {
                    'max_simultaneous': 3,
                    'time_window_minutes': 5
                },
                'geographic_anomaly': {
                    'max_geo_locations': 2,
                    'time_window_hours': 24
                },
                'device_anomaly': {
                    'max_devices': 3,
                    'time_window_hours': 1
                },
                'vc_lifecycle_anomaly': {
                    'max_lifecycle_events': 10,
                    'check_issuance_before_revocation': True
                },
                'rapid_events': {
                    'time_window_minutes': 1,
                    'max_events': 5
                },
                'issuer_trust_score': {
                    'min_trust_score': 0.3,
                    'trust_decay_days': 30
                }
            },
            model_config={
                'isolation_forest': {
                    'contamination': 0.1,  # 재현율 개선을 위해 0.2 -> 0.1로 조정
                    'random_state': 42
                },
                'feature_scaling': True
            },
            lstm_config={
                'sequence_length': 10, # 시퀀스 길이 유지
                'hidden_size': 64,     # 히든 사이즈 증가 (32->64)
                'num_layers': 2,       # 레이어 수 증가 (1->2)
                'dropout': 0.3,        # 드롭아웃 증가
                'epochs': 50,          # 에포크 수 증가 (20->50)
                'batch_size': 64,      # 배치 사이즈 조정 (128->64)
                'learning_rate': 0.001, # 학습률 조정 (0.002->0.001)
                'patience': 15         # 조기 종료 patience 증가 (8->15)
            }
        )
    
    def _load_data_config(self) -> DataConfig:
        """데이터 설정 로드"""
        return DataConfig(
            data_paths={
                'train': './data/train_msl_logs.csv',
                'test': './data/test_msl_logs.csv',
                'inference': './data/inference_msl_logs.csv',
                'balanced': './data/train_msl_logs_balanced_{method}.csv',
                'results': './data/detection_results.csv',
                'models': './models/',
                'images': './images/'
            },
            split_ratios={
                'train': 0.6,
                'validation': 0.2,
                'test': 0.2
            },
            balancing_config={
                'methods': ['smote', 'random_oversampling', 'undersampling', 'hybrid'],
                'target_ratio': 1.0,
                'min_samples': 100
            }
        )
    
    def _load_system_config(self) -> SystemConfig:
        """시스템 설정 로드"""
        return SystemConfig(
            logging_level=os.getenv('LOG_LEVEL', 'INFO'),
            random_seed=int(os.getenv('RANDOM_SEED', '42')),
            use_gpu=os.getenv('USE_GPU', 'true').lower() == 'true',
            n_jobs=int(os.getenv('N_JOBS', '4'))
        )
    
    def save_config(self):
        """설정을 파일로 저장"""
        config_dict = {
            'detection': {
                'thresholds': self.detection_config.thresholds,
                'ensemble_weights': self.detection_config.ensemble_weights,
                'rule_config': self.detection_config.rule_config,
                'model_config': self.detection_config.model_config,
                'lstm_config': self.detection_config.lstm_config
            },
            'data': {
                'data_paths': self.data_config.data_paths,
                'split_ratios': self.data_config.split_ratios,
                'balancing_config': self.data_config.balancing_config
            },
            'system': {
                'logging_level': self.system_config.logging_level,
                'random_seed': self.system_config.random_seed,
                'use_gpu': self.system_config.use_gpu,
                'n_jobs': self.system_config.n_jobs
            }
        }
        
        with open(self.config_file, 'w', encoding='utf-8') as f:
            json.dump(config_dict, f, ensure_ascii=False, indent=2)
        
        logger.info(f"설정이 {self.config_file}에 저장되었습니다.")
    
    def load_config(self):
        """파일에서 설정 로드"""
        if not os.path.exists(self.config_file):
            logger.warning(f"설정 파일 {self.config_file}이 없습니다. 기본 설정을 사용합니다.")
            return
        
        try:
            with open(self.config_file, 'r', encoding='utf-8') as f:
                config_dict = json.load(f)
            
            # 탐지 설정 업데이트
            if 'detection' in config_dict:
                detection = config_dict['detection']
                self.detection_config.thresholds.update(detection.get('thresholds', {}))
                self.detection_config.ensemble_weights.update(detection.get('ensemble_weights', {}))
                self.detection_config.rule_config.update(detection.get('rule_config', {}))
                self.detection_config.model_config.update(detection.get('model_config', {}))
                self.detection_config.lstm_config.update(detection.get('lstm_config', {}))
            
            # 데이터 설정 업데이트
            if 'data' in config_dict:
                data = config_dict['data']
                self.data_config.data_paths.update(data.get('data_paths', {}))
                self.data_config.split_ratios.update(data.get('split_ratios', {}))
                self.data_config.balancing_config.update(data.get('balancing_config', {}))
            
            # 시스템 설정 업데이트
            if 'system' in config_dict:
                system = config_dict['system']
                self.system_config.logging_level = system.get('logging_level', self.system_config.logging_level)
                self.system_config.random_seed = system.get('random_seed', self.system_config.random_seed)
                self.system_config.use_gpu = system.get('use_gpu', self.system_config.use_gpu)
                self.system_config.n_jobs = system.get('n_jobs', self.system_config.n_jobs)
            
            logger.info(f"설정이 {self.config_file}에서 로드되었습니다.")
            
        except Exception as e:
            logger.error(f"설정 로드 중 오류 발생: {e}")
    
    def update_threshold(self, method: str, threshold: float):
        """임계값 업데이트"""
        if method in self.detection_config.thresholds:
            self.detection_config.thresholds[method] = threshold
            logger.info(f"{method} 임계값이 {threshold}로 업데이트되었습니다.")
        else:
            logger.warning(f"알 수 없는 탐지 방법: {method}")
    
    def update_ensemble_weights(self, weights: Dict[str, float]):
        """앙상블 가중치 업데이트"""
        if abs(sum(weights.values()) - 1.0) < 0.01:  # 가중치 합이 1에 가까운지 확인
            self.detection_config.ensemble_weights.update(weights)
            logger.info(f"앙상블 가중치가 업데이트되었습니다: {weights}")
        else:
            logger.error(f"앙상블 가중치의 합이 1이 아닙니다: {sum(weights.values())}")
    
    def get_threshold(self, method: str) -> float:
        """임계값 조회"""
        return self.detection_config.thresholds.get(method, 0.5)
    
    def get_ensemble_weights(self) -> Dict[str, float]:
        """앙상블 가중치 조회"""
        return self.detection_config.ensemble_weights.copy()
    
    def get_data_path(self, key: str) -> str:
        """데이터 경로 조회"""
        return self.data_config.data_paths.get(key, f"./data/{key}.csv")
    
    def get_lstm_config(self) -> Dict[str, Any]:
        """LSTM 설정 조회"""
        return self.detection_config.lstm_config.copy()

# 전역 설정 인스턴스
config = ConfigManager()

def get_config() -> ConfigManager:
    """전역 설정 인스턴스 반환"""
    return config

def initialize_config(config_file: str = None):
    """설정 초기화"""
    global config
    config = ConfigManager(config_file)
    config.load_config()
    return config