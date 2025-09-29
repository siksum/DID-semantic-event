#!/usr/bin/env python3
"""
DID 플랫폼별 어댑터 인터페이스
각 DID 플랫폼(DIDNOW, Veramo, Sovrin)과 MSL 탐지 엔진을 연결하는 어댑터들
"""

import asyncio
import json
import logging
import time
from abc import ABC, abstractmethod
from datetime import datetime
from typing import Dict, List, Optional, Any, Union
import pandas as pd
import requests
from dataclasses import dataclass

from .msl_detection_core import MSLDetectionCore

logger = logging.getLogger(__name__)

@dataclass
class DIDEvent:
    """DID 이벤트 데이터 클래스"""
    event_id: str
    event_type: str
    timestamp: datetime
    did: str
    holder_did: Optional[str] = None
    verifier_id: Optional[str] = None
    vc_hash: Optional[str] = None
    issuer_did: Optional[str] = None
    metadata: Dict[str, Any] = None

class PlatformAdapter(ABC):
    """플랫폼 어댑터 기본 클래스"""
    
    def __init__(self, config: Dict[str, Any] = None):
        self.config = config or {}
        self.msl_detector = MSLDetectionCore(self.config.get('msl_config', {}))
        self.logger = logging.getLogger(f"{self.__class__.__name__}")
        self.is_connected = False
        
    @abstractmethod
    async def connect(self) -> bool:
        """플랫폼에 연결"""
        pass
    
    @abstractmethod
    async def disconnect(self) -> bool:
        """플랫폼 연결 해제"""
        pass
    
    @abstractmethod
    async def get_events(self, limit: int = 1000) -> List[DIDEvent]:
        """이벤트 데이터 가져오기"""
        pass
    
    @abstractmethod
    async def send_alert(self, threat_info: Dict[str, Any]) -> bool:
        """위협 알림 전송"""
        pass
    
    def convert_to_msl_format(self, events: List[DIDEvent]) -> pd.DataFrame:
        """DID 이벤트를 MSL 형식으로 변환"""
        data = []
        
        for event in events:
            msl_event = {
                'event_id': event.event_id,
                'timestamp': event.timestamp.isoformat(),
                'event_type': event.event_type,
                'holder_did': event.holder_did or '',
                'verifier_id': event.verifier_id or '',
                'vc_hash': event.vc_hash or '',
                'label': 'benign',  # 기본값, 실제로는 플랫폼에서 제공
                'optional': {
                    'issuer_did': event.issuer_did or '',
                    'platform': self.__class__.__name__.replace('Adapter', '').lower(),
                    'metadata': event.metadata or {}
                }
            }
            data.append(msl_event)
        
        return pd.DataFrame(data)
    
    async def detect_threats(self, events: List[DIDEvent]) -> Dict[str, Any]:
        """위협 탐지 실행"""
        try:
            # MSL 형식으로 변환
            df = self.convert_to_msl_format(events)
            
            # MSL 탐지 엔진으로 탐지
            results = self.msl_detector.detect_threats(df)
            
            return results
            
        except Exception as e:
            self.logger.error(f"위협 탐지 중 오류: {e}")
            return {"threats": [], "summary": {"error": str(e)}}
    
    async def train_model(self, training_data: List[DIDEvent]) -> bool:
        """모델 훈련"""
        try:
            df = self.convert_to_msl_format(training_data)
            return self.msl_detector.train(df)
        except Exception as e:
            self.logger.error(f"모델 훈련 중 오류: {e}")
            return False


class DIDNOWAdapter(PlatformAdapter):
    """DIDNOW 플랫폼 어댑터"""
    
    def __init__(self, config: Dict[str, Any] = None):
        super().__init__(config)
        self.api_url = self.config.get('api_url', 'http://localhost:3000')
        self.api_key = self.config.get('api_key', '')
        self.session = requests.Session()
        if self.api_key:
            self.session.headers.update({'Authorization': f'Bearer {self.api_key}'})
    
    async def connect(self) -> bool:
        """DIDNOW 플랫폼에 연결"""
        try:
            response = self.session.get(f"{self.api_url}/health")
            if response.status_code == 200:
                self.is_connected = True
                self.logger.info("DIDNOW 플랫폼 연결 성공")
                return True
            else:
                self.logger.error(f"DIDNOW 연결 실패: {response.status_code}")
                return False
        except Exception as e:
            self.logger.error(f"DIDNOW 연결 중 오류: {e}")
            return False
    
    async def disconnect(self) -> bool:
        """DIDNOW 플랫폼 연결 해제"""
        try:
            self.session.close()
            self.is_connected = False
            self.logger.info("DIDNOW 플랫폼 연결 해제")
            return True
        except Exception as e:
            self.logger.error(f"DIDNOW 연결 해제 중 오류: {e}")
            return False
    
    async def get_events(self, limit: int = 1000) -> List[DIDEvent]:
        """DIDNOW에서 이벤트 데이터 가져오기"""
        try:
            if not self.is_connected:
                await self.connect()
            
            response = self.session.get(f"{self.api_url}/events", params={'limit': limit})
            
            if response.status_code == 200:
                events_data = response.json()
                events = []
                
                for event_data in events_data.get('events', []):
                    event = DIDEvent(
                        event_id=event_data.get('id', ''),
                        event_type=event_data.get('type', 'UNKNOWN'),
                        timestamp=datetime.fromisoformat(event_data.get('timestamp', datetime.now().isoformat())),
                        did=event_data.get('did', ''),
                        holder_did=event_data.get('holder_did'),
                        verifier_id=event_data.get('verifier_id'),
                        vc_hash=event_data.get('vc_hash'),
                        issuer_did=event_data.get('issuer_did'),
                        metadata=event_data.get('metadata', {})
                    )
                    events.append(event)
                
                self.logger.info(f"DIDNOW에서 {len(events)}개 이벤트 가져옴")
                return events
            else:
                self.logger.error(f"DIDNOW 이벤트 가져오기 실패: {response.status_code}")
                return []
                
        except Exception as e:
            self.logger.error(f"DIDNOW 이벤트 가져오기 중 오류: {e}")
            return []
    
    async def send_alert(self, threat_info: Dict[str, Any]) -> bool:
        """DIDNOW에 위협 알림 전송"""
        try:
            alert_data = {
                'threat_type': threat_info.get('threat_type', 'unknown'),
                'confidence': threat_info.get('confidence', 0.0),
                'event_id': threat_info.get('event_id', ''),
                'timestamp': datetime.now().isoformat(),
                'details': threat_info.get('details', {})
            }
            
            response = self.session.post(f"{self.api_url}/alerts", json=alert_data)
            
            if response.status_code == 201:
                self.logger.info(f"DIDNOW에 위협 알림 전송 성공: {threat_info.get('event_id')}")
                return True
            else:
                self.logger.error(f"DIDNOW 알림 전송 실패: {response.status_code}")
                return False
                
        except Exception as e:
            self.logger.error(f"DIDNOW 알림 전송 중 오류: {e}")
            return False


class VeramoAdapter(PlatformAdapter):
    """Veramo 플랫폼 어댑터"""
    
    def __init__(self, config: Dict[str, Any] = None):
        super().__init__(config)
        self.threat_detection_url = self.config.get('threat_detection_url', 'http://localhost:5001')
        self.session = requests.Session()
    
    async def connect(self) -> bool:
        """Veramo 플랫폼에 연결"""
        try:
            response = self.session.get(f"{self.threat_detection_url}/health")
            if response.status_code == 200:
                self.is_connected = True
                self.logger.info("Veramo 플랫폼 연결 성공")
                return True
            else:
                self.logger.error(f"Veramo 연결 실패: {response.status_code}")
                return False
        except Exception as e:
            self.logger.error(f"Veramo 연결 중 오류: {e}")
            return False
    
    async def disconnect(self) -> bool:
        """Veramo 플랫폼 연결 해제"""
        try:
            self.session.close()
            self.is_connected = False
            self.logger.info("Veramo 플랫폼 연결 해제")
            return True
        except Exception as e:
            self.logger.error(f"Veramo 연결 해제 중 오류: {e}")
            return False
    
    async def get_events(self, limit: int = 1000) -> List[DIDEvent]:
        """Veramo에서 이벤트 데이터 가져오기"""
        try:
            if not self.is_connected:
                await self.connect()
            
            response = self.session.get(f"{self.threat_detection_url}/events", params={'limit': limit})
            
            if response.status_code == 200:
                events_data = response.json()
                events = []
                
                for event_data in events_data.get('events', []):
                    event = DIDEvent(
                        event_id=event_data.get('eventId', ''),
                        event_type=event_data.get('eventType', 'UNKNOWN'),
                        timestamp=datetime.fromisoformat(event_data.get('timestamp', datetime.now().isoformat())),
                        did=event_data.get('did', ''),
                        holder_did=event_data.get('holderDid'),
                        verifier_id=event_data.get('verifierDid'),
                        vc_hash=event_data.get('credentialHash'),
                        issuer_did=event_data.get('issuerDid'),
                        metadata=event_data.get('metadata', {})
                    )
                    events.append(event)
                
                self.logger.info(f"Veramo에서 {len(events)}개 이벤트 가져옴")
                return events
            else:
                self.logger.error(f"Veramo 이벤트 가져오기 실패: {response.status_code}")
                return []
                
        except Exception as e:
            self.logger.error(f"Veramo 이벤트 가져오기 중 오류: {e}")
            return []
    
    async def send_alert(self, threat_info: Dict[str, Any]) -> bool:
        """Veramo에 위협 알림 전송"""
        try:
            alert_data = {
                'threatDetected': True,
                'threatLevel': 'HIGH' if threat_info.get('confidence', 0) > 0.8 else 'MEDIUM',
                'threatScore': threat_info.get('confidence', 0.0),
                'detectedThreats': [threat_info.get('threat_type', 'unknown')],
                'eventId': threat_info.get('event_id', ''),
                'timestamp': datetime.now().isoformat(),
                'recommendations': ['Review DID operation', 'Check credential validity']
            }
            
            response = self.session.post(f"{self.threat_detection_url}/threat-detection", json=alert_data)
            
            if response.status_code == 200:
                self.logger.info(f"Veramo에 위협 알림 전송 성공: {threat_info.get('event_id')}")
                return True
            else:
                self.logger.error(f"Veramo 알림 전송 실패: {response.status_code}")
                return False
                
        except Exception as e:
            self.logger.error(f"Veramo 알림 전송 중 오류: {e}")
            return False


class SovrinAdapter(PlatformAdapter):
    """Sovrin 플랫폼 어댑터"""
    
    def __init__(self, config: Dict[str, Any] = None):
        super().__init__(config)
        self.pool_name = self.config.get('pool_name', 'sovrin')
        self.wallet_name = self.config.get('wallet_name', 'sovrin_wallet')
        self.wallet_key = self.config.get('wallet_key', 'wallet_key')
        self.threat_detection_url = self.config.get('threat_detection_url', 'http://localhost:5005')
        self.session = requests.Session()
    
    async def connect(self) -> bool:
        """Sovrin 플랫폼에 연결"""
        try:
            response = self.session.get(f"{self.threat_detection_url}/health")
            if response.status_code == 200:
                self.is_connected = True
                self.logger.info("Sovrin 플랫폼 연결 성공")
                return True
            else:
                self.logger.error(f"Sovrin 연결 실패: {response.status_code}")
                return False
        except Exception as e:
            self.logger.error(f"Sovrin 연결 중 오류: {e}")
            return False
    
    async def disconnect(self) -> bool:
        """Sovrin 플랫폼 연결 해제"""
        try:
            self.session.close()
            self.is_connected = False
            self.logger.info("Sovrin 플랫폼 연결 해제")
            return True
        except Exception as e:
            self.logger.error(f"Sovrin 연결 해제 중 오류: {e}")
            return False
    
    async def get_events(self, limit: int = 1000) -> List[DIDEvent]:
        """Sovrin에서 이벤트 데이터 가져오기"""
        try:
            if not self.is_connected:
                await self.connect()
            
            response = self.session.get(f"{self.threat_detection_url}/transactions", params={'limit': limit})
            
            if response.status_code == 200:
                events_data = response.json()
                events = []
                
                for event_data in events_data.get('transactions', []):
                    event = DIDEvent(
                        event_id=event_data.get('txn_id', ''),
                        event_type=event_data.get('txn_type', 'UNKNOWN'),
                        timestamp=datetime.fromisoformat(event_data.get('timestamp', datetime.now().isoformat())),
                        did=event_data.get('did', ''),
                        holder_did=event_data.get('did'),  # Sovrin에서는 did가 holder 역할
                        verifier_id=event_data.get('submitter_did'),
                        vc_hash=event_data.get('verkey'),  # Sovrin에서는 verkey 사용
                        issuer_did=event_data.get('submitter_did'),
                        metadata={
                            'pool_name': event_data.get('pool_name', self.pool_name),
                            'alias': event_data.get('alias'),
                            'role': event_data.get('role')
                        }
                    )
                    events.append(event)
                
                self.logger.info(f"Sovrin에서 {len(events)}개 이벤트 가져옴")
                return events
            else:
                self.logger.error(f"Sovrin 이벤트 가져오기 실패: {response.status_code}")
                return []
                
        except Exception as e:
            self.logger.error(f"Sovrin 이벤트 가져오기 중 오류: {e}")
            return []
    
    async def send_alert(self, threat_info: Dict[str, Any]) -> bool:
        """Sovrin에 위협 알림 전송"""
        try:
            alert_data = {
                'threat_detected': True,
                'threat_type': threat_info.get('threat_type', 'unknown'),
                'confidence': threat_info.get('confidence', 0.0),
                'event_id': threat_info.get('event_id', ''),
                'timestamp': datetime.now().isoformat(),
                'pool_name': self.pool_name,
                'details': threat_info.get('details', {})
            }
            
            response = self.session.post(f"{self.threat_detection_url}/alerts", json=alert_data)
            
            if response.status_code == 201:
                self.logger.info(f"Sovrin에 위협 알림 전송 성공: {threat_info.get('event_id')}")
                return True
            else:
                self.logger.error(f"Sovrin 알림 전송 실패: {response.status_code}")
                return False
                
        except Exception as e:
            self.logger.error(f"Sovrin 알림 전송 중 오류: {e}")
            return False


class PlatformManager:
    """플랫폼 관리자 - 여러 플랫폼을 통합 관리"""
    
    def __init__(self, config: Dict[str, Any] = None):
        self.config = config or {}
        self.adapters = {}
        self.logger = logging.getLogger("PlatformManager")
        
        # 플랫폼별 어댑터 초기화
        self._init_adapters()
    
    def _init_adapters(self):
        """어댑터 초기화"""
        platform_configs = self.config.get('platforms', {})
        
        # DIDNOW 어댑터
        if 'didnow' in platform_configs:
            self.adapters['didnow'] = DIDNOWAdapter(platform_configs['didnow'])
        
        # Veramo 어댑터
        if 'veramo' in platform_configs:
            self.adapters['veramo'] = VeramoAdapter(platform_configs['veramo'])
        
        # Sovrin 어댑터
        if 'sovrin' in platform_configs:
            self.adapters['sovrin'] = SovrinAdapter(platform_configs['sovrin'])
        
        self.logger.info(f"초기화된 플랫폼 어댑터: {list(self.adapters.keys())}")
    
    async def connect_all(self) -> Dict[str, bool]:
        """모든 플랫폼에 연결"""
        results = {}
        
        for platform_name, adapter in self.adapters.items():
            try:
                result = await adapter.connect()
                results[platform_name] = result
                self.logger.info(f"{platform_name} 연결 결과: {result}")
            except Exception as e:
                self.logger.error(f"{platform_name} 연결 중 오류: {e}")
                results[platform_name] = False
        
        return results
    
    async def disconnect_all(self) -> Dict[str, bool]:
        """모든 플랫폼 연결 해제"""
        results = {}
        
        for platform_name, adapter in self.adapters.items():
            try:
                result = await adapter.disconnect()
                results[platform_name] = result
                self.logger.info(f"{platform_name} 연결 해제 결과: {result}")
            except Exception as e:
                self.logger.error(f"{platform_name} 연결 해제 중 오류: {e}")
                results[platform_name] = False
        
        return results
    
    async def get_all_events(self, limit_per_platform: int = 1000) -> Dict[str, List[DIDEvent]]:
        """모든 플랫폼에서 이벤트 가져오기"""
        all_events = {}
        
        for platform_name, adapter in self.adapters.items():
            try:
                events = await adapter.get_events(limit_per_platform)
                all_events[platform_name] = events
                self.logger.info(f"{platform_name}에서 {len(events)}개 이벤트 가져옴")
            except Exception as e:
                self.logger.error(f"{platform_name} 이벤트 가져오기 중 오류: {e}")
                all_events[platform_name] = []
        
        return all_events
    
    async def detect_threats_all_platforms(self, limit_per_platform: int = 1000) -> Dict[str, Dict[str, Any]]:
        """모든 플랫폼에서 위협 탐지 실행"""
        all_results = {}
        
        for platform_name, adapter in self.adapters.items():
            try:
                events = await adapter.get_events(limit_per_platform)
                results = await adapter.detect_threats(events)
                all_results[platform_name] = results
                self.logger.info(f"{platform_name} 위협 탐지 완료: {results['summary'].get('threats_detected', 0)}개 탐지")
            except Exception as e:
                self.logger.error(f"{platform_name} 위협 탐지 중 오류: {e}")
                all_results[platform_name] = {"threats": [], "summary": {"error": str(e)}}
        
        return all_results
    
    async def send_alerts_all_platforms(self, threat_info: Dict[str, Any]) -> Dict[str, bool]:
        """모든 플랫폼에 위협 알림 전송"""
        results = {}
        
        for platform_name, adapter in self.adapters.items():
            try:
                result = await adapter.send_alert(threat_info)
                results[platform_name] = result
                self.logger.info(f"{platform_name} 알림 전송 결과: {result}")
            except Exception as e:
                self.logger.error(f"{platform_name} 알림 전송 중 오류: {e}")
                results[platform_name] = False
        
        return results
    
    def get_platform_status(self) -> Dict[str, Dict[str, Any]]:
        """플랫폼 상태 정보 반환"""
        status = {}
        
        for platform_name, adapter in self.adapters.items():
            status[platform_name] = {
                'connected': adapter.is_connected,
                'config': adapter.config,
                'performance': adapter.msl_detector.get_performance_summary()
            }
        
        return status