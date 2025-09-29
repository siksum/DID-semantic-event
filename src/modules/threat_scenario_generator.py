#!/usr/bin/env python3
"""
위협 시나리오 생성기 모듈
"""

import random
from datetime import datetime, timedelta
from typing import List
from .platform_adapters import DIDEvent

class ThreatScenarioGenerator:
    """위협 시나리오 생성기"""
    
    def __init__(self):
        self.scenarios = {
            'vc_reuse_attack': self._generate_vc_reuse_scenario,
            'issuer_impersonation': self._generate_issuer_impersonation_scenario,
            'time_anomaly': self._generate_time_anomaly_scenario,
            'rapid_events': self._generate_rapid_events_scenario,
            'credential_theft': self._generate_credential_theft_scenario,
            'sybil_attack': self._generate_sybil_attack_scenario,
            'replay_attack': self._generate_replay_attack_scenario,
            'mixed_threats': self._generate_mixed_threats_scenario
        }
    
    def generate_scenario(self, scenario_name: str, num_events: int = 100) -> List[DIDEvent]:
        """특정 시나리오 생성"""
        if scenario_name not in self.scenarios:
            raise ValueError(f"알 수 없는 시나리오: {scenario_name}")
        
        return self.scenarios[scenario_name](num_events)
    
    def _generate_vc_reuse_scenario(self, num_events: int) -> List[DIDEvent]:
        """VC 재사용 공격 시나리오"""
        events = []
        base_time = datetime.now()
        
        # 동일한 VC를 여러 검증자에게 제시
        vc_hash = "vc_reuse_attack_12345"
        holder_did = "did:example:holder1"
        
        verifiers = [f"did:example:verifier{i}" for i in range(1, 6)]
        
        for i in range(num_events):
            if i < 5:  # 처음 5개는 VC 재사용 공격
                event = DIDEvent(
                    event_id=f"vc_reuse_{i}",
                    event_type="PRESENTATION",
                    timestamp=base_time + timedelta(minutes=i*5),  # 5분 간격
                    did=holder_did,
                    holder_did=holder_did,
                    verifier_id=verifiers[i % len(verifiers)],
                    vc_hash=vc_hash,
                    issuer_did="did:example:issuer1",
                    metadata={"scenario": "vc_reuse_attack", "threat": True}
                )
            else:  # 나머지는 정상 이벤트
                event = DIDEvent(
                    event_id=f"normal_{i}",
                    event_type=random.choice(["ISSUANCE", "PRESENTATION", "VERIFICATION"]),
                    timestamp=base_time + timedelta(minutes=i*10),
                    did=f"did:example:holder{i}",
                    holder_did=f"did:example:holder{i}",
                    verifier_id=f"did:example:verifier{i}",
                    vc_hash=f"vc_normal_{i}",
                    issuer_did="did:example:issuer1",
                    metadata={"scenario": "vc_reuse_attack", "threat": False}
                )
            events.append(event)
        
        return events
    
    def _generate_issuer_impersonation_scenario(self, num_events: int) -> List[DIDEvent]:
        """발급자 위장 시나리오"""
        events = []
        base_time = datetime.now()
        
        untrusted_issuers = [
            "did:web:issuer3.untrusted.com",
            "did:web:fake-issuer.com",
            "did:web:malicious-issuer.org"
        ]
        
        for i in range(num_events):
            if i < 10:  # 처음 10개는 위장된 발급자
                event = DIDEvent(
                    event_id=f"impersonation_{i}",
                    event_type="ISSUANCE",
                    timestamp=base_time + timedelta(minutes=i*2),
                    did=f"did:example:holder{i}",
                    holder_did=f"did:example:holder{i}",
                    verifier_id=None,
                    vc_hash=f"vc_impersonation_{i}",
                    issuer_did=random.choice(untrusted_issuers),
                    metadata={"scenario": "issuer_impersonation", "threat": True}
                )
            else:  # 나머지는 정상 이벤트
                event = DIDEvent(
                    event_id=f"normal_{i}",
                    event_type=random.choice(["ISSUANCE", "PRESENTATION", "VERIFICATION"]),
                    timestamp=base_time + timedelta(minutes=i*5),
                    did=f"did:example:holder{i}",
                    holder_did=f"did:example:holder{i}",
                    verifier_id=f"did:example:verifier{i}",
                    vc_hash=f"vc_normal_{i}",
                    issuer_did="did:example:trusted-issuer.com",
                    metadata={"scenario": "issuer_impersonation", "threat": False}
                )
            events.append(event)
        
        return events
    
    def _generate_time_anomaly_scenario(self, num_events: int) -> List[DIDEvent]:
        """시간 이상 시나리오"""
        events = []
        base_time = datetime.now()
        
        # 동일한 holder가 짧은 시간 내 여러 VC 제시
        holder_did = "did:example:time_anomaly_holder"
        
        for i in range(num_events):
            if i < 8:  # 처음 8개는 시간 이상 (2분 간격으로 3개씩)
                event = DIDEvent(
                    event_id=f"time_anomaly_{i}",
                    event_type="PRESENTATION",
                    timestamp=base_time + timedelta(minutes=i*2),  # 2분 간격
                    did=holder_did,
                    holder_did=holder_did,
                    verifier_id=f"did:example:verifier{i}",
                    vc_hash=f"vc_time_anomaly_{i}",
                    issuer_did="did:example:issuer1",
                    metadata={"scenario": "time_anomaly", "threat": True}
                )
            else:  # 나머지는 정상 이벤트
                event = DIDEvent(
                    event_id=f"normal_{i}",
                    event_type=random.choice(["ISSUANCE", "PRESENTATION", "VERIFICATION"]),
                    timestamp=base_time + timedelta(minutes=i*15),
                    did=f"did:example:holder{i}",
                    holder_did=f"did:example:holder{i}",
                    verifier_id=f"did:example:verifier{i}",
                    vc_hash=f"vc_normal_{i}",
                    issuer_did="did:example:issuer1",
                    metadata={"scenario": "time_anomaly", "threat": False}
                )
            events.append(event)
        
        return events
    
    def _generate_rapid_events_scenario(self, num_events: int) -> List[DIDEvent]:
        """빠른 연속 이벤트 시나리오"""
        events = []
        base_time = datetime.now()
        
        # 동일한 holder가 1분 내 여러 이벤트 발생
        holder_did = "did:example:rapid_events_holder"
        
        for i in range(num_events):
            if i < 6:  # 처음 6개는 빠른 연속 이벤트 (30초 간격)
                event = DIDEvent(
                    event_id=f"rapid_{i}",
                    event_type=random.choice(["ISSUANCE", "PRESENTATION", "VERIFICATION"]),
                    timestamp=base_time + timedelta(seconds=i*30),  # 30초 간격
                    did=holder_did,
                    holder_did=holder_did,
                    verifier_id=f"did:example:verifier{i}",
                    vc_hash=f"vc_rapid_{i}",
                    issuer_did="did:example:issuer1",
                    metadata={"scenario": "rapid_events", "threat": True}
                )
            else:  # 나머지는 정상 이벤트
                event = DIDEvent(
                    event_id=f"normal_{i}",
                    event_type=random.choice(["ISSUANCE", "PRESENTATION", "VERIFICATION"]),
                    timestamp=base_time + timedelta(minutes=i*10),
                    did=f"did:example:holder{i}",
                    holder_did=f"did:example:holder{i}",
                    verifier_id=f"did:example:verifier{i}",
                    vc_hash=f"vc_normal_{i}",
                    issuer_did="did:example:issuer1",
                    metadata={"scenario": "rapid_events", "threat": False}
                )
            events.append(event)
        
        return events
    
    def _generate_credential_theft_scenario(self, num_events: int) -> List[DIDEvent]:
        """자격 증명 도난 시나리오"""
        events = []
        base_time = datetime.now()
        
        # 도난당한 VC를 다른 holder가 사용
        stolen_vc_hash = "stolen_vc_12345"
        original_holder = "did:example:original_holder"
        thief_holder = "did:example:thief_holder"
        
        for i in range(num_events):
            if i < 5:  # 처음 5개는 도난된 VC 사용
                event = DIDEvent(
                    event_id=f"theft_{i}",
                    event_type="PRESENTATION",
                    timestamp=base_time + timedelta(minutes=i*5),
                    did=thief_holder,
                    holder_did=thief_holder,
                    verifier_id=f"did:example:verifier{i}",
                    vc_hash=stolen_vc_hash,
                    issuer_did="did:example:issuer1",
                    metadata={"scenario": "credential_theft", "threat": True, "original_holder": original_holder}
                )
            else:  # 나머지는 정상 이벤트
                event = DIDEvent(
                    event_id=f"normal_{i}",
                    event_type=random.choice(["ISSUANCE", "PRESENTATION", "VERIFICATION"]),
                    timestamp=base_time + timedelta(minutes=i*8),
                    did=f"did:example:holder{i}",
                    holder_did=f"did:example:holder{i}",
                    verifier_id=f"did:example:verifier{i}",
                    vc_hash=f"vc_normal_{i}",
                    issuer_did="did:example:issuer1",
                    metadata={"scenario": "credential_theft", "threat": False}
                )
            events.append(event)
        
        return events
    
    def _generate_sybil_attack_scenario(self, num_events: int) -> List[DIDEvent]:
        """시빌 공격 시나리오"""
        events = []
        base_time = datetime.now()
        
        # 동일한 엔티티가 여러 DID로 활동
        sybil_holders = [f"did:example:sybil_holder_{i}" for i in range(1, 6)]
        
        for i in range(num_events):
            if i < 15:  # 처음 15개는 시빌 공격
                event = DIDEvent(
                    event_id=f"sybil_{i}",
                    event_type=random.choice(["ISSUANCE", "PRESENTATION"]),
                    timestamp=base_time + timedelta(minutes=i*3),
                    did=random.choice(sybil_holders),
                    holder_did=random.choice(sybil_holders),
                    verifier_id=f"did:example:verifier{i}",
                    vc_hash=f"vc_sybil_{i}",
                    issuer_did="did:example:issuer1",
                    metadata={"scenario": "sybil_attack", "threat": True, "sybil_group": "group1"}
                )
            else:  # 나머지는 정상 이벤트
                event = DIDEvent(
                    event_id=f"normal_{i}",
                    event_type=random.choice(["ISSUANCE", "PRESENTATION", "VERIFICATION"]),
                    timestamp=base_time + timedelta(minutes=i*12),
                    did=f"did:example:holder{i}",
                    holder_did=f"did:example:holder{i}",
                    verifier_id=f"did:example:verifier{i}",
                    vc_hash=f"vc_normal_{i}",
                    issuer_did="did:example:issuer1",
                    metadata={"scenario": "sybil_attack", "threat": False}
                )
            events.append(event)
        
        return events
    
    def _generate_replay_attack_scenario(self, num_events: int) -> List[DIDEvent]:
        """재전송 공격 시나리오"""
        events = []
        base_time = datetime.now()
        
        # 동일한 이벤트를 시간 간격을 두고 반복
        replay_event_id = "replay_event_12345"
        holder_did = "did:example:replay_holder"
        vc_hash = "vc_replay_12345"
        
        for i in range(num_events):
            if i < 4:  # 처음 4개는 재전송 공격 (동일한 이벤트 ID)
                event = DIDEvent(
                    event_id=replay_event_id,
                    event_type="PRESENTATION",
                    timestamp=base_time + timedelta(hours=i*2),  # 2시간 간격
                    did=holder_did,
                    holder_did=holder_did,
                    verifier_id=f"did:example:verifier{i}",
                    vc_hash=vc_hash,
                    issuer_did="did:example:issuer1",
                    metadata={"scenario": "replay_attack", "threat": True}
                )
            else:  # 나머지는 정상 이벤트
                event = DIDEvent(
                    event_id=f"normal_{i}",
                    event_type=random.choice(["ISSUANCE", "PRESENTATION", "VERIFICATION"]),
                    timestamp=base_time + timedelta(minutes=i*20),
                    did=f"did:example:holder{i}",
                    holder_did=f"did:example:holder{i}",
                    verifier_id=f"did:example:verifier{i}",
                    vc_hash=f"vc_normal_{i}",
                    issuer_did="did:example:issuer1",
                    metadata={"scenario": "replay_attack", "threat": False}
                )
            events.append(event)
        
        return events
    
    def _generate_mixed_threats_scenario(self, num_events: int) -> List[DIDEvent]:
        """복합 위협 시나리오"""
        events = []
        base_time = datetime.now()
        
        # 여러 위협 유형을 혼합
        threat_scenarios = [
            self._generate_vc_reuse_scenario(20),
            self._generate_issuer_impersonation_scenario(15),
            self._generate_time_anomaly_scenario(15),
            self._generate_rapid_events_scenario(10)
        ]
        
        # 모든 시나리오의 이벤트를 합치고 시간 순으로 정렬
        all_events = []
        for scenario_events in threat_scenarios:
            all_events.extend(scenario_events)
        
        # 시간 순으로 정렬
        all_events.sort(key=lambda x: x.timestamp)
        
        # 요청된 수만큼 반환
        return all_events[:num_events]