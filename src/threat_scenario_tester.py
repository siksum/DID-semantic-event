#!/usr/bin/env python3
"""
위협 시나리오 테스트 스크립트
MSL 탐지 엔진을 각 DID 플랫폼과 통합하여 다양한 위협 시나리오를 테스트
"""

import asyncio
import json
import logging
import time
import random
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional
import pandas as pd
import numpy as np
from pathlib import Path

# 모듈 import
from modules.msl_detection_core import MSLDetectionCore
from modules.platform_adapters import PlatformManager, DIDEvent

# 로깅 설정
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('threat_test_results.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

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


class ThreatScenarioTester:
    """위협 시나리오 테스터"""
    
    def __init__(self, config: Dict[str, Any] = None):
        self.config = config or {}
        self.scenario_generator = ThreatScenarioGenerator()
        self.platform_manager = PlatformManager(self.config.get('platforms', {}))
        self.results = {}
        
        # 결과 저장 디렉토리 생성
        self.results_dir = Path("threat_test_results")
        self.results_dir.mkdir(exist_ok=True)
    
    async def run_all_scenarios(self, num_events_per_scenario: int = 100) -> Dict[str, Any]:
        """모든 시나리오 실행"""
        logger.info("=== 위협 시나리오 테스트 시작 ===")
        
        # 플랫폼 연결
        connection_results = await self.platform_manager.connect_all()
        logger.info(f"플랫폼 연결 결과: {connection_results}")
        
        all_results = {}
        
        for scenario_name in self.scenario_generator.scenarios.keys():
            logger.info(f"\n--- {scenario_name} 시나리오 테스트 시작 ---")
            
            try:
                # 시나리오 생성
                events = self.scenario_generator.generate_scenario(scenario_name, num_events_per_scenario)
                logger.info(f"{scenario_name} 시나리오 생성 완료: {len(events)}개 이벤트")
                
                # 각 플랫폼에서 테스트
                scenario_results = await self._test_scenario_on_platforms(scenario_name, events)
                all_results[scenario_name] = scenario_results
                
                # 결과 저장
                await self._save_scenario_results(scenario_name, scenario_results)
                
                logger.info(f"{scenario_name} 시나리오 테스트 완료")
                
            except Exception as e:
                logger.error(f"{scenario_name} 시나리오 테스트 중 오류: {e}")
                all_results[scenario_name] = {"error": str(e)}
        
        # 전체 결과 요약
        summary = self._generate_summary(all_results)
        await self._save_summary(summary)
        
        # 플랫폼 연결 해제
        await self.platform_manager.disconnect_all()
        
        logger.info("=== 위협 시나리오 테스트 완료 ===")
        return all_results
    
    async def _test_scenario_on_platforms(self, scenario_name: str, events: List[DIDEvent]) -> Dict[str, Any]:
        """특정 시나리오를 모든 플랫폼에서 테스트"""
        platform_results = {}
        
        for platform_name, adapter in self.platform_manager.adapters.items():
            logger.info(f"{platform_name} 플랫폼에서 {scenario_name} 테스트 중...")
            
            try:
                # 위협 탐지 실행
                start_time = time.time()
                results = await adapter.detect_threats(events)
                processing_time = time.time() - start_time
                
                # 결과 분석
                analysis = self._analyze_results(events, results, scenario_name)
                analysis['processing_time'] = processing_time
                
                platform_results[platform_name] = analysis
                
                logger.info(f"{platform_name} 테스트 완료: {analysis['detection_rate']:.2%} 탐지율")
                
            except Exception as e:
                logger.error(f"{platform_name} 테스트 중 오류: {e}")
                platform_results[platform_name] = {"error": str(e)}
        
        return platform_results
    
    def _analyze_results(self, events: List[DIDEvent], results: Dict[str, Any], scenario_name: str) -> Dict[str, Any]:
        """결과 분석"""
        threats = results.get('threats', [])
        summary = results.get('summary', {})
        
        # 실제 위협 이벤트 수 계산
        actual_threats = sum(1 for event in events if event.metadata.get('threat', False))
        
        # 탐지된 위협 수
        detected_threats = sum(1 for threat in threats if threat.get('threat_detected', False))
        
        # True Positive, False Positive 계산
        true_positives = 0
        false_positives = 0
        false_negatives = 0
        
        for i, event in enumerate(events):
            is_actual_threat = event.metadata.get('threat', False)
            is_detected_threat = i < len(threats) and threats[i].get('threat_detected', False)
            
            if is_actual_threat and is_detected_threat:
                true_positives += 1
            elif not is_actual_threat and is_detected_threat:
                false_positives += 1
            elif is_actual_threat and not is_detected_threat:
                false_negatives += 1
        
        # 성능 지표 계산
        precision = true_positives / (true_positives + false_positives) if (true_positives + false_positives) > 0 else 0
        recall = true_positives / (true_positives + false_negatives) if (true_positives + false_negatives) > 0 else 0
        f1_score = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0
        accuracy = (true_positives + (len(events) - actual_threats - false_positives)) / len(events) if len(events) > 0 else 0
        
        # 위협 유형별 분석
        threat_types = {}
        for threat in threats:
            if threat.get('threat_detected', False):
                threat_type = threat.get('threat_type', 'unknown')
                threat_types[threat_type] = threat_types.get(threat_type, 0) + 1
        
        return {
            'scenario_name': scenario_name,
            'total_events': len(events),
            'actual_threats': actual_threats,
            'detected_threats': detected_threats,
            'true_positives': true_positives,
            'false_positives': false_positives,
            'false_negatives': false_negatives,
            'precision': precision,
            'recall': recall,
            'f1_score': f1_score,
            'accuracy': accuracy,
            'detection_rate': detected_threats / len(events) if len(events) > 0 else 0,
            'threat_types': threat_types,
            'summary': summary
        }
    
    async def _save_scenario_results(self, scenario_name: str, results: Dict[str, Any]):
        """시나리오 결과 저장"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = self.results_dir / f"{scenario_name}_{timestamp}.json"
        
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(results, f, indent=2, ensure_ascii=False, default=str)
        
        logger.info(f"{scenario_name} 결과 저장: {filename}")
    
    def _generate_summary(self, all_results: Dict[str, Any]) -> Dict[str, Any]:
        """전체 결과 요약 생성"""
        summary = {
            'test_timestamp': datetime.now().isoformat(),
            'total_scenarios': len(all_results),
            'platforms': list(self.platform_manager.adapters.keys()),
            'scenario_summaries': {},
            'overall_performance': {}
        }
        
        # 시나리오별 요약
        for scenario_name, scenario_results in all_results.items():
            if 'error' in scenario_results:
                summary['scenario_summaries'][scenario_name] = {'error': scenario_results['error']}
                continue
            
            scenario_summary = {
                'platforms_tested': len(scenario_results),
                'avg_precision': 0,
                'avg_recall': 0,
                'avg_f1_score': 0,
                'avg_accuracy': 0,
                'platform_results': {}
            }
            
            precisions = []
            recalls = []
            f1_scores = []
            accuracies = []
            
            for platform_name, platform_result in scenario_results.items():
                if 'error' in platform_result:
                    scenario_summary['platform_results'][platform_name] = {'error': platform_result['error']}
                    continue
                
                precisions.append(platform_result.get('precision', 0))
                recalls.append(platform_result.get('recall', 0))
                f1_scores.append(platform_result.get('f1_score', 0))
                accuracies.append(platform_result.get('accuracy', 0))
                
                scenario_summary['platform_results'][platform_name] = {
                    'precision': platform_result.get('precision', 0),
                    'recall': platform_result.get('recall', 0),
                    'f1_score': platform_result.get('f1_score', 0),
                    'accuracy': platform_result.get('accuracy', 0),
                    'detection_rate': platform_result.get('detection_rate', 0)
                }
            
            if precisions:
                scenario_summary['avg_precision'] = np.mean(precisions)
                scenario_summary['avg_recall'] = np.mean(recalls)
                scenario_summary['avg_f1_score'] = np.mean(f1_scores)
                scenario_summary['avg_accuracy'] = np.mean(accuracies)
            
            summary['scenario_summaries'][scenario_name] = scenario_summary
        
        # 전체 성능 요약
        all_precisions = []
        all_recalls = []
        all_f1_scores = []
        all_accuracies = []
        
        for scenario_summary in summary['scenario_summaries'].values():
            if 'error' not in scenario_summary:
                all_precisions.append(scenario_summary.get('avg_precision', 0))
                all_recalls.append(scenario_summary.get('avg_recall', 0))
                all_f1_scores.append(scenario_summary.get('avg_f1_score', 0))
                all_accuracies.append(scenario_summary.get('avg_accuracy', 0))
        
        if all_precisions:
            summary['overall_performance'] = {
                'avg_precision': np.mean(all_precisions),
                'avg_recall': np.mean(all_recalls),
                'avg_f1_score': np.mean(all_f1_scores),
                'avg_accuracy': np.mean(all_accuracies)
            }
        
        return summary
    
    async def _save_summary(self, summary: Dict[str, Any]):
        """요약 결과 저장"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = self.results_dir / f"test_summary_{timestamp}.json"
        
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(summary, f, indent=2, ensure_ascii=False, default=str)
        
        logger.info(f"테스트 요약 저장: {filename}")
        
        # 콘솔에 요약 출력
        self._print_summary(summary)
    
    def _print_summary(self, summary: Dict[str, Any]):
        """요약 결과 콘솔 출력"""
        print("\n" + "="*80)
        print("위협 시나리오 테스트 결과 요약")
        print("="*80)
        
        print(f"테스트 시간: {summary['test_timestamp']}")
        print(f"총 시나리오 수: {summary['total_scenarios']}")
        print(f"테스트된 플랫폼: {', '.join(summary['platforms'])}")
        
        if 'overall_performance' in summary and summary['overall_performance']:
            overall = summary['overall_performance']
            print(f"\n전체 성능:")
            print(f"  - 평균 Precision: {overall['avg_precision']:.3f}")
            print(f"  - 평균 Recall: {overall['avg_recall']:.3f}")
            print(f"  - 평균 F1-Score: {overall['avg_f1_score']:.3f}")
            print(f"  - 평균 Accuracy: {overall['avg_accuracy']:.3f}")
        
        print(f"\n시나리오별 성능:")
        for scenario_name, scenario_summary in summary['scenario_summaries'].items():
            if 'error' in scenario_summary:
                print(f"  - {scenario_name}: 오류 발생 - {scenario_summary['error']}")
                continue
            
            print(f"  - {scenario_name}:")
            print(f"    * 평균 F1-Score: {scenario_summary.get('avg_f1_score', 0):.3f}")
            print(f"    * 평균 Accuracy: {scenario_summary.get('avg_accuracy', 0):.3f}")
            
            for platform_name, platform_result in scenario_summary.get('platform_results', {}).items():
                if 'error' in platform_result:
                    print(f"      - {platform_name}: 오류")
                else:
                    print(f"      - {platform_name}: F1={platform_result.get('f1_score', 0):.3f}, Acc={platform_result.get('accuracy', 0):.3f}")
        
        print("="*80)


async def main():
    """메인 실행 함수"""
    # 설정
    config = {
        'platforms': {
            'didnow': {
                'api_url': 'http://localhost:3000',
                'api_key': 'test_key'
            },
            'veramo': {
                'threat_detection_url': 'http://localhost:5001'
            },
            'sovrin': {
                'threat_detection_url': 'http://localhost:5005',
                'pool_name': 'sovrin',
                'wallet_name': 'sovrin_wallet',
                'wallet_key': 'wallet_key'
            }
        },
        'msl_config': {
            'chunk_size': 1000,
            'max_workers': 4
        }
    }
    
    # 테스터 초기화 및 실행
    tester = ThreatScenarioTester(config)
    
    try:
        results = await tester.run_all_scenarios(num_events_per_scenario=50)
        logger.info("모든 시나리오 테스트 완료")
        
    except Exception as e:
        logger.error(f"테스트 실행 중 오류: {e}")
        raise


if __name__ == "__main__":
    asyncio.run(main())