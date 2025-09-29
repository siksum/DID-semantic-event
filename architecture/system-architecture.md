# DID Threat Detection Framework - System Architecture

## 1. 시스템 개요

### 1.1 목적
- MITRE ATT&CK에 포섭되지 않는 DID 고유 위협 모델 정의 및 탐지
- DID 시스템의 행위 기반 이벤트 로깅 및 실시간 위협 탐지
- 탐지 성공률/오탐률/실시간성 평가를 위한 PoC 구현

### 1.2 핵심 구성요소
1. **Threat Modeling Engine**: DID 특화 위협 모델 정의 및 관리
2. **Event Collection Layer**: DID 이벤트 수집 및 정규화
3. **Detection Engine**: 규칙/ML 기반 위협 탐지
4. **Analysis & Response**: 위협 분석 및 대응
5. **Evaluation Framework**: 성능 평가 및 메트릭 수집

## 2. 상세 아키텍처

### 2.1 계층 구조

```
┌─────────────────────────────────────────────────────────────┐
│                    Management & Monitoring UI                │
├─────────────────────────────────────────────────────────────┤
│                    Analysis & Response Layer                 │
│  ┌─────────────┐  ┌──────────────┐  ┌──────────────────┐  │
│  │   Incident   │  │   Forensic   │  │    Reporting     │  │
│  │  Management  │  │   Analysis   │  │   & Analytics    │  │
│  └─────────────┘  └──────────────┘  └──────────────────┘  │
├─────────────────────────────────────────────────────────────┤
│                     Detection Engine Layer                   │
│  ┌─────────────┐  ┌──────────────┐  ┌──────────────────┐  │
│  │ Rule-based  │  │  ML-based    │  │   Correlation    │  │
│  │  Detection  │  │  Detection   │  │     Engine       │  │
│  └─────────────┘  └──────────────┘  └──────────────────┘  │
├─────────────────────────────────────────────────────────────┤
│                  Event Processing Pipeline                   │
│  ┌─────────────┐  ┌──────────────┐  ┌──────────────────┐  │
│  │    Event    │  │    Event     │  │     Event        │  │
│  │ Aggregation │  │ Enrichment   │  │  Normalization   │  │
│  └─────────────┘  └──────────────┘  └──────────────────┘  │
├─────────────────────────────────────────────────────────────┤
│                   Event Collection Layer                     │
│  ┌─────────────┐  ┌──────────────┐  ┌──────────────────┐  │
│  │  DID Event  │  │  VC Event    │  │  Auth Event     │  │
│  │  Collector  │  │  Collector   │  │   Collector     │  │
│  └─────────────┘  └──────────────┘  └──────────────────┘  │
├─────────────────────────────────────────────────────────────┤
│                      Data Storage Layer                      │
│  ┌─────────────┐  ┌──────────────┐  ┌──────────────────┐  │
│  │  Time-series │  │   Graph DB   │  │  Object Store   │  │
│  │   Database   │  │ (Relations)  │  │   (Evidence)    │  │
│  └─────────────┘  └──────────────┘  └──────────────────┘  │
├─────────────────────────────────────────────────────────────┤
│                 Threat Intelligence Layer                    │
│  ┌─────────────┐  ┌──────────────┐  ┌──────────────────┐  │
│  │DID-specific │  │ MITRE ATT&CK │  │  Custom Threat  │  │
│  │Threat Model │  │  Mapping     │  │   Indicators    │  │
│  └─────────────┘  └──────────────┘  └──────────────────┘  │
└─────────────────────────────────────────────────────────────┘
```

### 2.2 핵심 컴포넌트 상세

#### 2.2.1 Threat Modeling Engine
```yaml
components:
  - threat_classifier:
      purpose: "MITRE ATT&CK 기술을 3가지로 분류"
      categories:
        - direct_applicable: "완전 일치"
        - partial_applicable: "부분 일치 (재해석 필요)"
        - did_specific: "DID 특화 (새로 정의)"
  
  - did_threat_registry:
      purpose: "DID 고유 위협 모델 정의 및 관리"
      threats:
        - credential_replay_attack
        - did_method_exploitation
        - verifier_collusion
        - selective_disclosure_abuse
        - revocation_bypass
```

#### 2.2.2 Event Collection Layer
```yaml
event_types:
  - did_events:
      - did_creation
      - did_update
      - did_deactivation
      - did_resolution
  
  - vc_events:
      - vc_issuance
      - vc_presentation
      - vc_verification
      - vc_revocation
  
  - auth_events:
      - authentication_request
      - authentication_success
      - authentication_failure
      - session_management

event_schema:
  base_fields:
    - event_id: "UUID"
    - timestamp: "ISO 8601"
    - event_type: "Enum"
    - actor_hash: "SHA-256(DID)"
    - target_hash: "SHA-256(DID/VC)"
    - metadata: "JSON"
```

#### 2.2.3 Detection Engine
```yaml
detection_methods:
  - rule_based:
      - threshold_rules: "빈도/횟수 기반"
      - pattern_rules: "시퀀스 패턴 매칭"
      - anomaly_rules: "기준선 이탈 탐지"
  
  - ml_based:
      - supervised:
          - random_forest: "알려진 위협 분류"
          - lstm: "시계열 이상 탐지"
      - unsupervised:
          - isolation_forest: "이상치 탐지"
          - dbscan: "클러스터링 기반 이상 탐지"
  
  - correlation:
      - temporal_correlation: "시간 기반 상관관계"
      - entity_correlation: "엔티티 간 관계 분석"
      - cross_event_correlation: "이벤트 간 패턴 분석"
```

## 3. 데이터 플로우

### 3.1 이벤트 수집 및 처리 흐름
```
DID System → Event Collectors → Message Queue → Stream Processor
                                                        ↓
    Detection Results ← Detection Engine ← Event Normalization
           ↓
    Alert Generation → Incident Management → Response Actions
```

### 3.2 위협 탐지 프로세스
```
1. Event Ingestion
   - 실시간 이벤트 스트리밍
   - 배치 이벤트 수집

2. Event Enrichment
   - 컨텍스트 정보 추가
   - 위협 인텔리전스 매핑

3. Detection Processing
   - 규칙 기반 매칭
   - ML 모델 예측
   - 상관관계 분석

4. Alert Management
   - 우선순위 지정
   - 중복 제거
   - 에스컬레이션
```

## 4. PoC 구현 아키텍처

### 4.1 대상 위협 시나리오
1. **Credential Stuffing in DID Context**
   - 여러 Verifier에 대한 동시다발적 VC 제시
   - 탐지: 비정상적 제시 패턴 분석

2. **DID Method Hopping Attack**
   - 다중 DID Method를 악용한 신원 위장
   - 탐지: Cross-method 활동 상관관계 분석

### 4.2 PoC 시스템 구성
```yaml
poc_components:
  - event_simulator:
      purpose: "정상/악의적 이벤트 생성"
      scenarios:
        - normal_user_behavior
        - credential_stuffing_pattern
        - did_method_hopping_pattern
  
  - mini_detection_engine:
      algorithms:
        - threshold_detector
        - pattern_matcher
        - ml_classifier
  
  - evaluation_framework:
      metrics:
        - detection_rate
        - false_positive_rate
        - processing_latency
        - resource_utilization
```

## 5. 기술 스택

### 5.1 Core Technologies
```yaml
event_collection:
  - Apache Kafka: "이벤트 스트리밍"
  - Logstash: "로그 수집 및 파싱"

data_storage:
  - InfluxDB: "시계열 이벤트 저장"
  - Neo4j: "엔티티 관계 그래프"
  - MinIO: "증거 보관"

processing:
  - Apache Flink: "실시간 스트림 처리"
  - Apache Spark: "배치 분석"

detection:
  - Sigma Rules: "규칙 기반 탐지"
  - scikit-learn: "ML 모델"
  - TensorFlow: "딥러닝 모델"

infrastructure:
  - Kubernetes: "컨테이너 오케스트레이션"
  - Prometheus/Grafana: "모니터링"
```

### 5.2 DID Integration
```yaml
did_libraries:
  - did-resolver: "DID 해석"
  - veramo: "DID/VC 처리"
  - ceramic: "분산 데이터 스트림"

blockchain_integration:
  - ethereum: "DID 앵커링"
  - hyperledger-indy: "엔터프라이즈 DID"
```

## 6. 보안 고려사항

### 6.1 Privacy Protection
- 모든 DID/VC는 해시 처리
- 개인정보 최소 수집 원칙
- 로그 보관 기간 제한

### 6.2 System Security
- TLS 1.3 for all communications
- Role-based access control
- Audit logging for all admin actions

## 7. 성능 요구사항

### 7.1 Scalability
- 초당 10,000 이벤트 처리
- 수평적 확장 가능
- 다중 지역 배포 지원

### 7.2 Performance Targets
- 이벤트 처리 지연: < 100ms
- 탐지 지연: < 1s
- 오탐률: < 5%
- 탐지율: > 95%

## 8. 배포 아키텍처

### 8.1 Development Environment
```yaml
containers:
  - event-collector: 3 replicas
  - detection-engine: 2 replicas
  - database: 1 replica each
  - ui-dashboard: 1 replica
```

### 8.2 Production Considerations
- High Availability 구성
- 재해 복구 계획
- 백업 및 복원 전략