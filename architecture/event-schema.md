# DID Event Logging Schema & Data Flow

## 1. Event Schema Design

### 1.1 Base Event Structure
```json
{
  "event_id": "550e8400-e29b-41d4-a716-446655440000",
  "timestamp": "2024-01-18T10:30:45.123Z",
  "event_type": "vc_verification",
  "event_category": "credential_lifecycle",
  "severity": "info",
  "actor": {
    "did_hash": "sha256:a665a45920422f9d417e4867efdc4fb8...",
    "role": "verifier",
    "metadata": {
      "agent": "veramo/5.0.0",
      "ip_hash": "sha256:b3d1b2c3d4e5f6..."
    }
  },
  "target": {
    "vc_hash": "sha256:7d865e959b2466918c9863afca942d0f...",
    "holder_did_hash": "sha256:8b7df143d91c716ecfa5f...",
    "issuer_did_hash": "sha256:9c8e4d5b3a2f1e..."
  },
  "context": {
    "session_id": "sess_123456",
    "correlation_id": "corr_789012",
    "geo_location": "KR",
    "network_type": "mainnet"
  },
  "result": {
    "status": "success",
    "duration_ms": 234,
    "error_code": null
  },
  "metadata": {}
}
```

### 1.2 Event Type Definitions

#### DID Lifecycle Events
```yaml
did_events:
  did_creation:
    fields:
      - did_method: "string"
      - key_type: "string"
      - service_endpoints: "array"
    risk_indicators:
      - rapid_creation_rate
      - suspicious_method_usage
      - abnormal_key_types

  did_update:
    fields:
      - update_type: "key_rotation|service_update|controller_change"
      - previous_state_hash: "string"
      - new_state_hash: "string"
    risk_indicators:
      - frequent_key_rotations
      - controller_takeover_attempts
      - service_endpoint_manipulation

  did_deactivation:
    fields:
      - reason: "string"
      - deactivation_proof: "object"
    risk_indicators:
      - mass_deactivation_patterns
      - suspicious_timing
```

#### Credential Lifecycle Events
```yaml
vc_events:
  vc_issuance:
    fields:
      - credential_type: "string[]"
      - credential_schema: "string"
      - issuance_purpose: "string"
      - validity_period: "object"
    risk_indicators:
      - bulk_issuance_spikes
      - unusual_credential_types
      - short_validity_abuse

  vc_presentation:
    fields:
      - presentation_type: "string"
      - requested_attributes: "string[]"
      - selective_disclosure: "boolean"
      - challenge: "string"
    risk_indicators:
      - credential_stuffing_patterns
      - replay_attack_attempts
      - selective_disclosure_abuse

  vc_verification:
    fields:
      - verification_method: "string"
      - verified_claims: "string[]"
      - verification_policies: "object"
    risk_indicators:
      - verification_flooding
      - policy_bypass_attempts
      - collusion_patterns

  vc_revocation:
    fields:
      - revocation_reason: "string"
      - revocation_method: "registry|accumulator|status_list"
    risk_indicators:
      - mass_revocation_events
      - revocation_bypass_attempts
```

#### Authentication Events
```yaml
auth_events:
  authentication_request:
    fields:
      - auth_method: "did_auth|vc_based|biometric"
      - requested_scopes: "string[]"
      - client_metadata: "object"
    risk_indicators:
      - brute_force_patterns
      - scope_escalation_attempts

  authentication_response:
    fields:
      - result: "success|failure|partial"
      - granted_scopes: "string[]"
      - mfa_used: "boolean"
      - failure_reason: "string"
    risk_indicators:
      - account_takeover_patterns
      - session_hijacking_attempts
```

### 1.3 Privacy-Preserving Fields
```yaml
hashing_strategy:
  - did_fields: "SHA-256 with salt"
  - ip_addresses: "SHA-256 prefix-preserving"
  - personal_data: "homomorphic_encryption"
  
anonymization:
  - k_anonymity: 5
  - l_diversity: 3
  - differential_privacy_epsilon: 0.1
```

## 2. Event Data Flow Architecture

### 2.1 Collection Pipeline
```
┌─────────────────┐     ┌─────────────────┐     ┌─────────────────┐
│   DID Systems   │────▶│ Event Adaptors  │────▶│  Kafka Topics   │
└─────────────────┘     └─────────────────┘     └─────────────────┘
                                                          │
                              ┌───────────────────────────┘
                              ▼
                    ┌─────────────────┐
                    │ Stream Processor │
                    │  (Apache Flink)  │
                    └─────────────────┘
                              │
        ┌─────────────────────┼─────────────────────┐
        ▼                     ▼                     ▼
┌───────────────┐   ┌───────────────┐   ┌───────────────┐
│ Normalization │   │  Enrichment   │   │  Validation   │
└───────────────┘   └───────────────┘   └───────────────┘
        │                     │                     │
        └─────────────────────┴─────────────────────┘
                              ▼
                    ┌─────────────────┐
                    │ Event Storage   │
                    │   (InfluxDB)    │
                    └─────────────────┘
```

### 2.2 Event Processing Stages

#### Stage 1: Collection & Ingestion
```yaml
collectors:
  - did_node_collector:
      protocol: "grpc"
      batch_size: 1000
      flush_interval: "1s"
  
  - vc_service_collector:
      protocol: "http/webhook"
      retry_policy: "exponential_backoff"
  
  - blockchain_collector:
      chains: ["ethereum", "polygon"]
      event_filters: ["DIDRegistered", "DIDUpdated"]
```

#### Stage 2: Stream Processing
```yaml
stream_processing:
  windowing:
    - tumbling_window: "5m"
    - sliding_window: "10m with 1m slide"
    - session_window: "30m gap"
  
  aggregations:
    - count_by_event_type
    - unique_actors_per_window
    - average_response_time
  
  stateful_operations:
    - session_tracking
    - entity_state_management
    - pattern_detection
```

#### Stage 3: Enrichment
```yaml
enrichment_sources:
  - threat_intelligence:
      - known_bad_dids
      - suspicious_patterns
      - vulnerability_indicators
  
  - context_data:
      - geo_ip_mapping
      - did_method_registry
      - credential_schema_registry
  
  - historical_data:
      - actor_behavior_profile
      - normal_baseline_metrics
```

### 2.3 Storage Strategy

#### Time-Series Storage (InfluxDB)
```sql
-- Measurement: did_events
CREATE CONTINUOUS QUERY "did_hourly_stats" ON "did_events_db"
BEGIN
  SELECT 
    COUNT(*) as event_count,
    MEAN(duration_ms) as avg_duration,
    PERCENTILE(duration_ms, 95) as p95_duration
  INTO "did_events_hourly"
  FROM "did_events"
  GROUP BY time(1h), event_type, did_method
END
```

#### Graph Storage (Neo4j)
```cypher
// Entity Relationship Model
CREATE (actor:DID {hash: $actor_hash})
CREATE (target:VC {hash: $vc_hash})
CREATE (actor)-[:PERFORMED {
  event_type: $event_type,
  timestamp: $timestamp,
  result: $result
}]->(target)
```

#### Evidence Storage (MinIO)
```yaml
bucket_structure:
  - /evidence/
    - /alerts/{date}/{alert_id}/
      - event_data.json
      - detection_context.json
      - forensic_artifacts/
```

## 3. Event Correlation Patterns

### 3.1 Temporal Correlations
```yaml
patterns:
  - rapid_fire_attempts:
      description: "Multiple failed attempts in short time"
      window: "5 minutes"
      threshold: 10
      
  - distributed_attack:
      description: "Coordinated attempts from multiple actors"
      window: "10 minutes"
      min_actors: 5
      target_overlap: 0.8
```

### 3.2 Behavioral Correlations
```yaml
behaviors:
  - credential_hopping:
      description: "Using multiple credentials in sequence"
      indicators:
        - multiple_vc_presentations
        - different_issuers
        - short_time_intervals
        
  - identity_morphing:
      description: "Changing DID methods to evade detection"
      indicators:
        - multiple_did_methods
        - similar_activity_patterns
        - temporal_proximity
```

## 4. Performance Optimization

### 4.1 Indexing Strategy
```yaml
indexes:
  - primary: [timestamp, event_id]
  - secondary:
    - [actor_hash, timestamp]
    - [event_type, severity]
    - [correlation_id]
  - composite:
    - [event_type, actor_hash, timestamp]
```

### 4.2 Partitioning Strategy
```yaml
partitioning:
  - time_based:
      interval: "daily"
      retention: "90 days"
  - hash_based:
      key: "actor_hash"
      buckets: 32
```

## 5. Data Flow Monitoring

### 5.1 Pipeline Metrics
```yaml
metrics:
  - ingestion_rate: "events/second"
  - processing_latency: "p50, p95, p99"
  - error_rate: "errors/total"
  - backpressure: "boolean"
  - storage_utilization: "percentage"
```

### 5.2 Quality Checks
```yaml
quality_checks:
  - schema_validation: "100% coverage"
  - data_completeness: "> 99%"
  - duplicate_detection: "< 0.1%"
  - timestamp_accuracy: "± 100ms"
```