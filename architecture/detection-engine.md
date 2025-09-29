# DID Threat Detection Engine Design

## 1. Detection Engine Architecture

### 1.1 Multi-Layer Detection Framework
```
┌──────────────────────────────────────────────────────────────┐
│                   Detection Orchestrator                      │
│  ┌────────────┐  ┌────────────┐  ┌────────────────────────┐ │
│  │  Priority   │  │  Resource  │  │   Result Aggregation   │ │
│  │   Queue     │  │  Manager   │  │   & Deduplication     │ │
│  └────────────┘  └────────────┘  └────────────────────────┘ │
├──────────────────────────────────────────────────────────────┤
│                    Detection Layers                           │
│  ┌────────────────────────────────────────────────────────┐ │
│  │              Layer 1: Real-time Rules                   │ │
│  │  • Threshold Detection  • Pattern Matching              │ │
│  │  • Blacklist Checking   • Signature Detection           │ │
│  └────────────────────────────────────────────────────────┘ │
│  ┌────────────────────────────────────────────────────────┐ │
│  │              Layer 2: Statistical Analysis              │ │
│  │  • Anomaly Detection    • Baseline Deviation            │ │
│  │  • Time-series Analysis • Frequency Analysis            │ │
│  └────────────────────────────────────────────────────────┘ │
│  ┌────────────────────────────────────────────────────────┐ │
│  │              Layer 3: Machine Learning                  │ │
│  │  • Classification Models • Clustering Algorithms         │ │
│  │  • Neural Networks      • Ensemble Methods              │ │
│  └────────────────────────────────────────────────────────┘ │
│  ┌────────────────────────────────────────────────────────┐ │
│  │              Layer 4: Correlation Engine                │ │
│  │  • Cross-event Analysis • Entity Behavior Analytics     │ │
│  │  • Kill Chain Mapping   • TTP Correlation               │ │
│  └────────────────────────────────────────────────────────┘ │
└──────────────────────────────────────────────────────────────┘
```

### 1.2 Detection Components

#### Rule-Based Detection Engine
```yaml
rule_engine:
  rule_format: "Sigma-compatible + DID extensions"
  rule_categories:
    - threshold_rules:
        example: "VC presentations > 100 in 5 minutes"
    - pattern_rules:
        example: "Sequential DID method changes"
    - state_rules:
        example: "Revoked VC still being used"
    - composite_rules:
        example: "Multiple indicators within context"

  rule_example:
    title: "DID Credential Stuffing Attack"
    id: "did-001"
    status: "production"
    description: "Detects credential stuffing using stolen VCs"
    references:
      - "https://did-threats.example.com/credential-stuffing"
    logsource:
      category: "vc_events"
      event_type: "vc_presentation"
    detection:
      selection:
        event_type: "vc_presentation"
        result.status: "failure"
      timeframe: 5m
      condition: selection | count() by actor.did_hash > 20
    falsepositives:
      - "Legitimate automated testing"
    level: "high"
    tags:
      - "attack.credential_access"
      - "did.credential_stuffing"
```

#### ML-Based Detection Models
```yaml
ml_models:
  supervised_models:
    - random_forest_classifier:
        purpose: "Multi-class threat classification"
        features:
          - event_frequency
          - time_between_events
          - unique_targets_count
          - method_diversity_score
        labels:
          - normal
          - credential_stuffing
          - did_hopping
          - replay_attack
        
    - gradient_boosting:
        purpose: "Anomaly severity scoring"
        output: "risk_score (0-100)"
        
    - lstm_sequence:
        purpose: "Temporal pattern detection"
        input: "Event sequences"
        output: "Next event prediction + anomaly flag"

  unsupervised_models:
    - isolation_forest:
        purpose: "Outlier detection"
        contamination: 0.01
        features: "All numerical event features"
        
    - dbscan_clustering:
        purpose: "Behavior grouping"
        eps: 0.3
        min_samples: 5
        
    - autoencoder:
        purpose: "Complex anomaly detection"
        architecture:
          - input: 50
          - encoder: [30, 15, 7]
          - decoder: [7, 15, 30]
          - output: 50
        threshold: "reconstruction_error > 2σ"
```

#### Correlation Engine
```yaml
correlation_engine:
  correlation_rules:
    - kill_chain_correlation:
        stages:
          - reconnaissance: "DID enumeration patterns"
          - resource_development: "Fake DID creation"
          - initial_access: "First successful VC verification"
          - execution: "Malicious action using VC"
          - persistence: "DID key rotation for backdoor"
          
    - entity_correlation:
        relationships:
          - same_origin: "DIDs from same IP/device"
          - temporal_proximity: "Actions within time window"
          - target_overlap: "Attacking same services"
          
    - ttp_mapping:
        mitre_extended:
          - T1078.DID: "Valid DID Accounts"
          - T1550.DID: "Use Alternate Authentication Material"
          - T1606.DID: "Forge Web Credentials (VC)"

  correlation_example:
    name: "Coordinated DID Attack Campaign"
    indicators:
      - pattern: "Multiple new DIDs created"
        weight: 0.3
      - pattern: "DIDs share similar attributes"
        weight: 0.2
      - pattern: "Synchronized VC presentations"
        weight: 0.5
    threshold: 0.7
    action: "Generate high-priority alert"
```

## 2. DID-Specific Threat Detection

### 2.1 DID Unique Threat Patterns
```yaml
did_specific_threats:
  - credential_replay_attack:
      description: "Reusing captured VC presentations"
      detection:
        - duplicate_challenge_detection
        - timestamp_validation
        - nonce_tracking
      indicators:
        - same_vc_hash_multiple_presentations
        - outdated_timestamps
        - duplicate_nonces
        
  - did_method_exploitation:
      description: "Exploiting weaknesses in specific DID methods"
      detection:
        - method_specific_validation
        - cross_method_correlation
        - registry_consistency_check
      indicators:
        - rapid_method_switching
        - exploiting_method_differences
        - registry_manipulation_attempts
        
  - selective_disclosure_abuse:
      description: "Manipulating selective disclosure for information gathering"
      detection:
        - disclosure_pattern_analysis
        - information_leakage_detection
        - attribute_correlation
      indicators:
        - incremental_attribute_requests
        - cross_service_attribute_mapping
        - privacy_boundary_violations
        
  - verifier_collusion:
      description: "Multiple verifiers sharing VC information"
      detection:
        - cross_verifier_correlation
        - information_flow_analysis
        - timing_analysis
      indicators:
        - synchronized_verification_requests
        - shared_vc_knowledge_patterns
        - coordinated_attribute_requests
```

### 2.2 Detection Algorithm Examples

#### Algorithm 1: Credential Stuffing Detection
```python
class CredentialStuffingDetector:
    def __init__(self, threshold=20, window=300):
        self.threshold = threshold
        self.window = window  # 5 minutes
        self.event_buffer = defaultdict(list)
    
    def detect(self, event):
        actor_hash = event['actor']['did_hash']
        timestamp = event['timestamp']
        
        # Clean old events
        self.event_buffer[actor_hash] = [
            e for e in self.event_buffer[actor_hash]
            if timestamp - e['timestamp'] <= self.window
        ]
        
        # Add current event
        self.event_buffer[actor_hash].append(event)
        
        # Check threshold
        if len(self.event_buffer[actor_hash]) > self.threshold:
            failed_attempts = sum(
                1 for e in self.event_buffer[actor_hash]
                if e['result']['status'] == 'failure'
            )
            
            if failed_attempts > self.threshold * 0.8:
                return {
                    'threat': 'credential_stuffing',
                    'confidence': min(failed_attempts / self.threshold, 1.0),
                    'actor': actor_hash,
                    'evidence': self.event_buffer[actor_hash]
                }
        
        return None
```

#### Algorithm 2: DID Method Hopping Detection
```python
class DIDMethodHoppingDetector:
    def __init__(self, method_threshold=3, time_window=3600):
        self.method_threshold = method_threshold
        self.time_window = time_window  # 1 hour
        self.actor_methods = defaultdict(lambda: defaultdict(set))
    
    def detect(self, event):
        if event['event_type'] not in ['did_creation', 'vc_presentation']:
            return None
            
        actor_hash = event['actor']['did_hash']
        timestamp = event['timestamp']
        method = self._extract_method(event)
        
        # Track methods used by actor
        time_bucket = timestamp // self.time_window
        self.actor_methods[actor_hash][time_bucket].add(method)
        
        # Check for method hopping
        recent_methods = set()
        for i in range(3):  # Check last 3 time windows
            bucket = time_bucket - i
            recent_methods.update(self.actor_methods[actor_hash].get(bucket, set()))
        
        if len(recent_methods) >= self.method_threshold:
            return {
                'threat': 'did_method_hopping',
                'confidence': min(len(recent_methods) / 5, 1.0),
                'actor': actor_hash,
                'methods_used': list(recent_methods),
                'time_range': f"{3 * self.time_window}s"
            }
        
        return None
```

## 3. Alert Generation & Management

### 3.1 Alert Schema
```json
{
  "alert_id": "alert-550e8400-e29b-41d4",
  "timestamp": "2024-01-18T10:30:45.123Z",
  "severity": "high",
  "confidence": 0.87,
  "threat_type": "credential_stuffing",
  "detection_layers": ["rule_based", "ml_classification"],
  "affected_entities": {
    "actors": ["sha256:abc...", "sha256:def..."],
    "targets": ["sha256:123...", "sha256:456..."],
    "services": ["verifier.example.com"]
  },
  "evidence": {
    "event_count": 45,
    "time_span": "5m",
    "pattern_matches": ["rapid_failure", "distributed_source"],
    "ml_scores": {
      "random_forest": 0.92,
      "isolation_forest": -0.15
    }
  },
  "recommended_actions": [
    "Block actor DIDs",
    "Increase authentication requirements",
    "Notify affected services"
  ],
  "mitre_mapping": ["T1110.DID", "T1078.DID"],
  "investigation_links": [
    "/investigate/alert-550e8400-e29b-41d4",
    "/forensics/timeline/2024-01-18T10:25:00Z"
  ]
}
```

### 3.2 Alert Prioritization
```yaml
prioritization_factors:
  - severity_weight: 0.3
  - confidence_weight: 0.2
  - impact_weight: 0.25
  - detection_consensus: 0.15
  - historical_accuracy: 0.1

priority_calculation:
  formula: "Σ(factor_value * factor_weight)"
  thresholds:
    - critical: "> 0.8"
    - high: "0.6 - 0.8"
    - medium: "0.4 - 0.6"
    - low: "< 0.4"
```

## 4. Performance Optimization

### 4.1 Detection Pipeline Optimization
```yaml
optimization_strategies:
  - parallel_processing:
      - partition_by: "actor_hash"
      - workers: 16
      - load_balancing: "consistent_hashing"
      
  - caching:
      - detection_cache: "Recent detection results"
      - feature_cache: "Computed ML features"
      - rule_cache: "Compiled detection rules"
      
  - batch_processing:
      - micro_batches: 100ms
      - batch_size: 1000 events
      - compression: "snappy"
      
  - model_optimization:
      - quantization: "INT8 for inference"
      - pruning: "Remove 30% smallest weights"
      - distillation: "Teacher-student models"
```

### 4.2 Resource Management
```yaml
resource_allocation:
  - cpu_allocation:
      rule_engine: "4 cores"
      ml_inference: "8 cores + GPU"
      correlation: "4 cores"
      
  - memory_allocation:
      event_buffer: "8GB"
      model_cache: "4GB"
      detection_state: "16GB"
      
  - scaling_policies:
      - horizontal: "CPU > 80% for 5min"
      - vertical: "Memory > 90%"
      - predictive: "Based on event rate trends"
```

## 5. Integration Points

### 5.1 SIEM Integration
```yaml
siem_integration:
  - output_formats:
      - cef: "Common Event Format"
      - leef: "Log Event Extended Format"
      - json: "Native JSON format"
      
  - integration_methods:
      - syslog: "UDP/TCP 514"
      - kafka: "Alert topic"
      - webhook: "HTTP POST"
      - api: "REST/GraphQL"
```

### 5.2 Response Integration
```yaml
response_actions:
  - automated:
      - block_did: "Add to blacklist"
      - rate_limit: "Throttle requests"
      - increase_auth: "Require MFA"
      
  - semi_automated:
      - investigation_ticket: "Create incident"
      - stakeholder_notification: "Email/Slack"
      
  - manual:
      - forensic_investigation: "Deep dive analysis"
      - policy_update: "Adjust detection rules"
```