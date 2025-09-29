# DID Threat Detection Framework - Implementation Guide

## 1. Quick Start Guide

### 1.1 Prerequisites
```yaml
system_requirements:
  - Python: ">=3.8"
  - Docker: ">=20.10"
  - Kubernetes: ">=1.21 (optional for production)"
  - Memory: ">=16GB recommended"
  - Storage: ">=100GB for PoC"

dependencies:
  python_packages:
    - apache-flink: "Stream processing"
    - influxdb-client: "Time-series storage"
    - neo4j: "Graph database"
    - scikit-learn: "ML models"
    - prometheus-client: "Metrics"
    - kafka-python: "Event streaming"
```

### 1.2 Project Structure
```
did-threat-detection/
├── architecture/           # Architecture documents
├── src/
│   ├── collectors/        # Event collectors
│   ├── detectors/         # Detection engines
│   ├── models/           # ML models
│   ├── processors/       # Stream processors
│   └── utils/           # Utilities
├── config/
│   ├── detection-rules/  # Detection rules
│   ├── schemas/         # Event schemas
│   └── settings/        # Configuration files
├── poc/
│   ├── scenarios/       # Attack scenarios
│   ├── generators/      # Traffic generators
│   └── evaluation/      # Evaluation scripts
├── deployment/
│   ├── docker/         # Docker configurations
│   ├── k8s/           # Kubernetes manifests
│   └── terraform/     # Infrastructure as code
└── tests/             # Test suites
```

## 2. Core Components Implementation

### 2.1 Event Collector Setup
```python
# src/collectors/did_event_collector.py
from kafka import KafkaProducer
import json
import hashlib
from datetime import datetime

class DIDEventCollector:
    def __init__(self, kafka_bootstrap_servers):
        self.producer = KafkaProducer(
            bootstrap_servers=kafka_bootstrap_servers,
            value_serializer=lambda v: json.dumps(v).encode('utf-8'),
            compression_type='snappy'
        )
        
    def collect_event(self, raw_event):
        """Collect and normalize DID event"""
        # Privacy-preserving transformation
        normalized_event = {
            'event_id': raw_event.get('id'),
            'timestamp': datetime.utcnow().isoformat(),
            'event_type': raw_event.get('type'),
            'actor': {
                'did_hash': self._hash_did(raw_event.get('actor_did')),
                'role': raw_event.get('actor_role')
            },
            'target': self._extract_target(raw_event),
            'result': raw_event.get('result'),
            'metadata': self._sanitize_metadata(raw_event.get('metadata', {}))
        }
        
        # Send to Kafka
        topic = f"did_events_{normalized_event['event_type']}"
        self.producer.send(topic, value=normalized_event)
        
    def _hash_did(self, did):
        """Hash DID for privacy"""
        if not did:
            return None
        return hashlib.sha256(did.encode()).hexdigest()
```

### 2.2 Detection Engine Setup
```python
# src/detectors/detection_engine.py
from abc import ABC, abstractmethod
import numpy as np
from collections import deque
import joblib

class DetectionEngine:
    def __init__(self):
        self.detectors = {
            'rules': RuleBasedDetector(),
            'ml': MLDetector(),
            'correlation': CorrelationDetector()
        }
        self.alert_manager = AlertManager()
        
    async def process_event(self, event):
        """Process event through detection pipeline"""
        detection_results = []
        
        # Run detectors in parallel
        for name, detector in self.detectors.items():
            result = await detector.detect(event)
            if result:
                detection_results.append({
                    'detector': name,
                    'result': result
                })
                
        # Generate alert if needed
        if detection_results:
            alert = self.alert_manager.create_alert(event, detection_results)
            await self.alert_manager.send_alert(alert)
            
        return detection_results

class RuleBasedDetector:
    def __init__(self):
        self.rules = self._load_rules()
        self.event_windows = defaultdict(lambda: deque(maxlen=1000))
        
    async def detect(self, event):
        """Apply detection rules"""
        actor = event['actor']['did_hash']
        self.event_windows[actor].append(event)
        
        for rule in self.rules:
            if self._evaluate_rule(rule, self.event_windows[actor]):
                return {
                    'threat_type': rule['threat_type'],
                    'confidence': rule['confidence'],
                    'rule_id': rule['id']
                }
        return None
```

### 2.3 Stream Processing Setup
```python
# src/processors/stream_processor.py
from pyflink.datastream import StreamExecutionEnvironment
from pyflink.table import StreamTableEnvironment
from pyflink.table.udf import udf
from pyflink.table.expressions import col, lit

class DIDStreamProcessor:
    def __init__(self):
        self.env = StreamExecutionEnvironment.get_execution_environment()
        self.t_env = StreamTableEnvironment.create(self.env)
        self._setup_environment()
        
    def _setup_environment(self):
        """Configure Flink environment"""
        self.env.set_parallelism(4)
        self.env.enable_checkpointing(60000)  # 1 minute
        
        # Register UDFs
        self.t_env.create_temporary_function(
            "detect_anomaly", 
            udf(self.detect_anomaly, result_type='BOOLEAN')
        )
        
    def create_processing_pipeline(self):
        """Create event processing pipeline"""
        # Define source
        self.t_env.execute_sql("""
            CREATE TABLE did_events (
                event_id STRING,
                timestamp TIMESTAMP(3),
                event_type STRING,
                actor ROW<did_hash STRING, role STRING>,
                target ROW<vc_hash STRING, verifier_hash STRING>,
                result ROW<status STRING, duration_ms BIGINT>,
                WATERMARK FOR timestamp AS timestamp - INTERVAL '5' SECOND
            ) WITH (
                'connector' = 'kafka',
                'topic' = 'did_events',
                'properties.bootstrap.servers' = 'localhost:9092',
                'format' = 'json'
            )
        """)
        
        # Process events
        processed = self.t_env.sql_query("""
            SELECT 
                actor.did_hash,
                event_type,
                COUNT(*) as event_count,
                AVG(result.duration_ms) as avg_duration,
                TUMBLE_START(timestamp, INTERVAL '5' MINUTE) as window_start
            FROM did_events
            GROUP BY 
                actor.did_hash,
                event_type,
                TUMBLE(timestamp, INTERVAL '5' MINUTE)
        """)
        
        # Detect anomalies
        anomalies = processed.filter(col('event_count') > lit(100))
        
        return anomalies
```

## 3. PoC Implementation Steps

### 3.1 Environment Setup
```bash
# Clone repository
git clone https://github.com/your-org/did-threat-detection.git
cd did-threat-detection

# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Start infrastructure
docker-compose -f deployment/docker/docker-compose.yml up -d
```

### 3.2 Configure Detection Rules
```yaml
# config/detection-rules/credential_stuffing.yaml
rules:
  - id: "CS001"
    name: "Rapid Credential Presentation"
    threat_type: "credential_stuffing"
    conditions:
      - field: "event_type"
        operator: "equals"
        value: "vc_presentation"
      - field: "result.status"
        operator: "equals"
        value: "failure"
    thresholds:
      count: 20
      time_window: "5m"
    confidence: 0.85
    
  - id: "CS002"
    name: "Distributed Credential Attack"
    threat_type: "credential_stuffing"
    conditions:
      - field: "event_type"
        operator: "equals"
        value: "vc_presentation"
    correlation:
      - unique_targets: "> 10"
      - time_window: "10m"
      - failure_rate: "> 0.7"
    confidence: 0.90
```

### 3.3 Train ML Models
```python
# poc/train_models.py
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
import joblib

def train_threat_classifier():
    """Train ML model for threat classification"""
    # Load training data
    data = pd.read_csv('data/labeled_events.csv')
    
    # Feature engineering
    features = engineer_features(data)
    labels = data['threat_type']
    
    # Split data
    X_train, X_test, y_train, y_test = train_test_split(
        features, labels, test_size=0.2, random_state=42
    )
    
    # Train model
    clf = RandomForestClassifier(
        n_estimators=100,
        max_depth=10,
        random_state=42
    )
    clf.fit(X_train, y_train)
    
    # Evaluate
    accuracy = clf.score(X_test, y_test)
    print(f"Model accuracy: {accuracy:.3f}")
    
    # Save model
    joblib.dump(clf, 'models/threat_classifier.pkl')
    
def engineer_features(data):
    """Extract features from event data"""
    features = pd.DataFrame()
    
    # Temporal features
    features['hour_of_day'] = pd.to_datetime(data['timestamp']).dt.hour
    features['day_of_week'] = pd.to_datetime(data['timestamp']).dt.dayofweek
    
    # Event features
    features['event_type_encoded'] = pd.Categorical(data['event_type']).codes
    features['failure_rate'] = data.groupby('actor_hash')['result_status'].transform(
        lambda x: (x == 'failure').mean()
    )
    
    # Activity features
    features['event_frequency'] = data.groupby('actor_hash')['event_id'].transform('count')
    features['unique_targets'] = data.groupby('actor_hash')['target_hash'].transform('nunique')
    
    return features
```

### 3.4 Run Attack Simulations
```python
# poc/run_simulation.py
import asyncio
from generators import NormalTrafficGenerator, AttackSimulator
from detectors import MiniDetectionEngine
from evaluation import EvaluationFramework

async def run_poc_simulation():
    """Run PoC simulation"""
    # Initialize components
    normal_gen = NormalTrafficGenerator(num_users=1000)
    attack_sim = AttackSimulator()
    detection_engine = MiniDetectionEngine()
    evaluator = EvaluationFramework()
    
    # Generate mixed traffic
    print("Generating traffic...")
    events = []
    
    # Normal traffic (80%)
    events.extend(normal_gen.generate_events(duration_minutes=60))
    
    # Attack traffic (20%)
    attack_events = attack_sim.simulate_credential_stuffing(
        duration_minutes=10,
        attack_rate=100
    )
    events.extend(attack_events)
    
    # Process events
    print(f"Processing {len(events)} events...")
    results = []
    
    for event in events:
        detection = await detection_engine.process_event(event)
        ground_truth = event.get('metadata', {}).get('is_attack', False)
        
        results.append({
            'event': event,
            'detection': detection,
            'ground_truth': ground_truth
        })
        
        # Update metrics
        evaluator.update_metrics(detection, ground_truth)
        
    # Generate report
    print("Generating evaluation report...")
    report = evaluator.generate_report()
    
    print(f"Detection Rate: {report['recall']:.2%}")
    print(f"False Positive Rate: {report['fpr']:.2%}")
    print(f"Avg Latency: {report['avg_latency']:.2f}ms")
    
    return report

# Run simulation
if __name__ == "__main__":
    asyncio.run(run_poc_simulation())
```

## 4. Deployment Guide

### 4.1 Docker Deployment
```dockerfile
# deployment/docker/Dockerfile
FROM python:3.9-slim

WORKDIR /app

# Install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application
COPY src/ ./src/
COPY config/ ./config/
COPY models/ ./models/

# Set environment variables
ENV PYTHONPATH=/app
ENV KAFKA_BOOTSTRAP_SERVERS=kafka:9092
ENV INFLUXDB_URL=http://influxdb:8086

# Run detection engine
CMD ["python", "-m", "src.main"]
```

### 4.2 Kubernetes Deployment
```yaml
# deployment/k8s/detection-engine.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: did-detection-engine
spec:
  replicas: 3
  selector:
    matchLabels:
      app: detection-engine
  template:
    metadata:
      labels:
        app: detection-engine
    spec:
      containers:
      - name: detection-engine
        image: did-detection:latest
        resources:
          requests:
            memory: "2Gi"
            cpu: "1"
          limits:
            memory: "4Gi"
            cpu: "2"
        env:
        - name: KAFKA_BOOTSTRAP_SERVERS
          value: "kafka-service:9092"
        - name: DETECTION_MODE
          value: "production"
        livenessProbe:
          httpGet:
            path: /health
            port: 8080
          initialDelaySeconds: 30
          periodSeconds: 10
---
apiVersion: v1
kind: Service
metadata:
  name: detection-engine-service
spec:
  selector:
    app: detection-engine
  ports:
  - port: 8080
    targetPort: 8080
```

## 5. Testing & Validation

### 5.1 Unit Tests
```python
# tests/test_detectors.py
import pytest
from src.detectors import CredentialStuffingDetector

def test_credential_stuffing_detection():
    """Test credential stuffing detection"""
    detector = CredentialStuffingDetector(threshold=20)
    
    # Generate test events
    events = []
    for i in range(25):
        events.append({
            'event_type': 'vc_presentation',
            'actor': {'did_hash': 'attacker123'},
            'result': {'status': 'failure'},
            'timestamp': f'2024-01-18T10:{i:02d}:00Z'
        })
        
    # Process events
    detections = []
    for event in events:
        result = detector.detect(event)
        if result:
            detections.append(result)
            
    # Verify detection
    assert len(detections) > 0
    assert detections[0]['threat_type'] == 'credential_stuffing'
    assert detections[0]['confidence'] > 0.8
```

### 5.2 Integration Tests
```python
# tests/test_integration.py
import asyncio
import pytest
from testcontainers.kafka import KafkaContainer
from testcontainers.compose import DockerCompose

@pytest.fixture
async def test_environment():
    """Setup test environment"""
    with DockerCompose("deployment/docker/") as compose:
        yield compose
        
async def test_end_to_end_detection(test_environment):
    """Test complete detection pipeline"""
    # Send test events
    producer = KafkaProducer(bootstrap_servers='localhost:9092')
    
    # Normal event
    producer.send('did_events', {
        'event_type': 'vc_presentation',
        'actor': {'did_hash': 'user123'},
        'result': {'status': 'success'}
    })
    
    # Attack events
    for i in range(50):
        producer.send('did_events', {
            'event_type': 'vc_presentation',
            'actor': {'did_hash': 'attacker456'},
            'result': {'status': 'failure'}
        })
        
    # Wait for processing
    await asyncio.sleep(5)
    
    # Check alerts
    alerts = fetch_alerts_from_db()
    assert len(alerts) > 0
    assert any(a['threat_type'] == 'credential_stuffing' for a in alerts)
```

## 6. Monitoring & Operations

### 6.1 Prometheus Metrics
```yaml
# config/prometheus/rules.yml
groups:
  - name: did_detection
    rules:
      - alert: HighFalsePositiveRate
        expr: rate(detection_false_positives_total[5m]) > 0.1
        for: 10m
        labels:
          severity: warning
        annotations:
          summary: "High false positive rate detected"
          
      - alert: DetectionLatencyHigh
        expr: histogram_quantile(0.95, detection_latency_seconds_bucket) > 0.1
        for: 5m
        labels:
          severity: critical
        annotations:
          summary: "Detection latency exceeds SLA"
```

### 6.2 Grafana Dashboard
```json
{
  "dashboard": {
    "title": "DID Threat Detection",
    "panels": [
      {
        "title": "Detection Rate",
        "targets": [
          {
            "expr": "rate(threats_detected_total[5m])"
          }
        ]
      },
      {
        "title": "System Performance",
        "targets": [
          {
            "expr": "histogram_quantile(0.95, event_processing_duration_seconds_bucket)"
          }
        ]
      }
    ]
  }
}
```

## 7. Troubleshooting Guide

### 7.1 Common Issues
```yaml
issues:
  - problem: "High false positive rate"
    causes:
      - "Threshold too low"
      - "Insufficient training data"
      - "Model drift"
    solutions:
      - "Adjust detection thresholds"
      - "Retrain models with more data"
      - "Implement online learning"
      
  - problem: "Detection latency spikes"
    causes:
      - "Resource contention"
      - "Large event backlogs"
      - "Inefficient rules"
    solutions:
      - "Scale detection workers"
      - "Optimize rule evaluation"
      - "Implement circuit breakers"
```

### 7.2 Performance Tuning
```python
# config/performance_tuning.py
PERFORMANCE_CONFIG = {
    'event_buffer_size': 10000,
    'batch_size': 1000,
    'parallelism': 8,
    'checkpointing_interval': 60000,
    'state_backend': 'rocksdb',
    'memory_per_worker': '4g',
    'cpu_per_worker': 2
}
```

## 8. Next Steps

### 8.1 Production Readiness Checklist
- [ ] Security hardening completed
- [ ] Performance benchmarks met
- [ ] Disaster recovery plan tested
- [ ] Monitoring alerts configured
- [ ] Documentation complete
- [ ] Team training conducted

### 8.2 Future Enhancements
1. Advanced ML models (deep learning)
2. Real-time model updates
3. Distributed tracing integration
4. Multi-region deployment
5. Advanced visualization dashboard