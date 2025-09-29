# PoC Implementation Architecture

## 1. PoC Overview

### 1.1 Target Scenarios
두 가지 DID 특화 위협 시나리오에 대한 개념 증명 구현:

1. **Scenario 1: Credential Stuffing in DID Context**
   - 탈취한 VC를 여러 Verifier에 대해 무차별 대입
   - 정상 행위와 구분되는 패턴 식별

2. **Scenario 2: DID Method Hopping Attack**
   - 여러 DID Method를 번갈아 사용하여 탐지 회피
   - Cross-method 상관관계 분석을 통한 탐지

### 1.2 PoC Architecture
```
┌────────────────────────────────────────────────────────┐
│                   PoC Control Panel                     │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐ │
│  │   Scenario   │  │   Attack     │  │  Evaluation  │ │
│  │   Manager    │  │  Simulator   │  │  Dashboard   │ │
│  └──────────────┘  └──────────────┘  └──────────────┘ │
├────────────────────────────────────────────────────────┤
│                  Event Generation Layer                 │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐ │
│  │   Normal     │  │  Malicious   │  │    Mixed     │ │
│  │   Traffic    │  │   Traffic    │  │   Traffic    │ │
│  └──────────────┘  └──────────────┘  └──────────────┘ │
├────────────────────────────────────────────────────────┤
│               Mini Detection Engine                     │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐ │
│  │ Rule-based   │  │   ML-based   │  │ Correlation  │ │
│  │  Detector    │  │  Detector    │  │   Engine     │ │
│  └──────────────┘  └──────────────┘  └──────────────┘ │
├────────────────────────────────────────────────────────┤
│                 Evaluation Framework                    │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐ │
│  │   Metrics    │  │   Ground     │  │   Report     │ │
│  │  Collector   │  │    Truth     │  │  Generator   │ │
│  └──────────────┘  └──────────────┘  └──────────────┘ │
└────────────────────────────────────────────────────────┘
```

## 2. Event Generation System

### 2.1 Normal Traffic Generator
```python
class NormalTrafficGenerator:
    def __init__(self, config):
        self.users = self._generate_user_profiles(config['num_users'])
        self.services = config['services']
        self.patterns = config['normal_patterns']
        
    def generate_events(self, duration_minutes=60):
        events = []
        current_time = datetime.now()
        end_time = current_time + timedelta(minutes=duration_minutes)
        
        while current_time < end_time:
            for user in self.users:
                # Normal user behavior patterns
                if random.random() < user['activity_rate']:
                    event = self._generate_user_event(user, current_time)
                    events.append(event)
                    
            current_time += timedelta(seconds=1)
            
        return events
    
    def _generate_user_event(self, user, timestamp):
        event_type = random.choice(user['typical_events'])
        
        if event_type == 'vc_presentation':
            return {
                'event_id': str(uuid.uuid4()),
                'timestamp': timestamp.isoformat(),
                'event_type': 'vc_presentation',
                'actor': {
                    'did_hash': user['did_hash'],
                    'role': 'holder'
                },
                'target': {
                    'vc_hash': random.choice(user['credentials']),
                    'verifier_hash': random.choice(self.services)
                },
                'result': {
                    'status': 'success' if random.random() < 0.95 else 'failure',
                    'duration_ms': random.gauss(200, 50)
                }
            }
```

### 2.2 Attack Simulators

#### Credential Stuffing Simulator
```python
class CredentialStuffingSimulator:
    def __init__(self, stolen_credentials, target_services):
        self.stolen_credentials = stolen_credentials
        self.target_services = target_services
        self.attack_patterns = {
            'rapid_fire': self._rapid_fire_attack,
            'distributed': self._distributed_attack,
            'low_and_slow': self._low_and_slow_attack
        }
        
    def simulate_attack(self, pattern='rapid_fire', duration_minutes=10):
        return self.attack_patterns[pattern](duration_minutes)
    
    def _rapid_fire_attack(self, duration_minutes):
        """빠른 속도로 여러 서비스에 VC 제시"""
        events = []
        attacker_did = self._generate_attacker_did()
        start_time = datetime.now()
        
        for minute in range(duration_minutes):
            current_time = start_time + timedelta(minutes=minute)
            
            # 분당 100-200회 시도
            attempts_per_minute = random.randint(100, 200)
            for i in range(attempts_per_minute):
                event_time = current_time + timedelta(seconds=i*60/attempts_per_minute)
                
                event = {
                    'event_id': str(uuid.uuid4()),
                    'timestamp': event_time.isoformat(),
                    'event_type': 'vc_presentation',
                    'actor': {
                        'did_hash': attacker_did,
                        'role': 'holder',
                        'metadata': {
                            'attack_marker': 'credential_stuffing'  # For evaluation
                        }
                    },
                    'target': {
                        'vc_hash': random.choice(self.stolen_credentials),
                        'verifier_hash': random.choice(self.target_services)
                    },
                    'result': {
                        'status': 'failure' if random.random() < 0.9 else 'success',
                        'duration_ms': random.gauss(150, 30),
                        'error_code': 'invalid_credential' if random.random() < 0.9 else None
                    }
                }
                events.append(event)
                
        return events
```

#### DID Method Hopping Simulator
```python
class DIDMethodHoppingSimulator:
    def __init__(self, did_methods=['did:ethr', 'did:web', 'did:key', 'did:ion']):
        self.did_methods = did_methods
        self.attacker_profiles = []
        
    def simulate_attack(self, duration_minutes=30):
        events = []
        start_time = datetime.now()
        
        # Create multiple DIDs with different methods
        attacker_dids = {
            method: self._create_did_with_method(method)
            for method in self.did_methods
        }
        
        # Simulate method hopping behavior
        for minute in range(duration_minutes):
            current_time = start_time + timedelta(minutes=minute)
            
            # Switch methods every few minutes
            active_method = self.did_methods[minute % len(self.did_methods)]
            active_did = attacker_dids[active_method]
            
            # Generate events with current DID
            events_per_minute = random.randint(20, 40)
            for i in range(events_per_minute):
                event_time = current_time + timedelta(seconds=i*60/events_per_minute)
                
                # Mix of different event types
                event_type = random.choice(['vc_presentation', 'authentication_request'])
                
                event = self._generate_hopping_event(
                    active_did, 
                    active_method, 
                    event_type, 
                    event_time
                )
                events.append(event)
                
            # Occasionally create new DIDs
            if random.random() < 0.1:
                new_method = random.choice(self.did_methods)
                creation_event = self._generate_did_creation_event(
                    new_method, 
                    current_time + timedelta(seconds=30)
                )
                events.append(creation_event)
                
        return events
```

### 2.3 Mixed Traffic Generator
```python
class MixedTrafficGenerator:
    def __init__(self, normal_generator, attack_simulators):
        self.normal_generator = normal_generator
        self.attack_simulators = attack_simulators
        
    def generate_dataset(self, config):
        """정상 트래픽과 공격 트래픽을 섞어서 생성"""
        all_events = []
        
        # Generate normal traffic
        normal_events = self.normal_generator.generate_events(
            duration_minutes=config['duration']
        )
        all_events.extend(normal_events)
        
        # Inject attacks at specific times
        for attack_config in config['attacks']:
            simulator = self.attack_simulators[attack_config['type']]
            attack_events = simulator.simulate_attack(
                pattern=attack_config.get('pattern', 'default'),
                duration_minutes=attack_config['duration']
            )
            
            # Shift attack events to start at specified time
            start_offset = timedelta(minutes=attack_config['start_minute'])
            for event in attack_events:
                event['timestamp'] = (
                    datetime.fromisoformat(event['timestamp']) + start_offset
                ).isoformat()
                
            all_events.extend(attack_events)
            
        # Sort by timestamp
        all_events.sort(key=lambda x: x['timestamp'])
        
        return all_events
```

## 3. Mini Detection Engine Implementation

### 3.1 Detection Engine Core
```python
class MiniDetectionEngine:
    def __init__(self):
        self.detectors = {
            'rule_based': RuleBasedDetector(),
            'ml_based': MLBasedDetector(),
            'correlation': CorrelationEngine()
        }
        self.alerts = []
        self.event_buffer = deque(maxlen=10000)
        
    def process_event(self, event):
        """단일 이벤트 처리 및 탐지"""
        self.event_buffer.append(event)
        
        detection_results = {}
        
        # Run all detectors
        for detector_name, detector in self.detectors.items():
            result = detector.detect(event, self.event_buffer)
            if result:
                detection_results[detector_name] = result
                
        # Generate alert if any detector triggered
        if detection_results:
            alert = self._generate_alert(event, detection_results)
            self.alerts.append(alert)
            return alert
            
        return None
```

### 3.2 Specific Detectors

#### Rule-Based Detector for Credential Stuffing
```python
class CredentialStuffingRuleDetector:
    def __init__(self):
        self.rules = [
            {
                'name': 'high_failure_rate',
                'condition': lambda stats: stats['failure_rate'] > 0.8,
                'threshold': 20,
                'window': 300  # 5 minutes
            },
            {
                'name': 'rapid_attempts',
                'condition': lambda stats: stats['event_rate'] > 10,  # per second
                'threshold': 100,
                'window': 60
            }
        ]
        
    def detect(self, event, event_buffer):
        if event['event_type'] != 'vc_presentation':
            return None
            
        actor_hash = event['actor']['did_hash']
        current_time = datetime.fromisoformat(event['timestamp'])
        
        # Calculate statistics for this actor
        stats = self._calculate_actor_stats(actor_hash, current_time, event_buffer)
        
        # Check rules
        for rule in self.rules:
            if rule['condition'](stats) and stats['event_count'] > rule['threshold']:
                return {
                    'threat_type': 'credential_stuffing',
                    'rule_triggered': rule['name'],
                    'confidence': min(stats['event_count'] / rule['threshold'], 1.0),
                    'evidence': stats
                }
                
        return None
```

#### ML-Based Detector
```python
class MLBasedDetector:
    def __init__(self, model_path='models/'):
        self.models = {
            'rf_classifier': self._load_model(f'{model_path}/rf_threat_classifier.pkl'),
            'isolation_forest': self._load_model(f'{model_path}/isolation_forest.pkl')
        }
        self.feature_extractor = FeatureExtractor()
        
    def detect(self, event, event_buffer):
        # Extract features
        features = self.feature_extractor.extract(event, event_buffer)
        feature_vector = np.array(features).reshape(1, -1)
        
        # Get predictions
        predictions = {}
        
        # Random Forest classification
        if 'rf_classifier' in self.models:
            threat_class = self.models['rf_classifier'].predict(feature_vector)[0]
            threat_proba = self.models['rf_classifier'].predict_proba(feature_vector)[0]
            predictions['classification'] = {
                'class': threat_class,
                'confidence': max(threat_proba)
            }
            
        # Isolation Forest anomaly detection
        if 'isolation_forest' in self.models:
            anomaly_score = self.models['isolation_forest'].decision_function(feature_vector)[0]
            is_anomaly = self.models['isolation_forest'].predict(feature_vector)[0] == -1
            predictions['anomaly'] = {
                'is_anomaly': is_anomaly,
                'score': float(anomaly_score)
            }
            
        # Generate alert if threat detected
        if (predictions.get('classification', {}).get('class') != 'normal' or
            predictions.get('anomaly', {}).get('is_anomaly')):
            return {
                'threat_type': predictions.get('classification', {}).get('class', 'anomaly'),
                'ml_predictions': predictions,
                'features': features
            }
            
        return None
```

## 4. Evaluation Framework

### 4.1 Metrics Collection
```python
class EvaluationMetrics:
    def __init__(self):
        self.metrics = {
            'true_positives': 0,
            'false_positives': 0,
            'true_negatives': 0,
            'false_negatives': 0,
            'detection_latencies': [],
            'processing_times': []
        }
        
    def update(self, event, detection_result, ground_truth):
        """실제 레이블과 탐지 결과 비교"""
        is_attack = ground_truth.get('is_attack', False)
        is_detected = detection_result is not None
        
        if is_attack and is_detected:
            self.metrics['true_positives'] += 1
        elif is_attack and not is_detected:
            self.metrics['false_negatives'] += 1
        elif not is_attack and is_detected:
            self.metrics['false_positives'] += 1
        else:
            self.metrics['true_negatives'] += 1
            
    def calculate_performance(self):
        """성능 지표 계산"""
        tp = self.metrics['true_positives']
        fp = self.metrics['false_positives']
        tn = self.metrics['true_negatives']
        fn = self.metrics['false_negatives']
        
        # Basic metrics
        accuracy = (tp + tn) / (tp + fp + tn + fn) if (tp + fp + tn + fn) > 0 else 0
        precision = tp / (tp + fp) if (tp + fp) > 0 else 0
        recall = tp / (tp + fn) if (tp + fn) > 0 else 0
        f1_score = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0
        
        # Latency metrics
        avg_latency = np.mean(self.metrics['detection_latencies']) if self.metrics['detection_latencies'] else 0
        p95_latency = np.percentile(self.metrics['detection_latencies'], 95) if self.metrics['detection_latencies'] else 0
        
        return {
            'accuracy': accuracy,
            'precision': precision,
            'recall': recall,
            'f1_score': f1_score,
            'false_positive_rate': fp / (fp + tn) if (fp + tn) > 0 else 0,
            'avg_detection_latency_ms': avg_latency,
            'p95_detection_latency_ms': p95_latency,
            'total_events_processed': tp + fp + tn + fn
        }
```

### 4.2 Ground Truth Management
```python
class GroundTruthManager:
    def __init__(self):
        self.attack_periods = []
        self.attack_actors = set()
        
    def mark_attack_period(self, start_time, end_time, attack_type, actors):
        """공격 기간과 공격자 표시"""
        self.attack_periods.append({
            'start': start_time,
            'end': end_time,
            'type': attack_type,
            'actors': actors
        })
        self.attack_actors.update(actors)
        
    def is_attack_event(self, event):
        """이벤트가 공격인지 확인"""
        event_time = datetime.fromisoformat(event['timestamp'])
        actor_hash = event['actor']['did_hash']
        
        # Check if actor is known attacker
        if actor_hash in self.attack_actors:
            return True
            
        # Check if event is within attack period
        for period in self.attack_periods:
            if period['start'] <= event_time <= period['end']:
                if actor_hash in period['actors']:
                    return True
                    
        # Check for attack markers (for evaluation)
        if event.get('actor', {}).get('metadata', {}).get('attack_marker'):
            return True
            
        return False
```

## 5. PoC Execution Pipeline

### 5.1 Experiment Configuration
```yaml
experiment_config:
  scenarios:
    - name: "Credential Stuffing Detection"
      dataset:
        duration_minutes: 120
        normal_users: 1000
        attacks:
          - type: "credential_stuffing"
            pattern: "rapid_fire"
            start_minute: 30
            duration: 10
          - type: "credential_stuffing"
            pattern: "distributed"
            start_minute: 70
            duration: 15
            
    - name: "DID Method Hopping Detection"
      dataset:
        duration_minutes: 180
        normal_users: 500
        attacks:
          - type: "did_hopping"
            start_minute: 45
            duration: 30
          - type: "did_hopping"
            start_minute: 120
            duration: 20
            
  detection_config:
    rule_thresholds:
      credential_stuffing: 20
      method_hopping: 3
    ml_models:
      - "rf_classifier_v1"
      - "isolation_forest_v1"
    correlation_window: 600  # 10 minutes
    
  evaluation_config:
    metrics_interval: 60  # Calculate metrics every minute
    report_format: "json"
    visualization: true
```

### 5.2 Execution Script
```python
class PoCExecutor:
    def __init__(self, config):
        self.config = config
        self.traffic_generator = self._setup_traffic_generator()
        self.detection_engine = MiniDetectionEngine()
        self.evaluator = EvaluationMetrics()
        self.ground_truth = GroundTruthManager()
        
    def run_experiment(self, scenario_name):
        """단일 실험 시나리오 실행"""
        scenario = self._get_scenario(scenario_name)
        
        # Generate dataset
        print(f"Generating dataset for {scenario_name}...")
        events = self.traffic_generator.generate_dataset(scenario['dataset'])
        
        # Setup ground truth
        self._setup_ground_truth(scenario['dataset']['attacks'])
        
        # Process events
        print(f"Processing {len(events)} events...")
        results = []
        
        for event in tqdm(events):
            start_time = time.time()
            
            # Detect
            detection_result = self.detection_engine.process_event(event)
            
            # Measure latency
            latency = (time.time() - start_time) * 1000  # ms
            
            # Update metrics
            ground_truth = {'is_attack': self.ground_truth.is_attack_event(event)}
            self.evaluator.update(event, detection_result, ground_truth)
            self.evaluator.metrics['detection_latencies'].append(latency)
            
            results.append({
                'event': event,
                'detection': detection_result,
                'ground_truth': ground_truth,
                'latency_ms': latency
            })
            
        # Calculate final metrics
        performance = self.evaluator.calculate_performance()
        
        return {
            'scenario': scenario_name,
            'results': results,
            'performance': performance,
            'alerts': self.detection_engine.alerts
        }
```

## 6. Results Visualization

### 6.1 Performance Dashboard
```python
class ResultsVisualizer:
    def __init__(self):
        self.fig, self.axes = plt.subplots(2, 2, figsize=(15, 10))
        
    def plot_results(self, experiment_results):
        """실험 결과 시각화"""
        # 1. Detection Performance
        self._plot_detection_metrics(
            experiment_results['performance'], 
            self.axes[0, 0]
        )
        
        # 2. Timeline Analysis
        self._plot_timeline(
            experiment_results['results'], 
            self.axes[0, 1]
        )
        
        # 3. Latency Distribution
        self._plot_latency_distribution(
            experiment_results['performance']['detection_latencies'],
            self.axes[1, 0]
        )
        
        # 4. Confusion Matrix
        self._plot_confusion_matrix(
            experiment_results['performance'],
            self.axes[1, 1]
        )
        
        plt.tight_layout()
        plt.savefig(f"results/{experiment_results['scenario']}_analysis.png")
```

### 6.2 Report Generation
```python
class ReportGenerator:
    def generate_report(self, all_results):
        """최종 보고서 생성"""
        report = {
            'summary': {
                'total_experiments': len(all_results),
                'timestamp': datetime.now().isoformat(),
                'overall_performance': self._calculate_overall_performance(all_results)
            },
            'scenarios': {}
        }
        
        for result in all_results:
            scenario_name = result['scenario']
            report['scenarios'][scenario_name] = {
                'performance_metrics': result['performance'],
                'detection_summary': {
                    'total_alerts': len(result['alerts']),
                    'alert_distribution': self._analyze_alert_distribution(result['alerts'])
                },
                'recommendations': self._generate_recommendations(result)
            }
            
        # Save report
        with open('poc_evaluation_report.json', 'w') as f:
            json.dump(report, f, indent=2)
            
        # Generate markdown summary
        self._generate_markdown_summary(report)
        
        return report
```