# Performance Evaluation & Metrics Framework

## 1. Evaluation Framework Overview

### 1.1 Evaluation Objectives
```yaml
primary_objectives:
  - detection_effectiveness:
      metrics: [precision, recall, f1_score]
      target: "> 0.95 for known threats"
      
  - false_positive_management:
      metrics: [false_positive_rate, alert_fatigue_index]
      target: "< 5% FPR"
      
  - real_time_performance:
      metrics: [detection_latency, throughput]
      target: "< 100ms p95 latency"
      
  - resource_efficiency:
      metrics: [cpu_usage, memory_usage, storage_growth]
      target: "Linear scaling with event volume"
```

### 1.2 Evaluation Architecture
```
┌────────────────────────────────────────────────────────────┐
│                  Evaluation Controller                      │
│  ┌───────────────┐  ┌──────────────┐  ┌────────────────┐  │
│  │   Experiment  │  │   Metrics    │  │    Baseline    │  │
│  │  Orchestrator │  │  Aggregator  │  │   Comparator   │  │
│  └───────────────┘  └──────────────┘  └────────────────┘  │
├────────────────────────────────────────────────────────────┤
│                    Data Collection Layer                    │
│  ┌───────────────┐  ┌──────────────┐  ┌────────────────┐  │
│  │  Performance  │  │  Detection   │  │    Resource    │  │
│  │   Profiler    │  │   Logger     │  │    Monitor     │  │
│  └───────────────┘  └──────────────┘  └────────────────┘  │
├────────────────────────────────────────────────────────────┤
│                   Analysis & Reporting                      │
│  ┌───────────────┐  ┌──────────────┐  ┌────────────────┐  │
│  │  Statistical  │  │ Visualization│  │     Report     │  │
│  │   Analysis    │  │   Engine     │  │   Generator    │  │
│  └───────────────┘  └──────────────┘  └────────────────┘  │
└────────────────────────────────────────────────────────────┘
```

## 2. Metrics Collection System

### 2.1 Core Metrics Definition
```python
class MetricsCollector:
    def __init__(self):
        self.metrics = {
            # Detection Metrics
            'detection': {
                'true_positives': Counter(),
                'false_positives': Counter(),
                'true_negatives': Counter(),
                'false_negatives': Counter(),
                'detection_confidence': [],
                'alert_quality_scores': []
            },
            
            # Performance Metrics
            'performance': {
                'event_processing_latency': TimeSeries(),
                'detection_latency': TimeSeries(),
                'throughput': TimeSeries(),
                'queue_depth': TimeSeries()
            },
            
            # Resource Metrics
            'resources': {
                'cpu_usage': TimeSeries(),
                'memory_usage': TimeSeries(),
                'disk_io': TimeSeries(),
                'network_io': TimeSeries()
            },
            
            # Quality Metrics
            'quality': {
                'alert_actionability': [],
                'investigation_time': [],
                'threat_coverage': {},
                'detection_drift': TimeSeries()
            }
        }
```

### 2.2 Advanced Metrics

#### Detection Quality Metrics
```yaml
detection_quality_metrics:
  - threat_coverage_ratio:
      formula: "detected_threat_types / total_threat_types"
      interpretation: "Breadth of detection capability"
      
  - detection_consistency:
      formula: "std_dev(detection_rates) across time windows"
      interpretation: "Stability of detection performance"
      
  - alert_enrichment_score:
      formula: "avg(evidence_items + context_fields + recommendations)"
      interpretation: "Quality of alert information"
      
  - mean_time_to_detect:
      formula: "avg(detection_time - attack_start_time)"
      interpretation: "Speed of threat identification"
```

#### Operational Metrics
```yaml
operational_metrics:
  - alert_fatigue_index:
      formula: "false_positives / (true_positives + false_positives)"
      threshold: "< 0.3 for sustainable operations"
      
  - investigation_efficiency:
      formula: "true_positives / total_investigation_time"
      unit: "verified threats per hour"
      
  - automation_rate:
      formula: "automated_responses / total_alerts"
      target: "> 0.7 for known patterns"
      
  - detection_lag:
      formula: "percentile(detection_time - event_time, 95)"
      target: "< 1 second"
```

### 2.3 Metrics Collection Implementation
```python
class RealTimeMetricsCollector:
    def __init__(self, prometheus_gateway='localhost:9091'):
        self.gateway = prometheus_gateway
        self.registry = CollectorRegistry()
        
        # Define Prometheus metrics
        self.event_counter = Counter(
            'did_events_processed_total',
            'Total number of DID events processed',
            ['event_type', 'result'],
            registry=self.registry
        )
        
        self.detection_histogram = Histogram(
            'detection_latency_seconds',
            'Detection latency distribution',
            ['detector_type', 'threat_type'],
            buckets=[0.01, 0.05, 0.1, 0.5, 1.0, 5.0],
            registry=self.registry
        )
        
        self.alert_gauge = Gauge(
            'active_alerts_count',
            'Current number of active alerts',
            ['severity', 'threat_type'],
            registry=self.registry
        )
        
    def record_event_processing(self, event, result, latency):
        """Record metrics for processed event"""
        self.event_counter.labels(
            event_type=event['event_type'],
            result=result['status'] if result else 'normal'
        ).inc()
        
        if result and 'threat_type' in result:
            self.detection_histogram.labels(
                detector_type=result['detector'],
                threat_type=result['threat_type']
            ).observe(latency)
            
    def push_metrics(self):
        """Push metrics to Prometheus gateway"""
        push_to_gateway(
            self.gateway, 
            job='did_detection_poc',
            registry=self.registry
        )
```

## 3. Evaluation Scenarios

### 3.1 Scenario Design Framework
```yaml
scenario_framework:
  baseline_scenarios:
    - name: "Normal Operations"
      description: "Typical DID system usage patterns"
      parameters:
        users: 10000
        transaction_rate: "100-500 per second"
        error_rate: "< 1%"
        duration: "24 hours"
        
  attack_scenarios:
    - name: "Credential Stuffing Campaign"
      description: "Large-scale credential abuse"
      parameters:
        attackers: 50
        stolen_credentials: 1000
        target_services: 20
        attack_rate: "1000-5000 per minute"
        duration: "2 hours"
        patterns: ["rapid_fire", "distributed", "low_and_slow"]
        
    - name: "DID Method Hopping"
      description: "Identity obfuscation through method switching"
      parameters:
        attacker_identities: 10
        did_methods: ["ethr", "web", "key", "ion"]
        switching_frequency: "every 5-10 minutes"
        malicious_actions: ["data_exfiltration", "privilege_escalation"]
        
  stress_scenarios:
    - name: "Flash Crowd"
      description: "Legitimate traffic spike"
      parameters:
        peak_multiplier: 10
        ramp_up_time: "5 minutes"
        sustained_duration: "30 minutes"
        
    - name: "Mixed Attack"
      description: "Multiple simultaneous attack types"
      parameters:
        attack_types: ["credential_stuffing", "did_hopping", "replay_attack"]
        coordination: "synchronized"
        noise_level: "high"
```

### 3.2 Scenario Execution Engine
```python
class ScenarioExecutor:
    def __init__(self, detection_system, metrics_collector):
        self.detection_system = detection_system
        self.metrics = metrics_collector
        self.results = {}
        
    def execute_scenario(self, scenario_config):
        """Execute evaluation scenario"""
        scenario_name = scenario_config['name']
        print(f"Executing scenario: {scenario_name}")
        
        # Initialize scenario
        traffic_generator = self._setup_traffic_generator(scenario_config)
        ground_truth = GroundTruthManager()
        
        # Start monitoring
        monitor = ResourceMonitor()
        monitor.start()
        
        # Generate and process events
        start_time = time.time()
        event_count = 0
        
        for event in traffic_generator.generate():
            # Process event
            detection_start = time.time()
            result = self.detection_system.process(event)
            detection_latency = time.time() - detection_start
            
            # Record metrics
            self.metrics.record_event_processing(event, result, detection_latency)
            
            # Verify against ground truth
            is_attack = ground_truth.is_attack(event)
            self._update_confusion_matrix(result, is_attack)
            
            event_count += 1
            
            # Periodic metric push
            if event_count % 1000 == 0:
                self.metrics.push_metrics()
                
        # Finalize scenario
        duration = time.time() - start_time
        resource_stats = monitor.stop()
        
        # Calculate results
        self.results[scenario_name] = {
            'duration': duration,
            'events_processed': event_count,
            'throughput': event_count / duration,
            'detection_metrics': self._calculate_detection_metrics(),
            'resource_usage': resource_stats,
            'latency_profile': self._analyze_latency()
        }
        
        return self.results[scenario_name]
```

## 4. Performance Profiling

### 4.1 System Profiling
```python
class PerformanceProfiler:
    def __init__(self):
        self.profiles = {
            'cpu': CPUProfiler(),
            'memory': MemoryProfiler(),
            'io': IOProfiler(),
            'network': NetworkProfiler()
        }
        
    def profile_detection_pipeline(self, event_stream, duration_seconds):
        """Profile detection pipeline performance"""
        results = {
            'pipeline_stages': {},
            'bottlenecks': [],
            'optimization_opportunities': []
        }
        
        with self.profiling_context():
            # Profile each pipeline stage
            stages = [
                'event_ingestion',
                'normalization',
                'feature_extraction',
                'detection',
                'correlation',
                'alert_generation'
            ]
            
            for stage in stages:
                stage_metrics = self._profile_stage(stage, event_stream)
                results['pipeline_stages'][stage] = stage_metrics
                
                # Identify bottlenecks
                if stage_metrics['latency_p95'] > 50:  # ms
                    results['bottlenecks'].append({
                        'stage': stage,
                        'latency_p95': stage_metrics['latency_p95'],
                        'cpu_usage': stage_metrics['cpu_usage']
                    })
                    
        # Analyze results
        results['optimization_opportunities'] = self._identify_optimizations(results)
        
        return results
```

### 4.2 Scalability Testing
```python
class ScalabilityTester:
    def __init__(self, detection_system):
        self.detection_system = detection_system
        self.test_points = [100, 500, 1000, 5000, 10000]  # events/second
        
    def test_scalability(self):
        """Test system scalability at different load levels"""
        results = []
        
        for target_rate in self.test_points:
            print(f"Testing at {target_rate} events/second...")
            
            # Configure load generator
            generator = LoadGenerator(target_rate=target_rate)
            
            # Run test
            test_duration = 300  # 5 minutes
            metrics = self._run_load_test(generator, test_duration)
            
            # Record results
            results.append({
                'target_rate': target_rate,
                'achieved_rate': metrics['actual_throughput'],
                'latency_p50': metrics['latency_p50'],
                'latency_p95': metrics['latency_p95'],
                'latency_p99': metrics['latency_p99'],
                'cpu_usage': metrics['avg_cpu'],
                'memory_usage': metrics['avg_memory'],
                'dropped_events': metrics['dropped_events'],
                'detection_accuracy': metrics['detection_accuracy']
            })
            
            # Check if system is saturated
            if metrics['actual_throughput'] < target_rate * 0.95:
                print(f"System saturated at {metrics['actual_throughput']} events/second")
                break
                
        return self._analyze_scalability(results)
```

## 5. Comparative Analysis

### 5.1 Baseline Comparison
```python
class BaselineComparator:
    def __init__(self, baseline_results):
        self.baseline = baseline_results
        
    def compare_with_baseline(self, current_results):
        """Compare current results with baseline"""
        comparison = {
            'detection_metrics': {},
            'performance_metrics': {},
            'resource_metrics': {},
            'regression_analysis': {}
        }
        
        # Detection metric comparison
        for metric in ['precision', 'recall', 'f1_score']:
            baseline_val = self.baseline['detection_metrics'][metric]
            current_val = current_results['detection_metrics'][metric]
            
            comparison['detection_metrics'][metric] = {
                'baseline': baseline_val,
                'current': current_val,
                'delta': current_val - baseline_val,
                'regression': current_val < baseline_val * 0.95
            }
            
        # Performance comparison
        for metric in ['avg_latency', 'p95_latency', 'throughput']:
            self._compare_performance_metric(
                metric, 
                comparison['performance_metrics']
            )
            
        # Statistical significance test
        comparison['statistical_significance'] = self._test_significance(
            self.baseline, 
            current_results
        )
        
        return comparison
```

### 5.2 Multi-Algorithm Comparison
```python
class AlgorithmComparator:
    def compare_detection_algorithms(self, algorithms, test_dataset):
        """Compare multiple detection algorithms"""
        results = {}
        
        for algo_name, algorithm in algorithms.items():
            print(f"Testing {algo_name}...")
            
            # Initialize metrics
            metrics = {
                'confusion_matrix': np.zeros((2, 2)),
                'detection_times': [],
                'memory_usage': [],
                'detection_details': []
            }
            
            # Process test dataset
            for event, label in test_dataset:
                start_time = time.time()
                start_memory = self._get_memory_usage()
                
                # Detect
                detection = algorithm.detect(event)
                
                # Record metrics
                detection_time = time.time() - start_time
                memory_delta = self._get_memory_usage() - start_memory
                
                metrics['detection_times'].append(detection_time)
                metrics['memory_usage'].append(memory_delta)
                
                # Update confusion matrix
                predicted = 1 if detection else 0
                actual = 1 if label == 'attack' else 0
                metrics['confusion_matrix'][actual, predicted] += 1
                
                # Store detailed results
                metrics['detection_details'].append({
                    'event': event,
                    'label': label,
                    'detection': detection,
                    'time': detection_time
                })
                
            # Calculate performance metrics
            results[algo_name] = self._calculate_algorithm_metrics(metrics)
            
        # Generate comparison report
        return self._generate_comparison_report(results)
```

## 6. Reporting Framework

### 6.1 Report Generator
```python
class EvaluationReportGenerator:
    def __init__(self, template_path='templates/'):
        self.template_path = template_path
        self.report_sections = []
        
    def generate_comprehensive_report(self, evaluation_results):
        """Generate comprehensive evaluation report"""
        report = {
            'metadata': {
                'timestamp': datetime.now().isoformat(),
                'version': '1.0',
                'environment': self._get_environment_info()
            },
            'executive_summary': self._generate_executive_summary(evaluation_results),
            'detailed_results': {},
            'visualizations': {},
            'recommendations': []
        }
        
        # Add detailed sections
        sections = [
            ('detection_performance', self._analyze_detection_performance),
            ('system_performance', self._analyze_system_performance),
            ('threat_coverage', self._analyze_threat_coverage),
            ('operational_metrics', self._analyze_operational_metrics),
            ('resource_utilization', self._analyze_resource_utilization)
        ]
        
        for section_name, analyzer in sections:
            report['detailed_results'][section_name] = analyzer(evaluation_results)
            
        # Generate visualizations
        report['visualizations'] = self._generate_visualizations(evaluation_results)
        
        # Generate recommendations
        report['recommendations'] = self._generate_recommendations(report)
        
        # Save report
        self._save_report(report)
        
        return report
```

### 6.2 Visualization Suite
```python
class EvaluationVisualizer:
    def __init__(self, style='seaborn'):
        plt.style.use(style)
        self.figures = {}
        
    def create_evaluation_dashboard(self, results):
        """Create comprehensive evaluation dashboard"""
        fig = plt.figure(figsize=(20, 15))
        
        # Create subplots
        gs = fig.add_gridspec(4, 3, hspace=0.3, wspace=0.3)
        
        # 1. Detection Performance Over Time
        ax1 = fig.add_subplot(gs[0, :2])
        self._plot_detection_timeline(results, ax1)
        
        # 2. ROC Curves
        ax2 = fig.add_subplot(gs[0, 2])
        self._plot_roc_curves(results, ax2)
        
        # 3. Latency Distribution
        ax3 = fig.add_subplot(gs[1, 0])
        self._plot_latency_distribution(results, ax3)
        
        # 4. Throughput vs Accuracy
        ax4 = fig.add_subplot(gs[1, 1])
        self._plot_throughput_accuracy(results, ax4)
        
        # 5. Resource Usage
        ax5 = fig.add_subplot(gs[1, 2])
        self._plot_resource_usage(results, ax5)
        
        # 6. Threat Coverage Heatmap
        ax6 = fig.add_subplot(gs[2, :])
        self._plot_threat_coverage_heatmap(results, ax6)
        
        # 7. Alert Quality Metrics
        ax7 = fig.add_subplot(gs[3, 0])
        self._plot_alert_quality(results, ax7)
        
        # 8. Comparative Analysis
        ax8 = fig.add_subplot(gs[3, 1:])
        self._plot_comparative_analysis(results, ax8)
        
        plt.suptitle('DID Threat Detection Evaluation Dashboard', fontsize=16)
        
        return fig
```

### 6.3 Interactive Dashboard
```python
class InteractiveDashboard:
    def __init__(self, results_data):
        self.results = results_data
        self.app = dash.Dash(__name__)
        self._setup_layout()
        self._setup_callbacks()
        
    def _setup_layout(self):
        """Setup dashboard layout"""
        self.app.layout = html.Div([
            html.H1('DID Threat Detection Evaluation Dashboard'),
            
            # Scenario selector
            dcc.Dropdown(
                id='scenario-selector',
                options=[{'label': s, 'value': s} for s in self.results.keys()],
                value=list(self.results.keys())[0]
            ),
            
            # Metrics overview
            html.Div(id='metrics-overview', className='metrics-grid'),
            
            # Performance graphs
            dcc.Graph(id='detection-performance'),
            dcc.Graph(id='latency-analysis'),
            dcc.Graph(id='resource-usage'),
            
            # Detailed analysis
            html.Div(id='detailed-analysis'),
            
            # Export button
            html.Button('Export Report', id='export-button')
        ])
        
    def run(self, port=8050):
        """Run interactive dashboard"""
        self.app.run_server(debug=True, port=port)
```

## 7. Continuous Evaluation

### 7.1 Automated Testing Pipeline
```yaml
continuous_evaluation:
  schedule:
    - daily_baseline: "00:00 UTC"
    - weekly_comprehensive: "Sunday 02:00 UTC"
    - monthly_stress: "1st of month 03:00 UTC"
    
  automated_tests:
    - regression_tests:
        trigger: "on every model update"
        scenarios: ["baseline", "known_attacks"]
        pass_criteria: "no metric degradation > 5%"
        
    - performance_tests:
        trigger: "on every code change"
        metrics: ["latency", "throughput"]
        pass_criteria: "p95 latency < 100ms"
        
    - integration_tests:
        trigger: "on deployment"
        scenarios: ["end_to_end", "failover"]
        pass_criteria: "all critical paths functional"
```

### 7.2 A/B Testing Framework
```python
class ABTestingFramework:
    def __init__(self):
        self.experiments = {}
        
    def setup_experiment(self, name, control_config, variant_config):
        """Setup A/B test for detection algorithms"""
        self.experiments[name] = {
            'control': self._setup_detector(control_config),
            'variant': self._setup_detector(variant_config),
            'metrics': defaultdict(list),
            'start_time': datetime.now()
        }
        
    def process_with_ab_test(self, event, experiment_name):
        """Process event with A/B testing"""
        experiment = self.experiments[experiment_name]
        
        # Randomly assign to control or variant
        group = 'control' if random.random() < 0.5 else 'variant'
        detector = experiment[group]
        
        # Process and collect metrics
        start_time = time.time()
        result = detector.process(event)
        latency = time.time() - start_time
        
        # Record metrics
        experiment['metrics'][group].append({
            'timestamp': datetime.now(),
            'latency': latency,
            'detected': result is not None,
            'confidence': result.get('confidence', 0) if result else 0
        })
        
        return result
        
    def analyze_experiment(self, experiment_name, min_samples=10000):
        """Analyze A/B test results"""
        experiment = self.experiments[experiment_name]
        
        if len(experiment['metrics']['control']) < min_samples:
            return {'status': 'insufficient_data'}
            
        # Statistical analysis
        control_metrics = self._calculate_group_metrics(experiment['metrics']['control'])
        variant_metrics = self._calculate_group_metrics(experiment['metrics']['variant'])
        
        # Perform significance tests
        significance = self._test_statistical_significance(
            control_metrics, 
            variant_metrics
        )
        
        return {
            'control': control_metrics,
            'variant': variant_metrics,
            'significance': significance,
            'recommendation': self._generate_recommendation(significance)
        }
```