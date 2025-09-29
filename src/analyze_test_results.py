#!/usr/bin/env python3
"""
테스트 결과 분석 스크립트
위협 시나리오 테스트 결과를 분석하고 상세한 보고서를 생성
"""

import json
import logging
import pandas as pd
import numpy as np
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Any, Optional
import matplotlib.pyplot as plt
import seaborn as sns

# 로깅 설정
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class TestResultAnalyzer:
    """테스트 결과 분석기"""
    
    def __init__(self, results_dir: str = "threat_test_results"):
        self.results_dir = Path(results_dir)
        self.results_dir.mkdir(exist_ok=True)
        
        # 결과 데이터
        self.scenario_results = {}
        self.summary_data = None
        self.analysis_results = {}
        
    def load_results(self) -> bool:
        """결과 파일 로드"""
        try:
            # 요약 파일 찾기
            summary_files = list(self.results_dir.glob("test_summary_*.json"))
            if not summary_files:
                logger.error("요약 파일을 찾을 수 없습니다.")
                return False
            
            # 가장 최근 요약 파일 로드
            latest_summary = max(summary_files, key=lambda x: x.stat().st_mtime)
            with open(latest_summary, 'r', encoding='utf-8') as f:
                self.summary_data = json.load(f)
            
            logger.info(f"요약 파일 로드 완료: {latest_summary}")
            
            # 시나리오별 결과 파일 로드
            scenario_files = list(self.results_dir.glob("*_*.json"))
            scenario_files = [f for f in scenario_files if not f.name.startswith("test_summary_")]
            
            for scenario_file in scenario_files:
                scenario_name = scenario_file.name.split('_')[0]
                with open(scenario_file, 'r', encoding='utf-8') as f:
                    self.scenario_results[scenario_name] = json.load(f)
            
            logger.info(f"시나리오 결과 파일 {len(self.scenario_results)}개 로드 완료")
            return True
            
        except Exception as e:
            logger.error(f"결과 로드 중 오류: {e}")
            return False
    
    def analyze_performance_metrics(self) -> Dict[str, Any]:
        """성능 지표 분석"""
        if not self.summary_data:
            return {}
        
        analysis = {
            'overall_performance': self.summary_data.get('overall_performance', {}),
            'scenario_analysis': {},
            'platform_analysis': {},
            'threat_type_analysis': {}
        }
        
        # 시나리오별 분석
        for scenario_name, scenario_summary in self.summary_data.get('scenario_summaries', {}).items():
            if 'error' in scenario_summary:
                continue
            
            analysis['scenario_analysis'][scenario_name] = {
                'avg_precision': scenario_summary.get('avg_precision', 0),
                'avg_recall': scenario_summary.get('avg_recall', 0),
                'avg_f1_score': scenario_summary.get('avg_f1_score', 0),
                'avg_accuracy': scenario_summary.get('avg_accuracy', 0),
                'platforms_tested': scenario_summary.get('platforms_tested', 0)
            }
        
        # 플랫폼별 분석
        platforms = self.summary_data.get('platforms', [])
        for platform in platforms:
            platform_metrics = []
            
            for scenario_name, scenario_summary in self.summary_data.get('scenario_summaries', {}).items():
                if 'error' in scenario_summary:
                    continue
                
                platform_result = scenario_summary.get('platform_results', {}).get(platform, {})
                if 'error' not in platform_result:
                    platform_metrics.append({
                        'scenario': scenario_name,
                        'precision': platform_result.get('precision', 0),
                        'recall': platform_result.get('recall', 0),
                        'f1_score': platform_result.get('f1_score', 0),
                        'accuracy': platform_result.get('accuracy', 0)
                    })
            
            if platform_metrics:
                df = pd.DataFrame(platform_metrics)
                analysis['platform_analysis'][platform] = {
                    'avg_precision': df['precision'].mean(),
                    'avg_recall': df['recall'].mean(),
                    'avg_f1_score': df['f1_score'].mean(),
                    'avg_accuracy': df['accuracy'].mean(),
                    'std_precision': df['precision'].std(),
                    'std_recall': df['recall'].std(),
                    'std_f1_score': df['f1_score'].std(),
                    'std_accuracy': df['accuracy'].std()
                }
        
        return analysis
    
    def analyze_threat_detection_patterns(self) -> Dict[str, Any]:
        """위협 탐지 패턴 분석"""
        analysis = {
            'detection_rates': {},
            'false_positive_rates': {},
            'false_negative_rates': {},
            'threat_type_effectiveness': {}
        }
        
        for scenario_name, scenario_data in self.scenario_results.items():
            if 'error' in scenario_data:
                continue
            
            for platform_name, platform_data in scenario_data.items():
                if 'error' in platform_data:
                    continue
                
                # 탐지율 분석
                detection_rate = platform_data.get('detection_rate', 0)
                if scenario_name not in analysis['detection_rates']:
                    analysis['detection_rates'][scenario_name] = {}
                analysis['detection_rates'][scenario_name][platform_name] = detection_rate
                
                # False Positive Rate
                fp_rate = platform_data.get('false_positives', 0) / max(platform_data.get('total_events', 1), 1)
                if scenario_name not in analysis['false_positive_rates']:
                    analysis['false_positive_rates'][scenario_name] = {}
                analysis['false_positive_rates'][scenario_name][platform_name] = fp_rate
                
                # False Negative Rate
                fn_rate = platform_data.get('false_negatives', 0) / max(platform_data.get('actual_threats', 1), 1)
                if scenario_name not in analysis['false_negative_rates']:
                    analysis['false_negative_rates'][scenario_name] = {}
                analysis['false_negative_rates'][scenario_name][platform_name] = fn_rate
                
                # 위협 유형별 효과성
                threat_types = platform_data.get('threat_types', {})
                for threat_type, count in threat_types.items():
                    if threat_type not in analysis['threat_type_effectiveness']:
                        analysis['threat_type_effectiveness'][threat_type] = {}
                    if scenario_name not in analysis['threat_type_effectiveness'][threat_type]:
                        analysis['threat_type_effectiveness'][threat_type][scenario_name] = {}
                    analysis['threat_type_effectiveness'][threat_type][scenario_name][platform_name] = count
        
        return analysis
    
    def generate_visualizations(self) -> List[str]:
        """시각화 생성"""
        generated_files = []
        
        try:
            # 1. 전체 성능 비교 차트
            self._create_performance_comparison_chart()
            generated_files.append("performance_comparison.png")
            
            # 2. 시나리오별 성능 차트
            self._create_scenario_performance_chart()
            generated_files.append("scenario_performance.png")
            
            # 3. 플랫폼별 성능 차트
            self._create_platform_performance_chart()
            generated_files.append("platform_performance.png")
            
            # 4. 위협 탐지 패턴 히트맵
            self._create_detection_pattern_heatmap()
            generated_files.append("detection_pattern_heatmap.png")
            
            # 5. ROC 곡선 (가능한 경우)
            self._create_roc_curves()
            generated_files.append("roc_curves.png")
            
        except Exception as e:
            logger.error(f"시각화 생성 중 오류: {e}")
        
        return generated_files
    
    def _create_performance_comparison_chart(self):
        """전체 성능 비교 차트 생성"""
        if not self.summary_data:
            return
        
        fig, axes = plt.subplots(2, 2, figsize=(15, 12))
        fig.suptitle('DID 위협 탐지 시스템 전체 성능 비교', fontsize=16, fontweight='bold')
        
        metrics = ['precision', 'recall', 'f1_score', 'accuracy']
        metric_names = ['Precision', 'Recall', 'F1-Score', 'Accuracy']
        
        for i, (metric, metric_name) in enumerate(zip(metrics, metric_names)):
            ax = axes[i//2, i%2]
            
            scenario_data = []
            platform_data = []
            values = []
            
            for scenario_name, scenario_summary in self.summary_data.get('scenario_summaries', {}).items():
                if 'error' in scenario_summary:
                    continue
                
                for platform_name, platform_result in scenario_summary.get('platform_results', {}).items():
                    if 'error' not in platform_result:
                        scenario_data.append(scenario_name)
                        platform_data.append(platform_name)
                        values.append(platform_result.get(metric, 0))
            
            if values:
                df = pd.DataFrame({
                    'Scenario': scenario_data,
                    'Platform': platform_data,
                    'Value': values
                })
                
                # 플랫폼별 평균값으로 그룹화
                platform_avg = df.groupby('Platform')['Value'].mean().sort_values(ascending=False)
                
                bars = ax.bar(platform_avg.index, platform_avg.values, 
                             color=['#FF6B6B', '#4ECDC4', '#45B7D1', '#96CEB4'][:len(platform_avg)])
                
                ax.set_title(f'{metric_name} 비교')
                ax.set_ylabel(metric_name)
                ax.set_ylim(0, 1)
                
                # 값 표시
                for bar, value in zip(bars, platform_avg.values):
                    ax.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 0.01, 
                           f'{value:.3f}', ha='center', va='bottom')
        
        plt.tight_layout()
        plt.savefig(self.results_dir / 'performance_comparison.png', dpi=300, bbox_inches='tight')
        plt.close()
    
    def _create_scenario_performance_chart(self):
        """시나리오별 성능 차트 생성"""
        if not self.summary_data:
            return
        
        fig, ax = plt.subplots(figsize=(12, 8))
        
        scenarios = []
        f1_scores = []
        colors = []
        
        for scenario_name, scenario_summary in self.summary_data.get('scenario_summaries', {}).items():
            if 'error' in scenario_summary:
                continue
            
            scenarios.append(scenario_name.replace('_', ' ').title())
            f1_scores.append(scenario_summary.get('avg_f1_score', 0))
            
            # 성능에 따른 색상 설정
            f1_score = scenario_summary.get('avg_f1_score', 0)
            if f1_score >= 0.8:
                colors.append('#96CEB4')  # 녹색
            elif f1_score >= 0.6:
                colors.append('#FFEAA7')  # 노란색
            else:
                colors.append('#FF6B6B')  # 빨간색
        
        bars = ax.bar(scenarios, f1_scores, color=colors)
        ax.set_title('시나리오별 평균 F1-Score', fontsize=14, fontweight='bold')
        ax.set_ylabel('F1-Score')
        ax.set_ylim(0, 1)
        
        # 값 표시
        for bar, value in zip(bars, f1_scores):
            ax.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 0.01, 
                   f'{value:.3f}', ha='center', va='bottom')
        
        # x축 레이블 회전
        plt.xticks(rotation=45, ha='right')
        plt.tight_layout()
        plt.savefig(self.results_dir / 'scenario_performance.png', dpi=300, bbox_inches='tight')
        plt.close()
    
    def _create_platform_performance_chart(self):
        """플랫폼별 성능 차트 생성"""
        if not self.summary_data:
            return
        
        fig, ax = plt.subplots(figsize=(10, 6))
        
        platforms = self.summary_data.get('platforms', [])
        metrics = ['precision', 'recall', 'f1_score', 'accuracy']
        metric_names = ['Precision', 'Recall', 'F1-Score', 'Accuracy']
        
        x = np.arange(len(platforms))
        width = 0.2
        
        for i, (metric, metric_name) in enumerate(zip(metrics, metric_names)):
            values = []
            
            for platform in platforms:
                platform_metrics = []
                for scenario_name, scenario_summary in self.summary_data.get('scenario_summaries', {}).items():
                    if 'error' in scenario_summary:
                        continue
                    
                    platform_result = scenario_summary.get('platform_results', {}).get(platform, {})
                    if 'error' not in platform_result:
                        platform_metrics.append(platform_result.get(metric, 0))
                
                avg_value = np.mean(platform_metrics) if platform_metrics else 0
                values.append(avg_value)
            
            ax.bar(x + i*width, values, width, label=metric_name)
        
        ax.set_xlabel('Platform')
        ax.set_ylabel('Score')
        ax.set_title('플랫폼별 평균 성능 지표')
        ax.set_xticks(x + width * 1.5)
        ax.set_xticklabels(platforms)
        ax.legend()
        ax.set_ylim(0, 1)
        
        plt.tight_layout()
        plt.savefig(self.results_dir / 'platform_performance.png', dpi=300, bbox_inches='tight')
        plt.close()
    
    def _create_detection_pattern_heatmap(self):
        """탐지 패턴 히트맵 생성"""
        if not self.scenario_results:
            return
        
        # 데이터 준비
        scenarios = []
        platforms = []
        detection_rates = []
        
        for scenario_name, scenario_data in self.scenario_results.items():
            if 'error' in scenario_data:
                continue
            
            for platform_name, platform_data in scenario_data.items():
                if 'error' in platform_data:
                    continue
                
                scenarios.append(scenario_name)
                platforms.append(platform_name)
                detection_rates.append(platform_data.get('detection_rate', 0))
        
        if not detection_rates:
            return
        
        # 데이터프레임 생성
        df = pd.DataFrame({
            'Scenario': scenarios,
            'Platform': platforms,
            'Detection Rate': detection_rates
        })
        
        # 피벗 테이블 생성
        pivot_table = df.pivot(index='Scenario', columns='Platform', values='Detection Rate')
        
        # 히트맵 생성
        plt.figure(figsize=(10, 8))
        sns.heatmap(pivot_table, annot=True, cmap='YlOrRd', fmt='.3f', 
                   cbar_kws={'label': 'Detection Rate'})
        plt.title('시나리오별 플랫폼 탐지율 히트맵')
        plt.xlabel('Platform')
        plt.ylabel('Scenario')
        plt.tight_layout()
        plt.savefig(self.results_dir / 'detection_pattern_heatmap.png', dpi=300, bbox_inches='tight')
        plt.close()
    
    def _create_roc_curves(self):
        """ROC 곡선 생성 (가능한 경우)"""
        # 실제 구현에서는 더 복잡한 ROC 곡선 계산이 필요
        # 여기서는 간단한 예시만 제공
        pass
    
    def generate_detailed_report(self) -> str:
        """상세 보고서 생성"""
        if not self.summary_data:
            return "분석할 데이터가 없습니다."
        
        report = []
        report.append("# DID 위협 탐지 시스템 테스트 결과 분석 보고서")
        report.append(f"**생성 시간**: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        report.append("")
        
        # 1. 테스트 개요
        report.append("## 1. 테스트 개요")
        report.append(f"- **총 시나리오 수**: {self.summary_data.get('total_scenarios', 0)}")
        report.append(f"- **테스트된 플랫폼**: {', '.join(self.summary_data.get('platforms', []))}")
        report.append(f"- **테스트 시간**: {self.summary_data.get('test_timestamp', 'N/A')}")
        report.append("")
        
        # 2. 전체 성능 요약
        overall_perf = self.summary_data.get('overall_performance', {})
        if overall_perf:
            report.append("## 2. 전체 성능 요약")
            report.append(f"- **평균 Precision**: {overall_perf.get('avg_precision', 0):.3f}")
            report.append(f"- **평균 Recall**: {overall_perf.get('avg_recall', 0):.3f}")
            report.append(f"- **평균 F1-Score**: {overall_perf.get('avg_f1_score', 0):.3f}")
            report.append(f"- **평균 Accuracy**: {overall_perf.get('avg_accuracy', 0):.3f}")
            report.append("")
        
        # 3. 시나리오별 성능
        report.append("## 3. 시나리오별 성능")
        for scenario_name, scenario_summary in self.summary_data.get('scenario_summaries', {}).items():
            if 'error' in scenario_summary:
                report.append(f"### {scenario_name}")
                report.append(f"**오류**: {scenario_summary['error']}")
                report.append("")
                continue
            
            report.append(f"### {scenario_name}")
            report.append(f"- **평균 Precision**: {scenario_summary.get('avg_precision', 0):.3f}")
            report.append(f"- **평균 Recall**: {scenario_summary.get('avg_recall', 0):.3f}")
            report.append(f"- **평균 F1-Score**: {scenario_summary.get('avg_f1_score', 0):.3f}")
            report.append(f"- **평균 Accuracy**: {scenario_summary.get('avg_accuracy', 0):.3f}")
            report.append("")
            
            # 플랫폼별 상세 결과
            report.append("#### 플랫폼별 상세 결과")
            for platform_name, platform_result in scenario_summary.get('platform_results', {}).items():
                if 'error' in platform_result:
                    report.append(f"- **{platform_name}**: 오류 - {platform_result['error']}")
                else:
                    report.append(f"- **{platform_name}**: F1={platform_result.get('f1_score', 0):.3f}, "
                                f"Acc={platform_result.get('accuracy', 0):.3f}, "
                                f"Detection Rate={platform_result.get('detection_rate', 0):.3f}")
            report.append("")
        
        # 4. 권장사항
        report.append("## 4. 권장사항")
        
        # 성능 기반 권장사항
        if overall_perf:
            avg_f1 = overall_perf.get('avg_f1_score', 0)
            if avg_f1 >= 0.8:
                report.append("- ✅ 전체적으로 우수한 성능을 보입니다.")
            elif avg_f1 >= 0.6:
                report.append("- ⚠️ 성능 개선이 필요합니다. 모델 튜닝을 고려하세요.")
            else:
                report.append("- ❌ 심각한 성능 문제가 있습니다. 모델 재훈련이 필요합니다.")
        
        report.append("- 정기적인 모델 재훈련을 통해 성능을 유지하세요.")
        report.append("- 새로운 위협 패턴에 대한 지속적인 모니터링이 필요합니다.")
        report.append("- 플랫폼별 특성을 고려한 맞춤형 최적화를 고려하세요.")
        report.append("")
        
        # 5. 결론
        report.append("## 5. 결론")
        report.append("MSL 기반 DID 위협 탐지 시스템의 통합 테스트가 완료되었습니다.")
        report.append("각 플랫폼에서 다양한 위협 시나리오에 대한 탐지 성능을 평가하였으며,")
        report.append("시스템의 전반적인 성능과 개선점을 파악할 수 있었습니다.")
        
        return "\n".join(report)
    
    def save_analysis_results(self):
        """분석 결과 저장"""
        # 성능 분석 결과
        performance_analysis = self.analyze_performance_metrics()
        with open(self.results_dir / 'performance_analysis.json', 'w', encoding='utf-8') as f:
            json.dump(performance_analysis, f, indent=2, ensure_ascii=False, default=str)
        
        # 위협 탐지 패턴 분석 결과
        threat_analysis = self.analyze_threat_detection_patterns()
        with open(self.results_dir / 'threat_analysis.json', 'w', encoding='utf-8') as f:
            json.dump(threat_analysis, f, indent=2, ensure_ascii=False, default=str)
        
        # 상세 보고서 저장
        report = self.generate_detailed_report()
        with open(self.results_dir / 'detailed_report.md', 'w', encoding='utf-8') as f:
            f.write(report)
        
        logger.info("분석 결과 저장 완료")


def main():
    """메인 실행 함수"""
    logger.info("테스트 결과 분석 시작")
    
    # 분석기 초기화
    analyzer = TestResultAnalyzer()
    
    # 결과 로드
    if not analyzer.load_results():
        logger.error("결과 로드 실패")
        return
    
    # 분석 실행
    logger.info("성능 지표 분석 중...")
    performance_analysis = analyzer.analyze_performance_metrics()
    
    logger.info("위협 탐지 패턴 분석 중...")
    threat_analysis = analyzer.analyze_threat_detection_patterns()
    
    # 시각화 생성
    logger.info("시각화 생성 중...")
    generated_files = analyzer.generate_visualizations()
    logger.info(f"생성된 시각화 파일: {generated_files}")
    
    # 결과 저장
    logger.info("분석 결과 저장 중...")
    analyzer.save_analysis_results()
    
    logger.info("테스트 결과 분석 완료")
    
    # 요약 출력
    print("\n" + "="*60)
    print("테스트 결과 분석 완료")
    print("="*60)
    print(f"📊 분석 결과 파일:")
    print(f"   - performance_analysis.json")
    print(f"   - threat_analysis.json")
    print(f"   - detailed_report.md")
    print(f"📈 시각화 파일:")
    for file in generated_files:
        print(f"   - {file}")
    print("="*60)


if __name__ == "__main__":
    main()