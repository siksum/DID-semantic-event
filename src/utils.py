#!/usr/bin/env python3
"""
DID 위협 탐지 시스템 - 유틸리티 함수
에러 처리, 로깅, 메모리 관리 등 공통 기능
"""

import logging
import traceback
import functools
import time
import psutil
import gc
from typing import Any, Callable, Dict, List, Optional, Tuple
import pandas as pd
import numpy as np
from contextlib import contextmanager

# 로깅 설정
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# 커스텀 예외 클래스들
class DetectionError(Exception):
    """탐지 관련 오류"""
    pass

class DataProcessingError(Exception):
    """데이터 처리 관련 오류"""
    pass

class ModelTrainingError(Exception):
    """모델 훈련 관련 오류"""
    pass

class ConfigurationError(Exception):
    """설정 관련 오류"""
    pass

class MemoryError(Exception):
    """메모리 관련 오류"""
    pass

def handle_errors(default_return: Any = None, log_error: bool = True):
    """에러 처리 데코레이터"""
    def decorator(func: Callable) -> Callable:
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            try:
                return func(*args, **kwargs)
            except Exception as e:
                if log_error:
                    logger.error(f"{func.__name__} 실행 중 오류 발생: {str(e)}")
                    logger.debug(f"상세 오류 정보:\n{traceback.format_exc()}")
                
                if default_return is not None:
                    return default_return
                else:
                    raise
        return wrapper
    return decorator

def retry_on_failure(max_retries: int = 3, delay: float = 1.0, backoff: float = 2.0):
    """재시도 데코레이터"""
    def decorator(func: Callable) -> Callable:
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            last_exception = None
            
            for attempt in range(max_retries + 1):
                try:
                    return func(*args, **kwargs)
                except Exception as e:
                    last_exception = e
                    if attempt < max_retries:
                        wait_time = delay * (backoff ** attempt)
                        logger.warning(f"{func.__name__} 실패 (시도 {attempt + 1}/{max_retries + 1}). {wait_time:.1f}초 후 재시도...")
                        time.sleep(wait_time)
                    else:
                        logger.error(f"{func.__name__} 최대 재시도 횟수 초과")
            
            raise last_exception
        return wrapper
    return decorator

def log_execution_time(func: Callable) -> Callable:
    """실행 시간 로깅 데코레이터"""
    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        start_time = time.time()
        try:
            result = func(*args, **kwargs)
            execution_time = time.time() - start_time
            logger.info(f"{func.__name__} 실행 완료: {execution_time:.2f}초")
            return result
        except Exception as e:
            execution_time = time.time() - start_time
            logger.error(f"{func.__name__} 실행 실패 ({execution_time:.2f}초): {str(e)}")
            raise
    return wrapper

@contextmanager
def memory_monitor(threshold_mb: float = 1000.0):
    """메모리 사용량 모니터링 컨텍스트 매니저"""
    process = psutil.Process()
    initial_memory = process.memory_info().rss / 1024 / 1024  # MB
    
    try:
        yield
    finally:
        final_memory = process.memory_info().rss / 1024 / 1024  # MB
        memory_used = final_memory - initial_memory
        
        if memory_used > threshold_mb:
            logger.warning(f"높은 메모리 사용량: {memory_used:.1f}MB (임계값: {threshold_mb}MB)")
        
        # 메모리 정리
        gc.collect()

def safe_divide(numerator: float, denominator: float, default: float = 0.0) -> float:
    """안전한 나눗셈"""
    try:
        if denominator == 0:
            return default
        return numerator / denominator
    except (TypeError, ValueError):
        return default

def validate_dataframe(df: pd.DataFrame, required_columns: List[str]) -> bool:
    """DataFrame 유효성 검사"""
    try:
        if df is None or df.empty:
            raise DataProcessingError("DataFrame이 비어있습니다.")
        
        missing_columns = set(required_columns) - set(df.columns)
        if missing_columns:
            raise DataProcessingError(f"필수 컬럼이 누락되었습니다: {missing_columns}")
        
        return True
    except Exception as e:
        logger.error(f"DataFrame 유효성 검사 실패: {str(e)}")
        return False

def clean_dataframe(df: pd.DataFrame) -> pd.DataFrame:
    """DataFrame 정리"""
    try:
        # 중복 제거
        original_len = len(df)
        df = df.drop_duplicates()
        if len(df) < original_len:
            logger.info(f"중복 행 {original_len - len(df)}개 제거")
        
        # NULL 값 처리
        null_counts = df.isnull().sum()
        if null_counts.sum() > 0:
            logger.warning(f"NULL 값 발견: {null_counts.to_dict()}")
            # 숫자형 컬럼은 0으로, 범주형 컬럼은 'unknown'으로 채움
            for col in df.columns:
                if df[col].dtype in ['int64', 'float64']:
                    df[col] = df[col].fillna(0)
                else:
                    df[col] = df[col].fillna('unknown')
        
        return df
    except Exception as e:
        logger.error(f"DataFrame 정리 중 오류: {str(e)}")
        raise DataProcessingError(f"DataFrame 정리 실패: {str(e)}")

def chunk_dataframe(df: pd.DataFrame, chunk_size: int = 1000) -> List[pd.DataFrame]:
    """DataFrame을 청크로 분할"""
    try:
        chunks = []
        for i in range(0, len(df), chunk_size):
            chunk = df.iloc[i:i + chunk_size].copy()
            chunks.append(chunk)
        
        logger.info(f"DataFrame을 {len(chunks)}개 청크로 분할 (청크 크기: {chunk_size})")
        return chunks
    except Exception as e:
        logger.error(f"DataFrame 청크 분할 중 오류: {str(e)}")
        raise DataProcessingError(f"청크 분할 실패: {str(e)}")

def calculate_memory_usage(obj: Any) -> float:
    """객체의 메모리 사용량 계산 (MB)"""
    try:
        import sys
        size_bytes = sys.getsizeof(obj)
        
        # pandas DataFrame의 경우 더 정확한 계산
        if isinstance(obj, pd.DataFrame):
            size_bytes = obj.memory_usage(deep=True).sum()
        
        return size_bytes / 1024 / 1024  # MB
    except Exception:
        return 0.0

def optimize_memory_usage(df: pd.DataFrame) -> pd.DataFrame:
    """DataFrame 메모리 사용량 최적화"""
    try:
        original_memory = calculate_memory_usage(df)
        
        # 숫자형 컬럼 최적화
        for col in df.select_dtypes(include=['int64']).columns:
            if df[col].min() >= 0:
                if df[col].max() < 255:
                    df[col] = df[col].astype('uint8')
                elif df[col].max() < 65535:
                    df[col] = df[col].astype('uint16')
                elif df[col].max() < 4294967295:
                    df[col] = df[col].astype('uint32')
            else:
                if df[col].min() > -128 and df[col].max() < 127:
                    df[col] = df[col].astype('int8')
                elif df[col].min() > -32768 and df[col].max() < 32767:
                    df[col] = df[col].astype('int16')
                elif df[col].min() > -2147483648 and df[col].max() < 2147483647:
                    df[col] = df[col].astype('int32')
        
        # 실수형 컬럼 최적화
        for col in df.select_dtypes(include=['float64']).columns:
            df[col] = pd.to_numeric(df[col], downcast='float')
        
        # 범주형 컬럼 최적화
        for col in df.select_dtypes(include=['object']).columns:
            if df[col].nunique() / len(df) < 0.5:  # 50% 미만의 고유값
                df[col] = df[col].astype('category')
        
        optimized_memory = calculate_memory_usage(df)
        reduction = (original_memory - optimized_memory) / original_memory * 100
        
        logger.info(f"메모리 사용량 최적화: {original_memory:.1f}MB → {optimized_memory:.1f}MB ({reduction:.1f}% 감소)")
        
        return df
    except Exception as e:
        logger.error(f"메모리 최적화 중 오류: {str(e)}")
        return df

def safe_json_loads(json_str: str, default: Any = None) -> Any:
    """안전한 JSON 로드"""
    try:
        import json
        return json.loads(json_str)
    except (json.JSONDecodeError, TypeError, ValueError):
        return default

def safe_json_dumps(obj: Any, default: str = "{}") -> str:
    """안전한 JSON 덤프"""
    try:
        import json
        return json.dumps(obj, ensure_ascii=False, indent=2)
    except (TypeError, ValueError):
        return default

def create_directory(path: str) -> bool:
    """디렉토리 생성"""
    try:
        import os
        os.makedirs(path, exist_ok=True)
        return True
    except Exception as e:
        logger.error(f"디렉토리 생성 실패 ({path}): {str(e)}")
        return False

def get_system_info() -> Dict[str, Any]:
    """시스템 정보 조회"""
    try:
        return {
            'cpu_count': psutil.cpu_count(),
            'memory_total_gb': psutil.virtual_memory().total / 1024 / 1024 / 1024,
            'memory_available_gb': psutil.virtual_memory().available / 1024 / 1024 / 1024,
            'memory_usage_percent': psutil.virtual_memory().percent,
            'disk_usage_percent': psutil.disk_usage('/').percent
        }
    except Exception as e:
        logger.error(f"시스템 정보 조회 실패: {str(e)}")
        return {}

def log_system_status():
    """시스템 상태 로깅"""
    info = get_system_info()
    if info:
        logger.info(f"시스템 상태 - CPU: {info['cpu_count']}코어, "
                   f"메모리: {info['memory_usage_percent']:.1f}% 사용, "
                   f"디스크: {info['disk_usage_percent']:.1f}% 사용")

class PerformanceMonitor:
    """성능 모니터링 클래스"""
    
    def __init__(self):
        self.metrics = {}
        self.start_times = {}
    
    def start_timer(self, name: str):
        """타이머 시작"""
        self.start_times[name] = time.time()
    
    def end_timer(self, name: str) -> float:
        """타이머 종료 및 실행 시간 반환"""
        if name in self.start_times:
            execution_time = time.time() - self.start_times[name]
            self.metrics[name] = execution_time
            logger.info(f"{name} 실행 시간: {execution_time:.2f}초")
            return execution_time
        return 0.0
    
    def get_metrics(self) -> Dict[str, float]:
        """성능 지표 반환"""
        return self.metrics.copy()
    
    def reset(self):
        """지표 초기화"""
        self.metrics.clear()
        self.start_times.clear()

# 전역 성능 모니터
performance_monitor = PerformanceMonitor()

def monitor_performance(name: str):
    """성능 모니터링 데코레이터"""
    def decorator(func: Callable) -> Callable:
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            performance_monitor.start_timer(name)
            try:
                result = func(*args, **kwargs)
                return result
            finally:
                performance_monitor.end_timer(name)
        return wrapper
    return decorator