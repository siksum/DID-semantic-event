#!/usr/bin/env python3
"""
DID-Graph Neural Network (DID-GNN) 구현
새로운 이론적 기여: DID 네트워크의 그래프 구조를 활용한 위협 탐지
"""

import torch
import torch.nn as nn
import torch.nn.functional as F
from torch_geometric.nn import GCNConv, GraphSAGE, TransformerConv
from torch_geometric.data import Data, DataLoader
import numpy as np
import pandas as pd
from typing import Dict, List, Tuple, Optional
import networkx as nx
from sklearn.metrics import roc_auc_score, f1_score
import logging

logger = logging.getLogger(__name__)

class DIDGraphNeuralNetwork(nn.Module):
    """
    DID-GNN: DID 네트워크의 그래프 구조를 학습하는 GNN 모델
    
    이론적 기여:
    1. DID 발급자-홀더-검증자 삼각 관계 모델링
    2. 신뢰 전파 알고리즘을 통한 이상 노드 탐지
    3. 시간적 그래프 진화 패턴 학습
    """
    
    def __init__(self, 
                 num_did_entities: int,
                 embedding_dim: int = 128,
                 num_gnn_layers: int = 3,
                 num_attention_heads: int = 8,
                 dropout: float = 0.1):
        super(DIDGraphNeuralNetwork, self).__init__()
        
        self.embedding_dim = embedding_dim
        self.num_gnn_layers = num_gnn_layers
        
        # DID 엔티티 임베딩 (발급자, 홀더, 검증자)
        self.did_embeddings = nn.Embedding(num_did_entities, embedding_dim)
        
        # Multi-layer GNN with different architectures
        self.gnn_layers = nn.ModuleList()
        for i in range(num_gnn_layers):
            if i == 0:
                # First layer: Graph Transformer for global attention
                self.gnn_layers.append(
                    TransformerConv(embedding_dim, embedding_dim // num_attention_heads, 
                                  heads=num_attention_heads, dropout=dropout)
                )
            elif i == num_gnn_layers - 1:
                # Last layer: GraphSAGE for final aggregation
                self.gnn_layers.append(
                    GraphSAGE(embedding_dim, embedding_dim, num_layers=1)
                )
            else:
                # Middle layers: GCN for local neighborhood aggregation
                self.gnn_layers.append(
                    GCNConv(embedding_dim, embedding_dim)
                )
        
        # Trust propagation layer
        self.trust_propagation = TrustPropagationLayer(embedding_dim)
        
        # Anomaly detection head
        self.anomaly_detector = nn.Sequential(
            nn.Linear(embedding_dim, embedding_dim // 2),
            nn.ReLU(),
            nn.Dropout(dropout),
            nn.Linear(embedding_dim // 2, 1),
            nn.Sigmoid()
        )
        
        # Temporal pattern encoder
        self.temporal_encoder = TemporalPatternEncoder(embedding_dim)
        
    def forward(self, x, edge_index, edge_attr=None, timestamps=None):
        """
        Forward pass through DID-GNN
        
        Args:
            x: Node features [num_nodes, feature_dim]
            edge_index: Graph connectivity [2, num_edges]
            edge_attr: Edge features [num_edges, edge_feature_dim]
            timestamps: Temporal information [num_nodes] or [num_edges]
        """
        # Initial DID entity embeddings
        node_embeddings = self.did_embeddings(x.long())
        
        # Multi-layer GNN processing
        for i, gnn_layer in enumerate(self.gnn_layers):
            if isinstance(gnn_layer, TransformerConv):
                node_embeddings = gnn_layer(node_embeddings, edge_index)
            elif isinstance(gnn_layer, GraphSAGE):
                node_embeddings = gnn_layer(node_embeddings, edge_index)
            else:  # GCNConv
                node_embeddings = gnn_layer(node_embeddings, edge_index)
            
            # Apply activation and dropout (except last layer)
            if i < len(self.gnn_layers) - 1:
                node_embeddings = F.relu(node_embeddings)
                node_embeddings = F.dropout(node_embeddings, training=self.training)
        
        # Trust propagation
        trust_scores = self.trust_propagation(node_embeddings, edge_index, edge_attr)
        
        # Temporal pattern encoding
        if timestamps is not None:
            temporal_features = self.temporal_encoder(node_embeddings, timestamps)
            node_embeddings = node_embeddings + temporal_features
        
        # Anomaly detection
        anomaly_scores = self.anomaly_detector(node_embeddings)
        
        return {
            'node_embeddings': node_embeddings,
            'trust_scores': trust_scores,
            'anomaly_scores': anomaly_scores
        }

class TrustPropagationLayer(nn.Module):
    """
    신뢰 전파 알고리즘 구현
    
    수학적 모델: T(t+1) = αAT(t) + (1-α)T(0) + β×Anomaly_Signal(t)
    - A: DID 관계 인접 행렬 (가중치 적용)
    - α: 신뢰 전파 감쇠 계수
    - β: 이상 신호 가중치
    """
    
    def __init__(self, embedding_dim: int, alpha: float = 0.85, beta: float = 0.1):
        super(TrustPropagationLayer, self).__init__()
        self.alpha = alpha
        self.beta = beta
        
        # Trust score prediction network
        self.trust_predictor = nn.Sequential(
            nn.Linear(embedding_dim * 2, embedding_dim),
            nn.ReLU(),
            nn.Linear(embedding_dim, 1),
            nn.Sigmoid()
        )
        
        # Edge weight predictor for adaptive trust propagation
        self.edge_weight_predictor = nn.Sequential(
            nn.Linear(embedding_dim * 2, 1),
            nn.Softplus()  # Ensure positive weights
        )
    
    def forward(self, node_embeddings, edge_index, edge_attr=None):
        """신뢰 전파 실행"""
        num_nodes = node_embeddings.size(0)
        device = node_embeddings.device
        
        # Calculate edge weights based on node similarity
        row, col = edge_index
        edge_embeddings = torch.cat([
            node_embeddings[row], 
            node_embeddings[col]
        ], dim=1)
        
        edge_weights = self.edge_weight_predictor(edge_embeddings).squeeze()
        
        # Initial trust scores (can be learned or predefined)
        initial_trust = torch.ones(num_nodes, 1, device=device) * 0.5
        
        # Iterative trust propagation
        current_trust = initial_trust
        for iteration in range(5):  # Fixed number of iterations
            # Create weighted adjacency matrix
            adjacency_matrix = self._create_weighted_adjacency(
                edge_index, edge_weights, num_nodes, device
            )
            
            # Trust propagation: T(t+1) = αAT(t) + (1-α)T(0)
            new_trust = (self.alpha * torch.mm(adjacency_matrix, current_trust) + 
                        (1 - self.alpha) * initial_trust)
            
            current_trust = new_trust
        
        return current_trust.squeeze()
    
    def _create_weighted_adjacency(self, edge_index, edge_weights, num_nodes, device):
        """가중치 인접 행렬 생성"""
        adjacency = torch.zeros(num_nodes, num_nodes, device=device)
        row, col = edge_index
        adjacency[row, col] = edge_weights
        
        # Normalize rows to ensure stochastic matrix
        row_sums = adjacency.sum(dim=1, keepdim=True)
        row_sums[row_sums == 0] = 1  # Avoid division by zero
        adjacency = adjacency / row_sums
        
        return adjacency

class TemporalPatternEncoder(nn.Module):
    """
    시간적 패턴 인코더
    DID 활동의 시간적 의존성을 학습
    """
    
    def __init__(self, embedding_dim: int):
        super(TemporalPatternEncoder, self).__init__()
        
        self.positional_encoding = PositionalEncoding(embedding_dim)
        self.temporal_transformer = nn.TransformerEncoder(
            nn.TransformerEncoderLayer(
                d_model=embedding_dim,
                nhead=8,
                dim_feedforward=embedding_dim * 2,
                dropout=0.1
            ),
            num_layers=2
        )
    
    def forward(self, node_embeddings, timestamps):
        """시간적 패턴 인코딩"""
        # Add positional encoding based on timestamps
        temporal_embeddings = self.positional_encoding(node_embeddings, timestamps)
        
        # Apply transformer for temporal dependencies
        temporal_features = self.temporal_transformer(temporal_embeddings.unsqueeze(1))
        
        return temporal_features.squeeze(1)

class PositionalEncoding(nn.Module):
    """시간 정보를 위한 포지셔널 인코딩"""
    
    def __init__(self, d_model: int, max_len: int = 10000):
        super(PositionalEncoding, self).__init__()
        
        pe = torch.zeros(max_len, d_model)
        position = torch.arange(0, max_len, dtype=torch.float).unsqueeze(1)
        div_term = torch.exp(torch.arange(0, d_model, 2).float() * 
                           (-np.log(10000.0) / d_model))
        
        pe[:, 0::2] = torch.sin(position * div_term)
        pe[:, 1::2] = torch.cos(position * div_term)
        
        self.register_buffer('pe', pe)
    
    def forward(self, x, timestamps):
        """타임스탬프 기반 포지셔널 인코딩 적용"""
        # Normalize timestamps to [0, max_len)
        normalized_timestamps = (timestamps % self.pe.size(0)).long()
        
        # Add positional encoding
        x = x + self.pe[normalized_timestamps]
        return x

class DIDGraphBuilder:
    """
    DID 네트워크를 그래프로 변환하는 클래스
    실제 DID 생태계 구조를 반영
    """
    
    def __init__(self):
        self.did_to_id = {}  # DID string to node ID mapping
        self.id_to_did = {}  # Node ID to DID string mapping
        self.node_counter = 0
    
    def build_graph_from_events(self, df: pd.DataFrame) -> Data:
        """
        DID 이벤트 데이터프레임으로부터 그래프 구성
        
        노드: DID 엔티티 (발급자, 홀더, 검증자)
        엣지: DID 관계 (발급, 검증, 신뢰 관계)
        """
        # Extract unique DIDs
        dids = set()
        if 'issuer_id' in df.columns:
            dids.update(df['issuer_id'].dropna().unique())
        if 'holder_did' in df.columns:
            dids.update(df['holder_did'].dropna().unique())
        if 'verifier_id' in df.columns:
            dids.update(df['verifier_id'].dropna().unique())
        
        # Create DID to node ID mapping
        for did in dids:
            if did not in self.did_to_id:
                self.did_to_id[did] = self.node_counter
                self.id_to_did[self.node_counter] = did
                self.node_counter += 1
        
        # Build edges based on DID relationships
        edge_list = []
        edge_attributes = []
        
        for _, row in df.iterrows():
            # Issuer -> Holder edge (credential issuance)
            if 'issuer_id' in row and 'holder_did' in row:
                if pd.notna(row['issuer_id']) and pd.notna(row['holder_did']):
                    issuer_id = self.did_to_id[row['issuer_id']]
                    holder_id = self.did_to_id[row['holder_did']]
                    edge_list.append([issuer_id, holder_id])
                    edge_attributes.append([1.0, 0.0])  # [issuance, verification]
            
            # Holder -> Verifier edge (credential presentation)
            if 'holder_did' in row and 'verifier_id' in row:
                if pd.notna(row['holder_did']) and pd.notna(row['verifier_id']):
                    holder_id = self.did_to_id[row['holder_did']]
                    verifier_id = self.did_to_id[row['verifier_id']]
                    edge_list.append([holder_id, verifier_id])
                    edge_attributes.append([0.0, 1.0])  # [issuance, verification]
        
        # Convert to tensor format
        if edge_list:
            edge_index = torch.tensor(edge_list, dtype=torch.long).t().contiguous()
            edge_attr = torch.tensor(edge_attributes, dtype=torch.float)
        else:
            edge_index = torch.empty((2, 0), dtype=torch.long)
            edge_attr = torch.empty((0, 2), dtype=torch.float)
        
        # Node features (can be enhanced with DID document features)
        num_nodes = len(self.did_to_id)
        node_features = torch.arange(num_nodes, dtype=torch.long)  # Simple ID features
        
        # Node labels (for supervised learning)
        node_labels = self._extract_node_labels(df)
        
        # Timestamps for temporal analysis
        timestamps = self._extract_timestamps(df)
        
        return Data(
            x=node_features,
            edge_index=edge_index,
            edge_attr=edge_attr,
            y=node_labels,
            timestamps=timestamps
        )
    
    def _extract_node_labels(self, df: pd.DataFrame) -> torch.Tensor:
        """노드별 레이블 추출 (정상/이상)"""
        num_nodes = len(self.did_to_id)
        labels = torch.zeros(num_nodes, dtype=torch.float)
        
        # Mark malicious DIDs based on threat events
        if 'threat_detected' in df.columns:
            malicious_events = df[df['threat_detected'] == True]
            
            for _, row in malicious_events.iterrows():
                # Mark involved DIDs as malicious
                if 'issuer_id' in row and pd.notna(row['issuer_id']):
                    if row['issuer_id'] in self.did_to_id:
                        labels[self.did_to_id[row['issuer_id']]] = 1.0
                
                if 'holder_did' in row and pd.notna(row['holder_did']):
                    if row['holder_did'] in self.did_to_id:
                        labels[self.did_to_id[row['holder_did']]] = 1.0
        
        return labels
    
    def _extract_timestamps(self, df: pd.DataFrame) -> torch.Tensor:
        """타임스탬프 정보 추출"""
        num_nodes = len(self.did_to_id)
        timestamps = torch.zeros(num_nodes, dtype=torch.long)
        
        if 'timestamp' in df.columns:
            # Assign latest timestamp for each DID
            for did, node_id in self.did_to_id.items():
                did_events = df[
                    (df.get('issuer_id') == did) | 
                    (df.get('holder_did') == did) | 
                    (df.get('verifier_id') == did)
                ]
                
                if not did_events.empty:
                    latest_timestamp = pd.to_datetime(did_events['timestamp']).max()
                    # Convert to Unix timestamp
                    timestamps[node_id] = int(latest_timestamp.timestamp())
        
        return timestamps

class DIDGNNTrainer:
    """DID-GNN 훈련 클래스"""
    
    def __init__(self, model: DIDGraphNeuralNetwork, device: str = 'cpu'):
        self.model = model.to(device)
        self.device = device
        self.optimizer = torch.optim.Adam(model.parameters(), lr=0.001, weight_decay=1e-5)
        self.scheduler = torch.optim.lr_scheduler.StepLR(self.optimizer, step_size=50, gamma=0.5)
        
    def train(self, train_data: Data, val_data: Data = None, epochs: int = 100):
        """모델 훈련"""
        self.model.train()
        train_losses = []
        val_accuracies = []
        
        for epoch in range(epochs):
            self.optimizer.zero_grad()
            
            # Forward pass
            output = self.model(
                train_data.x.to(self.device),
                train_data.edge_index.to(self.device),
                train_data.edge_attr.to(self.device),
                train_data.timestamps.to(self.device)
            )
            
            # Calculate loss
            loss = self._calculate_loss(output, train_data.y.to(self.device))
            
            # Backward pass
            loss.backward()
            self.optimizer.step()
            self.scheduler.step()
            
            train_losses.append(loss.item())
            
            # Validation
            if val_data is not None and epoch % 10 == 0:
                val_acc = self.evaluate(val_data)
                val_accuracies.append(val_acc)
                logger.info(f"Epoch {epoch}: Loss={loss.item():.4f}, Val_Acc={val_acc:.4f}")
        
        return {
            'train_losses': train_losses,
            'val_accuracies': val_accuracies
        }
    
    def _calculate_loss(self, output, labels):
        """손실 함수 계산"""
        # Multi-task loss: anomaly detection + trust score prediction
        anomaly_loss = F.binary_cross_entropy(
            output['anomaly_scores'].squeeze(),
            labels
        )
        
        # Trust score regularization (encourage trust scores to be meaningful)
        trust_reg = torch.mean((output['trust_scores'] - 0.5) ** 2)
        
        return anomaly_loss + 0.1 * trust_reg
    
    def evaluate(self, test_data: Data) -> float:
        """모델 평가"""
        self.model.eval()
        
        with torch.no_grad():
            output = self.model(
                test_data.x.to(self.device),
                test_data.edge_index.to(self.device),
                test_data.edge_attr.to(self.device),
                test_data.timestamps.to(self.device)
            )
            
            predictions = (output['anomaly_scores'].squeeze() > 0.5).float()
            accuracy = (predictions == test_data.y.to(self.device)).float().mean()
            
            # Calculate additional metrics
            y_true = test_data.y.cpu().numpy()
            y_scores = output['anomaly_scores'].squeeze().cpu().numpy()
            
            if len(np.unique(y_true)) > 1:
                auc_score = roc_auc_score(y_true, y_scores)
                f1 = f1_score(y_true, predictions.cpu().numpy())
                logger.info(f"AUC: {auc_score:.4f}, F1: {f1:.4f}")
            
        return accuracy.item()

# 사용 예제
if __name__ == "__main__":
    # 예제 DID 데이터 생성
    sample_data = pd.DataFrame({
        'issuer_id': ['did:example:issuer1', 'did:example:issuer2'] * 50,
        'holder_did': ['did:example:holder1', 'did:example:holder2'] * 50,
        'verifier_id': ['did:example:verifier1', 'did:example:verifier2'] * 50,
        'timestamp': pd.date_range('2024-01-01', periods=100, freq='H'),
        'threat_detected': [False] * 90 + [True] * 10  # 10% 위협
    })
    
    # 그래프 구성
    graph_builder = DIDGraphBuilder()
    graph_data = graph_builder.build_graph_from_events(sample_data)
    
    # 모델 초기화
    model = DIDGraphNeuralNetwork(
        num_did_entities=len(graph_builder.did_to_id),
        embedding_dim=64,
        num_gnn_layers=3
    )
    
    # 훈련
    trainer = DIDGNNTrainer(model)
    training_results = trainer.train(graph_data, epochs=50)
    
    print("DID-GNN 훈련 완료!")
    print(f"최종 정확도: {training_results['val_accuracies'][-1]:.4f}")