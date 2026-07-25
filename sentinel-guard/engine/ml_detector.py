"""
Sentinel Guard — Machine Learning Threat Detection Engine
Provides lightweight ML-based threat detection using TF-IDF and logistic regression-like scoring
"""

import os
import math
import re
import json
import collections
from typing import List, Dict, Tuple, Optional
from dataclasses import dataclass, field
from utils.logger import get_logger

logger = get_logger(__name__)


@dataclass
class MLPredictionResult:
    """Dataclass holding prediction results from the ML detector."""
    score: float          # 0-100 score indicating threat severity
    is_malicious: bool    # True if score >= 50.0
    confidence: float     # 0.0 - 1.0 confidence value
    top_features: List[str] = field(default_factory=list)  # Top contributing features


class MLDetector:
    """Lightweight ML-based threat detection engine using TF-IDF and logistic regression."""

    def __init__(self, model_path: str = "data/ml_model.json"):
        """Initialize the ML detector and attempt to load any existing model."""
        self.model_path = model_path
        self.vocabulary: List[str] = []
        self.weights: Dict[str, float] = {}
        self.bias: float = 0.0
        self.idf: Dict[str, float] = {}
        self.malware_profile: Dict[str, float] = {}

        # Attempt to load model on startup if it exists
        if os.path.exists(self.model_path):
            try:
                self.load_model(self.model_path)
            except Exception as e:
                logger.warning(f"Could not load ML model from {self.model_path}: {e}")

    def _compute_byte_histogram(self, content: bytes) -> List[float]:
        """Compute the normalized 256-byte frequency histogram."""
        histogram = [0.0] * 256
        if not content:
            return histogram
        for byte in content:
            histogram[byte] += 1
        total = len(content)
        return [count / total for count in histogram]

    def _compute_ngrams(self, content: bytes, n: int = 2) -> dict:
        """Compute relative frequency of byte n-grams (default 2-grams)."""
        if len(content) < n:
            return {}
        ngrams = collections.Counter()
        for i in range(len(content) - n + 1):
            gram = content[i:i+n]
            ngrams[gram.hex()] += 1
        total = len(content) - n + 1
        return {k: v / total for k, v in ngrams.items()}

    def _extract_strings(self, content: bytes, min_len: int = 4) -> List[str]:
        """Extract printable ASCII alphanumeric words/tokens of at least min_len characters."""
        pattern = re.compile(rb'[a-zA-Z0-9_\-.]{' + str(min_len).encode() + b',}')
        matches = pattern.findall(content)
        return [m.decode('utf-8', errors='ignore') for m in matches]

    def _shannon_entropy(self, data: bytes) -> float:
        """Calculate Shannon entropy of the given byte data."""
        if not data:
            return 0.0
        freq = [0] * 256
        for byte in data:
            freq[byte] += 1
        entropy = 0.0
        length = len(data)
        for count in freq:
            if count > 0:
                p = count / length
                entropy -= p * math.log2(p)
        return entropy

    def extract_features(self, content: bytes) -> dict:
        """
        Extract features from raw file content.
        Includes: byte histogram, 2-gram frequencies, string counts, and scaled Shannon entropy.
        """
        features = {}

        # Handle empty files
        if not content:
            for i in range(256):
                features[f"byte_{i:02x}"] = 0.0
            features["entropy"] = 0.0
            return features

        # 1. Byte Histogram
        hist = self._compute_byte_histogram(content)
        for i, val in enumerate(hist):
            features[f"byte_{i:02x}"] = val

        # 2. 2-gram frequencies
        grams = self._compute_ngrams(content, n=2)
        for gram, freq in grams.items():
            features[f"ngram_{gram}"] = freq

        # 3. String Counts / Frequency
        strings = self._extract_strings(content, min_len=4)
        total_strings = len(strings)
        if total_strings > 0:
            str_counts = collections.Counter(strings)
            for s, count in str_counts.items():
                s_clean = s.strip()[:64]
                # Clean up the key to avoid problematic characters in JSON/Feature matching
                s_clean = re.sub(r'[^a-zA-Z0-9_\-.]', '_', s_clean)
                if s_clean:
                    features[f"str_{s_clean}"] = count / total_strings

        # 4. Shannon Entropy (Scaled to [0, 1] range to be consistent with other features)
        features["entropy"] = self._shannon_entropy(content) / 8.0

        return features

    def train(self, malware_samples: List[bytes], benign_samples: List[bytes]):
        """
        Train the model using labeled malware and benign file samples.
        Builds feature weights, computes IDF values, and generates the malware profile.
        """
        if not malware_samples and not benign_samples:
            logger.warning("No samples provided for training.")
            return

        logger.info(f"Starting MLDetector training with {len(malware_samples)} malware and {len(benign_samples)} benign samples...")

        # Extract features for all samples
        malware_features = [self.extract_features(m) for m in malware_samples]
        benign_features = [self.extract_features(b) for b in benign_samples]

        all_features = malware_features + benign_features
        total_samples = len(all_features)

        # 1. Compute Document Frequency (DF) for IDF calculation
        df = collections.defaultdict(int)
        for feat_dict in all_features:
            for f in feat_dict:
                df[f] += 1

        # 2. Compute IDF for all features
        self.idf = {}
        for f, count in df.items():
            self.idf[f] = math.log((1 + total_samples) / (1 + count)) + 1.0

        # 3. Create Malware Profile Vector using L2-normalized TF-IDF average
        self.malware_profile = {}
        if malware_features:
            malware_tfidf_vectors = []
            for m_feat in malware_features:
                vec = {f: val * self.idf.get(f, 0.0) for f, val in m_feat.items()}
                sq_sum = sum(v * v for v in vec.values())
                if sq_sum > 0:
                    norm = math.sqrt(sq_sum)
                    vec = {k: v / norm for k, v in vec.items()}
                malware_tfidf_vectors.append(vec)

            malware_tfidf_sums = collections.defaultdict(float)
            for vec in malware_tfidf_vectors:
                for f, val in vec.items():
                    malware_tfidf_sums[f] += val
            num_malware = len(malware_tfidf_vectors)
            for f, total_tfidf in malware_tfidf_sums.items():
                self.malware_profile[f] = total_tfidf / num_malware

        # 4. Feature Selection: select top K most informative features based on difference in means
        mean_mal = collections.defaultdict(float)
        mean_ben = collections.defaultdict(float)

        num_mal = len(malware_features) if malware_features else 1
        num_ben = len(benign_features) if benign_features else 1

        for m_feat in malware_features:
            for f, val in m_feat.items():
                mean_mal[f] += val / num_mal

        for b_feat in benign_features:
            for f, val in b_feat.items():
                mean_ben[f] += val / num_ben

        feature_scores = {}
        all_known_features = set(mean_mal.keys()) | set(mean_ben.keys())
        for f in all_known_features:
            feature_scores[f] = abs(mean_mal[f] - mean_ben[f])

        # Sort and select top K (e.g., 1000) features
        sorted_features = sorted(feature_scores.items(), key=lambda x: x[1], reverse=True)
        vocab_size = min(1000, len(sorted_features))
        self.vocabulary = [f for f, score in sorted_features[:vocab_size]]

        # 5. Train Logistic Regression-like model using gradient descent
        # Prepare dataset using sparse vocabulary vectors
        dataset = []
        for m_feat in malware_features:
            x_sparse = {f: m_feat[f] for f in self.vocabulary if f in m_feat and m_feat[f] != 0}
            dataset.append((x_sparse, 1.0))

        for b_feat in benign_features:
            x_sparse = {f: b_feat[f] for f in self.vocabulary if f in b_feat and b_feat[f] != 0}
            dataset.append((x_sparse, 0.0))

        # Initialize weights and bias
        self.weights = {f: 0.0 for f in self.vocabulary}
        self.bias = 0.0

        # Hyperparameters
        epochs = 200
        lr = 0.5
        lam = 0.001  # L2 regularization strength
        m_samples = len(dataset)

        if m_samples > 0:
            for epoch in range(epochs):
                dw = {f: 0.0 for f in self.vocabulary}
                db = 0.0

                for x_sparse, y in dataset:
                    # Compute linear combination: z = bias + sum(w_i * x_i)
                    z = self.bias
                    for f, val in x_sparse.items():
                        z += self.weights[f] * val

                    # Sigmoid with overflow protection
                    if z > 15:
                        p = 1.0
                    elif z < -15:
                        p = 0.0
                    else:
                        p = 1.0 / (1.0 + math.exp(-z))

                    error = p - y

                    # Accumulate gradients
                    for f, val in x_sparse.items():
                        dw[f] += error * val
                    db += error

                # Gradient descent step with L2 regularization
                for f in self.vocabulary:
                    dw_total = (dw[f] / m_samples) + (lam * self.weights[f])
                    self.weights[f] -= lr * dw_total
                
                self.bias -= lr * (db / m_samples)

        logger.info(f"Training completed. Feature vocabulary size: {len(self.vocabulary)}")

    def _compute_tfidf_similarity(self, feat_dict: dict) -> float:
        """Compute the cosine similarity of the file's TF-IDF vector with the malware profile."""
        if not self.malware_profile:
            return 0.0

        # Convert feat_dict to TF-IDF vector
        tfidf_vec = {}
        for f, val in feat_dict.items():
            if f in self.idf:
                tfidf_vec[f] = val * self.idf[f]

        # L2 normalize tfidf_vec
        sq_sum = sum(v * v for v in tfidf_vec.values())
        if sq_sum > 0:
            norm = math.sqrt(sq_sum)
            tfidf_vec = {k: v / norm for k, v in tfidf_vec.items()}
        else:
            return 0.0

        # Compute dot product (since both are L2 normalized, cosine similarity is just dot product)
        dot_product = 0.0
        profile_sq_sum = sum(v * v for v in self.malware_profile.values())

        for f, val in self.malware_profile.items():
            if f in tfidf_vec:
                dot_product += val * tfidf_vec[f]

        if profile_sq_sum > 0:
            similarity = dot_product / math.sqrt(profile_sq_sum)
            return similarity
        return 0.0

    def predict(self, content: bytes) -> MLPredictionResult:
        """
        Score new file content between 0-100 and output a classification result.
        Uses combined scores from TF-IDF profile similarity and Logistic Regression.
        """
        if not self.vocabulary or not self.weights:
            logger.warning("MLDetector predict called but no model is loaded/trained. Returning clean result.")
            return MLPredictionResult(score=0.0, is_malicious=False, confidence=1.0, top_features=[])

        # Extract features
        feat_dict = self.extract_features(content)

        # 1. TF-IDF scoring against known malware patterns
        tfidf_sim = self._compute_tfidf_similarity(feat_dict)

        # 2. Logistic regression scoring
        z = self.bias
        for f in self.vocabulary:
            if f in feat_dict:
                z += self.weights[f] * feat_dict[f]

        # Sigmoid to get class probability
        if z > 15:
            lr_prob = 1.0
        elif z < -15:
            lr_prob = 0.0
        else:
            lr_prob = 1.0 / (1.0 + math.exp(-z))

        # Combine TF-IDF similarity and Logistic Regression probability
        # LR probability is highly discriminant, while TF-IDF similarity ensures robust overlap checking
        combined_score = (0.7 * lr_prob) + (0.3 * tfidf_sim)
        final_score = combined_score * 100.0

        # Determine if malicious (threshold at 50)
        is_malicious = final_score >= 50.0

        # Calculate confidence
        # For binary classifier, confidence is the probability of the predicted outcome class
        if lr_prob >= 0.5:
            confidence = lr_prob
        else:
            confidence = 1.0 - lr_prob

        # Extract top features contributing most to prediction
        contributions = []
        for f, val in feat_dict.items():
            if val > 0:
                weight = self.weights.get(f, 0.0)
                profile_val = self.malware_profile.get(f, 0.0)
                contribution = weight * val
                if contribution > 0 or profile_val > 0:
                    contributions.append((f, contribution, profile_val * val))

        # Sort by regression contribution, then malware profile overlap
        contributions.sort(key=lambda x: (x[1], x[2]), reverse=True)
        top_features = [c[0] for c in contributions[:5]]

        return MLPredictionResult(
            score=round(final_score, 2),
            is_malicious=is_malicious,
            confidence=round(confidence, 4),
            top_features=top_features
        )

    def save_model(self, path: str = None):
        """Serialize the trained model components to a JSON file."""
        if path is None:
            path = self.model_path

        dir_name = os.path.dirname(path)
        if dir_name and not os.path.exists(dir_name):
            os.makedirs(dir_name, exist_ok=True)

        model_data = {
            "vocabulary": self.vocabulary,
            "weights": self.weights,
            "bias": self.bias,
            "idf": self.idf,
            "malware_profile": self.malware_profile
        }

        with open(path, "w", encoding="utf-8") as f:
            json.dump(model_data, f, indent=4)
        logger.info(f"Saved ML model to {path}")

    def load_model(self, path: str = None):
        """Load a serialized model from a JSON file."""
        if path is None:
            path = self.model_path

        with open(path, "r", encoding="utf-8") as f:
            model_data = json.load(f)

        self.vocabulary = model_data.get("vocabulary", [])
        self.weights = model_data.get("weights", {})
        self.bias = model_data.get("bias", 0.0)
        self.idf = model_data.get("idf", {})
        self.malware_profile = model_data.get("malware_profile", {})
        logger.info(f"Loaded ML model from {path} with {len(self.vocabulary)} vocabulary features")
