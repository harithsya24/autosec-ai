"""
AutoSec AI - Data Loader Utilities
Handles loading and preprocessing of security datasets
"""

import pandas as pd
import numpy as np
from pathlib import Path
from typing import Dict, List, Tuple, Optional
import json
from datetime import datetime


class CICIDSLoader:
    """Load and preprocess CICIDS 2017 dataset"""
    
    def __init__(self, data_dir: str = "data/raw/cicids"):
        self.data_dir = Path(data_dir)
        self.label_column = ' Label'  
        
    def load_file(self, filename: str, sample_size: Optional[int] = None) -> pd.DataFrame:
        """
        Load a single CICIDS CSV file
        
        Args:
            filename: Name of CSV file
            sample_size: Optional - load only first N rows for testing
        
        Returns:
            DataFrame with loaded data
        """
        file_path = self.data_dir / filename
        
        try:
            df = pd.read_csv(file_path, encoding='utf-8', nrows=sample_size)
        except UnicodeDecodeError:
            df = pd.read_csv(file_path, encoding='latin-1', nrows=sample_size)
        
        df.columns = df.columns.str.strip()
        
        print(f" Loaded {filename}: {len(df):,} records")
        return df
    
    def load_all_files(self, sample_size: Optional[int] = None) -> pd.DataFrame:
        files = [
            "Monday-WorkingHours-pcap_ISCX.csv",
            "Tuesday-WorkingHours-pcap_ISCX.csv",
            "Wednesday-workingHours-pcap_ISCX.csv",
            "Thursday-WorkingHours-Morning-WebAttacks-pcap_ISCX.csv",
            "Thursday-WorkingHours-Afternoon-Infilteration-pcap_ISCX.csv",
            "Friday-WorkingHours-Morning-pcap_ISCX.csv",
            "Friday-WorkingHours-Afternoon-PortScan-pcap_ISCX.csv",\
            "Friday-WorkingHours-Afternoon-DDos-pcap_ISCX.csv"
]

        
        dfs = []
        for file in files:
            if (self.data_dir / file).exists():
                df = self.load_file(file, sample_size)
                dfs.append(df)
        
        combined_df = pd.concat(dfs, ignore_index=True)
        print(f"\n Total records: {len(combined_df):,}")
        return combined_df
    
    def get_label_distribution(self, df: pd.DataFrame) -> Dict[str, int]:
        return df['Label'].value_counts().to_dict()
    
    def split_benign_attack(self, df: pd.DataFrame) -> Tuple[pd.DataFrame, pd.DataFrame]:
        """
        Split dataset into benign and attack traffic
        
        Returns:
            (benign_df, attack_df)
        """
        benign = df[df['Label'] == 'BENIGN'].copy()
        attack = df[df['Label'] != 'BENIGN'].copy()
        
        print(f" Benign records: {len(benign):,}")
        print(f" Attack records: {len(attack):,}")
        
        return benign, attack
    
    def clean_data(self, df: pd.DataFrame) -> pd.DataFrame:
        """Clean and preprocess the data"""
        print("Cleaning data...")
        
        initial_len = len(df)
        df = df.drop_duplicates()
        print(f"   Removed {initial_len - len(df):,} duplicate rows")
        
        # Handle infinite values
        numeric_cols = df.select_dtypes(include=[np.number]).columns
        df[numeric_cols] = df[numeric_cols].replace([np.inf, -np.inf], np.nan)
        
        # Fill missing values with median for numeric columns
        for col in numeric_cols:
            if df[col].isnull().any():
                median_val = df[col].median()
                df[col].fillna(median_val, inplace=True)
        
        print("  Data cleaned")
        return df
    
    def extract_features(self, df: pd.DataFrame, feature_list: Optional[List[str]] = None) -> pd.DataFrame:
        """
        Extract specific features for ML model
        
        Args:
            df: Input DataFrame
            feature_list: List of features to extract (None = use default)
        
        Returns:
            DataFrame with selected features
        """
        if feature_list is None:
            # Default key features for anomaly detection
            feature_list = [
                'Flow Duration',
                'Total Fwd Packets',
                'Total Backward Packets',
                'Flow Bytes/s',
                'Flow Packets/s',
                'Destination Port',
                'Fwd Packet Length Mean',
                'Bwd Packet Length Mean',
                'Flow IAT Mean',
                'Fwd IAT Mean',
                'Bwd IAT Mean',
                'Fwd PSH Flags',
                'Bwd PSH Flags',
                'FIN Flag Count',
                'SYN Flag Count',
                'RST Flag Count',
                'ACK Flag Count',
                'Average Packet Size',
                'Label'
            ]
        
        # Check which features exist
        available_features = [f for f in feature_list if f in df.columns]
        missing_features = set(feature_list) - set(available_features)
        
        if missing_features:
            print(f"  Missing features: {missing_features}")
        
        return df[available_features].copy()


class MITRELoader:
    """Load and query MITRE ATT&CK data"""
    
    def __init__(self, data_dir: str = "data/threat_intel"):
        self.data_dir = Path(data_dir)
        self.techniques = None
        
    def load_techniques(self) -> List[Dict]:
        """Load MITRE ATT&CK techniques"""
        
        techniques_file = self.data_dir / "mitre_techniques.json"
        
        with open(techniques_file, 'r') as f:
            self.techniques = json.load(f)
        
        print(f"Loaded {len(self.techniques)} MITRE techniques")
        return self.techniques
    
    def search_technique(self, query: str) -> List[Dict]:
        """
        Search for techniques matching query
        
        Args:
            query: Search term (e.g., "brute force", "privilege")
        
        Returns:
            List of matching techniques
        """
        if self.techniques is None:
            self.load_techniques()
        
        query_lower = query.lower()
        matches = []
        
        for technique in self.techniques:
            name = technique.get('name', '').lower()
            description = technique.get('description', '').lower()
            
            if query_lower in name or query_lower in description:
                matches.append(technique)
        
        return matches
    
    def get_technique_by_id(self, technique_id: str) -> Optional[Dict]:
        """Get technique by MITRE ATT&CK ID (e.g., T1078)"""
        
        if self.techniques is None:
            self.load_techniques()
        
        for technique in self.techniques:
            if 'external_references' in technique:
                for ref in technique['external_references']:
                    if ref.get('external_id') == technique_id:
                        return technique
        
        return None


class CVELoader:
    """Load and query CVE vulnerability data"""
    
    def __init__(self, data_dir: str = "data/threat_intel"):
        self.data_dir = Path(data_dir)
        self.cves = None
    
    def load_cves(self) -> Dict:
        """Load CVE data from NVD"""
        
        cve_file = self.data_dir / "nvd_cve_sample.json"
        
        with open(cve_file, 'r') as f:
            self.cves = json.load(f)
        
        num_cves = len(self.cves.get('vulnerabilities', []))
        print(f" Loaded {num_cves} CVEs")
        return self.cves


# Utility functions
def load_all_data(sample_size: Optional[int] = None) -> Tuple[pd.DataFrame, List[Dict], Dict]:
    """
    Load all datasets at once
    
    Args:
        sample_size: Optional - limit rows per file for testing
    
    Returns:
        (cicids_df, mitre_techniques, cve_data)
    """
    print("Loading all datasets...")
    
    # Load CICIDS
    cicids_loader = CICIDSLoader()
    cicids_df = cicids_loader.load_all_files(sample_size)
    cicids_df = cicids_loader.clean_data(cicids_df)
    
    # Load MITRE
    mitre_loader = MITRELoader()
    mitre_techniques = mitre_loader.load_techniques()
    
    # Load CVE
    cve_loader = CVELoader()
    cve_data = cve_loader.load_cves()
    
    print("\n All data loaded successfully!")
    return cicids_df, mitre_techniques, cve_data


if __name__ == "__main__":
    print(" Testing Data Loaders...")
    
    # Test CICIDS loader
    loader = CICIDSLoader()
    df = loader.load_file("Monday-WorkingHours-pcap_ISCX.csv", sample_size=1000)
    print(f"\n Sample shape: {df.shape}")
    print(f" Columns: {list(df.columns[:5])}...")
    
    mitre = MITRELoader()
    techniques = mitre.load_techniques()
    
    # Search for brute force techniques
    matches = mitre.search_technique("brute force")
    print(f"\n Found {len(matches)} techniques matching 'brute force'")
    
    print("\n All loaders working!")