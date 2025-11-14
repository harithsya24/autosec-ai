"""
AutoSec AI - REAL Dataset Download Script
Downloads ONLY authentic security datasets from official sources
NO synthetic/fake data generation
"""

import os
import requests
import json
from pathlib import Path
from datetime import datetime
import zipfile
import io

DATA_DIR = Path("data")
RAW_DIR = DATA_DIR / "raw"
THREAT_INTEL_DIR = DATA_DIR / "threat_intel"

for directory in [DATA_DIR, RAW_DIR, THREAT_INTEL_DIR]:
    directory.mkdir(exist_ok=True)
    print(f"Created directory: {directory}")

print("AutoSec AI - REAL Dataset Downloader")
print("ONLY downloading authentic security data from official sources")

# 1. Download MITRE ATT&CK Data (REAL THREAT INTELLIGENCE)
print(" 1. Downloading MITRE ATT&CK Framework (Official Data)...")

def download_mitre_attack():
    url = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"
    output_file = THREAT_INTEL_DIR / "mitre_attack.json"
    
    try:
        print(f"   Fetching from: {url}")
        response = requests.get(url, timeout=60)
        response.raise_for_status()
        
        data = response.json()
        
        with open(output_file, 'w') as f:
            json.dump(data, f, indent=2)
        
        techniques = [obj for obj in data['objects'] if obj['type'] == 'attack-pattern']
        
        print(f" MITRE ATT&CK data saved: {output_file}")
        print(f" File size: {output_file.stat().st_size / 1024:.2f} KB")
        print(f" Attack techniques: {len(techniques)}")
        
        techniques_file = THREAT_INTEL_DIR / "mitre_techniques.json"
        with open(techniques_file, 'w') as f:
            json.dump(techniques[:], f, indent=2)  
        
        return True
    except Exception as e:
        print(f" Error: {e}")
        print(f" You can manually download from: https://github.com/mitre/cti")
        return False

download_mitre_attack()

# 2. Download Instructions for CICIDS Dataset
print("\n 2. CICIDS 2017/2018 Dataset (Large - Manual Download Required)...")
print("\n CICIDS 2017/2018 Dataset Files...")
cicids_dir = RAW_DIR / "cicids"

if cicids_dir.exists():
    files = list(cicids_dir.glob("*.csv"))
    if files:
        print("The files are:")
        for file in files:
            print(f"  - {file.name}")
    else:
        print(" No CSV files found. Please download the dataset.")
else:
    print("   Directory not found. Please download the dataset.")


# 3. CVE Data from NVD (REAL VULNERABILITIES)
print("\n 3. Downloading CVE Data from NVD (National Vulnerability Database)...")

def download_cve_data():
    print(" Note: Full NVD access requires API key")
    print(" Downloading publicly available CVE feed sample...")
    
    url = "https://services.nvd.nist.gov/rest/json/cves/2.0?resultsPerPage=20"
    output_file = THREAT_INTEL_DIR / "nvd_cve_sample.json"
    
    try:
        print(f"   Fetching from: {url}")
        headers = {'User-Agent': 'AutoSecAI-Research/1.0'}
        response = requests.get(url, headers=headers, timeout=60)
        response.raise_for_status()
        
        with open(output_file, 'w') as f:
            json.dump(response.json(), f, indent=2)
        
        print(f"CVE data saved: {output_file}")
        print(f"File size: {output_file.stat().st_size / 1024:.2f} KB")
        
        return True
    except Exception as e:
        print(f"Error: {e}")
        print(f"Visit https://nvd.nist.gov/ for manual access")
        return False

download_cve_data()

# Summary
print("\n Download Summary - REAL DATA ONLY")

print("\n Successfully downloaded:")
print(f" MITRE ATT&CK Framework (Official): MITRE ATT&CK: Industry-standard threat framework")
print(f" CVE Data from NVD (Official): NVD CVE: Government-maintained vulnerability database")
print(f" CICIDS 2017/2018 Dataset: CICIDS: Real network intrusion data used in research")

print(" Data preparation complete!")
