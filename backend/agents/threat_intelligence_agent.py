"""
Threat Intelligence Agent
Uses RAG to retrieve threat context and LLM to generate explanations
"""

import os
import sys
from typing import Dict, List, Optional, Tuple
from datetime import datetime
from pathlib import Path
import json

# Add parent directory to path
sys.path.append(str(Path(__file__).parent.parent.parent))

# Load environment variables from .env file
try:
    from dotenv import load_dotenv
    # Load .env from project root (3 levels up from backend/agents/)
    env_path = Path(__file__).parent.parent.parent / ".env"
    load_dotenv(env_path)
except ImportError:
    pass  # python-dotenv not installed, use system env vars only

# Fix huggingface tokenizers warning
import os
if "TOKENIZERS_PARALLELISM" not in os.environ:
    os.environ["TOKENIZERS_PARALLELISM"] = "false"

try:
    from langchain_openai import ChatOpenAI
    from langchain_core.prompts import ChatPromptTemplate
    from langchain_core.messages import HumanMessage, SystemMessage
    LANGCHAIN_AVAILABLE = True
except ImportError:
    LANGCHAIN_AVAILABLE = False
    print("  LangChain not available. Using fallback mode.")

from rag.vector_store.chroma_setup import ThreatIntelligenceRAG


class ThreatIntelligenceAgent:
    """
    AI Agent that explains threats using RAG + LLM reasoning
    
    Process:
    1. Takes detected anomaly
    2. Retrieves relevant threat intelligence via RAG
    3. Uses LLM to generate human-readable explanation
    4. Returns explanation with confidence score and citations
    """
    
    def __init__(
        self,
        rag: Optional[ThreatIntelligenceRAG] = None,
        llm_model: str = "gpt-4o-mini",
        temperature: float = 0.3,
        use_llm: bool = True
    ):
        """
        Initialize Threat Intelligence Agent
        
        Args:
            rag: ThreatIntelligenceRAG instance (creates new if None)
            llm_model: OpenAI model to use
            temperature: LLM temperature (lower = more deterministic)
            use_llm: Whether to use LLM (False = RAG only)
        """
        self.rag = rag or ThreatIntelligenceRAG()
        self.use_llm = use_llm and LANGCHAIN_AVAILABLE
        self.llm_model = llm_model
        self.temperature = temperature
        
        # Initialize LLM if available
        if self.use_llm:
            api_key = os.getenv("OPENAI_API_KEY")
            if not api_key:
                print("  OPENAI_API_KEY not found. Set it in .env file or disable LLM.")
                self.use_llm = False
            else:
                try:
                    self.llm = ChatOpenAI(
                        model=llm_model,
                        temperature=temperature
                    )
                    print(f"LLM initialized: {llm_model}")
                except Exception as e:
                    print(f"  Failed to initialize LLM: {e}")
                    self.use_llm = False
        else:
            self.llm = None
            if not LANGCHAIN_AVAILABLE:
                print("  LangChain not installed. Install with: pip install langchain langchain-openai")
            print("  Running in RAG-only mode (no LLM reasoning)")
    
    def analyze_threat(
        self,
        anomaly: Dict,
        n_retrievals: int = 3
    ) -> Dict:
        """
        Analyze a detected anomaly using RAG + LLM
        
        Args:
            anomaly: Detected anomaly from LogAnalyzerAgent
            n_retrievals: Number of threat documents to retrieve
            
        Returns:
            Analysis with explanation, confidence, and citations
        """
        # Step 1: Build query from anomaly
        query = self._build_query(anomaly)
        
        # Step 2: Retrieve relevant threats via RAG
        threat_results = self.rag.search_threats(query, n_results=n_retrievals)
        cve_results = self.rag.search_cves(query, n_results=2)
        incident_results = self.rag.search_incidents(query, n_results=2)
        
        # Step 3: Calculate enhanced confidence from multiple factors
        confidence = self._calculate_confidence(
            threat_results, cve_results, incident_results, anomaly
        )
        
        # Step 4: Generate explanation (LLM or template-based)
        if self.use_llm and self.llm:
            explanation = self._generate_llm_explanation(
                anomaly, threat_results, cve_results, incident_results
            )
        else:
            explanation = self._generate_template_explanation(
                anomaly, threat_results, cve_results, incident_results
            )
        
        # Step 5: Extract matched techniques and recommendations
        matched_techniques = self._extract_techniques(threat_results)
        recommendations = self._extract_recommendations(
            threat_results, cve_results, incident_results
        )
        
        return {
            "threat_type": self._classify_threat_type(anomaly, threat_results),
            "explanation": explanation,
            "confidence": confidence,
            "severity": anomaly.get("severity", "medium"),
            "anomaly_score": anomaly.get("anomaly_score", 0.0),
            "matched_techniques": matched_techniques,
            "recommendations": recommendations,
            "retrieved_context": {
                "threats": len(threat_results),
                "cves": len(cve_results),
                "incidents": len(incident_results)
            },
            "citations": self._format_citations(threat_results, cve_results, incident_results),
            "analyzed_at": datetime.now().isoformat()
        }
    
    def _build_query(self, anomaly: Dict) -> str:
        """Build search query from anomaly characteristics"""
        parts = []
        
        # Add action context
        action = anomaly.get("action", "")
        if action:
            parts.append(action)
        
        # Add status context
        status = anomaly.get("status", "")
        if status in ["failed", "denied", "error"]:
            parts.append("failed authentication")
            parts.append("unauthorized access")
        
        # Add behavioral indicators
        features = anomaly.get("features", {})
        if features.get("is_off_hours"):
            parts.append("off-hours access")
        if features.get("failed_action"):
            parts.append("multiple failed attempts")
        if features.get("data_transfer_volume", 0) > 10_000_000:
            parts.append("large data transfer")
        
        # Add severity context
        severity = anomaly.get("severity", "")
        if severity in ["high", "critical"]:
            parts.append("critical security threat")
        
        # Default query if nothing specific
        if not parts:
            parts = ["suspicious network activity", "security anomaly"]
        
        return " ".join(parts)
    
    def _calculate_confidence(
        self,
        threat_results: List[Dict],
        cve_results: List[Dict],
        incident_results: List[Dict],
        anomaly: Optional[Dict] = None
    ) -> float:
        """
        Enhanced confidence score calculation using multiple factors
        
        Factors:
        1. RAG retrieval quality (similarity scores)
        2. Number of matching sources
        3. Anomaly score strength
        4. Historical pattern matching
        
        Returns:
            Confidence score 0.0 to 1.0
        """
        # Factor 1: RAG Retrieval Quality (40% weight)
        rag_confidence = 0.0
        if threat_results:
            # Use distance as quality indicator (lower distance = better match)
            best_threat_distance = min(
                (r.get("distance", 1.0) for r in threat_results),
                default=1.0
            )
            # Convert distance to similarity (assuming cosine distance)
            threat_similarity = max(0, 1.0 - best_threat_distance)
            rag_confidence = threat_similarity * 0.4
        
        # Factor 2: Source Diversity (20% weight)
        source_confidence = 0.0
        source_count = 0
        if threat_results:
            source_count += len(threat_results)
        if cve_results:
            source_count += len(cve_results)
        if incident_results:
            source_count += len(incident_results)
        
        # More sources = higher confidence (capped at 3+ sources)
        source_confidence = min(0.2, (source_count / 5.0) * 0.2)
        
        # Factor 3: Anomaly Score Strength (30% weight)
        anomaly_confidence = 0.0
        if anomaly:
            anomaly_score = abs(anomaly.get("anomaly_score", 0.0))
            # Normalize anomaly score to 0-1 range (assuming scores are -1 to 0)
            normalized_score = min(1.0, abs(anomaly_score))
            anomaly_confidence = normalized_score * 0.3
        
        # Factor 4: Retrieval Quality Distribution (10% weight)
        quality_confidence = 0.0
        if threat_results:
            # Check if multiple high-quality matches exist
            high_quality_matches = sum(
                1 for r in threat_results 
                if r.get("distance", 1.0) < 0.3
            )
            if high_quality_matches >= 2:
                quality_confidence = 0.1
            elif high_quality_matches == 1:
                quality_confidence = 0.05
        
        # Combine all factors
        total_confidence = (
            rag_confidence +
            source_confidence +
            anomaly_confidence +
            quality_confidence
        )
        
        # Ensure confidence is in valid range
        return min(1.0, max(0.0, total_confidence))
    
    def _generate_llm_explanation(
        self,
        anomaly: Dict,
        threat_results: List[Dict],
        cve_results: List[Dict],
        incident_results: List[Dict]
    ) -> str:
        """Generate explanation using LLM"""
        
        # Build context from retrieved documents
        context_parts = []
        
        if threat_results:
            context_parts.append("## Relevant Threat Intelligence:")
            for i, result in enumerate(threat_results[:3], 1):
                doc = result.get("document", "")
                metadata = result.get("metadata", {})
                context_parts.append(f"\n{i}. {metadata.get('title', 'Threat')}: {doc[:200]}...")
        
        if cve_results:
            context_parts.append("\n## Related CVEs:")
            for result in cve_results[:2]:
                doc = result.get("document", "")
                context_parts.append(f"- {doc[:150]}...")
        
        if incident_results:
            context_parts.append("\n## Similar Past Incidents:")
            for result in incident_results[:2]:
                doc = result.get("document", "")
                context_parts.append(f"- {doc[:150]}...")
        
        context = "\n".join(context_parts)
        
        # Build anomaly description
        features = anomaly.get('features', {})
        features_str = ", ".join([
            f"{k}: {v}" for k, v in features.items() 
            if v and k not in ['hour_of_day', 'day_of_week']  # Skip numeric details
        ]) if features else "none"
        
        anomaly_desc = f"""
Anomaly Detected:
- Action: {anomaly.get('action', 'unknown')}
- Status: {anomaly.get('status', 'unknown')}
- Source IP: {anomaly.get('source_ip', 'unknown')}
- Severity: {anomaly.get('severity', 'medium')}
- Anomaly Score: {anomaly.get('anomaly_score', 0.0):.3f}
- Key Indicators: {features_str}
"""
        
        # Create prompt
        prompt = ChatPromptTemplate.from_messages([
            ("system", """You are a cybersecurity expert analyzing security threats. 
Your task is to explain detected anomalies in clear, actionable language.

Guidelines:
1. Explain what the anomaly likely represents
2. Reference specific threat intelligence when available
3. Use MITRE ATT&CK technique IDs when relevant
4. Be concise but informative
5. Focus on actionable insights

Format your response as a clear explanation (2-3 sentences) followed by key indicators."""),
            ("human", f"""Analyze this security anomaly:

{anomaly_desc}

Retrieved Threat Intelligence:
{context}

Provide a clear explanation of what this anomaly likely represents, referencing the threat intelligence above when relevant.""")
        ])
        
        try:
            messages = prompt.format_messages()
            response = self.llm.invoke(messages)
            
            # Handle different response formats
            if hasattr(response, 'content'):
                explanation = response.content
            elif isinstance(response, str):
                explanation = response
            elif hasattr(response, 'text'):
                explanation = response.text
            else:
                explanation = str(response)
            
            # Clean up the explanation (remove any JSON artifacts)
            if explanation.startswith('```'):
                # Remove markdown code blocks if present
                explanation = explanation.split('```')[1]
                if explanation.startswith('json'):
                    explanation = explanation[4:]
                explanation = explanation.strip()
            
            return explanation.strip()
            
        except Exception as e:
            import traceback
            error_detail = str(e)
            # Provide more helpful error message
            if "is_off_hours" in error_detail or "JSON" in error_detail:
                print(f" LLM call failed (formatting issue): {type(e).__name__}")
                print(f"   Falling back to template-based explanation")
            else:
                print(f" LLM call failed: {error_detail}")
                if os.getenv("DEBUG", "").lower() == "true":
                    traceback.print_exc()
            
            return self._generate_template_explanation(
                anomaly, threat_results, cve_results, incident_results
            )
    
    def _generate_template_explanation(
        self,
        anomaly: Dict,
        threat_results: List[Dict],
        cve_results: List[Dict],
        incident_results: List[Dict]
    ) -> str:
        """Generate explanation using templates (fallback when LLM unavailable)"""
        
        action = anomaly.get("action", "activity")
        severity = anomaly.get("severity", "medium")
        status = anomaly.get("status", "")
        
        explanation_parts = [
            f"Detected {severity.upper()} severity anomaly: {action}"
        ]
        
        if status in ["failed", "denied"]:
            explanation_parts.append(
                "Multiple failed authentication attempts detected, suggesting potential "
                "brute force or credential stuffing attack."
            )
        
        if threat_results:
            best_match = threat_results[0]
            title = best_match.get("metadata", {}).get("title", "")
            if title:
                explanation_parts.append(
                    f"This pattern matches known threat: {title}"
                )
        
        if cve_results:
            explanation_parts.append(
                f"Related to {len(cve_results)} known vulnerability(ies) in threat database."
            )
        
        if incident_results:
            explanation_parts.append(
                f"Similar to {len(incident_results)} past security incident(s)."
            )
        
        return " ".join(explanation_parts)
    
    def _extract_techniques(self, threat_results: List[Dict]) -> List[str]:
        """Extract MITRE ATT&CK technique IDs from results"""
        techniques = []
        for result in threat_results:
            metadata = result.get("metadata", {})
            # Try to extract technique ID from document or metadata
            doc = result.get("document", "")
            if "T" in doc and len(doc.split("T")[1].split()[0]) <= 5:
                # Simple heuristic to find technique IDs like T1078
                parts = doc.split()
                for part in parts:
                    if part.startswith("T") and len(part) <= 6:
                        techniques.append(part)
        return list(set(techniques))[:5]  # Return unique, limit to 5
    
    def _extract_recommendations(
        self,
        threat_results: List[Dict],
        cve_results: List[Dict],
        incident_results: List[Dict]
    ) -> List[str]:
        """Extract recommended actions from retrieved context"""
        recommendations = []
        
        # Extract from threat intelligence
        for result in threat_results:
            doc = result.get("document", "")
            if "mitigation" in doc.lower() or "recommend" in doc.lower():
                # Simple extraction - look for action verbs
                lines = doc.split("\n")
                for line in lines:
                    if any(word in line.lower() for word in ["enable", "implement", "apply", "update"]):
                        if len(line) < 100:  # Keep it concise
                            recommendations.append(line.strip())
        
        # Default recommendations if none found
        if not recommendations:
            recommendations = [
                "Review authentication logs for suspicious patterns",
                "Consider implementing rate limiting",
                "Enable additional monitoring for this source"
            ]
        
        return recommendations[:5]  # Limit to 5
    
    def _classify_threat_type(
        self,
        anomaly: Dict,
        threat_results: List[Dict]
    ) -> str:
        """Classify the type of threat"""
        action = anomaly.get("action", "").lower()
        status = anomaly.get("status", "").lower()
        
        # Check retrieved threats for classification
        if threat_results:
            doc = threat_results[0].get("document", "").lower()
            if "credential" in doc or "brute force" in doc:
                return "credential_stuffing"
            if "phishing" in doc:
                return "phishing"
            if "privilege" in doc:
                return "privilege_escalation"
        
        # Classify based on anomaly characteristics
        if status in ["failed", "denied"] and "login" in action:
            return "credential_stuffing"
        if anomaly.get("features", {}).get("data_transfer_volume", 0) > 10_000_000:
            return "data_exfiltration"
        if anomaly.get("features", {}).get("is_off_hours"):
            return "suspicious_access"
        
        return "unknown_threat"
    
    def _format_citations(
        self,
        threat_results: List[Dict],
        cve_results: List[Dict],
        incident_results: List[Dict]
    ) -> List[Dict]:
        """Format citations for display"""
        citations = []
        
        for result in threat_results[:3]:
            metadata = result.get("metadata", {})
            citations.append({
                "type": "threat_intelligence",
                "title": metadata.get("title", "Threat Pattern"),
                "source": "MITRE ATT&CK",
                "similarity": 1.0 - result.get("distance", 0.5)
            })
        
        for result in cve_results[:2]:
            metadata = result.get("metadata", {})
            citations.append({
                "type": "cve",
                "cve_id": metadata.get("cve_id", "CVE-XXXX-XXXX"),
                "source": "NVD",
                "similarity": 1.0 - result.get("distance", 0.5)
            })
        
        return citations


if __name__ == "__main__":
    """Test the Threat Intelligence Agent"""
    print(" Testing Threat Intelligence Agent...")
    
    # Initialize RAG
    rag = ThreatIntelligenceRAG()
    
    # Add sample data if needed
    from rag.vector_store.chroma_setup import (
        create_sample_threat_documents,
        create_sample_cve_documents,
        create_sample_incident_reports
    )
    
    stats = rag.get_collection_stats()
    if stats['threats'] == 0:
        print(" Loading sample threat intelligence...")
        rag.add_threat_documents(create_sample_threat_documents())
        rag.add_cve_documents(create_sample_cve_documents())
        rag.add_incident_reports(create_sample_incident_reports())
        print(f"Loaded: {rag.get_collection_stats()}")
    
    # Initialize agent
    # Check if OPENAI_API_KEY is set
    import os
    has_api_key = bool(os.getenv("OPENAI_API_KEY"))
    use_llm = has_api_key  # Use LLM if API key is available
    
    if not has_api_key:
        print("  Note: OPENAI_API_KEY not set. Running in RAG-only mode.")
        print("  To enable LLM: Set OPENAI_API_KEY in .env file or environment")
    else:
        print("  OPENAI_API_KEY found. LLM will be used for reasoning.")
    
    agent = ThreatIntelligenceAgent(rag=rag, use_llm=use_llm)
    
    # Create sample anomaly
    sample_anomaly = {
        "action": "login",
        "status": "failed",
        "source_ip": "203.45.67.89",
        "severity": "high",
        "anomaly_score": -0.75,
        "features": {
            "is_off_hours": True,
            "failed_action": True,
            "data_transfer_volume": 0
        }
    }
    
    # Analyze
    print("\n Analyzing sample anomaly...")
    analysis = agent.analyze_threat(sample_anomaly)
    
    print("\n Analysis Results:")
    print(f"  Threat Type: {analysis['threat_type']}")
    print(f"  Confidence: {analysis['confidence']:.2%}")
    print(f"  Severity: {analysis['severity']}")
    print(f"\n  Explanation:\n  {analysis['explanation']}")
    print(f"\n  Matched Techniques: {analysis['matched_techniques']}")
    print(f"\n  Recommendations:")
    for i, rec in enumerate(analysis['recommendations'], 1):
        print(f"    {i}. {rec}")
    print(f"\n  Citations: {len(analysis['citations'])} sources")
    
    print("\nThreat Intelligence Agent test complete!")

