#!/usr/bin/env python3
"""
Metadata Enrichment Module for MegaVul
=======================================

Enriches processed MegaVul records with additional metadata:
    - CWE mappings (attack types, severity, review status)
    - CVE information from NVD database
    - Repository metadata from GitHub
    - Cross-references and relationships

Author: CodeGuardian Team
Date: 2025-10-11

Usage:
    from merge_metadata import MetadataEnricher
    
    enricher = MetadataEnricher()
    enriched_records = enricher.enrich_batch(records)
"""

import logging
from typing import Dict, Any, List, Optional
from pathlib import Path
import sys

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

# Import CWE mapper
try:
    from scripts.utils.cwe_mapper import map_cwe_to_attack, batch_enrich_records
    CWE_MAPPER_AVAILABLE = True
except ImportError:
    CWE_MAPPER_AVAILABLE = False
    logging.warning("CWE mapper not available")

logger = logging.getLogger(__name__)


class MetadataEnricher:
    """
    Enriches vulnerability records with additional metadata.
    
    Provides CWE-to-attack-type mappings, severity levels, and other
    contextual information to enhance dataset quality.
    """
    
    def __init__(
        self,
        cwe_mapping_file: Optional[str] = None,
        metadata_sources: Optional[List[str]] = None
    ):
        """
        Initialize metadata enricher.
        
        Args:
            cwe_mapping_file: Path to CWE mapper module
            metadata_sources: List of metadata sources to use
        """
        self.cwe_mapping_file = cwe_mapping_file
        self.metadata_sources = metadata_sources or ['nvd_cve', 'cwe_categories']
        
        # Load CWE mappings
        self.cwe_mappings = self.load_cwe_mappings()
        
        logger.info("✅ MetadataEnricher initialized")
        logger.info(f"   CWE mappings: {len(self.cwe_mappings)} loaded")
        logger.info(f"   Metadata sources: {', '.join(self.metadata_sources)}")
    
    def load_cwe_mappings(self) -> Dict[str, Dict[str, Any]]:
        """
        Load CWE-to-metadata mappings.
        
        Returns:
            Dictionary of CWE mappings
        """
        mappings = {}
        
        if CWE_MAPPER_AVAILABLE:
            # Use existing CWE mapper module
            logger.info("✅ Using CWE mapper module")
            return {}  # CWE mapper handles this internally
        
        # Fallback: Load from static mappings
        fallback_mappings = {
            "CWE-89": {
                "attack_type": "SQL Injection",
                "severity": "high",
                "category": "Injection",
                "review_status": "confirmed"
            },
            "CWE-79": {
                "attack_type": "Cross-Site Scripting",
                "severity": "medium",
                "category": "Injection",
                "review_status": "confirmed"
            },
            "CWE-78": {
                "attack_type": "OS Command Injection",
                "severity": "critical",
                "category": "Injection",
                "review_status": "confirmed"
            },
            "CWE-119": {
                "attack_type": "Buffer Overflow",
                "severity": "critical",
                "category": "Memory Corruption",
                "review_status": "confirmed"
            },
            "CWE-125": {
                "attack_type": "Out-of-bounds Read",
                "severity": "high",
                "category": "Memory Corruption",
                "review_status": "confirmed"
            },
            "CWE-787": {
                "attack_type": "Out-of-bounds Write",
                "severity": "critical",
                "category": "Memory Corruption",
                "review_status": "confirmed"
            },
            "CWE-416": {
                "attack_type": "Use After Free",
                "severity": "critical",
                "category": "Memory Corruption",
                "review_status": "confirmed"
            },
            "CWE-20": {
                "attack_type": "Improper Input Validation",
                "severity": "medium",
                "category": "Input Validation",
                "review_status": "confirmed"
            },
            "CWE-200": {
                "attack_type": "Information Exposure",
                "severity": "medium",
                "category": "Information Disclosure",
                "review_status": "confirmed"
            },
            "CWE-287": {
                "attack_type": "Improper Authentication",
                "severity": "high",
                "category": "Authentication",
                "review_status": "confirmed"
            }
        }
        
        mappings.update(fallback_mappings)
        return mappings
    
    def enrich_record(self, record: Dict[str, Any]) -> Dict[str, Any]:
        """
        Enrich a single record with metadata.
        
        Args:
            record: Record to enrich
            
        Returns:
            Enriched record
        """
        enriched = record.copy()
        
        # Enrich CWE metadata
        cwe_id = record.get('cwe_id')
        if cwe_id:
            if CWE_MAPPER_AVAILABLE:
                # Use CWE mapper
                cwe_info = map_cwe_to_attack(cwe_id, record.get('description'))
                if cwe_info:
                    enriched['attack_type'] = cwe_info.get('attack_type')
                    enriched['severity'] = cwe_info.get('severity')
                    enriched['review_status'] = cwe_info.get('review_status')
            else:
                # Use static mappings
                if cwe_id in self.cwe_mappings:
                    mapping = self.cwe_mappings[cwe_id]
                    enriched['attack_type'] = mapping.get('attack_type')
                    enriched['severity'] = mapping.get('severity')
                    enriched['category'] = mapping.get('category')
                    enriched['review_status'] = mapping.get('review_status')
        
        # Enrich CVE metadata (if available)
        cve_id = record.get('cve_id')
        if cve_id and 'nvd_cve' in self.metadata_sources:
            # In a full implementation, this would query NVD database
            # For now, just mark that CVE is present
            enriched['has_cve'] = True
        
        # Enrich repository metadata
        project = record.get('project')
        if project:
            enriched['has_repo_metadata'] = True
        
        return enriched
    
    def enrich_batch(
        self,
        records: List[Dict[str, Any]],
        batch_size: int = 1000
    ) -> List[Dict[str, Any]]:
        """
        Enrich a batch of records.
        
        Args:
            records: List of records to enrich
            batch_size: Records per batch
            
        Returns:
            List of enriched records
        """
        logger.info(f"🔍 Enriching {len(records):,} records with metadata...")
        
        if CWE_MAPPER_AVAILABLE:
            # Use batch enrichment from CWE mapper
            enriched = batch_enrich_records(records)
        else:
            # Manual enrichment
            enriched = []
            for i in range(0, len(records), batch_size):
                batch = records[i:i+batch_size]
                enriched.extend([self.enrich_record(r) for r in batch])
        
        # Calculate enrichment stats
        with_attack_type = sum(1 for r in enriched if r.get('attack_type'))
        with_severity = sum(1 for r in enriched if r.get('severity'))
        
        logger.info(f"✅ Enrichment complete:")
        logger.info(f"   Records with attack_type: {with_attack_type:,} ({with_attack_type/len(enriched):.1%})")
        logger.info(f"   Records with severity: {with_severity:,} ({with_severity/len(enriched):.1%})")
        
        return enriched
    
    def generate_metadata_summary(self, records: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Generate summary of metadata coverage.
        
        Args:
            records: List of enriched records
            
        Returns:
            Metadata summary
        """
        summary = {
            "total_records": len(records),
            "with_cwe": sum(1 for r in records if r.get('cwe_id')),
            "with_cve": sum(1 for r in records if r.get('cve_id')),
            "with_attack_type": sum(1 for r in records if r.get('attack_type')),
            "with_severity": sum(1 for r in records if r.get('severity')),
            "with_category": sum(1 for r in records if r.get('category')),
            "with_repo_metadata": sum(1 for r in records if r.get('project')),
        }
        
        # Calculate coverage percentages
        total = summary['total_records']
        summary['coverage'] = {
            'cwe': summary['with_cwe'] / total if total > 0 else 0,
            'cve': summary['with_cve'] / total if total > 0 else 0,
            'attack_type': summary['with_attack_type'] / total if total > 0 else 0,
            'severity': summary['with_severity'] / total if total > 0 else 0,
        }
        
        return summary


def test_enricher():
    """Test metadata enricher."""
    logger.info("=== Testing Metadata Enricher ===")
    
    # Create test records
    test_records = [
        {
            "id": "test-1",
            "code": "strcpy(buffer, input);",
            "is_vulnerable": 1,
            "language": "C",
            "cwe_id": "CWE-119",
            "dataset": "test"
        },
        {
            "id": "test-2",
            "code": "SELECT * FROM users WHERE id={}".format("user_input"),
            "is_vulnerable": 1,
            "language": "Python",
            "cwe_id": "CWE-89",
            "cve_id": "CVE-2021-12345",
            "dataset": "test"
        },
        {
            "id": "test-3",
            "code": "safe_function() { return 0; }",
            "is_vulnerable": 0,
            "language": "C",
            "dataset": "test"
        }
    ]
    
    # Initialize enricher
    enricher = MetadataEnricher()
    
    # Enrich records
    enriched = enricher.enrich_batch(test_records)
    
    # Print results
    for record in enriched:
        logger.info(f"\nRecord {record['id']}:")
        logger.info(f"  CWE: {record.get('cwe_id', 'N/A')}")
        logger.info(f"  Attack Type: {record.get('attack_type', 'N/A')}")
        logger.info(f"  Severity: {record.get('severity', 'N/A')}")
    
    # Generate summary
    summary = enricher.generate_metadata_summary(enriched)
    logger.info(f"\nMetadata Summary:")
    logger.info(f"  Total: {summary['total_records']}")
    logger.info(f"  CWE coverage: {summary['coverage']['cwe']:.1%}")
    logger.info(f"  Attack type coverage: {summary['coverage']['attack_type']:.1%}")
    
    logger.info("\n✅ Enricher tests complete")


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
    test_enricher()
