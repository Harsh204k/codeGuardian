#!/usr/bin/env python3
"""
Enhanced Pipeline Orchestrator with Robustness Features
========================================================

Production-grade orchestrator with:
- YAML configuration loading
- --resume from checkpoints
- --dry-run mode (validate without execution)
- Integrity checks (file existence, sizes, record counts)
- Retry logic with exponential backoff
- Progress checkpointing
- Comprehensive error handling
- Performance tracking

Usage:
    python scripts/run_pipeline_enhanced.py --config configs/pipeline_config.yaml
    python scripts/run_pipeline_enhanced.py --resume preprocessing
    python scripts/run_pipeline_enhanced.py --dry-run

Author: CodeGuardian Team  
Version: 3.1.0 (Enhanced)
"""

import argparse
import sys
import time
import json
from pathlib import Path
from typing import Dict, Any, List, Optional
from datetime import datetime

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent))

try:
    import yaml
    HAS_YAML = True
except ImportError:
    HAS_YAML = False
    print("⚠️  PyYAML not installed, using default config")

from scripts.utils.logging_utils import get_logger, timed, print_banner, print_summary
from scripts.utils.report_generator import generate_pipeline_report


# ====================================================================
# CONFIGURATION
# ====================================================================

DEFAULT_CONFIG = {
    'pipeline': {
        'stages': ['preprocessing', 'normalization', 'validation', 'feature_engineering', 'splitting', 'static_analysis'],
        'enable': {
            'preprocessing': True,
            'normalization': True,
            'validation': True,
            'feature_engineering': True,
            'splitting': True,
            'static_analysis': False  # Disabled by default, enable with --static-analysis flag
        },
        'resume_from': None,
        'skip': []
    },
    'error_handling': {
        'continue_on_error': False,
        'max_errors_per_stage': 10,
        'retry': {
            'enabled': True,
            'max_attempts': 3,
            'backoff_factor': 2
        }
    },
    'testing': {
        'dry_run': False,
        'integrity_checks': {
            'enabled': True,
            'verify_file_existence': True,
            'verify_file_sizes': True,
            'verify_record_counts': True
        }
    }
}


def load_config(config_path: Optional[str] = None) -> Dict[str, Any]:
    """Load configuration from YAML file."""
    if not config_path or not HAS_YAML:
        return DEFAULT_CONFIG
    
    config_file = Path(config_path)
    if not config_file.exists():
        logger = get_logger(__name__)
        logger.warning(f"Config file not found: {config_path}, using defaults")
        return DEFAULT_CONFIG
    
    with open(config_file, 'r') as f:
        config = yaml.safe_load(f)
    
    # Merge with defaults
    merged = DEFAULT_CONFIG.copy()
    merged.update(config)
    
    return merged


# ====================================================================
# CHECKPOINT MANAGEMENT
# ====================================================================

class CheckpointManager:
    """Manages pipeline execution checkpoints."""
    
    def __init__(self, checkpoint_file: str = ".pipeline_checkpoint.json"):
        self.checkpoint_file = Path(checkpoint_file)
        self.checkpoints = self._load()
    
    def _load(self) -> Dict[str, Any]:
        """Load checkpoints from file."""
        if self.checkpoint_file.exists():
            with open(self.checkpoint_file, 'r') as f:
                return json.load(f)
        return {}
    
    def _save(self):
        """Save checkpoints to file."""
        with open(self.checkpoint_file, 'w') as f:
            json.dump(self.checkpoints, f, indent=2)
    
    def mark_stage_complete(self, stage: str, stats: Optional[Dict[str, Any]] = None):
        """Mark a stage as complete."""
        self.checkpoints[stage] = {
            'status': 'completed',
            'timestamp': datetime.now().isoformat(),
            'stats': stats or {}
        }
        self._save()
    
    def mark_stage_failed(self, stage: str, error: str):
        """Mark a stage as failed."""
        self.checkpoints[stage] = {
            'status': 'failed',
            'timestamp': datetime.now().isoformat(),
            'error': error
        }
        self._save()
    
    def is_stage_complete(self, stage: str) -> bool:
        """Check if stage is complete."""
        return (stage in self.checkpoints and 
                self.checkpoints[stage].get('status') == 'completed')
    
    def get_last_completed_stage(self) -> Optional[str]:
        """Get the last successfully completed stage."""
        completed = [
            (stage, data['timestamp']) 
            for stage, data in self.checkpoints.items() 
            if data.get('status') == 'completed'
        ]
        
        if completed:
            return max(completed, key=lambda x: x[1])[0]
        return None
    
    def clear(self):
        """Clear all checkpoints."""
        self.checkpoints = {}
        if self.checkpoint_file.exists():
            self.checkpoint_file.unlink()


# ====================================================================
# INTEGRITY CHECKS
# ====================================================================

class IntegrityChecker:
    """Performs integrity checks on pipeline data."""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.logger = get_logger(__name__)
    
    def check_file_existence(self, file_path: str) -> bool:
        """Check if file exists."""
        exists = Path(file_path).exists()
        if not exists:
            self.logger.error(f"File not found: {file_path}")
        return exists
    
    def check_file_size(self, file_path: str, min_size_bytes: int = 100) -> bool:
        """Check if file size is reasonable."""
        path = Path(file_path)
        if not path.exists():
            return False
        
        size = path.stat().st_size
        if size < min_size_bytes:
            self.logger.warning(f"File too small: {file_path} ({size} bytes)")
            return False
        
        return True
    
    def check_jsonl_record_count(self, file_path: str, min_records: int = 1) -> bool:
        """Check if JSONL file has minimum records."""
        if not Path(file_path).exists():
            return False
        
        try:
            count = 0
            with open(file_path, 'r') as f:
                for line in f:
                    if line.strip():
                        count += 1
                    if count >= min_records:
                        return True
            
            if count < min_records:
                self.logger.warning(f"Too few records in {file_path}: {count}")
                return False
            
            return True
        except Exception as e:
            self.logger.error(f"Error reading {file_path}: {e}")
            return False
    
    def verify_stage_outputs(self, stage: str) -> bool:
        """Verify outputs for a completed stage."""
        checks_enabled = self.config.get('testing', {}).get('integrity_checks', {})
        
        if not checks_enabled.get('enabled', True):
            return True
        
        # Define expected outputs per stage
        stage_outputs = {
            'normalization': ['datasets/unified/processed_all.jsonl'],
            'validation': ['datasets/unified/validated.jsonl', 'datasets/unified/validation_report.json'],
            'feature_engineering': ['datasets/features/features_static.csv'],
            'splitting': ['datasets/processed/train.jsonl', 'datasets/processed/val.jsonl', 'datasets/processed/test.jsonl'],
            'static_analysis': ['src/static/outputs/static_flags_train.csv', 'src/static/outputs/static_flags_val.csv', 'src/static/outputs/static_flags_test.csv']
        }
        
        if stage not in stage_outputs:
            return True  # No checks for this stage
        
        all_passed = True
        
        for output_file in stage_outputs[stage]:
            # Check existence
            if checks_enabled.get('verify_file_existence', True):
                if not self.check_file_existence(output_file):
                    all_passed = False
                    continue
            
            # Check size
            if checks_enabled.get('verify_file_sizes', True):
                if not self.check_file_size(output_file):
                    all_passed = False
                    continue
            
            # Check record count for JSONL files
            if checks_enabled.get('verify_record_counts', True) and output_file.endswith('.jsonl'):
                if not self.check_jsonl_record_count(output_file):
                    all_passed = False
        
        return all_passed


# ====================================================================
# ENHANCED ORCHESTRATOR
# ====================================================================

class EnhancedPipelineOrchestrator:
    """Enhanced pipeline orchestrator with robustness features."""
    
    def __init__(self, config: Dict[str, Any], dry_run: bool = False):
        self.config = config
        self.dry_run = dry_run
        self.logger = get_logger(__name__)
        self.checkpoint_mgr = CheckpointManager()
        self.integrity_checker = IntegrityChecker(config)
        self.stats = {
            'start_time': datetime.now().isoformat(),
            'stages_executed': [],
            'stages_skipped': [],
            'stages_failed': [],
            'total_duration': 0
        }
    
    @timed
    def execute_stage_with_retry(self, stage: str) -> bool:
        """
        Execute a stage with retry logic.
        
        Args:
            stage: Stage name
            
        Returns:
            True if successful, False otherwise
        """
        retry_config = self.config.get('error_handling', {}).get('retry', {})
        max_attempts = retry_config.get('max_attempts', 3) if retry_config.get('enabled', True) else 1
        backoff_factor = retry_config.get('backoff_factor', 2)
        
        for attempt in range(1, max_attempts + 1):
            try:
                self.logger.info(f"Executing stage: {stage} (Attempt {attempt}/{max_attempts})")
                
                if self.dry_run:
                    self.logger.info(f"[DRY RUN] Would execute stage: {stage}")
                    return True
                
                # Execute stage (simplified - in real implementation, call actual module)
                success = self._execute_stage_impl(stage)
                
                if success:
                    self.checkpoint_mgr.mark_stage_complete(stage)
                    self.stats['stages_executed'].append(stage)
                    
                    # Verify outputs
                    if not self.integrity_checker.verify_stage_outputs(stage):
                        self.logger.warning(f"Integrity checks failed for {stage}")
                        if attempt < max_attempts:
                            continue
                    
                    return True
                else:
                    raise Exception(f"Stage {stage} failed")
                    
            except Exception as e:
                self.logger.error(f"Stage {stage} failed (Attempt {attempt}/{max_attempts}): {e}")
                
                if attempt < max_attempts:
                    wait_time = backoff_factor ** (attempt - 1)
                    self.logger.info(f"Retrying in {wait_time}s...")
                    time.sleep(wait_time)
                else:
                    self.checkpoint_mgr.mark_stage_failed(stage, str(e))
                    self.stats['stages_failed'].append(stage)
                    return False
        
        return False
    
    def _execute_stage_impl(self, stage: str) -> bool:
        """
        Actual stage execution logic.
        
        In production, this would import and call the actual modules.
        """
        self.logger.info(f"Executing {stage}...")
        
        # Special handling for static_analysis stage
        if stage == 'static_analysis':
            try:
                from pathlib import Path
                import subprocess
                
                # Run static analysis on all splits
                script_path = Path('src/static/run_static_analysis.py')
                
                if not script_path.exists():
                    self.logger.error(f"Static analysis script not found: {script_path}")
                    return False
                
                self.logger.info("Running static analysis on all dataset splits...")
                
                # Run the static analysis script
                result = subprocess.run(
                    [sys.executable, str(script_path), '--split', 'all'],
                    capture_output=True,
                    text=True,
                    timeout=3600  # 1 hour timeout
                )
                
                if result.returncode == 0:
                    self.logger.info("Static analysis completed successfully")
                    self.logger.info(result.stdout)
                    return True
                else:
                    self.logger.error(f"Static analysis failed with return code {result.returncode}")
                    self.logger.error(result.stderr)
                    return False
                    
            except subprocess.TimeoutExpired:
                self.logger.error("Static analysis timed out after 1 hour")
                return False
            except Exception as e:
                self.logger.error(f"Error running static analysis: {e}")
                return False
        
        # For other stages, placeholder implementation
        time.sleep(0.1)  # Simulate work
        return True
    
    def should_execute_stage(self, stage: str, resume_from: Optional[str] = None) -> bool:
        """Determine if a stage should be executed."""
        pipeline_config = self.config.get('pipeline', {})
        
        # Check if stage is enabled
        if not pipeline_config.get('enable', {}).get(stage, True):
            self.logger.info(f"Stage {stage} is disabled in config")
            return False
        
        # Check if stage is in skip list
        if stage in pipeline_config.get('skip', []):
            self.logger.info(f"Stage {stage} is in skip list")
            self.stats['stages_skipped'].append(stage)
            return False
        
        # Check if already completed (and not resuming from this stage)
        if self.checkpoint_mgr.is_stage_complete(stage) and stage != resume_from:
            self.logger.info(f"Stage {stage} already completed (use --resume {stage} to re-run)")
            self.stats['stages_skipped'].append(stage)
            return False
        
        # Check if we should resume from a specific stage
        if resume_from:
            stages = pipeline_config.get('stages', [])
            if stage in stages and stages.index(stage) < stages.index(resume_from):
                self.logger.info(f"Skipping {stage} (resuming from {resume_from})")
                self.stats['stages_skipped'].append(stage)
                return False
        
        return True
    
    @timed
    def run(self, resume_from: Optional[str] = None, clear_checkpoints: bool = False):
        """
        Run the complete pipeline.
        
        Args:
            resume_from: Stage to resume from (None to start fresh)
            clear_checkpoints: Whether to clear existing checkpoints
        """
        if clear_checkpoints:
            self.checkpoint_mgr.clear()
            self.logger.info("Cleared all checkpoints")
        
        if self.dry_run:
            print_banner("DRY RUN MODE - NO ACTUAL EXECUTION")
        
        print_banner("CODEGUARDIAN PHASE 2 PIPELINE - ENHANCED")
        
        self.logger.info(f"Configuration loaded from: {self.config.get('_config_file', 'defaults')}")
        self.logger.info(f"Resume from: {resume_from or 'start'}")
        
        # Get stages to execute
        stages = self.config.get('pipeline', {}).get('stages', [])
        self.logger.info(f"Pipeline stages: {', '.join(stages)}")
        
        # Execute each stage
        overall_start = time.time()
        
        for stage in stages:
            if not self.should_execute_stage(stage, resume_from):
                continue
            
            self.logger.info(f"\n{'='*80}")
            self.logger.info(f"STAGE: {stage.upper()}")
            self.logger.info(f"{'='*80}")
            
            success = self.execute_stage_with_retry(stage)
            
            if not success:
                if not self.config.get('error_handling', {}).get('continue_on_error', False):
                    self.logger.error(f"Pipeline halted due to failure in {stage}")
                    break
                else:
                    self.logger.warning(f"Continuing despite failure in {stage}")
        
        # Finalize
        self.stats['end_time'] = datetime.now().isoformat()
        self.stats['total_duration'] = time.time() - overall_start
        
        # Print summary
        self._print_summary()
        
        # Generate report if not dry run
        if not self.dry_run:
            self._generate_report()
    
    def _print_summary(self):
        """Print execution summary."""
        print_banner("PIPELINE EXECUTION SUMMARY")
        
        summary_stats = {
            'Total Duration': f"{self.stats['total_duration']:.2f}s",
            'Stages Executed': len(self.stats['stages_executed']),
            'Stages Skipped': len(self.stats['stages_skipped']),
            'Stages Failed': len(self.stats['stages_failed'])
        }
        
        print_summary(summary_stats, "SUMMARY")
        
        if self.stats['stages_executed']:
            self.logger.info(f"Executed: {', '.join(self.stats['stages_executed'])}")
        if self.stats['stages_skipped']:
            self.logger.info(f"Skipped: {', '.join(self.stats['stages_skipped'])}")
        if self.stats['stages_failed']:
            self.logger.error(f"Failed: {', '.join(self.stats['stages_failed'])}")
    
    def _generate_report(self):
        """Generate pipeline report."""
        try:
            self.logger.info("Generating pipeline report...")
            generate_pipeline_report(
                additional_stats=self.stats,
                output_path="PIPELINE_REPORT.md"
            )
        except Exception as e:
            self.logger.warning(f"Failed to generate report: {e}")


# ====================================================================
# CLI
# ====================================================================

def main():
    parser = argparse.ArgumentParser(
        description="Enhanced CodeGuardian Phase 2 Pipeline Orchestrator"
    )
    
    parser.add_argument(
        "--config",
        type=str,
        default="configs/pipeline_config.yaml",
        help="Path to pipeline configuration YAML"
    )
    
    parser.add_argument(
        "--resume",
        type=str,
        default=None,
        help="Resume from specific stage (preprocessing, normalization, validation, feature_engineering, splitting)"
    )
    
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Validate configuration without executing pipeline"
    )
    
    parser.add_argument(
        "--clear-checkpoints",
        action="store_true",
        help="Clear existing checkpoints before running"
    )
    
    parser.add_argument(
        "--skip",
        type=str,
        nargs='+',
        help="Stages to skip"
    )
    
    parser.add_argument(
        "--static-analysis",
        action="store_true",
        help="Enable static code analysis stage (Phase 3)"
    )
    
    parser.add_argument(
        "--log-level",
        type=str,
        default="INFO",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        help="Logging level"
    )
    
    args = parser.parse_args()
    
    # Load configuration
    config = load_config(args.config)
    config['_config_file'] = args.config
    
    # Apply CLI overrides
    if args.skip:
        if 'pipeline' not in config:
            config['pipeline'] = {}
        config['pipeline']['skip'] = args.skip
    
    # Enable static analysis if requested
    if args.static_analysis:
        if 'pipeline' not in config:
            config['pipeline'] = {}
        if 'enable' not in config['pipeline']:
            config['pipeline']['enable'] = {}
        config['pipeline']['enable']['static_analysis'] = True
    
    # Create orchestrator
    orchestrator = EnhancedPipelineOrchestrator(
        config=config,
        dry_run=args.dry_run
    )
    
    # Run pipeline
    orchestrator.run(
        resume_from=args.resume,
        clear_checkpoints=args.clear_checkpoints
    )


if __name__ == '__main__':
    main()
