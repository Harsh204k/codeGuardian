"""
Static Analysis Entrypoint
Command-line interface for running static code analysis on datasets
"""
import argparse
import logging
import sys
from pathlib import Path
from datetime import datetime

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from src.static.analyzers.multi_analyzer import MultiAnalyzer


# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler('logs/static_analysis.log')
    ]
)

logger = logging.getLogger(__name__)


def main():
    """Main entrypoint for static analysis"""
    parser = argparse.ArgumentParser(
        description='Run static vulnerability analysis on code datasets',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Analyze training set only
  python src/static/run_static_analysis.py --split train
  
  # Analyze all splits
  python src/static/run_static_analysis.py --split all
  
  # Analyze with custom paths
  python src/static/run_static_analysis.py --split train \\
      --input-dir datasets/processed \\
      --output-dir src/static/outputs
  
  # Use more workers for faster processing
  python src/static/run_static_analysis.py --split all --workers 8
        """
    )
    
    parser.add_argument(
        '--split',
        type=str,
        required=True,
        choices=['train', 'val', 'test', 'all'],
        help='Dataset split to analyze (train, val, test, or all)'
    )
    
    parser.add_argument(
        '--input-dir',
        type=Path,
        default=Path('datasets/processed'),
        help='Directory containing input JSONL files (default: datasets/processed)'
    )
    
    parser.add_argument(
        '--output-dir',
        type=Path,
        default=Path('src/static/outputs'),
        help='Directory for output files (default: src/static/outputs)'
    )
    
    parser.add_argument(
        '--rules-dir',
        type=Path,
        default=Path('src/static/rules'),
        help='Directory containing YAML rule files (default: src/static/rules)'
    )
    
    parser.add_argument(
        '--workers',
        type=int,
        default=4,
        help='Number of parallel workers (default: 4)'
    )
    
    parser.add_argument(
        '--batch-size',
        type=int,
        default=100,
        help='Batch size for processing (default: 100)'
    )
    
    parser.add_argument(
        '--export',
        action='store_true',
        help='Export results in additional formats'
    )
    
    parser.add_argument(
        '--verbose',
        action='store_true',
        help='Enable verbose logging'
    )
    
    args = parser.parse_args()
    
    # Set logging level
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    # Validate paths
    if not args.input_dir.exists():
        logger.error(f"Input directory not found: {args.input_dir}")
        sys.exit(1)
    
    if not args.rules_dir.exists():
        logger.error(f"Rules directory not found: {args.rules_dir}")
        sys.exit(1)
    
    # Initialize multi-analyzer
    logger.info("=" * 80)
    logger.info("CodeGuardian Static Analysis Module - Phase 3")
    logger.info("=" * 80)
    logger.info(f"Start time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    logger.info(f"Input directory: {args.input_dir}")
    logger.info(f"Output directory: {args.output_dir}")
    logger.info(f"Rules directory: {args.rules_dir}")
    logger.info(f"Workers: {args.workers}")
    
    try:
        multi_analyzer = MultiAnalyzer(
            rules_dir=args.rules_dir,
            max_workers=args.workers
        )
    except Exception as e:
        logger.error(f"Failed to initialize analyzer: {e}")
        sys.exit(1)
    
    # Determine which splits to analyze
    if args.split == 'all':
        splits = ['train', 'val', 'test']
    else:
        splits = [args.split]
    
    # Analyze each split
    all_stats = {}
    
    for split in splits:
        logger.info("=" * 80)
        logger.info(f"Analyzing {split} split...")
        logger.info("=" * 80)
        
        input_file = args.input_dir / f"{split}.jsonl"
        
        if not input_file.exists():
            logger.warning(f"Input file not found: {input_file}, skipping")
            continue
        
        try:
            stats = multi_analyzer.analyze_dataset(
                dataset_path=input_file,
                output_dir=args.output_dir,
                batch_size=args.batch_size
            )
            
            all_stats[split] = stats
            
            # Print summary
            logger.info("")
            logger.info(f"{'='*80}")
            logger.info(f"Summary for {split} split:")
            logger.info(f"{'='*80}")
            logger.info(f"  Total records: {stats['total_records']}")
            logger.info(f"  Analyzed: {stats['analyzed']}")
            logger.info(f"  Skipped: {stats['skipped']}")
            logger.info(f"  Total vulnerabilities: {stats['total_vulnerabilities']}")
            logger.info(f"  Unique CWEs: {len(stats['unique_cwes'])}")
            logger.info(f"  CWE list: {', '.join(stats['unique_cwes'][:10])}...")
            logger.info("")
            logger.info("  Per-language statistics:")
            for lang, lang_stats in stats['languages'].items():
                logger.info(f"    {lang}:")
                logger.info(f"      Records: {lang_stats['total_records']}")
                logger.info(f"      Vulnerabilities: {lang_stats['total_vulnerabilities']}")
                logger.info(f"      Avg Complexity: {lang_stats['avg_complexity']:.2f}")
            logger.info(f"{'='*80}")
            logger.info("")
            
        except Exception as e:
            logger.error(f"Error analyzing {split} split: {e}", exc_info=True)
            continue
    
    # Final summary
    logger.info("=" * 80)
    logger.info("Static Analysis Complete!")
    logger.info("=" * 80)
    logger.info(f"End time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    
    if all_stats:
        total_records = sum(s['total_records'] for s in all_stats.values())
        total_analyzed = sum(s['analyzed'] for s in all_stats.values())
        total_vulns = sum(s['total_vulnerabilities'] for s in all_stats.values())
        
        logger.info("")
        logger.info("Overall Statistics:")
        logger.info(f"  Total records processed: {total_records}")
        logger.info(f"  Total analyzed: {total_analyzed}")
        logger.info(f"  Total vulnerabilities detected: {total_vulns}")
        logger.info("")
        logger.info(f"Output files saved to: {args.output_dir}")
        logger.info(f"  - static_flags_*.csv (for ML model)")
        logger.info(f"  - static_analysis_*.jsonl (full results)")
        logger.info(f"  - logs/analyzer_report_*.json (vulnerability reports)")
        logger.info(f"  - logs/analysis_stats_*.json (statistics)")
    
    logger.info("=" * 80)
    logger.info("Next steps:")
    logger.info("  1. Review vulnerability reports in outputs/logs/")
    logger.info("  2. Use static_flags_*.csv as input to XGBoost fusion model")
    logger.info("  3. Analyze CWE distribution and detection accuracy")
    logger.info("=" * 80)


if __name__ == '__main__':
    main()
