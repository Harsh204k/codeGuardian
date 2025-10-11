#!/usr/bin/env python3
"""
Google Drive Sync Module for MegaVul Preprocessing
===================================================

Handles Google Drive mounting, upload, download, and verification for processed
chunks. Critical for Kaggle Free Tier sessions with limited 20GB disk space.

Features:
    - Automatic Drive mounting (Colab/Kaggle compatible)
    - SHA-256 checksum verification
    - Retry logic with exponential backoff
    - Safe deletion after upload verification
    - Progress tracking and logging

Author: CodeGuardian Team
Date: 2025-10-11
"""

import os
import hashlib
import logging
import time
import shutil
from pathlib import Path
from typing import Optional, List, Dict, Any
from datetime import datetime

logger = logging.getLogger(__name__)


class DriveSync:
    """
    Manages Google Drive synchronization for processed chunks.
    
    Ensures data persistence across Kaggle sessions by uploading chunks to
    Drive and verifying integrity before local deletion.
    """
    
    def __init__(
        self,
        drive_root: str = "/content/drive/MyDrive/codeGuardian/MegaVulProcessed",
        verify_checksum: bool = True,
        max_retries: int = 3,
        retry_delay: int = 5,
        delete_after_upload: bool = True
    ):
        """
        Initialize Drive sync manager.
        
        Args:
            drive_root: Root directory in Google Drive
            verify_checksum: Enable SHA-256 verification
            max_retries: Maximum upload retry attempts
            retry_delay: Seconds between retries
            delete_after_upload: Delete local files after successful upload
        """
        self.drive_root = Path(drive_root)
        self.verify_checksum = verify_checksum
        self.max_retries = max_retries
        self.retry_delay = retry_delay
        self.delete_after_upload = delete_after_upload
        
        self.drive_mounted = False
        self.upload_log = []
        
        logger.info(f"DriveSync initialized: {self.drive_root}")
        logger.info(f"Checksum verification: {self.verify_checksum}")
        logger.info(f"Delete after upload: {self.delete_after_upload}")
    
    def mount_drive(self, force_remount: bool = False) -> bool:
        """
        Mount Google Drive (Colab/Kaggle compatible).
        
        Args:
            force_remount: Force remount even if already mounted
            
        Returns:
            True if mounted successfully
        """
        # Check if already mounted
        if self.drive_mounted and not force_remount:
            logger.info("Drive already mounted")
            return True
        
        try:
            # Try Colab-style mounting first
            try:
                from google.colab import drive
                drive.mount('/content/drive', force_remount=force_remount)
                logger.info("✅ Google Drive mounted (Colab)")
                self.drive_mounted = True
                
            except ImportError:
                # Kaggle environment - check if Drive is accessible
                if Path("/content/drive").exists() or Path(self.drive_root).exists():
                    logger.info("✅ Google Drive accessible (Kaggle)")
                    self.drive_mounted = True
                else:
                    logger.warning("⚠️ Drive not accessible - uploads will be skipped")
                    logger.warning("   Run on Colab or manually mount Drive in Kaggle")
                    self.drive_mounted = False
                    return False
            
            # Create directory structure
            if self.drive_mounted:
                self.drive_root.mkdir(parents=True, exist_ok=True)
                
                # Create subdirectories
                (self.drive_root / "logs").mkdir(exist_ok=True)
                (self.drive_root / "chunks").mkdir(exist_ok=True)
                (self.drive_root / "merged").mkdir(exist_ok=True)
                
                logger.info(f"Directory structure created: {self.drive_root}")
            
            return self.drive_mounted
            
        except Exception as e:
            logger.error(f"Failed to mount Drive: {e}")
            self.drive_mounted = False
            return False
    
    def compute_checksum(self, file_path: Path) -> str:
        """
        Compute SHA-256 checksum of a file.
        
        Args:
            file_path: Path to file
            
        Returns:
            Hexadecimal checksum string
        """
        sha256 = hashlib.sha256()
        
        with open(file_path, 'rb') as f:
            while True:
                chunk = f.read(8192)
                if not chunk:
                    break
                sha256.update(chunk)
        
        return sha256.hexdigest()
    
    def upload_file(
        self,
        local_path: Path,
        remote_subdir: str = "chunks",
        remote_name: Optional[str] = None
    ) -> Optional[Path]:
        """
        Upload a file to Google Drive with retry logic.
        
        Args:
            local_path: Path to local file
            remote_subdir: Subdirectory in Drive root (chunks, merged, logs)
            remote_name: Custom filename (default: keep original name)
            
        Returns:
            Path to uploaded file in Drive, or None if failed
        """
        local_path = Path(local_path)
        
        if not local_path.exists():
            logger.error(f"Local file not found: {local_path}")
            return None
        
        # Ensure Drive is mounted
        if not self.drive_mounted:
            if not self.mount_drive():
                logger.error("Cannot upload - Drive not mounted")
                return None
        
        # Determine remote path
        remote_dir = self.drive_root / remote_subdir
        remote_dir.mkdir(parents=True, exist_ok=True)
        
        remote_filename = remote_name if remote_name else local_path.name
        remote_path = remote_dir / remote_filename
        
        # Compute checksum before upload
        local_checksum = None
        if self.verify_checksum:
            logger.info(f"Computing checksum for {local_path.name}...")
            local_checksum = self.compute_checksum(local_path)
            logger.info(f"Local checksum: {local_checksum}")
        
        # Upload with retry logic
        for attempt in range(1, self.max_retries + 1):
            try:
                logger.info(f"Uploading {local_path.name} (attempt {attempt}/{self.max_retries})")
                
                # Copy file to Drive
                shutil.copy2(local_path, remote_path)
                
                file_size_mb = remote_path.stat().st_size / (1024 * 1024)
                logger.info(f"✅ Uploaded: {remote_path.name} ({file_size_mb:.2f} MB)")
                
                # Verify checksum if enabled
                if self.verify_checksum:
                    logger.info(f"Verifying checksum...")
                    remote_checksum = self.compute_checksum(remote_path)
                    
                    if local_checksum == remote_checksum:
                        logger.info(f"✅ Checksum verified: {remote_checksum}")
                    else:
                        logger.error(f"❌ Checksum mismatch!")
                        logger.error(f"   Local:  {local_checksum}")
                        logger.error(f"   Remote: {remote_checksum}")
                        
                        # Delete corrupted file
                        remote_path.unlink()
                        
                        if attempt < self.max_retries:
                            logger.info(f"Retrying in {self.retry_delay}s...")
                            time.sleep(self.retry_delay)
                            continue
                        else:
                            return None
                
                # Log successful upload
                self.upload_log.append({
                    "timestamp": datetime.now().isoformat(),
                    "local_path": str(local_path),
                    "remote_path": str(remote_path),
                    "size_mb": file_size_mb,
                    "checksum": local_checksum,
                    "status": "success"
                })
                
                # Delete local file if configured
                if self.delete_after_upload:
                    logger.info(f"Deleting local file: {local_path.name}")
                    local_path.unlink()
                
                return remote_path
                
            except Exception as e:
                logger.error(f"Upload attempt {attempt} failed: {e}")
                
                if attempt < self.max_retries:
                    logger.info(f"Retrying in {self.retry_delay}s...")
                    time.sleep(self.retry_delay)
                else:
                    logger.error(f"All upload attempts failed for {local_path.name}")
                    
                    self.upload_log.append({
                        "timestamp": datetime.now().isoformat(),
                        "local_path": str(local_path),
                        "status": "failed",
                        "error": str(e)
                    })
                    
                    return None
    
    def download_file(
        self,
        remote_path: Path,
        local_dir: Path,
        verify: bool = True
    ) -> Optional[Path]:
        """
        Download a file from Google Drive.
        
        Args:
            remote_path: Path to file in Drive
            local_dir: Local directory for download
            verify: Verify checksum after download
            
        Returns:
            Path to downloaded file, or None if failed
        """
        remote_path = Path(remote_path)
        local_dir = Path(local_dir)
        
        if not self.drive_mounted:
            if not self.mount_drive():
                logger.error("Cannot download - Drive not mounted")
                return None
        
        if not remote_path.exists():
            logger.error(f"Remote file not found: {remote_path}")
            return None
        
        local_dir.mkdir(parents=True, exist_ok=True)
        local_path = local_dir / remote_path.name
        
        try:
            # Compute remote checksum if verification enabled
            remote_checksum = None
            if verify:
                logger.info(f"Computing remote checksum...")
                remote_checksum = self.compute_checksum(remote_path)
            
            # Download file
            logger.info(f"Downloading {remote_path.name}...")
            shutil.copy2(remote_path, local_path)
            
            file_size_mb = local_path.stat().st_size / (1024 * 1024)
            logger.info(f"✅ Downloaded: {local_path.name} ({file_size_mb:.2f} MB)")
            
            # Verify checksum
            if verify and remote_checksum:
                logger.info(f"Verifying checksum...")
                local_checksum = self.compute_checksum(local_path)
                
                if local_checksum == remote_checksum:
                    logger.info(f"✅ Checksum verified")
                else:
                    logger.error(f"❌ Checksum mismatch after download!")
                    local_path.unlink()
                    return None
            
            return local_path
            
        except Exception as e:
            logger.error(f"Download failed: {e}")
            return None
    
    def list_remote_files(
        self,
        subdir: str = "chunks",
        pattern: str = "*.jsonl*"
    ) -> List[Path]:
        """
        List files in Drive directory.
        
        Args:
            subdir: Subdirectory to list
            pattern: Glob pattern for filtering
            
        Returns:
            List of file paths
        """
        if not self.drive_mounted:
            if not self.mount_drive():
                logger.error("Cannot list files - Drive not mounted")
                return []
        
        remote_dir = self.drive_root / subdir
        
        if not remote_dir.exists():
            logger.warning(f"Directory not found: {remote_dir}")
            return []
        
        files = sorted(remote_dir.glob(pattern))
        logger.info(f"Found {len(files)} files in {subdir}/ matching {pattern}")
        
        return files
    
    def get_disk_usage(self) -> Dict[str, Any]:
        """
        Get disk usage statistics for Drive directory.
        
        Returns:
            Dictionary with usage statistics
        """
        if not self.drive_mounted:
            if not self.mount_drive():
                return {"error": "Drive not mounted"}
        
        if not self.drive_root.exists():
            return {"error": "Drive directory not found"}
        
        total_size = 0
        file_count = 0
        
        for file_path in self.drive_root.rglob("*"):
            if file_path.is_file():
                total_size += file_path.stat().st_size
                file_count += 1
        
        return {
            "total_size_mb": total_size / (1024 * 1024),
            "total_size_gb": total_size / (1024 * 1024 * 1024),
            "file_count": file_count,
            "directory": str(self.drive_root)
        }
    
    def save_upload_log(self, log_path: Optional[Path] = None) -> Path:
        """
        Save upload log to Drive.
        
        Args:
            log_path: Custom log path (default: auto-generated in Drive)
            
        Returns:
            Path to saved log file
        """
        if not log_path:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            log_path = self.drive_root / "logs" / f"upload_log_{timestamp}.json"
        
        log_path = Path(log_path)
        log_path.parent.mkdir(parents=True, exist_ok=True)
        
        import json
        with open(log_path, 'w') as f:
            json.dump(self.upload_log, f, indent=2)
        
        logger.info(f"Upload log saved: {log_path}")
        return log_path
    
    def cleanup_local_chunks(self, local_dir: Path, keep_latest: int = 0):
        """
        Clean up local chunks after successful upload.
        
        Args:
            local_dir: Local directory containing chunks
            keep_latest: Number of latest chunks to keep (0 = delete all)
        """
        local_dir = Path(local_dir)
        
        if not local_dir.exists():
            logger.warning(f"Directory not found: {local_dir}")
            return
        
        chunk_files = sorted(local_dir.glob("chunk_*.jsonl*"))
        
        if keep_latest > 0:
            files_to_delete = chunk_files[:-keep_latest]
        else:
            files_to_delete = chunk_files
        
        deleted_count = 0
        freed_mb = 0
        
        for file_path in files_to_delete:
            try:
                file_size = file_path.stat().st_size / (1024 * 1024)
                file_path.unlink()
                deleted_count += 1
                freed_mb += file_size
                logger.info(f"Deleted: {file_path.name}")
            except Exception as e:
                logger.error(f"Failed to delete {file_path.name}: {e}")
        
        logger.info(f"✅ Cleaned up {deleted_count} files, freed {freed_mb:.2f} MB")


def test_drive_sync():
    """Test Drive sync functionality."""
    import tempfile
    import json
    
    # Create test file
    test_dir = Path(tempfile.mkdtemp())
    test_file = test_dir / "test_chunk.jsonl"
    
    test_data = [{"id": i, "code": f"test_{i}"} for i in range(100)]
    with open(test_file, 'w') as f:
        for record in test_data:
            f.write(json.dumps(record) + '\n')
    
    logger.info(f"Test file created: {test_file}")
    
    # Initialize DriveSync
    drive = DriveSync(
        drive_root="/content/drive/MyDrive/codeGuardian/MegaVulTest",
        delete_after_upload=False  # Keep for testing
    )
    
    # Test mounting
    logger.info("\n=== Testing Drive Mount ===")
    if drive.mount_drive():
        logger.info("✅ Drive mounted successfully")
    else:
        logger.warning("⚠️ Drive not mounted - skipping upload tests")
        return
    
    # Test checksum
    logger.info("\n=== Testing Checksum ===")
    checksum = drive.compute_checksum(test_file)
    logger.info(f"Checksum: {checksum}")
    
    # Test upload
    logger.info("\n=== Testing Upload ===")
    remote_path = drive.upload_file(test_file, remote_subdir="test_chunks")
    
    if remote_path:
        logger.info(f"✅ Upload successful: {remote_path}")
        
        # Test download
        logger.info("\n=== Testing Download ===")
        download_dir = test_dir / "downloads"
        local_path = drive.download_file(remote_path, download_dir)
        
        if local_path:
            logger.info(f"✅ Download successful: {local_path}")
    
    # Test listing
    logger.info("\n=== Testing File Listing ===")
    files = drive.list_remote_files("test_chunks")
    for f in files:
        logger.info(f"Found: {f.name}")
    
    # Test disk usage
    logger.info("\n=== Testing Disk Usage ===")
    usage = drive.get_disk_usage()
    logger.info(f"Total size: {usage.get('total_size_mb', 0):.2f} MB")
    logger.info(f"File count: {usage.get('file_count', 0)}")
    
    logger.info("\n✅ Drive sync tests complete")


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
    test_drive_sync()
