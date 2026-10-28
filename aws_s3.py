"""
AWS S3 Cloud Storage Integration Module for CloudSentinel.
Provides secure cloud archiving across four standardized S3 prefixes:
  - s3://<bucket>/datasets/  (Training and benchmark security telemetry)
  - s3://<bucket>/logs/      (Exported security event telemetry logs)
  - s3://<bucket>/reports/   (Executive security analytics and incident reports)
  - s3://<bucket>/backups/   (Encrypted database snapshot backups)

Safely discovers credentials via:
  1. EC2 IAM Instance Profile Role (Production Best Practice)
  2. Environment variables (AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY)
  3. AWS credential chain (~/.aws/credentials)
  4. Streamlit secrets (.streamlit/secrets.toml)

Enforces Server-Side Encryption (AES256) and degrades gracefully to Local Simulation Mode
with zero application crashes when unconfigured.
"""

from pathlib import Path
import os
import sys
from typing import Optional, Dict, Any, List, Tuple
from datetime import datetime
import boto3
from botocore.exceptions import ClientError, NoCredentialsError, EndpointConnectionError

BASE_DIR = Path(__file__).resolve().parent
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

# S3 configuration from environment variables (with secure defaults)
DEFAULT_REGION = os.getenv("AWS_DEFAULT_REGION", os.getenv("AWS_REGION", "ap-south-1"))
DEFAULT_BUCKET = os.getenv("CLOUDSENTINEL_S3_BUCKET", "cloudsentinel-security-vault")

# Standardized S3 Key Prefixes
PREFIX_DATASETS = "datasets/"
PREFIX_LOGS = "logs/"
PREFIX_REPORTS = "reports/"
PREFIX_BACKUPS = "backups/"


def get_s3_client():
    """
    Initializes and returns an S3 client using the standard AWS credential chain
    (IAM Role on EC2 -> Env Vars -> ~/.aws/credentials -> Streamlit secrets).
    Returns None if credentials cannot be resolved.
    """
    # 1. Check Streamlit secrets if running inside Streamlit
    try:
        import streamlit as st
        if hasattr(st, "secrets") and "aws" in st.secrets:
            aws_secrets = st.secrets["aws"]
            return boto3.client(
                "s3",
                aws_access_key_id=aws_secrets.get("aws_access_key_id"),
                aws_secret_access_key=aws_secrets.get("aws_secret_access_key"),
                region_name=aws_secrets.get("region", DEFAULT_REGION)
            )
    except Exception:
        pass

    # 2. Check environment variables
    has_key = bool(os.getenv("AWS_ACCESS_KEY_ID"))
    has_secret = bool(os.getenv("AWS_SECRET_ACCESS_KEY"))
    if has_key and has_secret:
        try:
            return boto3.client("s3", region_name=DEFAULT_REGION)
        except Exception as e:
            print(f"[AWS S3] Environment client initialization failed: {e}")
            return None

    # 3. Check EC2 IAM Instance Profile / default AWS credential chain
    try:
        session = boto3.Session()
        creds = session.get_credentials()
        if creds and creds.access_key:
            return session.client("s3", region_name=DEFAULT_REGION)
    except Exception:
        pass

    return None


def is_s3_configured() -> bool:
    """Returns True if AWS S3 client can be successfully initialized."""
    return get_s3_client() is not None


def get_s3_status() -> Dict[str, Any]:
    """
    Returns diagnostic connectivity status of AWS S3 cloud storage.
    Verifies bucket existence and permissions using HeadBucket.
    """
    bucket_name = os.getenv("CLOUDSENTINEL_S3_BUCKET", DEFAULT_BUCKET)
    region = DEFAULT_REGION

    client = get_s3_client()
    if not client:
        return {
            "configured": False,
            "bucket": bucket_name,
            "region": region,
            "encryption": "AES256 (Enforced when active)",
            "message": "AWS S3 is in Local Simulation Mode. Reports and backups are stored locally. Configure an EC2 IAM role or AWS credentials to activate cloud persistence."
        }

    try:
        client.head_bucket(Bucket=bucket_name)
        return {
            "configured": True,
            "bucket": bucket_name,
            "region": region,
            "encryption": "ServerSideEncryption=AES256",
            "message": f"Connected to AWS S3 bucket: s3://{bucket_name} ({region}) with AES256 encryption."
        }
    except ClientError as e:
        err_code = e.response.get("Error", {}).get("Code", "Unknown")
        if err_code in ("404", "NoSuchBucket"):
            msg = f"S3 bucket '{bucket_name}' not found. Please create bucket in region {region}."
        elif err_code in ("403", "AccessDenied"):
            msg = f"Access denied to S3 bucket '{bucket_name}'. Check IAM permissions."
        else:
            msg = f"S3 HeadBucket returned error code: {err_code}."
        return {
            "configured": False,
            "bucket": bucket_name,
            "region": region,
            "encryption": "AES256",
            "message": msg
        }
    except EndpointConnectionError:
        return {
            "configured": False,
            "bucket": bucket_name,
            "region": region,
            "encryption": "AES256",
            "message": "Could not connect to AWS S3 endpoint. Check network or internet connectivity."
        }
    except Exception as e:
        return {
            "configured": False,
            "bucket": bucket_name,
            "region": region,
            "encryption": "AES256",
            "message": f"AWS S3 status error: {str(e)}"
        }


def upload_file(
    file_path: str,
    prefix: str = PREFIX_REPORTS,
    object_name: Optional[str] = None,
    bucket_name: Optional[str] = None
) -> Tuple[bool, str]:
    """
    Uploads a local file to S3 with AES256 server-side encryption.
    Places the object under the specified prefix.
    """
    path = Path(file_path)
    if not path.is_file():
        return False, f"Local file not found: {path}"

    client = get_s3_client()
    if not client:
        return False, "AWS S3 not configured. File stored locally."

    bucket = bucket_name or os.getenv("CLOUDSENTINEL_S3_BUCKET", DEFAULT_BUCKET)
    clean_prefix = prefix.strip("/") + "/" if prefix else ""
    target_key = f"{clean_prefix}{object_name or path.name}"

    try:
        client.upload_file(
            str(path),
            bucket,
            target_key,
            ExtraArgs={"ServerSideEncryption": "AES256"}
        )
        s3_uri = f"s3://{bucket}/{target_key}"
        return True, f"Successfully uploaded to {s3_uri} (Encrypted: AES256)"
    except ClientError as e:
        err_code = e.response.get("Error", {}).get("Code", "ClientError")
        return False, f"S3 upload error ({err_code}): {e.response.get('Error', {}).get('Message', str(e))}"
    except (NoCredentialsError, EndpointConnectionError) as e:
        return False, f"S3 connection error: {str(e)}"


def upload_bytes(
    data_bytes: bytes,
    object_name: str,
    prefix: str = PREFIX_REPORTS,
    bucket_name: Optional[str] = None
) -> Tuple[bool, str]:
    """
    Uploads raw bytes (e.g. CSV report data) directly to S3 with AES256 server-side encryption.
    """
    client = get_s3_client()
    if not client:
        return False, "AWS S3 not configured. Cannot upload directly to cloud."

    bucket = bucket_name or os.getenv("CLOUDSENTINEL_S3_BUCKET", DEFAULT_BUCKET)
    clean_prefix = prefix.strip("/") + "/" if prefix else ""
    target_key = f"{clean_prefix}{object_name.lstrip('/')}"

    try:
        client.put_object(
            Bucket=bucket,
            Key=target_key,
            Body=data_bytes,
            ServerSideEncryption="AES256"
        )
        s3_uri = f"s3://{bucket}/{target_key}"
        return True, f"Uploaded {len(data_bytes)} bytes to {s3_uri} (Encrypted: AES256)"
    except ClientError as e:
        err_code = e.response.get("Error", {}).get("Code", "ClientError")
        return False, f"S3 put_object error ({err_code}): {e.response.get('Error', {}).get('Message', str(e))}"
    except Exception as e:
        return False, f"S3 error: {str(e)}"


def upload_dataset_to_s3(dataset_path: str) -> Tuple[bool, str]:
    """Uploads a security dataset to s3://<bucket>/datasets/."""
    return upload_file(dataset_path, prefix=PREFIX_DATASETS)


def upload_log_to_s3(log_path: str) -> Tuple[bool, str]:
    """Uploads exported security logs to s3://<bucket>/logs/."""
    return upload_file(log_path, prefix=PREFIX_LOGS)


def upload_report_to_s3(report_bytes: bytes, filename: str) -> Tuple[bool, str]:
    """Uploads an executive security report to s3://<bucket>/reports/."""
    return upload_bytes(report_bytes, object_name=filename, prefix=PREFIX_REPORTS)


def backup_database_to_s3(db_path: Optional[Path] = None) -> Tuple[bool, str]:
    """
    Creates an encrypted timestamped backup of the security database and uploads it to s3://<bucket>/backups/.
    """
    from database.database import LOCAL_DB_PATH
    source_db = db_path or LOCAL_DB_PATH
    if not source_db.exists():
        return False, "Local database file does not exist."

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    target_name = f"security_db_backup_{timestamp}.db"
    return upload_file(str(source_db), prefix=PREFIX_BACKUPS, object_name=target_name)


def list_files(prefix: str = "", bucket_name: Optional[str] = None) -> List[Dict[str, Any]]:
    """Lists files in S3 under the specified prefix."""
    client = get_s3_client()
    if not client:
        return []

    bucket = bucket_name or os.getenv("CLOUDSENTINEL_S3_BUCKET", DEFAULT_BUCKET)
    try:
        response = client.list_objects_v2(Bucket=bucket, Prefix=prefix)
        items = response.get("Contents", [])
        return [{
            "key": item["Key"],
            "size": item["Size"],
            "last_modified": item["LastModified"].isoformat()
        } for item in items]
    except Exception as e:
        print(f"[AWS S3] List files failed: {e}")
        return []


ALLOWED_PREFIXES = {"datasets", "logs", "reports", "backups"}


def upload_bytes_to_s3(
    file_bytes: bytes,
    filename: str,
    prefix: str = "reports",
    content_type: str = "text/csv"
) -> Dict[str, Any]:
    """
    Standardized wrapper for byte uploads. Validates prefix, enforces AES256,
    and falls back to Local Simulation Mode when AWS is not configured.
    """
    clean_prefix = prefix.strip("/")
    if clean_prefix not in ALLOWED_PREFIXES:
        return {"success": False, "error": f"Invalid S3 prefix: '{prefix}'. Allowed: {ALLOWED_PREFIXES}"}

    # Normalize filename: strip leading slashes and any redundant prefix folder
    clean_filename = filename.lstrip("/")
    if clean_filename.startswith(clean_prefix + "/"):
        clean_filename = clean_filename[len(clean_prefix) + 1:]

    client = get_s3_client()
    if client:
        success, message = upload_bytes(file_bytes, object_name=clean_filename, prefix=clean_prefix + "/")
        s3_uri = f"s3://{DEFAULT_BUCKET}/{clean_prefix}/{clean_filename}"
        if success:
            return {"success": True, "s3_uri": s3_uri, "s3_url": s3_uri, "message": message}
        # If cloud upload fails (e.g. NoSuchBucket / AccessDenied), gracefully fall back to local simulation
        print(f"[AWS S3 Notice] Cloud upload failed ({message}). Falling back to Local Simulation Mode.")

    # Graceful Local Simulation Mode: ensure all parent directories exist
    sim_dir = BASE_DIR / "data" / "s3_simulation" / clean_prefix
    local_target = sim_dir / clean_filename
    local_target.parent.mkdir(parents=True, exist_ok=True)
    local_target.write_bytes(file_bytes)
    sim_uri = f"s3://{DEFAULT_BUCKET}/{clean_prefix}/{clean_filename} (Local Simulation)"
    return {
        "success": True,
        "simulated": True,
        "local_path": str(local_target),
        "s3_uri": sim_uri,
        "s3_url": sim_uri
    }


def upload_file_to_s3(
    local_path: Path,
    prefix: str = "backups",
    content_type: str = "application/octet-stream"
) -> Dict[str, Any]:
    """
    Standardized wrapper for file uploads. Validates prefix, enforces AES256,
    and falls back to Local Simulation Mode when AWS is not configured.
    """
    clean_prefix = prefix.strip("/")
    if clean_prefix not in ALLOWED_PREFIXES:
        return {"success": False, "error": f"Invalid S3 prefix: '{prefix}'. Allowed: {ALLOWED_PREFIXES}"}

    path = Path(local_path)
    if not path.is_file():
        return {"success": False, "error": f"Local file does not exist: {path}"}

    client = get_s3_client()
    if client:
        success, message = upload_file(str(path), prefix=clean_prefix + "/")
        s3_uri = f"s3://{DEFAULT_BUCKET}/{clean_prefix}/{path.name}"
        if success:
            return {"success": True, "s3_uri": s3_uri, "s3_url": s3_uri, "message": message}
        print(f"[AWS S3 Notice] Cloud upload failed ({message}). Falling back to Local Simulation Mode.")

    # Graceful Local Simulation Mode
    sim_dir = BASE_DIR / "data" / "s3_simulation" / clean_prefix
    local_target = sim_dir / path.name
    local_target.parent.mkdir(parents=True, exist_ok=True)
    import shutil
    shutil.copy2(path, local_target)
    sim_uri = f"s3://{DEFAULT_BUCKET}/{clean_prefix}/{path.name} (Local Simulation)"
    return {
        "success": True,
        "simulated": True,
        "local_path": str(local_target),
        "s3_uri": sim_uri,
        "s3_url": sim_uri
    }


if __name__ == "__main__":
    print("Testing AWS S3 Integration module...")
    status = get_s3_status()
    print("S3 Status:", status)
