import boto3
import botocore
from botocore.config import Config
from botocore.exceptions import ClientError
import io
import random
import string

class s3Checks:
    def record_parser(record):
        record_id = record['id']
        subDomain = record['subDomain']
        
        
    def head_check_bucket(s3, bucket_name, results):
        """
        Performs a head check on the bucket to determine if it exists and is accessible.
        """
        try:
            # Perform a head check on the bucket
            s3.head_bucket(Bucket=bucket_name,signature_version=botocore.UNSIGNED)
            results["head"] = True  # Bucket exists and is accessible
            results["error"] = None
            print(f"Bucket '{bucket_name}' exists and is accessible.")
            return True
        except ClientError as e:
            code = e.response['Error']['Code']
            if code == "403":
                results["head"] = False
                results["error"] = "Bucket exists but access is denied (403)."
            elif code == "404":
                results["head"] = False
                results["error"] = "Bucket does not exist (404)."
            else:
                results["head"] = False
                results["error"] = f"ClientError: {code}"
            print(f"Bucket '{bucket_name}' head check failed: {results['error']}")
            return False
        except Exception as e:
            results["head"] = False
            results["error"] = f"Unexpected error: {e}"
            print(f"Bucket '{bucket_name}' head check failed: {results['error']}")
            return False


    def upload_pseudo_file_to_s3(s3, bucket_name, results):
        """
        Attempts to upload a random file anonymously (if write misconfigured).
        """
        try:
            object_name = ''.join(random.choices(string.ascii_letters + string.digits, k=10)) + ".txt"
            content = ''.join(random.choices(string.ascii_letters + string.digits, k=50))
            pseudo_file = io.BytesIO(content.encode('utf-8'))

            s3.upload_fileobj(pseudo_file, bucket_name, object_name)

            # Attempt to confirm existence
            try:
                s3.head_object(Bucket=bucket_name, Key=object_name)
                results["unauth_upload"] = True
                results["uploaded_key"] = object_name
                results["is_valid"] = True
                return True
            except ClientError:
                results["unauth_upload"] = False
                return False
        except Exception:
            results["unauth_upload"] = False
            return False

    def list_bucket_contents(s3, bucket_name, results):
        try:
            response = s3.list_objects_v2(Bucket=bucket_name)
            if 'Contents' in response:
                results["contents_accessible"] = True
                results["contents"] = [obj['Key'] for obj in response['Contents']]
                results["is_valid"] = True
            else:
                results["contents_accessible"] = False
                results["contents"] = []
        except Exception:
            results["contents_accessible"] = False
            results["contents"] = []

# Example bucket list
if __name__ == "__main__":
    for bucket_name in computations:
        results = {
            "bucket_name": bucket_name,
            "is_valid": False,
            "head": False,  # Changed from "is_valid" to "head"
            "unauth_upload": False,
            "uploaded_key": None,
            "contents_accessible": False,
            "contents": [],
            "error": None
        }
        
        s3 = get_anon_s3_client()

        # Perform the head check
        head_check_bucket(s3, bucket_name, results)

        # Attempt to upload a pseudo file
        upload_pseudo_file_to_s3(s3, bucket_name, results)

        # Attempt to list bucket contents
        list_bucket_contents(s3, bucket_name, results)

        print(results)

print("stop")

