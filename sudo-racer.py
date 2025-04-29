#!/usr/bin/env python3
import argparse
import json
import hashlib
import requests
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
import logging
import sys
import os

def setup_logging(log_file):
    """Configure logging to file only."""
    logging.basicConfig(
        level=logging.INFO,
        format="[%(asctime)s] %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
        handlers=[logging.FileHandler(log_file)]
    )
    return logging.getLogger()

def run_rcd_test(url, method, headers, body, concurrency, timeout, retries, log_file):
    """Run race condition detection test."""
    logger = setup_logging(log_file)
    logger.info(f"Running RCD scan for {method} {url}")
    if body:
        logger.info(f"Request body: {body}")

    # Setup session with retries
    session = requests.Session()
    retry_strategy = Retry(
        total=retries,
        backoff_factor=0.1,
        status_forcelist=[429, 500, 502, 503, 504]
    )
    session.mount("https://", HTTPAdapter(max_retries=retry_strategy))
    session.mount("http://", HTTPAdapter(max_retries=retry_strategy))

    responses = []
    request_counter = 0

    def send_request(req_id):
        """Send a single HTTP request."""
        nonlocal request_counter
        try:
            resp = session.request(
                method=method,
                url=url,
                headers=headers,
                data=body if method in ["POST", "PUT"] and body else None,
                timeout=timeout
            )
            logger.info(f"Request {req_id}: Status {resp.status_code}, Content-Length {len(resp.content)}")
            return {
                "status_code": resp.status_code,
                "content_hash": hashlib.sha256(resp.content).hexdigest(),
                "headers": dict(resp.headers),
                "body": resp.text[:1000]
            }
        except Exception as e:
            logger.info(f"Request {req_id}: Failed with error: {str(e)}")
            return {"error": str(e)}
        finally:
            nonlocal request_counter
            request_counter += 1

    # Send concurrent requests
    with ThreadPoolExecutor(max_workers=concurrency) as executor:
        futures = [executor.submit(send_request, i + 1) for i in range(concurrency)]
        for future in futures:
            responses.append(future.result())

    logger.info(f"Completed {request_counter} of {concurrency} requests")

    # Analyze responses
    positive_codes = {200, 201, 204}
    response_counts = {}
    positive_count = 0
    for resp in responses:
        if "error" in resp:
            continue
        key = f"{resp['status_code']}_{resp['content_hash']}"
        response_counts[key] = response_counts.get(key, 0) + 1
        if resp["status_code"] in positive_codes:
            positive_count += 1

    # Check for vulnerability
    findings = []
    vulnerable = any(
        count >= 6 for key, count in response_counts.items()
        if key.split('_')[0] in map(str, positive_codes)
    )
    if vulnerable:
        max_count = max(
            (count for key, count in response_counts.items()
             if key.split('_')[0] in map(str, positive_codes)),
            default=0
        )
        findings.append({
            "description": f"Race condition detected on {url} "
                          f"({positive_count} positive responses, max {max_count} identical)",
            "severity": "HIGH",
            "details": {
                "test": "rcd",
                "url": url,
                "method": method,
                "headers": headers,
                "body": body,
                "positive_responses": positive_count,
                "identical_responses": max_count,
                "sample_responses": responses[:5]
            }
        })
        logger.info(f"RCD Found: {positive_count} positive responses ({max_count} identical) on {url}")
    else:
        logger.info(f"No race condition detected on {url}")

    return findings

def main():
    """Parse arguments and run RCD test."""
    try:
        parser = argparse.ArgumentParser(description="Sudo Racer: Race Condition Detection")
        parser.add_argument("--url", required=True, help="Target URL")
        parser.add_argument("--method", default="GET", help="HTTP method (GET, POST, PUT, etc.)")
        parser.add_argument("--headers", default="{}", help="JSON string or file with headers")
        parser.add_argument("--body", default="", help="Request body or file with body content")
        parser.add_argument("--concurrency", type=int, default=10, help="Number of concurrent requests")
        parser.add_argument("--timeout", type=float, default=10.0, help="Request timeout in seconds")
        parser.add_argument("--retries", type=int, default=3, help="Number of retries for failed requests")
        parser.add_argument("--log-file", default="/tmp/sudo_racer.log", help="Log file path")
        args = parser.parse_args()

        # Ensure log file directory exists
        os.makedirs(os.path.dirname(args.log_file), exist_ok=True)

        # Parse headers
        headers = {}
        if os.path.isfile(args.headers):
            with open(args.headers, "r") as f:
                headers = json.load(f)
        else:
            try:
                headers = json.loads(args.headers)
            except json.JSONDecodeError:
                raise ValueError(f"Invalid headers JSON: {args.headers}")

        # Parse body
        body = args.body
        if os.path.isfile(body):
            with open(body, "r") as f:
                body = f.read()

        # Convert headers list to dict if needed (tasks.py format)
        if isinstance(headers, list):
            headers_dict = {}
            for h in headers:
                try:
                    key, value = h.split(": ", 1)
                    headers_dict[key] = value
                except ValueError:
                    continue
            headers = headers_dict

        findings = run_rcd_test(
            args.url, args.method, headers, body,
            args.concurrency, args.timeout, args.retries, args.log_file
        )

        # Output JSON
        print(json.dumps(findings, indent=2))
    except Exception as e:
        # Output error as JSON
        print(json.dumps({"error": f"sudo-racer failed: {str(e)}"}, indent=2))
        sys.exit(1)

if __name__ == "__main__":
    main()
