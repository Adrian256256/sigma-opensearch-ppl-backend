import json
import os
import re
import sys

import requests


def extract_query(raw: str) -> str:
    """Strip ```plaintext ... ``` or ``` ... ``` fences and return the bare query."""
    raw = raw.strip()
    # Match fenced code blocks with optional language tag
    m = re.match(r'^```[a-z]*\n?(.*?)```$', raw, re.DOTALL)
    if m:
        return m.group(1).strip()
    return raw


def validate_ppl_queries(out_dir: str, opensearch_url: str) -> dict:
    results = {}
    files = sorted(f for f in os.listdir(out_dir) if f.endswith('.txt'))
    if not files:
        print(f"[WARN] No .txt files found in {out_dir}")
        return results

    for fname in files:
        fpath = os.path.join(out_dir, fname)
        with open(fpath, 'r') as f:
            raw = f.read()

        query = extract_query(raw)
        payload = {'query': query}

        try:
            resp = requests.post(
                opensearch_url,
                json=payload,
                headers={'Content-Type': 'application/json'},
                timeout=10,
            )
            try:
                body = resp.json()
            except ValueError:
                body = resp.text

            if resp.status_code == 200 and (not isinstance(body, dict) or 'error' not in body):
                results[fname] = ('VALID', query, None)
            else:
                error_reason = (
                    body.get('error', {}).get('reason', json.dumps(body))
                    if isinstance(body, dict)
                    else str(body)
                )
                results[fname] = ('ERROR', query, error_reason)
        except requests.exceptions.ConnectionError:
            results[fname] = ('EXCEPTION', query, 'Could not connect to OpenSearch at ' + opensearch_url)
        except Exception as e:
            results[fname] = ('EXCEPTION', query, str(e))

    return results


def print_results(results: dict) -> int:
    valid_count = 0
    error_count = 0
    for fname, (status, query, detail) in sorted(results.items()):
        if status == 'VALID':
            print(f'  ✅  {fname}')
            valid_count += 1
        else:
            print(f'  ❌  {fname}  [{status}]')
            print(f'       Query   : {query[:120]}{"..." if len(query) > 120 else ""}')
            print(f'       Reason  : {detail}')
            error_count += 1
    print()
    print(f'Results: {valid_count} valid, {error_count} invalid out of {len(results)} queries.')
    return error_count


if __name__ == '__main__':
    out_dir = os.path.join(os.path.dirname(__file__), 'out')
    opensearch_url = 'http://localhost:9200/_plugins/_ppl'

    print(f'Validating PPL queries in: {out_dir}')
    print(f'OpenSearch endpoint      : {opensearch_url}')
    print()

    results = validate_ppl_queries(out_dir, opensearch_url)
    errors = print_results(results)
    sys.exit(1 if errors else 0)
