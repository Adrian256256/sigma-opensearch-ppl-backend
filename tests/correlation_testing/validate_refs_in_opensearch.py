import os
import requests

def validate_ppl_queries(refs_dir, opensearch_url):
    results = {}
    for fname in os.listdir(refs_dir):
        if not fname.endswith('.txt'):
            continue
        fpath = os.path.join(refs_dir, fname)
        with open(fpath, 'r') as f:
            query = f.read().strip()
        # Remove code block markers if present
        if query.startswith('```'):
            query = query.strip('`').strip('plaintext').strip()
        payload = {'query': query}
        try:
            resp = requests.post(opensearch_url, json=payload)
            if resp.status_code == 200 and 'error' not in resp.text:
                results[fname] = 'VALID'
            else:
                results[fname] = f'ERROR: {resp.text}'
        except Exception as e:
            results[fname] = f'EXCEPTION: {e}'
    return results

if __name__ == '__main__':
    refs_dir = os.path.join(os.path.dirname(__file__), 'ppl_refs')
    opensearch_url = 'http://localhost:9200/_plugins/_ppl'
    results = validate_ppl_queries(refs_dir, opensearch_url)
    for fname, status in results.items():
        print(f'{fname}: {status}')
