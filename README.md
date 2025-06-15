# SigStrike

A fast Cobalt Strike beacon parser.
Parses 1000 beacon under 1 second.
Can crawl 1M of potential beacon URLs in under 10 minutes.

Parsing logic in based on [dissect.cobaltstrike](https://github.com/fox-it/dissect.cobaltstrike) Python library.
The library tries to match the output of `dissect.cobaltstrike` so it can be used as a drop-in replacement.

# Installation

## Rust CLI using Cargo

```bash
cargo install sigstrike
```

## Using Python and pip

Requires Python 3.9+.

```bash
pip install sigstrike
```

# Usage

```bash
sigstrike --help
```

## Scanning local files

### Parsing a single file

```bash
sigstrike process --input-path beacon.bin --output-path beacon.json
```

### Parsing multiple files in a directory

```bash
sigstrike process --input-path /path/to/beacons/ --output-path beacons.json
```

## Scanning URLs

```bash
sigstrike crawl --input-path urls.txt --output-path beacons.json   --max-concurrent 1000
```

## Using with Python

### Extracting beacon data

```python
>> > import sigstrike, pprint, json
>> > data = open("/Users/aa/Downloads/cb.bin", mode="rb").read()
>> > pprint.pprint(json.loads(sigstrike.extract_beacon(data)), indent=2)
{'encrypted': True,
 'guardrail_key': None,
 'guardrailed': False,
 'input_hash': '060e4e8b0226e0bd37745c90c18694b89aec54efee6ccbd7c82a136811d7d66d',
 'items': {'SETTING_BOF_ALLOCATOR': 'VirtualAlloc',
           'SETTING_C2_CHUNK_POST': 0,
           'SETTING_C2_POSTREQ': [['_HEADER',
                                   'Content-Type: '
                                   'application/octet-stream'],
                                  ['BUILD', 'id'],
                                  ['PARAMETER', 'id'],
                                  ['BUILD', 'output'],
                                  ['PRINT', True]],
           'SETTING_C2_RECOVER': [['print', True]],
           'SETTING_C2_REQUEST': [['BUILD', 'metadata'],
                                  ['BASE64', True],
                                  ['HEADER', 'Cookie']],
           'SETTING_C2_VERB_GET': 'GET',
           'SETTING_C2_VERB_POST': 'POST',
           'SETTING_CFG_CAUTION': 0,
           'SETTING_CLEANUP': 0,
           'SETTING_CRYPTO_SCHEME': 0,
           'SETTING_DOMAINS': '....,/ca',
           'SETTING_DOMAIN_STRATEGY': 0,
           'SETTING_DOMAIN_STRATEGY_FAIL_SECONDS': 4294967295,
           'SETTING_DOMAIN_STRATEGY_FAIL_X': 4294967295,
           'SETTING_DOMAIN_STRATEGY_SECONDS': 4294967295,
           'SETTING_EXIT_FUNK': 0,
           'SETTING_GARGLE_NOOK': 0,
           'SETTING_HOST_HEADER': '',
           'SETTING_HTTP_NO_COOKIES': 1,
           'SETTING_JITTER': 0,
           'SETTING_KILLDATE': 0,
           'SETTING_MAXGET': 1048576,
           'SETTING_MAX_RETRY_STRATEGY_ATTEMPTS': 0,
           'SETTING_MAX_RETRY_STRATEGY_DURATION': 0,
           'SETTING_MAX_RETRY_STRATEGY_INCREASE': 0,
           'SETTING_PORT': 5566,
           'SETTING_PROCINJ_ALLOCATOR': 0,
           'SETTING_PROCINJ_BOF_REUSE_MEM': 1,
           'SETTING_PROCINJ_EXECUTE': ['CreateThread',
                                       'SetThreadContext',
                                       'CreateRemoteThread',
                                       'RtlCreateUserThread'],
           'SETTING_PROCINJ_MINALLOC': 0,
           'SETTING_PROCINJ_PERMS': 64,
           'SETTING_PROCINJ_PERMS_I': 64,
           'SETTING_PROCINJ_STUB': 'b50b86d7...4ad8d01781c',
           'SETTING_PROCINJ_TRANSFORM_X64': [['append', ''], ['prepend', '']],
           'SETTING_PROCINJ_TRANSFORM_X86': [['append', ''], ['prepend', '']],
           'SETTING_PROTOCOL': ['HTTP'],
           'SETTING_PROXY_BEHAVIOR': 2,
           'SETTING_PUBKEY': '51a8d41b43f9....9f9bae3fb9b82c43e40e7289',
           'SETTING_SLEEPTIME': 60000,
           'SETTING_SMB_FRAME_HEADER': '',
           'SETTING_SPAWNTO': 'd7a9ca15a07f8....b63020da38aa16',
           'SETTING_SPAWNTO_X64': '%windir%\\sysnative\\rundll32.exe',
           'SETTING_SPAWNTO_X86': '%windir%\\syswow64\\rundll32.exe',
           'SETTING_SUBMITURI': '/submit.php',
           'SETTING_TCP_FRAME_HEADER': '',
           'SETTING_USERAGENT': 'Mozilla/5.0 (compatible; MSIE 9.0; Windows '
                                'NT 6.1; Trident/5.0; BOIE9;ENIN)',
           'SETTING_WATERMARK': ....,
           'SETTING_WATERMARKHASH': 'idv...PjBw=='},
 'xor_key': 46}
```

### Crawling URLs using Python

```python
>> import sigstrike

>> sigstrike.crawl(
    input_path="urls.txt",
    output_path="beacons.json",
    max_concurrent=1000,
    max_retries=3,
    timeout=10
)
```

## Parsing Speed

Processing 1000 beacons takes around 1 second.

```bash
[2025-06-14T21:57:40Z INFO  sigstrike::io] Total files found: 614
[2025-06-14T21:56:41Z INFO  sigstrike::cli] Total execution time: 428.313792ms
```

## Crawling Speed

```bash
sigstrike crawl --input-path 404_sample.txt --output-path output.json --max-concurrent 8000

Crawl Summary:
  Total URLs processed: 244332
  Found: 337
  Failed: 243995
  Non-matching content type/status: 157100
  Unreachable: 86895
Total execution time: 85.333871001s
```

