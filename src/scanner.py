# scan function, patterns dictionnary, ignored items
import re
from pathlib import Path
from rich.console import Console
from rich.table import Table
import json
import yaml
from collections import defaultdict
import math
from collections import Counter 
import pyfiglet 

PATTERNS = [
    # AWS
    {"name": "AWS Access Key ID", "regex": r"AKIA[0-9A-Z]{16}", "multiline": False, "group": "aws"},
    {"name": "AWS Secret Access Key", "regex": r"(?i)aws_secret_access_key\s*=\s*[\"']?[A-Za-z0-9/+=]{40}[\"']?", "multiline": False, "group": "aws"},
    {"name": "AWS Session Token", "regex": r"(?i)aws_session_token\s*=\s*[\"']?[A-Za-z0-9/+=]{100,}[\"']?", "multiline": False, "group": "aws"},

    # Google
    {"name": "GCP API Key", "regex": r"AIza[0-9A-Za-z\-_]{35}", "multiline": False, "group": "google"},
    {"name": "Google OAuth Client ID", "regex": r"[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com", "multiline": False, "group": "google"},
    {"name": "Google OAuth Access Token", "regex": r"ya29\.[0-9A-Za-z\-_]+", "multiline": False, "group": "google"},

    # GitHub
    {"name": "GitHub Personal Access Token", "regex": r"ghp_[0-9A-Za-z]{36}", "multiline": False, "group": "github"},
    {"name": "GitHub OAuth Token", "regex": r"gho_[0-9A-Za-z]{36}", "multiline": False, "group": "github"},
    {"name": "GitHub App Token", "regex": r"ghs_[0-9A-Za-z]{36}", "multiline": False, "group": "github"},
    {"name": "GitHub Refresh Token", "regex": r"ghr_[0-9A-Za-z]{36}", "multiline": False, "group": "github"},
    {"name": "GitHub Fine-grained PAT", "regex": r"github_pat_[0-9A-Za-z_]{82}", "multiline": False, "group": "github"},

    # Slack
    {"name": "Slack Token", "regex": r"xox[baprs]-[0-9A-Za-z\-]{10,48}", "multiline": False, "group": "slack"},
    {"name": "Slack Webhook", "regex": r"https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+", "multiline": False, "group": "slack"},

    # Stripe
    {"name": "Stripe Live Secret Key", "regex": r"sk_live_[0-9A-Za-z]{24,}", "multiline": False, "group": "stripe"},
    {"name": "Stripe Test Secret Key", "regex": r"sk_test_[0-9A-Za-z]{24,}", "multiline": False, "group": "stripe"},
    {"name": "Stripe Live Publishable Key", "regex": r"pk_live_[0-9A-Za-z]{24,}", "multiline": False, "group": "stripe"},
    {"name": "Stripe Restricted Key", "regex": r"rk_live_[0-9A-Za-z]{24,}", "multiline": False, "group": "stripe"},

    # Twilio
    {"name": "Twilio Account SID", "regex": r"AC[a-z0-9]{32}", "multiline": False, "group": "twilio"},
    {"name": "Twilio API Key SID", "regex": r"SK[a-z0-9]{32}", "multiline": False, "group": "twilio"},

    # SendGrid / Mailgun
    {"name": "SendGrid API Key", "regex": r"SG\.[A-Za-z0-9\-_]{22}\.[A-Za-z0-9\-_]{43}", "multiline": False, "group": "sendgrid"},
    {"name": "Mailgun API Key", "regex": r"key-[0-9a-zA-Z]{32}", "multiline": False, "group": "mailgun"},

    # Telegram
    {"name": "Telegram Bot Token", "regex": r"[0-9]{8,10}:[A-Za-z0-9\-_]{35}", "multiline": False, "group": "telegram"},

    # Facebook / Meta
    {"name": "Facebook Access Token", "regex": r"EAACEdEose0cBA[0-9A-Za-z]+", "multiline": False, "group": "facebook"},
    {"name": "Facebook App Secret", "regex": r"(?i)fb_app_secret\s*=\s*[\"']?[a-f0-9]{32}[\"']?", "multiline": False, "group": "facebook"},

    # NPM
    {"name": "NPM Access Token", "regex": r"npm_[A-Za-z0-9]{36}", "multiline": False, "group": "npm"},

    # Azure
    {"name": "Azure Storage Account Key", "regex": r"(?i)AccountKey=[A-Za-z0-9+/=]{88}", "multiline": False, "group": "azure"},

    # Cloudflare
    {"name": "Cloudflare Access Token", "regex": r"(?i)cf-access-token\s*[=:]\s*[\"']?[A-Za-z0-9\-_]+[\"']?", "multiline": False, "group": "cloudflare"},

    # Private Keys / Certs
    {"name": "Private Key", "regex": r"-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----", "multiline": True, "group": "crypto"},
    {"name": "Certificate", "regex": r"-----BEGIN CERTIFICATE-----", "multiline": True, "group": "crypto"},
    {"name": "PGP Private Key", "regex": r"-----BEGIN PGP PRIVATE KEY BLOCK-----", "multiline": True, "group": "crypto"},

    # JWT
    {"name": "JWT Token", "regex": r"eyJ[A-Za-z0-9\-_]+\.eyJ[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+", "multiline": False, "group": "jwt"},

    # Connection Strings
    {"name": "PostgreSQL Connection String", "regex": r"(?i)postgres(?:ql)?://[^:]+:[^@]+@[^\s\"']+", "multiline": False, "group": "database"},
    {"name": "MySQL Connection String", "regex": r"(?i)mysql://[^:]+:[^@]+@[^\s\"']+", "multiline": False, "group": "database"},
    {"name": "MongoDB Connection String", "regex": r"(?i)mongodb(\+srv)?://[^:]+:[^@]+@[^\s\"']+", "multiline": False, "group": "database"},
    {"name": "Redis Connection String", "regex": r"(?i)redis://:[^@]+@[^\s\"']+", "multiline": False, "group": "database"},
    {"name": "RabbitMQ Connection String", "regex": r"(?i)amqp://[^:]+:[^@]+@[^\s\"']+", "multiline": False, "group": "database"},

        # AI / LLM
    {"name": "OpenAI API Key", "regex": r"sk-[a-zA-Z0-9]{48}", "multiline": False, "group": "openai"},
    {"name": "Anthropic API Key", "regex": r"sk-ant-api03-[a-zA-Z0-9\-_]{93}-AA", "multiline": False, "group": "anthropic"},
    {"name": "HuggingFace Token", "regex": r"hf_[a-zA-Z0-9]{34}", "multiline": False, "group": "huggingface"},

    # Discord
    {"name": "Discord Bot Token", "regex": r"[MNO][a-zA-Z0-9_-]{23,25}\.[a-zA-Z0-9_-]{6}\.[a-zA-Z0-9_-]{27}", "multiline": False, "group": "discord"},
    {"name": "Discord Webhook", "regex": r"https://discord\.com/api/webhooks/[0-9]+/[a-zA-Z0-9_-]+", "multiline": False, "group": "discord"},

    # Cloud / Infrastructure
    {"name": "DigitalOcean PAT", "regex": r"dop_v1_[a-f0-9]{64}", "multiline": False, "group": "digitalocean"},
    {"name": "Heroku API Key", "regex": r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}", "multiline": False, "group": "heroku"},
    {"name": "Supabase API Key", "regex": r"sbp_[a-zA-Z0-9]{40}", "multiline": False, "group": "supabase"},

    # Tools / Productivity
    {"name": "Notion API Key", "regex": r"secret_[a-zA-Z0-9]{43}", "multiline": False, "group": "notion"},
    {"name": "Datadog Access Token", "regex": r"ddo_[A-Za-z0-9]{32}", "multiline": False, "group": "datadog"},
    
    # GitLab
    {"name": "GitLab Personal Access Token", "regex": r"glpat-[a-zA-Z0-9\-=_]{20}", "multiline": False, "group": "gitlab"},


    # Generic
    {"name": "Generic Secret Assignment", "regex": r"(?i)(?:api_key|apikey|api_secret|app_secret|auth_token|access_token|secret_key|private_key|client_secret|password|passwd|pwd)\s*[=:]\s*[\"']?[A-Za-z0-9\-_/+=.]{16,}[\"']?", "multiline": False, "group": "generic"},
]

# compile regex
# pattern regex
for pattern in PATTERNS:
    flags = re.DOTALL if pattern["multiline"] else 0
    pattern["compiled"] = re.compile(pattern["regex"], flags)

# entropy regex
ENTROPY_PATTERNS = [
    {"name":"Entropy (String inside quotes)","regex": r"['\"][a-zA-Z0-9+/=]{20,}['\"]","group":"entropy"}, 
    {"name":"Entropy (Long unbroken word)","regex": r"\b[a-zA-Z0-9]{20,}\b","group":"entropy"}
]

for p in ENTROPY_PATTERNS:
    p["compiled"] = re.compile(p["regex"])


IGNORED_DIRS = {
    # Version control
    ".git", ".svn", ".hg",

    # Dependencies
    "node_modules", "vendor", "venv", ".venv",
    "__pycache__", ".tox", ".eggs", "dist", "build", "site-packages",

    # IDE / editor
    ".idea", ".vscode", ".eclipse", ".settings",

    # Test fixtures / mocks (often contain fake secrets)
    "fixtures", "mocks", "stubs", "testdata", "__snapshots__",

    # Generated / compiled
    "coverage", ".nyc_output", "htmlcov", ".pytest_cache", ".mypy_cache",
}

IGNORED_EXTENSIONS = {
    # Binary / media
    ".png", ".jpg", ".jpeg", ".gif", ".ico", ".svg", ".webp",
    ".mp4", ".mp3", ".wav", ".avi", ".mov",
    ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
    ".zip", ".tar", ".gz", ".rar", ".7z",
    ".exe", ".dll", ".so", ".dylib", ".bin", ".obj",
    ".pyc", ".pyo", ".class",

    # Fonts
    ".ttf", ".otf", ".woff", ".woff2", ".eot",

    # Lock files (high noise, low signal)
    ".lock",
}

IGNORED_FILES = {
    # Lock files
    "package-lock.json", "yarn.lock", "poetry.lock", "Pipfile.lock", "composer.lock",

    # Minified
    "*.min.js", "*.min.css",

    # Common false-positive files
    "CHANGELOG.md", "CHANGELOG.txt", "LICENSE", "LICENSE.md",
}


def should_ignore(path: Path) -> bool:
    if any(part in IGNORED_DIRS for part in path.parts):
        return True
    if path.suffix.lower() in IGNORED_EXTENSIONS:
        return True
    if path.name in IGNORED_FILES:
        return True
    return False

def calculate_entropy(word):
    length = len(word)
    counts = Counter(word).values()
    return -sum((c / length) * math.log2(c / length) for c in counts)
    

def scan_content(content: str, filepath) -> list[dict]:
    findings = []

    for pattern in PATTERNS:
        for match in pattern["compiled"].finditer(content):
            s = match.group()
            line = content[:match.start()].count("\n") + 1
            redacted_s = s[:4] + "*" * 8 + s[-4:]
            findings.append({
                "name": pattern["name"],
                "group": pattern["group"],
                "line": line,
                "match": redacted_s,
                "filepath": filepath.as_posix()
            })
    for entropy_pattern in ENTROPY_PATTERNS:
        for match in entropy_pattern["compiled"].finditer(content):
            word = match.group()
            score = calculate_entropy(word)
            line = content[:match.start()].count("\n") + 1
            redacted_match = word[:4] + "*" * 8 + word[-4:]
            # skip big blocks
            if len(word) > 200:
                continue
            # check score and if entropy match isnt already caught by regex (duplicate)
            if score > 3.0 and not any((d.get("line") == line and d.get("filepath") == filepath.as_posix()) for d in findings):
                findings.append({
                "name": entropy_pattern["name"],
                "group": entropy_pattern["group"],
                "line": line,
                "match": redacted_match,
                "filepath": filepath.as_posix()
            })

    return findings

def print_findings(findings: list[dict], output_format, filepath):
    findings_ascii = pyfiglet.figlet_format('Findings :')
    print(findings_ascii)
    if output_format == 'json':
        print(json.dumps(findings, indent=2))
    elif output_format == 'yaml':
        cleaned_findings = clean_yaml(findings)
        print(yaml.dump(cleaned_findings, default_flow_style=False, sort_keys=False, allow_unicode=True))
    elif output_format == 'table' or not output_format:
        # print table
        console = Console()
        table = Table(title=f"[bold] Directory/file: {filepath.as_posix()}[/bold]", show_lines=True)

        table.add_column("Filepath", style="white", width=50)
        table.add_column("Group", style="cyan", width=10)
        table.add_column("Pattern", style="white", width=30)
        table.add_column("Match", style="red", width=20)
        table.add_column("Line", style="yellow", width=3)

        for f in findings:
            table.add_row(
                f["filepath"],
                f["group"],
                f["name"],
                f["match"][:60] + "..." if len(f["match"]) > 60 else f["match"],
                str(f["line"]),
            )

        console.print(table)


def clean_yaml(findings: list[dict]):
    grouped = defaultdict(list)
    for item in findings:
        fp = item["filepath"]
        entry = {k: v for k, v in item.items() if k != "filepath"}
        grouped[fp].append(entry)
    output = [{"filepath": fp, "findings": f} for fp, f in grouped.items()]
    return output

def export_findings(findings: list[dict], output_file_name: str):
    if output_file_name and output_file_name.endswith('.json'):
        with open(output_file_name, "w") as file:
            json.dump(findings, file, indent=2)
    elif output_file_name and (output_file_name.endswith('.yaml') or output_file_name.endswith('.yml')):
        with open(output_file_name, "w") as file:
                cleaned_yaml = clean_yaml(findings)
                yaml.dump(cleaned_yaml, file, default_flow_style=False, sort_keys=False, allow_unicode=True)
    else:
        raise ValueError(f"Invalid file extension. Only .json, .yaml/.yml formats accepted.")
