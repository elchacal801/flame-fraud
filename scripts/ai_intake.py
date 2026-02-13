#!/usr/bin/env python3
"""
ai_intake.py — FLAME AI-Assisted Threat Path Generator

Takes a URL (from a GitHub issue), fetches the content,
sends it to an LLM with a structured prompt, and generates
a threat path markdown file matching the FLAME schema.

Usage:
    python scripts/ai_intake.py \
        --url "https://example.com/article" \
        --author "AuthorName" \
        --sector "banking" \
        --fraud-types "account-takeover,wire-fraud" \
        --context "Focus on the BEC variant" \
        --output-dir ThreatPaths

Environment variables:
    ANTHROPIC_API_KEY  — Claude API key (primary)
    OPENAI_API_KEY     — GPT-4o API key (fallback)
"""

import argparse
import json
import os
import re
import sys
import unicodedata
from datetime import date
from pathlib import Path

import requests
from bs4 import BeautifulSoup


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

REPO_ROOT = Path(__file__).resolve().parent.parent
THREAT_PATHS_DIR = REPO_ROOT / "ThreatPaths"
CFPF_TECHNIQUES_FILE = REPO_ROOT / "cfpf_techniques.json"
TEMPLATE_FILE = REPO_ROOT / "Templates" / "threat-path-template.md"

# LLM configuration
ANTHROPIC_MODEL = "claude-3-7-sonnet-latest"
OPENAI_MODEL = "gpt-4o"

ANTHROPIC_URL = "https://api.anthropic.com/v1/messages"
OPENAI_URL = "https://api.openai.com/v1/chat/completions"

MAX_ARTICLE_CHARS = 30000  # truncate long articles to fit context
MAX_TOKENS = 8000          # max response tokens


# ---------------------------------------------------------------------------
# URL fetching
# ---------------------------------------------------------------------------

def fetch_url_content(url: str) -> str:
    """Fetch a URL and extract readable text content."""
    headers = {
        "User-Agent": (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
            "(KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
        ),
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    }

    try:
        resp = requests.get(url, headers=headers, timeout=30, allow_redirects=True)
        resp.raise_for_status()
    except requests.RequestException as e:
        print(f"ERROR: Failed to fetch URL: {e}", file=sys.stderr)
        sys.exit(1)

    content_type = resp.headers.get("content-type", "")

    if "application/pdf" in content_type:
        # For PDFs, extract text if possible, otherwise return raw
        return f"[PDF document from {url} — content extraction not supported. " \
               f"The AI should note this is a PDF source and work with available metadata.]"

    # Parse HTML
    soup = BeautifulSoup(resp.text, "html.parser")

    # Remove script, style, nav, footer, header elements
    for tag in soup(["script", "style", "nav", "footer", "header", "aside",
                     "form", "button", "noscript", "iframe"]):
        tag.decompose()

    # Extract text
    text = soup.get_text(separator="\n", strip=True)

    # Collapse multiple blank lines
    text = re.sub(r"\n{3,}", "\n\n", text)

    # Truncate to fit context window
    if len(text) > MAX_ARTICLE_CHARS:
        text = text[:MAX_ARTICLE_CHARS] + "\n\n[... content truncated for length ...]"

    return text


# ---------------------------------------------------------------------------
# TP ID management
# ---------------------------------------------------------------------------

def get_next_tp_id() -> str:
    """Scan ThreatPaths/ and return the next available TP-XXXX ID."""
    existing_ids = []
    if THREAT_PATHS_DIR.exists():
        for f in THREAT_PATHS_DIR.glob("TP-*.md"):
            match = re.match(r"TP-(\d{4})", f.stem)
            if match:
                existing_ids.append(int(match.group(1)))

    next_num = max(existing_ids, default=0) + 1
    return f"TP-{next_num:04d}"


def slugify(text: str) -> str:
    """Convert text to a URL-safe slug."""
    text = unicodedata.normalize("NFKD", text)
    text = text.encode("ascii", "ignore").decode("ascii")
    text = text.lower()
    text = re.sub(r"[^a-z0-9]+", "-", text)
    text = text.strip("-")
    # Limit length
    if len(text) > 60:
        text = text[:60].rsplit("-", 1)[0]
    return text


# ---------------------------------------------------------------------------
# CFPF techniques loader
# ---------------------------------------------------------------------------

def load_cfpf_techniques() -> str:
    """Load CFPF techniques catalog as a formatted reference string."""
    if not CFPF_TECHNIQUES_FILE.exists():
        return "CFPF techniques catalog not available."

    with open(CFPF_TECHNIQUES_FILE, "r", encoding="utf-8") as f:
        data = json.load(f)

    lines = []
    for phase_key in ["P1", "P2", "P3", "P4", "P5"]:
        phase = data["phases"].get(phase_key, {})
        lines.append(f"\n### {phase_key}: {phase.get('name', '')}")
        for tech in phase.get("techniques", []):
            lines.append(f"- {tech['id']}: {tech['name']} — {tech['description'][:120]}")

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# LLM prompt construction
# ---------------------------------------------------------------------------

def build_system_prompt(cfpf_ref: str) -> str:
    """Build the system prompt for the LLM."""
    return f"""You are FLAME-AI, an expert fraud intelligence analyst. Your role is to analyze source material about fraud schemes and generate structured threat path documents for the FLAME (Fraud Lifecycle Analysis & Mitigation Exchange) platform.

You must output a complete threat path markdown document following the FLAME schema exactly. The output must be valid markdown that can be committed to a Git repository.

## Output Format

The document MUST follow this exact structure:

1. A title line: `# TP-XXXX: Title Here`
2. A YAML frontmatter block wrapped in triple backticks with ```yaml ... ```. IMPORTANT: Inside the code block, the content MUST be wrapped in `---` delimiters (standard frontmatter format).
3. Required sections: Summary, Threat Path Hypothesis, CFPF Phase Mapping (with technique tables), Look Left / Look Right, Controls & Mitigations, Detection Approaches, References, Revision History

## Frontmatter Schema

The YAML block inside the code fence must contain these fields:
- id: string (provided to you)
- title: string (descriptive, professional)
- category: "ThreatPath"
- date: string (YYYY-MM-DD, today's date provided to you)
- author: string (provided to you)
- source: string (the source URL)
- tlp: "WHITE"
- sector: list of strings (from: banking, credit-union, insurance, fintech, crypto, cross-sector, investment, payments, healthcare, government)
- fraud_types: list of strings (use kebab-case, e.g., account-takeover, wire-fraud, BEC, phishing)
- cfpf_phases: list (subset of [P1, P2, P3, P4, P5] — only include phases actually covered by the scheme)
- mitre_attack: list of MITRE ATT&CK technique IDs (e.g., T1566.001) — only include if genuinely applicable
- ft3_tactics: [] (empty for now)
- mitre_f3: [] (empty for now)
- groupib_stages: list of Group-IB Fraud Matrix stage names if applicable (from: Reconnaissance, Resource Development, Trust Abuse, End-user Interaction, Credential Access, Account Access, Defence Evasion, Perform Fraud, Monetization, Laundering)
- tags: list of descriptive kebab-case tags

## CFPF Phase Mapping Reference

Use real CFPF technique IDs from this catalog where they match. If no existing technique matches, describe the technique narratively without inventing IDs.

{cfpf_ref}

## Quality Standards

- Be specific and factual. Only include information supported by the source material.
- Write professionally. No emojis, no filler, no speculation beyond what the evidence supports.
- Confidence levels must be justified.
- Detection queries should be realistic (Splunk SPL, KQL, SQL, or Sigma).
- Each CFPF phase table must have: Technique | Description | Indicators columns.
- Only map to CFPF phases that are actually described or implied in the source material.
- MITRE ATT&CK mappings should only be included when genuinely applicable — do not force-map.

## Critical Rules

- Output ONLY the markdown document. No preamble, no explanation, no commentary.
- The YAML frontmatter must be wrapped in a ```yaml code fence, not raw --- delimiters.
- Do not invent facts. If the source doesn't cover a section, note it briefly and move on.
- Use the provided TP ID and date exactly as given."""


def build_user_prompt(
    tp_id: str,
    today: str,
    author: str,
    source_url: str,
    sector: str,
    fraud_types: str,
    context: str,
    article_text: str,
) -> str:
    """Build the user prompt with the article content and metadata."""
    prompt = f"""Generate a FLAME threat path document from the following source material.

## Assignment Details
- **TP ID**: {tp_id}
- **Date**: {today}
- **Author**: {author}
- **Source URL**: {source_url}
- **Primary Sector**: {sector}
- **Fraud Types**: {fraud_types}
"""

    if context:
        prompt += f"- **Additional Context**: {context}\n"

    prompt += f"""
## Source Material

{article_text}

---

Generate the complete threat path markdown document now. Remember: output ONLY the markdown, starting with the # title line."""

    return prompt


# ---------------------------------------------------------------------------
# LLM API calls
# ---------------------------------------------------------------------------

def call_anthropic(system_prompt: str, user_prompt: str, api_key: str) -> str:
    """Call Anthropic Claude API."""
    headers = {
        "x-api-key": api_key,
        "anthropic-version": "2023-06-01",
        "content-type": "application/json",
    }

    payload = {
        "model": ANTHROPIC_MODEL,
        "max_tokens": MAX_TOKENS,
        "system": system_prompt,
        "messages": [
            {"role": "user", "content": user_prompt}
        ],
    }

    try:
        resp = requests.post(ANTHROPIC_URL, headers=headers, json=payload, timeout=120)
        resp.raise_for_status()
        data = resp.json()
        return data["content"][0]["text"]
    except requests.RequestException as e:
        print(f"WARNING: Anthropic API call failed: {e}", file=sys.stderr)
        if hasattr(e, "response") and e.response is not None:
            print(f"  Response: {e.response.text[:500]}", file=sys.stderr)
        return None


def call_openai(system_prompt: str, user_prompt: str, api_key: str) -> str:
    """Call OpenAI GPT-4o API."""
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
    }

    payload = {
        "model": OPENAI_MODEL,
        "max_tokens": MAX_TOKENS,
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt},
        ],
    }

    try:
        resp = requests.post(OPENAI_URL, headers=headers, json=payload, timeout=120)
        resp.raise_for_status()
        data = resp.json()
        return data["choices"][0]["message"]["content"]
    except requests.RequestException as e:
        print(f"WARNING: OpenAI API call failed: {e}", file=sys.stderr)
        if hasattr(e, "response") and e.response is not None:
            print(f"  Response: {e.response.text[:500]}", file=sys.stderr)
        return None


def generate_threat_path(system_prompt: str, user_prompt: str) -> tuple[str, str]:
    """
    Call LLM with fallback chain. Returns (response_text, model_used).
    """
    anthropic_key = os.environ.get("ANTHROPIC_API_KEY", "").strip()
    openai_key = os.environ.get("OPENAI_API_KEY", "").strip()

    if not anthropic_key and not openai_key:
        print("ERROR: No API keys found. Set ANTHROPIC_API_KEY or OPENAI_API_KEY.", file=sys.stderr)
        sys.exit(1)

    # Try Anthropic first
    if anthropic_key:
        print(f"Calling {ANTHROPIC_MODEL}...", file=sys.stderr)
        result = call_anthropic(system_prompt, user_prompt, anthropic_key)
        if result:
            return result, ANTHROPIC_MODEL

    # Fallback to OpenAI
    if openai_key:
        print(f"Calling {OPENAI_MODEL} (fallback)...", file=sys.stderr)
        result = call_openai(system_prompt, user_prompt, openai_key)
        if result:
            return result, OPENAI_MODEL

    print("ERROR: All LLM API calls failed.", file=sys.stderr)
    sys.exit(1)


# ---------------------------------------------------------------------------
# Post-processing
# ---------------------------------------------------------------------------

def extract_title_from_output(content: str) -> str:
    """Extract the title from the generated markdown."""
    for line in content.split("\n"):
        line = line.strip()
        if line.startswith("# TP-"):
            # Remove the "# TP-XXXX: " prefix
            match = re.match(r"#\s+TP-\d{4}:\s*(.+)", line)
            if match:
                return match.group(1).strip()
    return "untitled"


def clean_output(content: str) -> str:
    """
    Clean up LLM output.
    Ensures the content follows FLAME's specific format:
    1. Title line (# TP-XXXX: ...)
    2. YAML frontmatter wrapped in ```yaml ... ``` code block
    """
    content = content.strip()

    # 1. Remove wrapping ```markdown ... ``` if the LLM enclosed the whole file
    if content.startswith("```markdown") or content.startswith("```md"):
        lines = content.splitlines()
        # Remove first line if it's the fence
        if lines[0].startswith("```"):
            lines = lines[1:]
        # Remove last line if it's closing fence
        if lines and lines[-1].strip() == "```":
            lines = lines[:-1]
        content = "\n".join(lines).strip()

    # 2. Ensure frontmatter is wrapped in ```yaml
    # The validator requires:
    # ```yaml
    # ---
    # ...
    # ---
    # ```
    
    # Check if we have a YAML block
    if "```yaml" not in content:
        # If the LLM output raw YAML (starting with ---), wrap it
        # But be careful not to wrap the Title line if it's first!
        
        lines = content.splitlines()
        new_lines = []
        in_yaml = False
        yaml_started = False
        
        for i, line in enumerate(lines):
            if line.strip() == "---":
                if not in_yaml:
                    if not yaml_started:
                        # Start of YAML block
                        new_lines.append("```yaml")
                        new_lines.append("---")
                        in_yaml = True
                        yaml_started = True
                    else:
                        # This shouldn't happen for standard frontmatter 
                        # unless there are multiple --- blocks?
                        new_lines.append(line)
                else:
                    # End of YAML block
                    new_lines.append("---")
                    new_lines.append("```")
                    in_yaml = False
            else:
                new_lines.append(line)
        
        if yaml_started:
            content = "\n".join(new_lines)

    return content


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description="FLAME AI Intake — generate threat path from URL")
    parser.add_argument("--url", required=True, help="Source URL to analyze")
    parser.add_argument("--author", default="FLAME AI Intake", help="Author name")
    parser.add_argument("--sector", default="cross-sector", help="Primary sector")
    parser.add_argument("--fraud-types", default="", help="Comma-separated fraud types")
    parser.add_argument("--context", default="", help="Additional context for the AI")
    parser.add_argument("--output-dir", default="ThreatPaths", help="Output directory")
    args = parser.parse_args()

    # Fetch article
    print(f"Fetching: {args.url}", file=sys.stderr)
    article_text = fetch_url_content(args.url)
    print(f"Fetched {len(article_text)} characters", file=sys.stderr)

    # Determine next TP ID
    tp_id = get_next_tp_id()
    today = date.today().isoformat()
    print(f"Assigning ID: {tp_id}", file=sys.stderr)

    # Load CFPF reference
    cfpf_ref = load_cfpf_techniques()

    # Build prompts
    system_prompt = build_system_prompt(cfpf_ref)
    user_prompt = build_user_prompt(
        tp_id=tp_id,
        today=today,
        author=args.author,
        source_url=args.url,
        sector=args.sector,
        fraud_types=args.fraud_types,
        context=args.context,
        article_text=article_text,
    )

    # Generate
    print("Generating threat path...", file=sys.stderr)
    raw_output, model_used = generate_threat_path(system_prompt, user_prompt)
    content = clean_output(raw_output)
    print(f"Generated by: {model_used}", file=sys.stderr)

    # Extract title for filename
    title = extract_title_from_output(content)
    slug = slugify(title)
    filename = f"{tp_id}-{slug}.md" if slug else f"{tp_id}-untitled.md"

    # Write output
    output_dir = REPO_ROOT / args.output_dir
    output_dir.mkdir(parents=True, exist_ok=True)
    output_path = output_dir / filename

    with open(output_path, "w", encoding="utf-8") as f:
        f.write(content)
        if not content.endswith("\n"):
            f.write("\n")

    print(f"Written: {output_path.relative_to(REPO_ROOT)}", file=sys.stderr)

    # Output JSON summary to stdout for the GitHub Action to consume
    summary = {
        "tp_id": tp_id,
        "title": title,
        "filename": filename,
        "filepath": str(output_path.relative_to(REPO_ROOT)),
        "model": model_used,
        "source_url": args.url,
        "article_length": len(article_text),
    }
    print(json.dumps(summary))

    return 0


if __name__ == "__main__":
    sys.exit(main())
