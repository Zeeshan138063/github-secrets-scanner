import os
import subprocess
import shutil
import argparse
import csv
import re
from pathlib import Path
from dataclasses import dataclass
from typing import List, Optional
from dotenv import load_dotenv
from datetime import datetime

RULE_DESCRIPTIONS = {
    'slack-webhook-url': 'Slack Webhook URL - Used for sending messages to Slack channels',
    'aws-access-token': 'AWS Access Token - Credentials for AWS services',
    'generic-api-key': 'Generic API Key - General purpose API authentication token',
    'rapidapi-access-token': 'RapidAPI Access Token - Authentication for RapidAPI services',
}


def strip_ansi_codes(text: str) -> str:
    """Remove ANSI color codes from text"""
    ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
    return ansi_escape.sub('', text)


@dataclass
class CredentialFinding:
    """Represents a detected credential or secret in the codebase"""
    rule_id: str
    description: str
    file_path: str
    line_number: str
    secret: str
    code_line: str  # The actual line of code containing the secret
    start_line: int
    start_column: int
    end_line: int
    end_column: int
    commit: str = "Unknown"
    author: str = "Unknown"
    date: str = ""


class GitHubRepository:
    def __init__(self, url: str, token: str):
        self.url = url
        self.token = token
        self.name = url.split("/")[-1].replace(".git", "")
        self.clone_dir = Path(f"temp_repo_{self.name}")

    def clone(self) -> bool:
        try:
            auth_url = self.url.replace("https://", f"https://{self.token}@")
            result = subprocess.run(
                ["git", "clone", "--depth", "1", auth_url, str(self.clone_dir)],
                capture_output=True,
                text=True,
                check=True
            )
            print(f"✓ Successfully cloned repository: {self.name}")
            return True
        except subprocess.CalledProcessError as e:
            print(f"✗ Failed to clone repository {self.name}: {e.stderr}")
            return False

    def cleanup(self):
        if self.clone_dir.exists():
            shutil.rmtree(self.clone_dir)
            print(f"✓ Cleaned up {self.clone_dir}")


class CredentialScanner:
    def __init__(self):
        self._check_gitleaks_installation()

    @staticmethod
    def _check_gitleaks_installation():
        try:
            result = subprocess.run(["gitleaks", "version"], capture_output=True, text=True, check=True)
            print(f"✓ Using {result.stdout.strip()}")
        except (subprocess.CalledProcessError, FileNotFoundError):
            raise RuntimeError("✗ gitleaks is not installed. Please install it first.")

    def parse_finding(self, lines: List[str]) -> Optional[CredentialFinding]:
        """Parse a group of lines into a CredentialFinding object"""
        finding_data = {}

        for line in lines:
            line = line.strip()
            if not line or line.startswith('Fingerprint:'):
                continue

            if ':' in line:
                key, value = [x.strip() for x in line.split(':', 1)]
                finding_data[key] = strip_ansi_codes(value).strip()

        if not finding_data:
            return None

        # Extract file path and line number from the finding
        file_path = finding_data.get('File', 'Unknown')
        if file_path != 'Unknown':
            # Remove temp_repo_RepoName/ from the start of the path
            file_path = re.sub(r'^temp_repo_[^/]+/', '', file_path)
        line_number = finding_data.get('Line', '0')

        # Get the actual line of code containing the secret
        code_line = finding_data.get('Finding', finding_data.get('Secret', 'Unknown'))

        # Parse line and column numbers
        try:
            start_line = int(line_number)
            start_column = 1
            end_line = start_line
            end_column = len(code_line) if code_line else 1
        except ValueError:
            start_line = end_line = 0
            start_column = end_column = 1

        return CredentialFinding(
            rule_id=finding_data.get('RuleID', 'Unknown'),
            description=RULE_DESCRIPTIONS.get(finding_data.get('RuleID', ''), 'Potential credential or secret'),
            file_path=file_path,
            line_number=line_number,
            secret=finding_data.get('Secret', 'Unknown'),
            code_line=code_line,
            start_line=start_line,
            start_column=start_column,
            end_line=end_line,
            end_column=end_column,
            date=datetime.now().strftime("%Y-%m-%d")
        )

    def scan(self, repo_dir: Path) -> List[CredentialFinding]:
        print(f"\n🔍 Scanning {repo_dir.name} for credentials...")

        try:
            result = subprocess.run([
                "gitleaks", "detect",
                "-s", str(repo_dir),
                "-v",
                "--no-git",
                "--follow-symlinks"
            ], capture_output=True, text=True, check=False)

            # Split output into groups of findings
            output_lines = result.stdout.splitlines()
            current_lines = []
            findings = []

            for line in output_lines:
                if line.strip():
                    current_lines.append(line)
                elif current_lines:  # Empty line - process current finding
                    finding = self.parse_finding(current_lines)
                    if finding:
                        findings.append(finding)
                    current_lines = []

            # Process last finding if exists
            if current_lines:
                finding = self.parse_finding(current_lines)
                if finding:
                    findings.append(finding)

            # Print findings
            if findings:
                print(f"\n⚠️  Found {len(findings)} potential credential(s)")
                for finding in findings:
                    print(f"\n❌ {finding.rule_id} in {finding.file_path}:{finding.line_number}")
                    print(f"Description: {finding.description}")
                    print(f"Line content: {finding.code_line}")
            else:
                print("✓ No credentials detected")

            return findings

        except subprocess.CalledProcessError as e:
            print(f"✗ Error running scan: {e.stderr}")
            return []


class ReportGenerator:
    def __init__(self, output_dir: Path):
        self.output_dir = output_dir
        self.output_dir.mkdir(exist_ok=True)

    def generate(self, repo_name: str, findings: List[CredentialFinding]) -> Path:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        report_file = self.output_dir / f"{repo_name}_credentials_{timestamp}.md"

        with report_file.open(mode="w", encoding="utf-8") as file:
            file.write(f"# Credential Scan Report - {repo_name}\n\n")
            file.write(f"**Date:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")

            if not findings:
                file.write("## No credentials found ✅\n")
            else:
                file.write("## Detected Credentials\n\n")
                file.write(
                    "| Rule ID | Description | File | Line | Line Content | Start Line | Start Column | End Line | End Column | Date |\n")
                file.write(
                    "|---------|------------|------|------|-------------|------------|--------------|---------|-----------|------|\n")

                for finding in findings:
                    file.write(
                        f"| {finding.rule_id} | {finding.description} | {finding.file_path} | {finding.line_number} | "
                        f"`{finding.code_line}` | {finding.start_line} | {finding.start_column} | {finding.end_line} | "
                        f"{finding.end_column} | {finding.date} |\n"
                    )

        print(f"\n📄 Markdown report generated: {report_file}")
        return report_file
def main():
    parser = argparse.ArgumentParser(
        description="Scan GitHub repositories for exposed credentials and secrets",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""Example usage:
          1. Set your GitHub token in .env file:
               GITHUB_TOKEN=your_token_here
          2. Create a repos.txt file with repository URLs:
               https://github.com/user/repo1
               https://github.com/user/repo2
          3. Run the scanner:
               python3 scan_credentials.py --repo-file repos.txt
               """
    )

    parser.add_argument(
        "--repo-file",
        type=Path,
        required=True,
        help="Path to a file containing repository URLs (one per line)"
    )

    args = parser.parse_args()

    try:
        # Load GitHub token
        load_dotenv()
        github_token = os.getenv("GITHUB_TOKEN")
        if not github_token:
            raise ValueError("GitHub token not found. Please set GITHUB_TOKEN in your .env file.")

        # Read repository URLs
        if not args.repo_file.exists():
            raise FileNotFoundError(f"Repository file not found: {args.repo_file}")

        repos = [url.strip() for url in args.repo_file.read_text().splitlines() if url.strip()]

        scanner = CredentialScanner()
        report_generator = ReportGenerator(Path("reports"))

        # Scan each repository
        for repo_url in repos:
            repo = GitHubRepository(repo_url, github_token)
            try:
                if repo.clone():
                    findings = scanner.scan(repo.clone_dir)
                    report_generator.generate(repo.name, findings)
            finally:
                repo.cleanup()

    except Exception as e:
        print(f"✗ Error: {e}")
        exit(1)


if __name__ == "__main__":
    main()
