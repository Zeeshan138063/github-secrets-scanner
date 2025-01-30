import os
from datetime import datetime
from typing import List, Optional

import pandas as pd
import streamlit as st

# Import your existing classes
from scan_credentials import GitHubRepository, CredentialScanner, CredentialFinding


class StreamlitUI:
    def __init__(self):
        st.set_page_config(page_title="GitHub Secrets Scanner", page_icon="🔍", layout="wide")
        self.scanner = CredentialScanner()
        self.initialize_session_state()

    def initialize_session_state(self):
        """Initialize session state variables"""
        if 'scan_results' not in st.session_state:
            st.session_state.scan_results = {}
        if 'current_repo' not in st.session_state:
            st.session_state.current_repo = None
        if 'element_counter' not in st.session_state:
            st.session_state.element_counter = 0

    def render_header(self):
        """Render the app header"""
        st.title("🔍 GitHub Secrets Scanner")
        st.markdown("""
        Scan GitHub repositories for exposed credentials, API keys, tokens, and secrets.
        """)

    def get_github_token(self) -> Optional[str]:
        """Get GitHub token from user input or environment"""
        with st.sidebar:
            st.header("Configuration")
            token_input = st.text_input("GitHub Token", type="password", help="Enter your GitHub Personal Access Token")
            return token_input or os.getenv("GITHUB_TOKEN")

    def get_repository_urls(self) -> List[str]:
        """Get repository URLs from user input"""
        st.subheader("Repository Input")
        input_method = st.radio("Choose input method", ["Direct Input", "Upload File"])

        if input_method == "Direct Input":
            repos_text = st.text_area("Enter repository URLs (one per line)",
                help="Example: https://github.com/username/repo.git")
            return [url.strip() for url in repos_text.split('\n') if url.strip()]
        else:
            uploaded_file = st.file_uploader("Upload repos.txt file", type="txt")
            if uploaded_file:
                content = uploaded_file.getvalue().decode()
                return [url.strip() for url in content.split('\n') if url.strip()]
        return []

    def scan_repository(self, repo_url: str, token: str) -> List[CredentialFinding]:
        """Scan a single repository and return findings"""
        repo = GitHubRepository(repo_url, token)
        findings = []

        try:
            with st.spinner(f"Cloning repository: {repo.name}"):
                if repo.clone():
                    with st.spinner(f"Scanning repository: {repo.name}"):
                        findings = self.scanner.scan(repo.clone_dir)
        finally:
            repo.cleanup()

        return findings

    def display_findings(self, repo_name: str, findings: List[CredentialFinding]):
        """Display scan findings in an interactive format"""
        if findings:
            # Increment counter for unique keys
            st.session_state.element_counter += 1
            unique_id = st.session_state.element_counter

            st.warning(f"Found {len(findings)} potential credential(s) in {repo_name}")

            # Convert findings to DataFrame for display
            df = pd.DataFrame([
                {'Rule ID': f.rule_id, 'Description': f.description, 'File': f.file_path, 'Line': f.line_number,
                    'Content': f.code_line, 'Date': f.date} for f in findings])

            # Display interactive table with unique key
            st.dataframe(df, use_container_width=True, hide_index=True, key=f"df_{repo_name}_{unique_id}")

            # Add download button with unique key
            csv = df.to_csv(index=False)
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            st.download_button(label="Download Results as CSV", data=csv,
                file_name=f"{repo_name}_scan_results_{timestamp}.csv", mime="text/csv",
                key=f"download_{repo_name}_{unique_id}")
        else:
            st.success(f"No credentials detected in {repo_name}")

    def render(self):
        """Main render method"""
        self.render_header()

        # Get GitHub token
        token = self.get_github_token()
        if not token:
            st.error("Please provide a GitHub token to proceed")
            return

        # Get repository URLs
        repo_urls = self.get_repository_urls()

        if repo_urls and st.button("Start Scan", type="primary"):
            progress_bar = st.progress(0)
            total_repos = len(repo_urls)

            for idx, repo_url in enumerate(repo_urls, 1):
                st.subheader(f"Scanning: {repo_url}")

                findings = self.scan_repository(repo_url, token)
                repo_name = repo_url.split("/")[-1].replace(".git", "")

                # Store results in session state
                st.session_state.scan_results[repo_name] = findings

                # Display findings for current repository
                self.display_findings(repo_name, findings)

                # Update progress
                progress_bar.progress(idx / total_repos)

            st.success("Scan completed!")

        # Display historical results
        if st.session_state.scan_results:
            st.subheader("Historical Scan Results")
            for repo_name, findings in st.session_state.scan_results.items():
                with st.expander(f"Results for {repo_name}"):
                    self.display_findings(repo_name, findings)


def main():
    ui = StreamlitUI()
    ui.render()


if __name__ == "__main__":
    main()
