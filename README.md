# GitHub Credential Scanner

A Python-based tool to scan GitHub repositories for exposed credentials, API keys, tokens, and secrets using Gitleaks. Automatically generates detailed reports for multiple repositories.

## Features
- Scan multiple repositories in one go
- Interactive Streamlit web interface for easy scanning
- Real-time scan progress monitoring
- Interactive visualization of scan results
- Export results in CSV format
- Generate detailed Markdown reports
- Supports both public and private repositories
- Easy to set up and use


## Prerequisites
- Python 3.x
- Gitleaks installed on your system.
- A GitHub Personal Access Token (PAT) with `repo` scope.

## Installation

1. **Clone this repository**:
   ```bash
   git clone https://github.com/your-username/credential-scanner.git
   cd credential-scanner
   ```

2. **Install the required Python packages**:
   ```bash
   pip install -r requirements.txt
   ```

3. **Install Gitleaks**:
   - On macOS (using Homebrew):
     ```bash
     brew install gitleaks
     ```
   - On Ubuntu:
     ```bash
     wget https://github.com/gitleaks/gitleaks/releases/download/v8.18.1/gitleaks_8.18.1_linux_x64.tar.gz
     tar -xvzf gitleaks_8.18.1_linux_x64.tar.gz
     sudo mv gitleaks /usr/local/bin/
     ```

4. **Create a `.env` file**:
   Add your GitHub token to the `.env` file:
   ```env
   GITHUB_TOKEN='your_github_personal_access_token'
   ```


## Usage

### Streamlit Web Interface
1. **Start the Streamlit app**:
   ```bash
   streamlit run streamlit_app.py
   ```

2. **Access the web interface**:
   - Open your browser and go to `http://localhost:8501`
   - Enter your GitHub token in the sidebar (or it will use the token from `.env`)
   - Input repository URLs directly or upload a text file
   - Click "Start Scan" to begin scanning

3. **View and Export Results**:
   - Monitor real-time scanning progress
   - View interactive tables of findings
   - Download results as CSV files
   - Access historical scan results within the session

### Command Line Interface
1. **Add repositories to scan**:
   Add the repositories you want to scan in `repos.txt` (one repository URL per line):
   ```
   git@github.com:Merchant-Crawler.git
   git@github.com:scout-system.git
   git@github.com:shakespeare.git
   ```

2. **Run the script**:
   ```bash
   python scan_credentials.py --repo-file repos.txt
   ```

3. **Check the generated reports**:
   - Each repository will have a Markdown report named `<repo_name>_report.md` in the `reports/` directory

## Example Report

Here’s an example of what the report looks like:

```markdown
# Repository: Merchant-Crawler

## Scan Results

| Rule ID | Description | File | Line | Line Content | Start Line | Start Column | End Line | End Column | Date |
|---------|------------|------|------|-------------|------------|--------------|---------|-----------|------|
| slack-webhook-url | Slack Webhook URL - Used for sending messages to Slack channels | slack_notification.py | 8 | `url = "https://hooks.slack.com/services/TALp8hw\OmZ"` | 8 | 1 | 8 | 86 | 2025-01-30 |
```



## Folder Structure

```
credential-scanner/
├── .env
├── .gitignore
├── LICENSE
├── README.md
├── requirements.txt
├── repos.txt
├── scan_credentials.py
└── reports/
    ├── repo1_report.md
    ├── repo2_report.md
    └── repo3_report.md
```

## Contributing

Contributions are welcome! Please follow these steps:

1. Fork the repository.
2. Create a new branch (`git checkout -b feature/YourFeature`).
3. Commit your changes (`git commit -m 'Add some feature'`).
4. Push to the branch (`git push origin feature/YourFeature`).
5. Open a pull request.

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

## Acknowledgments

- [Gitleaks](https://github.com/gitleaks/gitleaks) for the secret detection engine.
- Python community for awesome libraries.

---

## How It Works

1. **Clone Repositories**:
   - The script uses your GitHub token to clone the repositories listed in `repos.txt`.

2. **Run Gitleaks**:
   - It runs `gitleaks detect` on each repository to scan for secrets.

3. **Generate Reports**:
   - The script generates a Markdown report for each repository, detailing any secrets found.

4. **Clean Up**:
   - The cloned repositories are deleted after the scan to avoid leaving sensitive data on disk.

---

## Support

If you encounter any issues or have questions, feel free to open an issue on the [GitHub repository](https://github.com/your-username/credential-scanner/issues).

---

## Author

[Zeeshan](https://github.com/Zeeshan138063)
