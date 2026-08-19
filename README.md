# File Evidence Analyzer

A Python-based digital forensics tool for analyzing files, verifying evidence integrity, detecting suspicious indicators, performing PDF forensic analysis, and generating automated forensic reports.

## Features

### 1. File Identification

* File name and extension detection
* File size calculation
* MIME type detection
* File signature analysis
* Detected file type identification
* Extension/type consistency check

### 2. File Integrity & Hashing

* MD5
* SHA-1
* SHA-256
* Expected SHA-256 verification
* Integrity status: MATCH / MISMATCH

### 3. File System Analysis

* Created timestamp
* Modified timestamp
* Accessed timestamp
* Read/write/execute permission analysis
* Current user detection
* File owner detection

### 4. Suspicious Content Detection

The analyzer checks file content for:

* URLs
* Email addresses
* IP addresses
* Suspicious keywords

### 5. PDF Forensic Analysis

For PDF files, the analyzer can inspect:

* PDF metadata
* Page count
* Character and word count
* Embedded images
* Embedded files
* PDF image information
* Embedded image SHA-256 hashes
* PDF objects
* PDF structure
* JavaScript
* Links
* Fonts
* Annotations
* Encryption/security
* PDF permissions
* Page dimensions

### 6. PDF Active-Content Detection

The analyzer checks for:

* JavaScript
* OpenAction
* Additional Actions
* Launch Action
* Embedded Files
* RichMedia
* AcroForm
* XFA

Detected active-content indicators are flagged for manual forensic review.

### 7. Forensic Risk Assessment

The tool generates:

* Risk Score
* Risk Level
* Verdict
* Risk Factors

Example:

```text
FORENSIC RISK ASSESSMENT
------------------------
Risk Score: 10/100
Risk Level: LOW
Verdict: No significant suspicious indicators detected

Risk Factors:
- OpenAction indicator detected
```

### 8. Automated Forensic Report

After analysis, the tool generates a forensic report containing:

* Analysis information
* File information
* Timestamps
* File hashes
* Suspicious content findings
* Embedded content
* PDF structure indicators
* Risk assessment
* Evidence integrity information

Example:

```text
FORENSIC REPORT
---------------
[+] Report generated successfully!
[+] Saved to:
C:\Users\ANURAG\Downloads\DFIR_Report_DFIR.txt
```

## Technologies Used

* Python 3.13
* PyMuPDF
* hashlib
* pathlib
* mimetypes
* os
* re
* subprocess

## Installation

Clone the repository:

```bash
git clone <YOUR-GITHUB-REPOSITORY-URL>
cd File-Evidence-Analyzer
```

Install the required dependency:

```bash
python -m pip install PyMuPDF
```

## Usage

Run the analyzer:

```bash
python main.py
```

Enter the complete path of the file when prompted.

Example:

```text
C:\Users\ANURAG\Downloads\DFIR.pdf
```

The analyzer will perform the available forensic checks and display the results in the terminal.

A forensic report is generated automatically after analysis.

## Example Integrity Verification

```text
SHA-256:
a9c89c9a80a5c8bf26e37223a58a0fab4f78e880a315867d4737a313a48c102a

[+] Integrity Status: MATCH
```

## Project Structure

```text
File-Evidence-Analyzer/
│
├── .gitignore
├── README.md
├── main.py
│
└── analyzer/
    └── file_analyzer.py
```

`__pycache__` and generated Python bytecode files are excluded from version control using `.gitignore`.

## Forensic Use Cases

This project can be used for learning and authorized forensic analysis involving:

* File identification
* Evidence integrity verification
* Cryptographic hashing
* File-system metadata analysis
* PDF forensic examination
* Suspicious indicator detection
* PDF active-content inspection
* Risk assessment
* Automated forensic reporting

## Limitations

This is an educational digital forensics project and is not intended to replace professional DFIR platforms.

A detected indicator does not automatically mean that a file is malicious. Findings should be manually investigated and correlated with additional forensic evidence.

## Future Enhancements

Possible future enhancements include:

* Graphical User Interface
* HTML/PDF report generation
* YARA integration
* IOC extraction and export
* VirusTotal integration
* Timeline visualization
* Additional file-format parsers
* Case management

## Disclaimer

This project is intended for educational, defensive-security, and authorized forensic analysis purposes only.

Do not analyze files that you do not have permission to examine.

## Author

**ANURAG**

Digital Forensics & Cybersecurity Project
