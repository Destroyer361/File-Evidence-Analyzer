## Features

### 🔍 File Identification & Metadata

* File name and extension detection
* File size analysis
* MIME type detection
* File signature/type detection
* Extension and detected-type comparison
* File creation, modification, and access timestamps

### 🔐 Cryptographic Hashing & Integrity

* MD5 hash generation
* SHA-1 hash generation
* SHA-256 hash generation
* Evidence integrity verification
* MATCH / MISMATCH status
* Cryptographic hashes included in forensic reports

### 👤 File System & Permission Analysis

* Current user identification
* File owner detection
* Read permission analysis
* Write permission analysis
* Execute permission analysis
* Windows-specific permission handling

### 🚨 Suspicious Content Detection

The analyzer scans file content for potentially suspicious indicators:

* URLs
* Email addresses
* IP addresses
* Suspicious keywords
* Indicator count and reporting

### 📄 PDF Forensic Analysis

For PDF files, the analyzer performs detailed structural analysis:

* PDF metadata analysis
* Page count
* Character and word count
* PDF page dimensions
* Embedded image detection
* Embedded file detection
* Image dimensions and format
* Image SHA-256 hashing
* PDF object analysis
* Font analysis
* Link detection
* Annotation detection
* Encryption/security analysis
* PDF permission analysis

### ⚠️ PDF Active-Content Analysis

The tool checks for potentially active PDF components:

* JavaScript
* OpenAction
* Additional Actions
* Launch Actions
* Embedded Files
* RichMedia
* AcroForm
* XFA

Detected active-content indicators are reported separately for manual forensic review.

### 📊 Forensic Risk Assessment

The analyzer generates a risk assessment based on detected indicators:

* Risk Score: `0–100`
* Risk Level
* Verdict
* Identified risk factors

Example:

```text
Risk Score: 10/100
Risk Level: LOW
Verdict: No significant suspicious indicators detected

Risk Factors:
- OpenAction indicator detected
```

### 🧾 Automated Forensic Reporting

A structured forensic report is automatically generated after analysis containing:

* Analysis information
* File information
* Timestamps
* Cryptographic hashes
* Suspicious content findings
* Embedded content
* PDF structure indicators
* Risk assessment
* Evidence integrity information

Example:

```text
[+] Integrity Status: MATCH

FORENSIC REPORT
---------------
[+] Report generated successfully!
[+] Saved to:
C:\Users\ANURAG\Downloads\DFIR_Report_DFIR.txt
```

### 📁 Multi-Format File Analysis

The analyzer can process different file types.

For supported PDF files, detailed PDF-specific forensic analysis is performed.

For non-PDF files such as `.xlsx`, the tool still performs general file identification, metadata, hashing, suspicious-content, and integrity analysis while appropriately skipping PDF-specific checks.

### 🛡️ Evidence Integrity

The SHA-256 hash provides a cryptographic fingerprint that can be used to verify whether the analyzed evidence has remained unchanged.

```text
Calculated SHA-256:
a9c89c9a80a5c8bf26e37223a58a0fab4f78e880a315867d4737a313a48c102a

Integrity Status: MATCH
```

### 📝 Forensic Review Indicators

When potentially interesting structural indicators are detected, the analyzer clearly reports them and recommends manual forensic review rather than automatically declaring the file malicious.
