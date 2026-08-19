from pathlib import Path
import mimetypes
from datetime import datetime
import hashlib
import fitz
import os
import getpass
import subprocess
import re


def detect_file_signature(file_signature):
    if file_signature.startswith(b"%PDF"):
        return "PDF Document"
    if file_signature.startswith(b"\xFF\xD8\xFF"):
        return "JPEG Image"
    if file_signature.startswith(b"\x89PNG"):
        return "PNG Image"
    if file_signature.startswith(b"PK"):
        return "ZIP / Office Document"
    if file_signature.startswith(b"MZ"):
        return "Windows Executable"
    return "Unknown"


def check_file_consistency(extension, detected_type):
    extension = extension.lower()

    if detected_type == "PDF Document" and extension == ".pdf":
        return True

    if detected_type == "JPEG Image" and extension in [".jpg", ".jpeg"]:
        return True

    if detected_type == "PNG Image" and extension == ".png":
        return True

    if detected_type == "ZIP / Office Document" and extension in [
        ".zip", ".docx", ".xlsx", ".pptx"
    ]:
        return True

    if detected_type == "Windows Executable" and extension in [
        ".exe", ".dll"
    ]:
        return True

    return False


def format_file_size(size):
    if size < 1024:
        return f"{size} bytes"

    if size < 1024 ** 2:
        return f"{size / 1024:.2f} KB"

    if size < 1024 ** 3:
        return f"{size / (1024 ** 2):.2f} MB"

    return f"{size / (1024 ** 3):.2f} GB"


def calculate_hashes(file):
    md5 = hashlib.md5()
    sha1 = hashlib.sha1()
    sha256 = hashlib.sha256()

    with open(file, "rb") as f:
        while chunk := f.read(4096):
            md5.update(chunk)
            sha1.update(chunk)
            sha256.update(chunk)

    return md5.hexdigest(), sha1.hexdigest(), sha256.hexdigest()


def analyze_pdf_metadata(file):
    document = fitz.open(file)
    metadata = document.metadata

    print("\nPDF METADATA")
    print("------------")
    print(f"Title: {metadata.get('title') or 'Not available'}")
    print(f"Author: {metadata.get('author') or 'Not available'}")
    print(f"Subject: {metadata.get('subject') or 'Not available'}")
    print(f"Creator: {metadata.get('creator') or 'Not available'}")
    print(f"Producer: {metadata.get('producer') or 'Not available'}")
    print(f"Creation date: {metadata.get('creationDate') or 'Not available'}")
    print(f"Modification date: {metadata.get('modDate') or 'Not available'}")
    print(f"Pages: {len(document)}")

    document.close()


def analyze_pdf_content(file):
    document = fitz.open(file)

    total_text = ""

    for page in document:
        total_text += page.get_text()

    print("\nCONTENT ANALYSIS")
    print("----------------")
    print(f"Pages: {len(document)}")
    print(f"Total characters: {len(total_text)}")
    print(f"Total words: {len(total_text.split())}")

    document.close()

    return total_text


def analyze_suspicious_content(text):
    print("\nSUSPICIOUS CONTENT")
    print("------------------")

    urls = re.findall(
        r"https?://[^\s]+",
        text,
        re.IGNORECASE
    )

    emails = re.findall(
        r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b",
        text
    )

    ip_addresses = re.findall(
        r"\b(?:\d{1,3}\.){3}\d{1,3}\b",
        text
    )

    suspicious_keywords = [
        "password",
        "malware",
        "phishing",
        "ransomware",
        "trojan",
        "virus",
        "exploit",
        "payload",
        "credential",
        "backdoor",
        "keylogger",
        "cmd",
        "powershell"
    ]

    found_keywords = []
    text_lower = text.lower()

    for keyword in suspicious_keywords:
        if keyword in text_lower:
            found_keywords.append(keyword)

    print(f"URLs found: {len(urls)}")
    print(f"Email addresses found: {len(emails)}")
    print(f"IP addresses found: {len(ip_addresses)}")

    print("\nSuspicious keywords:")

    if found_keywords:
        for keyword in found_keywords:
            print(f"[!] {keyword}")
    else:
        print("[+] None detected")

    return {
        "urls": len(urls),
        "emails": len(emails),
        "ips": len(ip_addresses),
        "keywords": len(found_keywords)
    }


def analyze_pdf_embedded_content(file):
    document = fitz.open(file)

    image_count = 0

    for page in document:
        image_count += len(page.get_images(full=True))

    embedded_files = document.embfile_names()

    print("\nEMBEDDED CONTENT")
    print("----------------")
    print(f"Images: {image_count}")
    print(f"Embedded files: {len(embedded_files)}")

    if embedded_files:
        print("\nEmbedded file names:")

        for name in embedded_files:
            print(f"- {name}")

    document.close()

    return {
        "images": image_count,
        "embedded_files": len(embedded_files)
    }


def analyze_pdf_images(file):
    document = fitz.open(file)

    images = []

    for page_number in range(len(document)):
        page = document[page_number]

        for image in page.get_images(full=True):
            xref = image[0]
            width = image[2]
            height = image[3]
            color_space = image[5]

            try:
                image_info = document.extract_image(xref)

                image_format = image_info.get(
                    "ext",
                    "Unknown"
                )

                bpc = image_info.get(
                    "bpc",
                    "Unknown"
                )

            except Exception:
                image_format = "Unknown"
                bpc = "Unknown"

            images.append({
                "page": page_number + 1,
                "xref": xref,
                "width": width,
                "height": height,
                "format": image_format.upper(),
                "color_space": color_space or "Unknown",
                "bpc": bpc
            })

    print("\nPDF IMAGES")
    print("----------")
    print(f"Total images: {len(images)}")

    for index, image in enumerate(images, start=1):
        print(f"\n[{index}] Page: {image['page']}")
        print(f"    XREF: {image['xref']}")
        print(
            f"    Dimensions: "
            f"{image['width']} x {image['height']} px"
        )
        print(f"    Format: {image['format']}")
        print(f"    Color Space: {image['color_space']}")
        print(f"    Bits Per Component: {image['bpc']}")

    if not images:
        print("[+] No embedded images detected.")

    document.close()


def analyze_pdf_image_hashes(file):
    document = fitz.open(file)

    print("\nPDF IMAGE HASHES")
    print("----------------")

    image_number = 0

    for page_number in range(len(document)):
        page = document[page_number]

        for image in page.get_images(full=True):
            image_number += 1
            xref = image[0]

            print(
                f"[{image_number}] "
                f"Page: {page_number + 1}"
            )
            print(f"    XREF: {xref}")

            try:
                image_info = document.extract_image(xref)
                image_data = image_info.get("image")

                if image_data:
                    image_hash = hashlib.sha256(
                        image_data
                    ).hexdigest()

                    print(f"    SHA-256: {image_hash}")
                else:
                    print("    SHA-256: Unable to calculate")

            except Exception as error:
                print(
                    "    SHA-256: "
                    f"Unable to calculate ({error})"
                )

    if image_number == 0:
        print("[+] No embedded images detected.")

    document.close()


def analyze_pdf_objects(file):
    document = fitz.open(file)

    print("\nPDF OBJECTS")
    print("-----------")

    total_objects = document.xref_length()

    print(f"Total objects: {total_objects}")

    object_types = {}

    for xref in range(1, total_objects):
        try:
            object_text = document.xref_object(
                xref,
                compressed=False
            )

            if not object_text:
                continue

            if "/Type /Catalog" in object_text:
                object_type = "Catalog"
            elif "/Type /Pages" in object_text:
                object_type = "Pages"
            elif "/Type /Page" in object_text:
                object_type = "Page"
            elif "/Type /Font" in object_text:
                object_type = "Font"
            elif "/Subtype /Image" in object_text:
                object_type = "Image"
            elif "/Subtype /Form" in object_text:
                object_type = "Form"
            elif "/Type /Annot" in object_text:
                object_type = "Annotation"
            elif "/Type /Metadata" in object_text:
                object_type = "Metadata"
            elif "/Type /XObject" in object_text:
                object_type = "XObject"
            else:
                object_type = "Other"

            object_types[object_type] = (
                object_types.get(object_type, 0) + 1
            )

        except Exception:
            continue

    print("\nObject type summary:")

    for object_type, count in sorted(object_types.items()):
        print(f"- {object_type}: {count}")

    print("\nObject listing:")

    displayed = 0

    for xref in range(1, total_objects):
        try:
            object_text = document.xref_object(
                xref,
                compressed=False
            )

            if not object_text:
                continue

            if "/Type /Catalog" in object_text:
                object_type = "Catalog"
            elif "/Type /Pages" in object_text:
                object_type = "Pages"
            elif "/Type /Page" in object_text:
                object_type = "Page"
            elif "/Type /Font" in object_text:
                object_type = "Font"
            elif "/Subtype /Image" in object_text:
                object_type = "Image"
            elif "/Subtype /Form" in object_text:
                object_type = "Form"
            elif "/Type /Annot" in object_text:
                object_type = "Annotation"
            elif "/Type /Metadata" in object_text:
                object_type = "Metadata"
            elif "/Type /XObject" in object_text:
                object_type = "XObject"
            else:
                object_type = "Other"

            print(f"[{xref}] Type: {object_type}")
            displayed += 1

        except Exception:
            continue

    if displayed == 0:
        print("[+] No objects listed.")

    document.close()


def analyze_pdf_structure(file):
    document = fitz.open(file)

    indicators = {
        "JavaScript": ["/JavaScript", "/JS"],
        "OpenAction": ["/OpenAction"],
        "Additional Actions": ["/AA"],
        "Launch Action": ["/Launch"],
        "Embedded File": ["/EmbeddedFile"],
        "RichMedia": ["/RichMedia"],
        "AcroForm": ["/AcroForm"],
        "XFA": ["/XFA"]
    }

    detected = {
        name: []
        for name in indicators
    }

    total_objects = document.xref_length()

    for xref in range(1, total_objects):
        try:
            object_text = document.xref_object(
                xref,
                compressed=False
            )

            if not object_text:
                continue

            for name, patterns in indicators.items():
                for pattern in patterns:
                    if pattern in object_text:
                        detected[name].append(xref)
                        break

        except Exception:
            continue

    print("\nPDF STRUCTURE ANALYSIS")
    print("----------------------")

    suspicious_found = False

    for name, objects in detected.items():

        if objects:
            suspicious_found = True

            unique_objects = sorted(set(objects))

            print(
                f"{name}: DETECTED "
                f"(Objects: {unique_objects})"
            )

        else:
            print(f"{name}: Not detected")

    if suspicious_found:
        print(
            "\n[!] Active-content indicators detected."
        )
        print(
            "[!] Manual forensic review recommended."
        )
    else:
        print(
            "\n[+] No suspicious PDF "
            "active-content indicators detected."
        )

    document.close()

    return detected


def analyze_pdf_javascript(file):
    document = fitz.open(file)

    javascript_found = False

    for page in document:
        for link in page.get_links():
            if link.get("kind") == fitz.LINK_LAUNCH:
                javascript_found = True

    text = ""

    for page in document:
        text += page.get_text()

    if "javascript" in text.lower():
        javascript_found = True

    print("\nPDF JAVASCRIPT")
    print("--------------")

    if javascript_found:
        print("JavaScript detected: Yes")
    else:
        print("JavaScript detected: No")

    document.close()


def analyze_pdf_links(file):
    document = fitz.open(file)

    links = []

    for page_number in range(len(document)):
        for link in document[page_number].get_links():
            uri = link.get("uri")

            if uri:
                links.append({
                    "page": page_number + 1,
                    "url": uri
                })

    print("\nPDF LINKS")
    print("---------")
    print(f"Total links: {len(links)}")

    if links:
        for index, link in enumerate(links, start=1):
            print(
                f"[{index}] Page {link['page']}: "
                f"{link['url']}"
            )
    else:
        print("[+] No clickable links detected.")

    document.close()


def analyze_pdf_fonts(file):
    document = fitz.open(file)

    fonts = set()

    for page in document:
        for font in page.get_fonts(full=True):
            fonts.add((font[3], font[2]))

    print("\nPDF FONTS")
    print("---------")
    print(f"Fonts found: {len(fonts)}")

    for index, (name, font_type) in enumerate(
        sorted(fonts),
        start=1
    ):
        print(
            f"[{index}] {name} | "
            f"Type: {font_type}"
        )

    if not fonts:
        print("[+] No fonts detected.")

    document.close()


def analyze_pdf_annotations(file):
    document = fitz.open(file)

    annotations = []

    for page_number in range(len(document)):
        annotation = document[page_number].first_annot

        while annotation:
            annotations.append({
                "page": page_number + 1,
                "type": annotation.type[1]
            })

            annotation = annotation.next

    print("\nPDF ANNOTATIONS")
    print("----------------")
    print(f"Total annotations: {len(annotations)}")

    if annotations:
        for index, item in enumerate(
            annotations,
            start=1
        ):
            print(
                f"[{index}] Page {item['page']} | "
                f"Type: {item['type']}"
            )
    else:
        print("[+] No annotations detected.")

    document.close()


def analyze_pdf_security(file):
    document = fitz.open(file)

    print("\nPDF SECURITY")
    print("------------")
    print(
        f"Encrypted: "
        f"{'Yes' if document.is_encrypted else 'No'}"
    )
    print(
        f"Permissions flag: "
        f"{document.permissions}"
    )

    document.close()


def analyze_pdf_permissions(file):
    document = fitz.open(file)

    permissions = document.permissions

    print("\nPDF PERMISSIONS")
    print("---------------")

    print(
        f"Printing: "
        f"{'Allowed' if permissions & fitz.PDF_PERM_PRINT else 'Not allowed'}"
    )

    print(
        f"Copying: "
        f"{'Allowed' if permissions & fitz.PDF_PERM_COPY else 'Not allowed'}"
    )

    print(
        f"Modifying: "
        f"{'Allowed' if permissions & fitz.PDF_PERM_MODIFY else 'Not allowed'}"
    )

    print(
        f"Form filling: "
        f"{'Allowed' if permissions & fitz.PDF_PERM_FORM else 'Not allowed'}"
    )

    print(
        f"Annotating: "
        f"{'Allowed' if permissions & fitz.PDF_PERM_ANNOTATE else 'Not allowed'}"
    )

    document.close()


def analyze_pdf_page_dimensions(file):
    document = fitz.open(file)

    print("\nPDF PAGE DIMENSIONS")
    print("-------------------")
    print(f"Total pages: {len(document)}")

    for page_number in range(len(document)):
        page = document[page_number]

        width = page.rect.width
        height = page.rect.height

        width_mm = width * 25.4 / 72
        height_mm = height * 25.4 / 72

        print(
            f"Page {page_number + 1}: "
            f"{width:.2f} x {height:.2f} pt "
            f"({width_mm:.2f} x {height_mm:.2f} mm)"
        )

    document.close()


def analyze_permissions(file):
    print("\nPERMISSIONS")
    print("-----------")

    print(
        f"Readable: "
        f"{'Yes' if os.access(file, os.R_OK) else 'No'}"
    )

    print(
        f"Writable: "
        f"{'Yes' if os.access(file, os.W_OK) else 'No'}"
    )

    if os.name == "nt":
        print("Executable: Not evaluated on Windows")
    else:
        print(
            f"Executable: "
            f"{'Yes' if os.access(file, os.X_OK) else 'No'}"
        )


def analyze_current_user():
    print("\nCURRENT USER")
    print("------------")
    print(f"User: {getpass.getuser()}")


def analyze_file_owner(file):
    print("\nFILE OWNER")
    print("----------")

    if os.name == "nt":
        try:
            result = subprocess.run(
                [
                    "powershell",
                    "-NoProfile",
                    "-Command",
                    f"(Get-Acl -LiteralPath '{file}').Owner"
                ],
                capture_output=True,
                text=True
            )

            owner = result.stdout.strip()

            print(
                f"Owner: "
                f"{owner if owner else 'Not available'}"
            )

        except Exception:
            print("Owner: Unable to determine")

    else:
        try:
            import pwd

            owner = pwd.getpwuid(
                file.stat().st_uid
            ).pw_name

            print(f"Owner: {owner}")

        except Exception:
            print("Owner: Unable to determine")


def calculate_risk_score(
    file_type_match,
    suspicious_content,
    embedded_content,
    structure_indicators
):
    score = 0
    reasons = []

    if not file_type_match:
        score += 20
        reasons.append("File extension/type mismatch")

    if suspicious_content["urls"] > 0:
        score += min(
            suspicious_content["urls"] * 5,
            15
        )
        reasons.append("URL(s) detected")

    if suspicious_content["emails"] > 0:
        score += min(
            suspicious_content["emails"] * 2,
            5
        )
        reasons.append("Email address(es) detected")

    if suspicious_content["ips"] > 0:
        score += min(
            suspicious_content["ips"] * 5,
            10
        )
        reasons.append("IP address(es) detected")

    if suspicious_content["keywords"] > 0:
        score += min(
            suspicious_content["keywords"] * 5,
            20
        )
        reasons.append("Suspicious keyword(s) detected")

    if embedded_content["embedded_files"] > 0:
        score += 20
        reasons.append("Embedded file(s) detected")

    active_content_weights = {
        "JavaScript": 25,
        "OpenAction": 10,
        "Additional Actions": 15,
        "Launch Action": 25,
        "Embedded File": 20,
        "RichMedia": 15,
        "AcroForm": 5,
        "XFA": 10
    }

    for indicator, objects in structure_indicators.items():
        if objects:
            score += active_content_weights.get(
                indicator,
                5
            )

            reasons.append(
                f"{indicator} indicator detected"
            )

    score = min(score, 100)

    if score < 25:
        level = "LOW"
        verdict = "No significant suspicious indicators detected"

    elif score < 50:
        level = "MEDIUM"
        verdict = "Some suspicious indicators require review"

    elif score < 75:
        level = "HIGH"
        verdict = "Multiple suspicious indicators detected"

    else:
        level = "CRITICAL"
        verdict = "Strong indicators of potentially malicious content"

    return score, level, verdict, reasons


def print_risk_assessment(
    score,
    level,
    verdict,
    reasons
):
    print("\nFORENSIC RISK ASSESSMENT")
    print("------------------------")
    print(f"Risk Score: {score}/100")
    print(f"Risk Level: {level}")
    print(f"Verdict: {verdict}")

    print("\nRisk Factors:")

    if reasons:
        for reason in reasons:
            print(f"- {reason}")
    else:
        print("[+] No risk factors identified.")


# ============================================================
# FEATURE 43 - FORENSIC REPORT GENERATOR
# ============================================================

def generate_forensic_report(
    file,
    readable_size,
    file_type,
    detected_type,
    file_type_match,
    created_time,
    modified_time,
    accessed_time,
    md5_hash,
    sha1_hash,
    sha256_hash,
    suspicious_content,
    embedded_content,
    structure_indicators,
    score,
    level,
    verdict,
    reasons
):
    report_name = f"DFIR_Report_{file.stem}.txt"
    report_path = file.parent / report_name

    try:
        with open(
            report_path,
            "w",
            encoding="utf-8"
        ) as report:

            report.write("=" * 70 + "\n")
            report.write(
                "              FILE EVIDENCE ANALYZER\n"
            )
            report.write(
                "              FORENSIC ANALYSIS REPORT\n"
            )
            report.write("=" * 70 + "\n\n")

            report.write("ANALYSIS INFORMATION\n")
            report.write("-" * 70 + "\n")
            report.write(
                f"Analysis Time: {datetime.now()}\n"
            )
            report.write(
                f"Analyzed File: {file}\n\n"
            )

            report.write("FILE INFORMATION\n")
            report.write("-" * 70 + "\n")
            report.write(
                f"File Name: {file.name}\n"
            )
            report.write(
                f"File Size: {readable_size}\n"
            )
            report.write(
                f"Extension: {file.suffix}\n"
            )
            report.write(
                f"MIME Type: {file_type}\n"
            )
            report.write(
                f"Detected Type: {detected_type}\n"
            )
            report.write(
                "Extension Match: "
                f"{'Yes' if file_type_match else 'No'}\n\n"
            )

            report.write("TIMESTAMPS\n")
            report.write("-" * 70 + "\n")
            report.write(
                f"Created: {created_time}\n"
            )
            report.write(
                f"Last Modified: {modified_time}\n"
            )
            report.write(
                f"Last Accessed: {accessed_time}\n\n"
            )

            report.write("FILE HASHES\n")
            report.write("-" * 70 + "\n")
            report.write(
                f"MD5: {md5_hash}\n"
            )
            report.write(
                f"SHA-1: {sha1_hash}\n"
            )
            report.write(
                f"SHA-256: {sha256_hash}\n\n"
            )

            report.write("SUSPICIOUS CONTENT\n")
            report.write("-" * 70 + "\n")
            report.write(
                f"URLs: {suspicious_content['urls']}\n"
            )
            report.write(
                "Email Addresses: "
                f"{suspicious_content['emails']}\n"
            )
            report.write(
                "IP Addresses: "
                f"{suspicious_content['ips']}\n"
            )
            report.write(
                "Suspicious Keywords: "
                f"{suspicious_content['keywords']}\n\n"
            )

            report.write("EMBEDDED CONTENT\n")
            report.write("-" * 70 + "\n")
            report.write(
                f"Images: {embedded_content['images']}\n"
            )
            report.write(
                "Embedded Files: "
                f"{embedded_content['embedded_files']}\n\n"
            )

            report.write("PDF STRUCTURE INDICATORS\n")
            report.write("-" * 70 + "\n")

            if structure_indicators:
                for indicator, objects in (
                    structure_indicators.items()
                ):
                    if objects:
                        report.write(
                            f"{indicator}: DETECTED "
                            f"(Objects: "
                            f"{sorted(set(objects))})\n"
                        )
                    else:
                        report.write(
                            f"{indicator}: "
                            "Not detected\n"
                        )
            else:
                report.write(
                    "No PDF structure analysis available.\n"
                )

            report.write("\n")

            report.write("FORENSIC RISK ASSESSMENT\n")
            report.write("-" * 70 + "\n")
            report.write(
                f"Risk Score: {score}/100\n"
            )
            report.write(
                f"Risk Level: {level}\n"
            )
            report.write(
                f"Verdict: {verdict}\n\n"
            )

            report.write("Risk Factors:\n")

            if reasons:
                for reason in reasons:
                    report.write(
                        f"- {reason}\n"
                    )
            else:
                report.write(
                    "- None identified\n"
                )

            report.write("\n")

            report.write("EVIDENCE INTEGRITY\n")
            report.write("-" * 70 + "\n")
            report.write(
                "Calculated SHA-256:\n"
            )
            report.write(
                f"{sha256_hash}\n\n"
            )

            report.write(
                "The SHA-256 hash can be used to "
                "verify evidence integrity.\n\n"
            )

            report.write("=" * 70 + "\n")
            report.write(
                "END OF FORENSIC REPORT\n"
            )
            report.write("=" * 70 + "\n")

        print("\nFORENSIC REPORT")
        print("---------------")
        print(
            "[+] Report generated successfully!"
        )
        print(
            f"[+] Saved to: {report_path}"
        )

        return report_path

    except Exception as error:
        print("\n[!] Report generation failed.")
        print(f"[!] Error: {error}")
        return None


def analyze_file():
    file_path = input("Enter file path: ")

    file = Path(file_path)

    if not file.exists():
        print("\n[-] File not found!")
        return

    file_size = file.stat().st_size
    readable_size = format_file_size(file_size)

    file_type, encoding = mimetypes.guess_type(file)

    stats = file.stat()

    created_time = datetime.fromtimestamp(
        stats.st_ctime
    )
    modified_time = datetime.fromtimestamp(
        stats.st_mtime
    )
    accessed_time = datetime.fromtimestamp(
        stats.st_atime
    )

    with open(file, "rb") as f:
        file_signature = f.read(8)

    detected_type = detect_file_signature(
        file_signature
    )

    md5_hash, sha1_hash, sha256_hash = calculate_hashes(
        file
    )

    print("\n[+] File found successfully!")
    print(f"File name: {file.name}")
    print(f"File size: {readable_size}")
    print(f"File extension: {file.suffix}")
    print(f"MIME type: {file_type}")
    print(
        f"File signature: "
        f"{file_signature.decode(errors='replace')}"
    )
    print(f"Detected type: {detected_type}")

    print("\nFILE TYPE CHECK")
    print("---------------")

    file_type_match = check_file_consistency(
        file.suffix,
        detected_type
    )

    if file_type_match:
        print(
            "[+] Extension matches "
            "detected file type."
        )
    else:
        print(
            "[!] WARNING: Extension does not "
            "match detected file type!"
        )

    print("\nTIMESTAMPS")
    print(f"Created: {created_time}")
    print(f"Last modified: {modified_time}")
    print(f"Last accessed: {accessed_time}")

    print("\nHASHES")
    print(f"MD5: {md5_hash}")
    print(f"SHA-1: {sha1_hash}")
    print(f"SHA-256: {sha256_hash}")

    analyze_permissions(file)
    analyze_current_user()
    analyze_file_owner(file)

    suspicious_content = {
        "urls": 0,
        "emails": 0,
        "ips": 0,
        "keywords": 0
    }

    embedded_content = {
        "images": 0,
        "embedded_files": 0
    }

    structure_indicators = {}

    score = 0
    level = "LOW"
    verdict = "No significant suspicious indicators detected"
    reasons = []

    if file.suffix.lower() == ".pdf":

        pdf_text = analyze_pdf_content(file)

        analyze_pdf_metadata(file)

        suspicious_content = analyze_suspicious_content(
            pdf_text
        )

        embedded_content = analyze_pdf_embedded_content(
            file
        )

        analyze_pdf_images(file)
        analyze_pdf_image_hashes(file)
        analyze_pdf_objects(file)

        structure_indicators = analyze_pdf_structure(
            file
        )

        analyze_pdf_javascript(file)
        analyze_pdf_links(file)
        analyze_pdf_fonts(file)
        analyze_pdf_annotations(file)
        analyze_pdf_security(file)
        analyze_pdf_permissions(file)
        analyze_pdf_page_dimensions(file)

        score, level, verdict, reasons = (
            calculate_risk_score(
                file_type_match,
                suspicious_content,
                embedded_content,
                structure_indicators
            )
        )

        print_risk_assessment(
            score,
            level,
            verdict,
            reasons
        )

    else:
        print(
            "\n[*] PDF-specific analysis skipped "
            "because the file is not a PDF."
        )

    expected_hash = input(
        "\nEnter expected SHA-256 "
        "(or press Enter to skip): "
    ).strip()

    integrity_status = "SKIPPED"

    if expected_hash:
        if expected_hash.lower() == sha256_hash.lower():
            print(
                "\n[+] Integrity Status: MATCH"
            )
            integrity_status = "MATCH"
        else:
            print(
                "\n[!] Integrity Status: MISMATCH"
            )
            integrity_status = "MISMATCH"
    else:
        print(
            "\n[*] Hash verification skipped."
        )

    # Generate final forensic report
    generate_forensic_report(
        file,
        readable_size,
        file_type,
        detected_type,
        file_type_match,
        created_time,
        modified_time,
        accessed_time,
        md5_hash,
        sha1_hash,
        sha256_hash,
        suspicious_content,
        embedded_content,
        structure_indicators,
        score,
        level,
        verdict,
        reasons
    )


if __name__ == "__main__":
    analyze_file()
    