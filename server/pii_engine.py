import re
from docx import Document


def extract_docx_text(file_path):
    document = Document(file_path)

    texts = []

    for paragraph in document.paragraphs:
        if paragraph.text.strip():
            texts.append(paragraph.text)

    return "\n".join(texts)


def detect_pii(text):
    results = {
        "resident_number": [],
        "phone_number": [],
        "email": [],
        "account_number": []
    }

    resident_pattern = r"\b\d{6}-[1-4]\d{6}\b"

    phone_pattern = r"\b01[016789]-\d{3,4}-\d{4}\b"

    email_pattern = (
        r"\b[A-Za-z0-9._%+-]+"
        r"@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"
    )

    account_pattern = r"\b\d{2,6}-\d{2,6}-\d{2,6}\b"

    results["resident_number"] = re.findall(
        resident_pattern,
        text
    )

    results["phone_number"] = re.findall(
        phone_pattern,
        text
    )

    results["email"] = re.findall(
        email_pattern,
        text
    )

    account_candidates = re.findall(
        account_pattern,
        text
    )

    results["account_number"] = [
        account
        for account in account_candidates
        if account not in results["phone_number"]
        and account not in results["resident_number"]
    ]

    return results
def calculate_pii_score(results):
    score = 0
    reasons = []

    resident_count = len(results["resident_number"])
    phone_count = len(results["phone_number"])
    email_count = len(results["email"])
    account_count = len(results["account_number"])

    if resident_count > 0:
        score += min(resident_count * 40, 80)
        reasons.append(
            f"주민등록번호 {resident_count}건 탐지"
        )

    if phone_count > 0:
        score += min(phone_count * 10, 30)
        reasons.append(
            f"전화번호 {phone_count}건 탐지"
        )

    if email_count > 0:
        score += min(email_count * 5, 20)
        reasons.append(
            f"이메일 {email_count}건 탐지"
        )

    if account_count > 0:
        score += min(account_count * 20, 40)
        reasons.append(
            f"계좌번호 후보 {account_count}건 탐지"
        )

    score = min(score, 100)

    if score >= 70:
        grade = "대외비"

    elif score >= 30:
        grade = "내부"

    else:
        grade = "일반"

    return score, grade, reasons


def analyze_document(file_path):
    text = extract_docx_text(file_path)

    pii_results = detect_pii(text)

    pii_score, file_grade, reasons = calculate_pii_score(
        pii_results
    )

    return {
        "pii_score": pii_score,
        "file_grade": file_grade,
        "reasons": reasons,
        "detected": pii_results
    }
if __name__ == "__main__":
    import os

    BASE_DIR = os.path.dirname(
        os.path.dirname(os.path.abspath(__file__))
    )

    test_file = os.path.join(
        BASE_DIR,
        "test_documents",
        "customer_personal_data.docx"
    )

    result = analyze_document(test_file)

    print("PII Score:", result["pii_score"])
    print("문서 등급:", result["file_grade"])

    print("\n탐지 이유:")

    for reason in result["reasons"]:
        print("-", reason)

    print("\n탐지 결과:")
    print(result["detected"])