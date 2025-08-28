#!/usr/bin/env python3
import re, sys, json, csv


def is_phone_number(text):
    # Check if text is a 10-digit phone number
    if not isinstance(text, str):
        text = str(text)
    # Cleaning the number
    clean_text = re.sub(r"[\s\-\(\)\+]", "", text)
    # Checking if it's 10 digits or not
    return bool(re.match(r"^\d{10}$", clean_text))


def is_aadhar_number(text):
    # Check if text is a 12-digit Aadhar number
    if not isinstance(text, str):
        text = str(text)
    # Removing spaces
    clean_text = re.sub(r"[\s\-]", "", text)
    # Checking if 12 digits are present or not
    return bool(re.match(r"^\d{12}$", clean_text))


def is_passport_number(text):
    # Check if char is a passport number
    if not isinstance(text, str):
        return False
    return bool(re.match(r"^[A-Z]\d{7,8}$", text.upper()))


def is_upi_id(text):
    # Verifying if text is a UPI ID
    if not isinstance(text, str):
        return False
    upi_pattern = r"^[a-zA-Z0-9._-]+@[a-zA-Z0-9.-]+$"
    return bool(re.match(upi_pattern, text))


def is_full_name(text):
    # Checking  if name contains both first and last name
    if not isinstance(text, str):
        return False
    # Splitting by spaces and checking if we have at least 2 words
    parts = text.strip().split()
    if len(parts) < 2:
        return False
    # Checking if all parts are text and not numbers
    for part in parts:
        if not re.match(r"^[A-Za-z\.\-\']+$", part):
            return False
    return True


def is_email(text):
    # Checking if email is a valid email address
    if not isinstance(text, str):
        return False
    email_pattern = r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"
    return bool(re.match(email_pattern, text))


def is_physical_address(text):
    # Checking if address looks like a physical address with street, city, pin
    if not isinstance(text, str):
        return False
    text = text.strip()
    if len(text) < 10:  # Too short for full address
        return False

    # Checking for pin code pattern (6 digits)
    has_pincode = bool(re.search(r"\b\d{6}\b", text))

    # Checking for multiple components separated by commas or spaces
    components = re.split(r"[,\n]", text)
    has_multiple_parts = len(components) >= 3

    return has_pincode and has_multiple_parts


def redact_phone(phone):
    # Redacting phone number keeping first 2 and last 4 digits
    clean_phone = re.sub(r"[\s\-\(\)\+]", "", str(phone))
    if len(clean_phone) == 10:
        return f"{clean_phone[:2]}XXXXXX{clean_phone[-2:]}"
    return "[REDACTED_PHONE]"


def redact_aadhar(aadhar):
    # Redacting Aadhar number keeping first 2 and last 4 digits
    clean_aadhar = re.sub(r"[\s\-]", "", str(aadhar))
    if len(clean_aadhar) == 12:
        return f"{clean_aadhar[:2]}XXXXXXXX{clean_aadhar[-2:]}"
    return "[REDACTED_AADHAR]"


def redact_passport(passport):
    # Redacting passport number
    return f"{passport[0]}XXXXXXX" if len(passport) > 1 else "[REDACTED_PASSPORT]"


def redact_upi(upi):
    # Redacting UPI ID
    parts = upi.split("@")
    if len(parts) == 2:
        username = parts[0]
        domain = parts[1]
        if len(username) > 2:
            return f"{username[:2]}XXX@{domain}"
        else:
            return f"XXX@{domain}"
    return "[REDACTED_UPI]"


def redact_name(name):
    # Redacting full name keeping first letter of each part
    parts = name.strip().split()
    redacted_parts = []
    for part in parts:
        if len(part) > 1:
            redacted_parts.append(f"{part[0]}{'X' * (len(part) - 1)}")
        else:
            redacted_parts.append("X")
    return " ".join(redacted_parts)


def redact_email(email):
    # Redacting email keeping first 2 chars and domain
    parts = email.split("@")
    if len(parts) == 2:
        username = parts[0]
        domain = parts[1]
        if len(username) > 2:
            return f"{username[:2]}XXX@{domain}"
        else:
            return f"XXX@{domain}"
    return "[REDACTED_EMAIL]"


def redact_address(address):
    # Replacing street or apartment number with X
    redacted = re.sub(r"\d", "X", address)
    # Partially redacting words longer than 3 characters
    words = redacted.split()
    final_words = []
    for word in words:
        if len(word) > 3 and word.upper() not in ["ROAD", "STREET", "CITY", "STATE"]:
            final_words.append(f"{word[:2]}{'X' * (len(word) - 2)}")
        else:
            final_words.append(word)
    return " ".join(final_words)


# Main function to detect and redact PII from json data
def detect_and_redact_pii(data_json):
    try:
        data = json.loads(data_json)
    except:
        return data_json, False

    is_pii = False
    redacted_data = data.copy()

    combinatorial_pii = []

    for key, value in data.items():
        if value is None or value == "":
            continue

        value_str = str(value)

        # Checking standalone PII
        if key in ["phone", "contact"] and is_phone_number(value_str):
            redacted_data[key] = redact_phone(value_str)
            is_pii = True
        elif key == "aadhar" and is_aadhar_number(value_str):
            redacted_data[key] = redact_aadhar(value_str)
            is_pii = True
        elif key == "passport" and is_passport_number(value_str):
            redacted_data[key] = redact_passport(value_str)
            is_pii = True
        elif key == "upi_id" and is_upi_id(value_str):
            redacted_data[key] = redact_upi(value_str)
            is_pii = True

        # Checking combinatorial PII
        elif key == "name" and is_full_name(value_str):
            combinatorial_pii.append("name")
            redacted_data[key] = redact_name(value_str)
        elif key == "email" and is_email(value_str):
            combinatorial_pii.append("email")
            redacted_data[key] = redact_email(value_str)
        elif key == "address" and is_physical_address(value_str):
            combinatorial_pii.append("address")
            redacted_data[key] = redact_address(value_str)
        elif key in ["device_id", "ip_address"]:
            # These are PII only when combined with other identifiers
            if any(other_key in data for other_key in ["name", "email", "address"]):
                combinatorial_pii.append(key)
                redacted_data[key] = "[REDACTED_ID]"

    # Checking if we have combinatorial PII (2 or more PII)
    if len(combinatorial_pii) >= 2:
        is_pii = True

    json_str = json.dumps(redacted_data)
    # Escape double quotes for CSV format
    escaped_json = json_str.replace('"', '""')
    return f'"{escaped_json}"', is_pii


def main():
    if len(sys.argv) != 2:
        print("Usage: python3 detector_full_candidate_name.py input.csv")
        sys.exit(1)

    input_file = sys.argv[1]
    output_file = "redacted_output_candidate_full_name.csv"

    try:
        with open(input_file, "r", encoding="utf-8") as infile:
            reader = csv.DictReader(infile)

            columns = reader.fieldnames
            print(f"Found columns: {columns}")

            id_col = None
            data_col = None

            for col in columns:
                if "id" in col.lower():
                    id_col = col
                if "data" in col.lower() or "json" in col.lower():
                    data_col = col

            if not id_col or not data_col:
                print("Error: Could not find record_id and Data_json columns")
                print("Available columns:", columns)
                sys.exit(1)

            print(f"Using '{id_col}' as record_id and '{data_col}' as data column")

            with open(output_file, "w", encoding="utf-8", newline="") as outfile:
                fieldnames = ["record_id", "redacted_data_json", "is_pii"]
                writer = csv.DictWriter(outfile, fieldnames=fieldnames)
                writer.writeheader()

                print("\nrecord_id,redacted_data_json,is_pii\n")

                processed_count = 0
                pii_found_count = 0

                for row in reader:
                    record_id = row[id_col]
                    data_json = row[data_col]

                    redacted_json, is_pii = detect_and_redact_pii(data_json)

                    writer.writerow(
                        {
                            "record_id": record_id,
                            "redacted_data_json": redacted_json,
                            "is_pii": is_pii,
                        }
                    )

                    print(f"{record_id},{redacted_json},{is_pii}")

                    processed_count += 1
                    if is_pii:
                        pii_found_count += 1

        print(
            f"\nProcessed {processed_count} records, {pii_found_count} with PII detected."
        )
        print(f"Output saved to {output_file}")

    except FileNotFoundError:
        print(f"Error: Input file '{input_file}' not found.")
        sys.exit(1)
    except Exception as e:
        print(f"Error processing file: {str(e)}")
        sys.exit(1)


if __name__ == "__main__":
    main()
