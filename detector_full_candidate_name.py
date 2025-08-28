#!/usr/bin/env python3
import csv
import json
import re
import sys

def is_phone_number(text):
    """Check if text is a 10-digit phone number"""
    if not isinstance(text, str):
        text = str(text)
    # Remove spaces, hyphens, and other common separators
    clean_text = re.sub(r'[\s\-\(\)\+]', '', text)
    # Check if it's exactly 10 digits
    return bool(re.match(r'^\d{10}$', clean_text))

def is_aadhar_number(text):
    """Check if text is a 12-digit Aadhar number"""
    if not isinstance(text, str):
        text = str(text)
    # Remove spaces and hyphens
    clean_text = re.sub(r'[\s\-]', '', text)
    # Check if it's exactly 12 digits
    return bool(re.match(r'^\d{12}$', clean_text))

def is_passport_number(text):
    """Check if text is a passport number (common alphanumeric format)"""
    if not isinstance(text, str):
        return False
    # Common passport formats: P1234567, A12345678, etc.
    return bool(re.match(r'^[A-Z]\d{7,8}$', text.upper()))

def is_upi_id(text):
    """Check if text is a UPI ID"""
    if not isinstance(text, str):
        return False
    # Format: user@upi or 9876543210@ybl
    upi_pattern = r'^[a-zA-Z0-9._-]+@[a-zA-Z0-9.-]+$'
    return bool(re.match(upi_pattern, text))

def is_full_name(text):
    """Check if text contains both first and last name"""
    if not isinstance(text, str):
        return False
    # Split by spaces and check if we have at least 2 parts
    parts = text.strip().split()
    if len(parts) < 2:
        return False
    # Check if all parts are alphabetic (allowing some special chars)
    for part in parts:
        if not re.match(r'^[A-Za-z\.\-\']+$', part):
            return False
    return True

def is_email(text):
    """Check if text is a valid email address"""
    if not isinstance(text, str):
        return False
    email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return bool(re.match(email_pattern, text))

def is_physical_address(text):
    """Check if text looks like a physical address with street, city, pin"""
    if not isinstance(text, str):
        return False
    # Look for common address patterns - should have multiple components
    text = text.strip()
    if len(text) < 10:  # Too short to be a full address
        return False
    
    # Check for pin code pattern (6 digits)
    has_pincode = bool(re.search(r'\b\d{6}\b', text))
    
    # Check for multiple components separated by commas or spaces
    components = re.split(r'[,\n]', text)
    has_multiple_parts = len(components) >= 3
    
    return has_pincode and has_multiple_parts

def redact_phone(phone):
    """Redact phone number keeping first 2 and last 4 digits"""
    clean_phone = re.sub(r'[\s\-\(\)\+]', '', str(phone))
    if len(clean_phone) == 10:
        return f"{clean_phone[:2]}XXXXXX{clean_phone[-2:]}"
    return "[REDACTED_PHONE]"

def redact_aadhar(aadhar):
    """Redact Aadhar number keeping first 2 and last 4 digits"""
    clean_aadhar = re.sub(r'[\s\-]', '', str(aadhar))
    if len(clean_aadhar) == 12:
        return f"{clean_aadhar[:2]}XXXXXXXX{clean_aadhar[-2:]}"
    return "[REDACTED_AADHAR]"

def redact_passport(passport):
    """Redact passport number"""
    return f"{passport[0]}XXXXXXX" if len(passport) > 1 else "[REDACTED_PASSPORT]"

def redact_upi(upi):
    """Redact UPI ID"""
    parts = upi.split('@')
    if len(parts) == 2:
        username = parts[0]
        domain = parts[1]
        if len(username) > 2:
            return f"{username[:2]}XXX@{domain}"
        else:
            return f"XXX@{domain}"
    return "[REDACTED_UPI]"

def redact_name(name):
    """Redact full name keeping first letter of each part"""
    parts = name.strip().split()
    redacted_parts = []
    for part in parts:
        if len(part) > 1:
            redacted_parts.append(f"{part[0]}{'X' * (len(part) - 1)}")
        else:
            redacted_parts.append("X")
    return " ".join(redacted_parts)

def redact_email(email):
    """Redact email keeping first 2 chars and domain"""
    parts = email.split('@')
    if len(parts) == 2:
        username = parts[0]
        domain = parts[1]
        if len(username) > 2:
            return f"{username[:2]}XXX@{domain}"
        else:
            return f"XXX@{domain}"
    return "[REDACTED_EMAIL]"

def redact_address(address):
    """Redact address keeping basic structure"""
    # Replace numbers with X but keep structure
    redacted = re.sub(r'\d', 'X', address)
    # Partially redact words longer than 3 characters
    words = redacted.split()
    final_words = []
    for word in words:
        if len(word) > 3 and word.upper() not in ['ROAD', 'STREET', 'CITY', 'STATE']:
            final_words.append(f"{word[:2]}{'X' * (len(word) - 2)}")
        else:
            final_words.append(word)
    return " ".join(final_words)

def detect_and_redact_pii(data_json):
    """Main function to detect and redact PII from JSON data"""
    try:
        data = json.loads(data_json)
    except:
        return f'"{data_json}"', False
    
    is_pii = False
    redacted_data = data.copy()
    
    # Track combinatorial PII elements
    combinatorial_pii = []
    
    for key, value in data.items():
        if value is None or value == "":
            continue
            
        value_str = str(value)
        
        # Check standalone PII first
        if key in ['phone', 'contact'] and is_phone_number(value_str):
            redacted_data[key] = redact_phone(value_str)
            is_pii = True
        elif key == 'aadhar' and is_aadhar_number(value_str):
            redacted_data[key] = redact_aadhar(value_str)
            is_pii = True
        elif key == 'passport' and is_passport_number(value_str):
            redacted_data[key] = redact_passport(value_str)
            is_pii = True
        elif key == 'upi_id' and is_upi_id(value_str):
            redacted_data[key] = redact_upi(value_str)
            is_pii = True
        # Check combinatorial PII elements
        elif key == 'name' and is_full_name(value_str):
            combinatorial_pii.append('name')
            redacted_data[key] = redact_name(value_str)
        elif key == 'email' and is_email(value_str):
            combinatorial_pii.append('email')
            redacted_data[key] = redact_email(value_str)
        elif key == 'address' and is_physical_address(value_str):
            combinatorial_pii.append('address')
            redacted_data[key] = redact_address(value_str)
        elif key in ['device_id', 'ip_address']:
            # These are PII only when combined with other identifiers
            combinatorial_pii.append(key)
            redacted_data[key] = "[REDACTED_ID]"
    
    # Check if we have combinatorial PII (2 or more elements)
    if len(combinatorial_pii) >= 2:
        is_pii = True
    
    # Format JSON with escaped quotes for CSV compatibility
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
        with open(input_file, 'r', encoding='utf-8') as infile:
            reader = csv.DictReader(infile)
            
            # Check available columns and adapt
            columns = reader.fieldnames
            print(f"Found columns: {columns}")
            
            # Try to find the right column names
            id_col = None
            data_col = None
            
            for col in columns:
                if 'id' in col.lower():
                    id_col = col
                if 'data' in col.lower() or 'json' in col.lower():
                    data_col = col
            
            if not id_col or not data_col:
                print("Error: Could not find record_id and Data_json columns")
                print("Available columns:", columns)
                sys.exit(1)
            
            print(f"Using '{id_col}' as record_id and '{data_col}' as data column")
            
            with open(output_file, 'w', encoding='utf-8', newline='') as outfile:
                fieldnames = ['record_id', 'redacted_data_json', 'is_pii']
                writer = csv.DictWriter(outfile, fieldnames=fieldnames)
                writer.writeheader()
                
                # Print CSV header for terminal output
                print("\nrecord_id,redacted_data_json,is_pii")
                
                processed_count = 0
                pii_found_count = 0
                
                for row in reader:
                    record_id = row[id_col]
                    data_json = row[data_col]
                    
                    redacted_json, is_pii = detect_and_redact_pii(data_json)
                    
                    # Write to file
                    writer.writerow({
                        'record_id': record_id,
                        'redacted_data_json': redacted_json,
                        'is_pii': is_pii
                    })
                    
                    # Display in terminal - same format as CSV
                    print(f"{record_id},{redacted_json},{is_pii}")
                    
                    processed_count += 1
                    if is_pii:
                        pii_found_count += 1
        
        print(f"\nProcessed {processed_count} records, {pii_found_count} with PII detected.")
        print(f"Output saved to {output_file}")
        
    except FileNotFoundError:
        print(f"Error: Input file '{input_file}' not found.")
        sys.exit(1)
    except Exception as e:
        print(f"Error processing file: {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    main()