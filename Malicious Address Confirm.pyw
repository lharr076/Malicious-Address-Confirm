import os
import re
import requests
from collections import defaultdict
import tkinter as tk
from tkinter import filedialog, simpledialog, messagebox
import boto3
from botocore.exceptions import ClientError
import json

API_URL = 'https://api.abuseipdb.com/api/v2/check'

def get_secret():
    """
    Retrieves the API key from AWS Secrets Manager.
    """
    secret_name = "" #Name of your secret in AWS Secrets Manager
    region_name = "" #Location of where the key will be stored in AWS Secrets Manager. Ex us-west-1

    session = boto3.session.Session()
    client = session.client(
        service_name='secretsmanager',
        region_name=region_name
    )

    try:
        get_secret_value_response = client.get_secret_value(SecretId=secret_name)
    except ClientError as e:
        raise e

    # Secrets Manager returns the secret in 'SecretString'
    secret = get_secret_value_response['SecretString']

    # Convert the secret string from JSON format into a dictionary
    secret_dict = json.loads(secret)

    # Access the API key using its key
    api_key = secret_dict['name_of_api_key']
    
    return api_key

def redact_specific_ip_addresses(log_content, ip1, ip2):
    """
    Redacts the specified IP addresses from the log content.
    """
    ip_pattern = rf'\b(?:{re.escape(ip1)}|{re.escape(ip2)})\b'
    return re.sub(ip_pattern, 'REDACTED', log_content)

def read_file(file_path):
    """
    Reads and returns the content of a file.
    """
    with open(file_path, 'r') as file:
        return file.read()

def write_file(file_path, content):
    """
    Writes the provided content to a file.
    """
    with open(file_path, 'w') as file:
        file.write(content)

def redact_log():
    """
    Prompts user for IP addresses and a log file to redact, then saves the redacted file.
    """
    root = tk.Tk()
    root.withdraw()  # Hide the root window

    base_directory = os.path.abspath('choose/your/path')
    max_attempts = 3 # Maximum number of attempts
    attempt_count = 0
    
    while attempt_count < max_attempts:
        input_file = os.path.abspath(filedialog.askopenfilename(title="Select log file to redact"))
        if os.path.commonpath([base_directory]) == os.path.commonpath([base_directory, input_file]):
            break
        else:
            attempt_count += 1
            messagebox.showinfo("Error", f"Invalid file selected. {max_attempts - attempt_count} attempts remaining.")

    if attempt_count == max_attempts:
        messagebox.showerror("Error", "Maximum attempts reached. Operation cancelled.")
        return

    ip1 = simpledialog.askstring("Input", "Enter the first IP address to redact:")
    ip2 = simpledialog.askstring("Input", "Enter the second IP address to redact:")
    
    if not ip1 or not ip2:
        messagebox.showinfo("Error", "IP address input cancelled.")
        return

    output_file = filedialog.asksaveasfilename(title="Save redacted log as", defaultextension=".txt")
    if not output_file:
        messagebox.showinfo("Error", "File save cancelled.")
        return

    try:
        log_content = read_file(input_file)
        redacted_content = redact_specific_ip_addresses(log_content, ip1, ip2)
        write_file(output_file, redacted_content)
        messagebox.showinfo("Success", f"Redacted log saved to {output_file}")
    except Exception as e:
        messagebox.showerror("Error", f"An error occurred: {str(e)}")

def check_ip_malicious(ip_address):
    """
    Checks if an IP address is malicious using the AbuseIPDB API.
    """
    headers = {
        'Accept': 'application/json',
        'Key': get_secret()  # Retrieve the API key using get_secret
    }
    response = requests.get(f"{API_URL}?ipAddress={ip_address}", headers=headers)
    
    if response.status_code == 200:
        data = response.json()
        return data['data']['isPublic']  # Example, adapt based on AbuseIPDB response structure
    
    return False  # Return False in case of an API error or invalid response

def count_and_check_ip_addresses():
    """
    Counts occurrences of IP addresses in a log file and checks if any are malicious.
    """
    root = tk.Tk()
    root.withdraw()  # Hide the root window

    ip_count = defaultdict(int)
    ip_pattern = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')

    base_directory = os.path.abspath('Choose/your/path')
    max_attempts = 3 # Maximum number of attempts
    attempt_count = 0
    
    while attempt_count < max_attempts:
        input_file = os.path.abspath(filedialog.askopenfilename(title="Select log file"))
        if os.path.commonpath([base_directory]) == os.path.commonpath([base_directory, input_file]):
            break
        else:
            attempt_count += 1
            messagebox.showinfo("Error", f"Invalid file selected. {max_attempts - attempt_count} attempts remaining.")

    if attempt_count == max_attempts:
        messagebox.showerror("Error", "Maximum attempts reached. Operation cancelled.")
        return

    try:
        with open(input_file, 'r') as log_file:
            for line in log_file:
                ip_addresses = ip_pattern.findall(line)
                for ip_address in ip_addresses:
                    ip_count[ip_address] += 1

        save_file = filedialog.asksaveasfile(title="Save file as", defaultextension=".txt")
        if not save_file:
            messagebox.showinfo("Error", "File save cancelled.")
            return

        with open(save_file.name, 'w') as output_file:
            for ip_address, count in sorted(ip_count.items(), key=lambda item: item[1], reverse=True):
                if count > 1:
                    is_malicious = check_ip_malicious(ip_address)
                    output_file.write(f"{ip_address}: {count}, Malicious: {is_malicious}\n")

        messagebox.showinfo("Success", "IP address count and check completed.")
    except Exception as e:
        messagebox.showerror("Error", f"An error occurred: {str(e)}")

# Example of calling the functions
# redact_log() # Uncomment to use redaction
# count_and_check_ip_addresses() # Uncomment to use IP count and check
