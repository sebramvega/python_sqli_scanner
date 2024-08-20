import requests
from bs4 import BeautifulSoup
import logging
import time
from urllib.parse import urljoin
import sys

# Set up logging
logging.basicConfig(
    level=logging.DEBUG,
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[logging.FileHandler("sql_injection_scan.log")],
)

# Create a session object to persist certain parameters across requests
s = requests.Session()
# Set the User-Agent header for the session to simulate a browser request
s.headers["User-Agent"] = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/103.0.0.0 Safari/537.36"
)


# Function to fetch and return all forms from the provided URL
def get_forms(url):
    logging.info(f"Fetching forms from {url}")  # Log the URL being accessed
    try:
        # Send a GET request to the URL and parse the HTML content
        soup = BeautifulSoup(s.get(url).content, "html.parser")
        # Find all form elements in the HTML
        forms = soup.find_all("form")
        logging.debug(
            f"Found {len(forms)} forms on {url}"
        )  # Log the number of forms found
        return forms
    except Exception as e:
        logging.exception(
            "An error occurred while fetching forms"
        )  # Log any exceptions that occur
        print(
            "Error occurred while fetching forms. Check log file for details."
        )  # Inform the user of an error
        return []


# Function to extract and return details of a form element
def form_details(form):
    logging.debug("Extracting form details")  # Log the extraction process
    detailsOfForm = {}
    # Extract the form's action and method attributes
    action = form.attrs.get("action")
    method = form.attrs.get("method", "get")
    inputs = []

    # Iterate over all input elements in the form
    for input_tag in form.find_all("input"):
        input_type = input_tag.attrs.get("type", "text")
        input_name = input_tag.attrs.get("name")
        input_value = input_tag.attrs.get("value", "")
        # Append input details to the inputs list
        inputs.append(
            {
                "type": input_type,
                "name": input_name,
                "value": input_value,
            }
        )

    # Store the extracted details in a dictionary
    detailsOfForm["action"] = action
    detailsOfForm["method"] = method
    detailsOfForm["inputs"] = inputs
    logging.debug(f"Form details: {detailsOfForm}")  # Log the form details
    return detailsOfForm


# Function to check if the response indicates an SQL injection vulnerability
def vulnerable(response):
    logging.debug("Checking if the response is vulnerable to SQL injection")
    # Common error messages that indicate SQL injection vulnerabilities
    errors = {
        "quoted string not properly terminated",
        "unclosed quotation mark after the character string",
        "you have an error in your SQL syntax",
    }
    # Check if any of the error messages are in the response content
    for error in errors:
        if error in response.content.decode().lower():
            logging.warning(
                "Vulnerability detected in the response"
            )  # Log a warning if a vulnerability is detected
            return True
    return False


# Main function to perform the SQL injection scan
def sql_injection_scan(url):
    logging.info(f"Starting SQL injection scan on {url}")  # Log the start of the scan
    forms = get_forms(url)  # Get all forms from the URL
    logging.info(
        f"Detected {len(forms)} forms on {url}."
    )  # Log the number of forms found

    # If no forms are found, exit the function
    if not forms:
        print("No forms found. Exiting.")
        return

    vulnerabilities_found = False  # Flag to track if any vulnerabilities are found

    # Iterate over each form found
    for form in forms:
        details = form_details(form)  # Extract form details

        # Test the form with common SQL injection payloads
        for i in "\"'":
            data = {}
            for input_tag in details["inputs"]:
                if input_tag["type"] == "hidden" or input_tag["value"]:
                    data[input_tag["name"]] = input_tag["value"] + i
                elif input_tag["type"] != "submit":
                    data[input_tag["name"]] = f"test{i}"

            logging.debug(
                f"Testing with payload: {data}"
            )  # Log the payload being tested

            try:
                start_time = time.time()  # Track the start time for the request
                # Send the form data using the appropriate method (GET or POST)
                if details["method"] == "post":
                    res = s.post(url, data=data)
                elif details["method"] == "get":
                    res = s.get(url, params=data)
                elapsed_time = time.time() - start_time  # Calculate the request time
                logging.debug(f"Request completed in {elapsed_time:.2f} seconds")

                # Check if the response indicates a vulnerability
                if vulnerable(res):
                    logging.error(
                        f"SQL injection attack vulnerability detected in link: {url}"
                    )
                    vulnerabilities_found = True
                    break  # Stop testing if a vulnerability is found
            except Exception as e:
                logging.exception(
                    "An error occurred during the request"
                )  # Log any exceptions that occur during the request
                print("Error occurred during request. Check log file for details.")
                return

    # Print and log the results of the scan
    if vulnerabilities_found:
        print(f"Vulnerabilities found in forms on {url}. Check log file for details.")
    else:
        print(
            f"{len(forms)} forms checked, NO vulnerabilities found. Check log file for details"
        )


# Main entry point of the script
if __name__ == "__main__":
    # Prompt the user to enter the URL to be checked
    urlToBeChecked = input("Enter the URL to be checked: ").strip()
    sql_injection_scan(urlToBeChecked)  # Start the scan
