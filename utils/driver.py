from seleniumwire import webdriver
from selenium.webdriver.firefox.options import Options
from colorama import Fore


def create_driver(custom_headers=None):
    try:
        # Set up Firefox options to run in headless mode (no GUI)
        options = Options()
        options.add_argument("--headless")

        # Additional seleniumwire options for request interception
        seleniumwire_options = {}

        # Initialize the Firefox WebDriver with the specified options
        driver = webdriver.Firefox(options=options, seleniumwire_options=seleniumwire_options)

        # If custom headers are provided, set up an interceptor to modify request headers
        if custom_headers:
            def interceptor(request):
                request.headers = custom_headers.copy()  # Replace request headers with custom ones

            driver.request_interceptor = interceptor  # Apply the interceptor to the driver

        return driver  # Return the configured driver
    except Exception as e:
        # Print error in red if WebDriver creation fails
        print(Fore.RED + f"[!] Error creating WebDriver: {e}")
        raise  # Raise the exception for external handling