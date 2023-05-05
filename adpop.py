import string
import random
import argparse
import subprocess

# Function to install packages via pip (aka Pip Cheat)
def install_library(package):
    # Run pip as a subprocess
    subprocess.call(['pip', 'install', package])
    return

# Install missing packages
while True:
    try:
        import names
        import area_code_nanp
        import random_address
        break
    except Exception as e:
        Missing_Library = str(e).strip("No module named ")
        Missing_Library = Missing_Library.strip("'")
        
        if Missing_Library == "area_code_nanp":
            install_library("py-area-code-nanp")
        else:
            install_library(Missing_Library)
            

# Dictionary of different departments and positions
Departments = {
    "Finance & Accounting":("Manager", "Accountant", "Data Entry"),
    "Human Resources":("Manager", "Administrator", "Officer", "Coordinator"),
    "Sales":("Manager", "Representative", "Consultant"),
    "Marketing":("Manager", "Coordinator", "Assistant", "Specialist"),
    "Engineering":("Manager", "Engineer", "Scientist"),
    "Consulting":("Manager", "Associate Consultant", "Consultant", "Senior Consultant"),
    "IT":("Manager", "System Administrator", "Engineer", "Technician"),
    "Planning":("Manager", "Engineer"),
    "Contracts":("Manager", "Coordinator", "Clerk"),
    "Purchasing":("Manager", "Coordinator", "Clerk", "Purchaser")
}


# Define a function to check if an OU exits
def check_ou(organization_unit):
    # Create powershell command
    ou_command = "Get-ADOrganizationalUnit -Filter 'Name -like \"{}\"'".format(organization_unit)
    
    # Check if OU exists
    ou_check = subprocess.check_output(["powershell.exe", ou_command]).decode("utf-8")
    if len(ou_check) > 0:
        return True
    else:
        return False


# Define function to create OUs within the domain (OUs are taken from the departments)
def create_ou(domain, departments):
    # Break domain name apart so that it is in DC= format
    dc_domain = ""
    domain_pieces = str(domain).split('.')
    
    i = 0
    while i < len(domain_pieces):
        if i != (len(domain_pieces) - 1):
            dc_domain += "DC=" + str(domain_pieces[i]) + ","
        else: 
            dc_domain += "DC=" + str(domain_pieces[i])
        i += 1
    
    # Create list of departments
    ou_list = list(departments.keys())

    # Create OUs with powershell
    for item in ou_list:
        # Check if OU already exists
        ou_exists = check_ou(item)
        
        if ou_exists == True:
            pass
        else:
            # Create pworshell command
            ou_command = "New-ADOrganizationalUnit -Name '{}' -Path '{}' | Out-Null".format(str(item), dc_domain)
            # Create OU
            try:
                subprocess.check_output(["powershell.exe", ou_command])
            except Exception as e:
                print(e)
    
    return


# Define function to generate random "real" user data
def generate_random_data():
    # Dictionary of US states and their abbreviations
    us_states = {
        "AL":"Alabama", 
        "AK":"Alaska",
        "AZ":"Arizona",
        "AR":"Arkansas",
        "CA":"California",
        "CO":"Colorado",
        "CT":"Connecticut",
        "DE":"Delaware",
        "DC":"District of Columbia",
        "FL":"Florida",
        "GA":"Georgia",
        "HI":"Hawaii",
        "ID":"Idaho",
        "IL":"Illinois",
        "IN":"Indiana",
        "IA":"Iowa",
        "KS":"Kansas",
        "KY":"Kentucky",
        "LA":"Louisiana",
        "ME":"Maine",
        "MT":"Montana",
        "NE":"Nebraska",
        "NV":"Nevada",
        "NH":"New Hampshire",
        "NJ":"New Jersey",
        "NM":"New Mexico",
        "NY":"New York",
        "NC":"North Carolina",
        "ND":"North Dakota",
        "OH":"Ohio",
        "OK":"Oklahoma",
        "OR":"Oregon",
        "MD":"Maryland",
        "MA":"Massachusetts",
        "MI":"Michigan",
        "MN":"Minnesota",
        "MS":"Mississippi",
        "MO":"Missouri",
        "PA":"Pennsylvania",
        "RI":"Rhode Island",
        "SC":"South Carolina",
        "SD":"South Dakota",
        "TN":"Tennessee",
        "TX":"Texas",
        "UT":"Utah",
        "VT":"Vermont",
        "VA":"Virginia",
        "WA":"Washington",
        "WV":"West Virginia",
        "WI":"Wisconsin",
        "WY":"Wyoming"
    }

    # Generate a random first and last names
    current_first_name = names.get_first_name()
    current_last_name = names.get_last_name()
    current_name = current_first_name + " " + current_last_name
    
    # Generates a random address
    current_address = random_address.real_random_address()
    
    # Create list fo required fields
    required_keys = ["address1", "city", "state", "postalCode"]
    
    # If any fields are missing, create new address
    for key in required_keys:
        if key not in list(current_address.keys()):
            print("{} missing from generated address. Generating new one".format(key))
            current_address = random_address.real_random_address()
        else:
            pass
    
    # Not all of these always exist
    try:
        street_address = current_address["address1"]
        city = current_address["city"]
        state = current_address["state"]
        postal_code = current_address["postalCode"]
    except:
        print(current_address)
    
    # Get a list of area codes for a given state
    area_codes = area_code_nanp.get_area_codes(us_states[state])
    
    # Area codes don't seem to work for the dc area
    if ((area_codes == None) and (us_states[state] == "District of Columbia")):
        area_codes = [202]

    # Randomly generate a phone number
    # Get area code
    current_phone = str(random.choice(area_codes))
    # Randomly generate the last 7 digitsc
    for i in range(0, 7):
        current_phone += str(random.randrange(0, 9, 1))
    
    # Create dictionary of user data
    user_data = {
        "full name":current_name,
        "first name":current_first_name,
        "last name":current_last_name,
        "address":current_address,
        "street":street_address,
        "city":city,
        "state":state,
        "postalcode":postal_code,
        "phone":current_phone,
    }
    
    # Returns a dictionary of user data
    return user_data


# Define function to create a random password (default length is 16 characters)
def generate_password(password_length):
    # Get all lowercase, uppercase, numbers, and symbols
    lowercase = string.ascii_lowercase
    uppercase = string.ascii_uppercase
    numbers = string.digits
    symbols = string.punctuation
    
    # Redact quotes (single and double) from symbols list as it creates issues
    symbols = symbols.replace('"', '')
    symbols = symbols.replace("'", '')
    
    # Concatenate all characters
    all_characters = lowercase + uppercase + numbers + symbols
    
    # Create random password using the given length
    password_list = random.sample(all_characters, password_length)
    password = ''.join(password_list)
    
    return password


# Define function to generate all active directory attributes for user
def generate_ad_user(domain, organization_unit, company_name, departments):
    # Get random user attributes
    current_user = generate_random_data()

    # Break domain name apart so that it is in DC= format
    dc_domain = ""
    domain_pieces = str(domain).split('.')
    
    i = 0
    while i < len(domain_pieces):
        if i != (len(domain_pieces) - 1):
            dc_domain += "DC=" + str(domain_pieces[i]) + ","
        else: 
            dc_domain += "DC=" + str(domain_pieces[i])
        i += 1
        
    # Add in random intial so there aren't duplicate users (or as many at least)
    middle_initial = (random.choice(string.ascii_letters)).upper()

    # SamAccountName is first name . intial . last name
    SamAccountName = str(current_user["first name"] + "." + middle_initial + "." + current_user["last name"])
    Name = str(current_user["first name"] + " " + middle_initial + " " + current_user["last name"])
    Path = str("OU=" + organization_unit + "," + dc_domain)
    Password = generate_password(password_length)
    GivenName = str(current_user["first name"])
    Surname = str(current_user["last name"])
    DisplayName = Name
    EmailAddress = str(SamAccountName + "@" + domain)
    StreetAddress = str(current_user["street"])
    City = str(current_user["city"])
    PostalCode = str(current_user["postalcode"])
    State = str(current_user["state"])
    Country = "US"
    UserPrincipalName = str(SamAccountName + "@" + domain)
    Company = company_name
    Department = str(random.choice(list(departments.keys())))
    Title = str(random.choice(list(departments[Department])))
    OfficePhone = str(current_user["phone"])
    
    # Create dictionary of all user data
    ad_user_data = {
        "SamAccountName":SamAccountName,
        "Name":Name,
        "Path":Path,
        "Password":Password,
        "GivenName":GivenName,
        "Surname":Surname,
        "DisplayName":DisplayName,
        "EmailAddress":EmailAddress,
        "StreetAddress":StreetAddress,
        "City":City,
        "PostalCode":PostalCode,
        "State":State,
        "Country":Country,
        "UserPrincipalName":UserPrincipalName,
        "Company":Company,
        "Department":Department,
        "Title":Title,
        "OfficePhone":OfficePhone
    }

    return ad_user_data
    

# Define function to crate users using powershell
def create_users(domain, company_name, departments, number_of_users):
    # Create all Active Directory users
    i = 0
    while i < int(number_of_users):
        # Organization unit (default is Users)
        organization_unit = "Users"

        # Generate active directory attributes for a given user
        ad_user = generate_ad_user(domain, organization_unit, company_name, departments)

        # Powershell command to actually create the user
        user_command = "New-ADUser -SamAccountName '{}' -Name '{}' -Path '{}' -AccountPassword (ConvertTo-SecureString -AsPlainText '{}' -Force) -Enabled $true -GivenName '{}' -Surname '{}' -DisplayName '{}' -EmailAddress '{}' -StreetAddress '{}' -City '{}' -PostalCode '{}' -State '{}' -Country '{}' -UserPrincipalName '{}' -Company '{}' -Department '{}' -Title '{}' -OfficePhone '{}' -PasswordNeverExpires $true -ChangePasswordAtLogon $false | Out-Null".format(
            ad_user["SamAccountName"],
            ad_user["Name"],
            ad_user["Path"],
            ad_user["Password"],
            ad_user["GivenName"],
            ad_user["Surname"],
            ad_user["DisplayName"],
            ad_user["EmailAddress"],
            ad_user["StreetAddress"],
            ad_user["City"],
            ad_user["PostalCode"],
            ad_user["State"],
            ad_user["Country"],
            ad_user["UserPrincipalName"],
            ad_user["Company"],
            ad_user["Department"],
            ad_user["Title"],
            ad_user["OfficePhone"]
        )

        # Create user
        try:
            subprocess.check_output(["powershell.exe", user_command])
        except subprocess.CalledProcessError as e:
            print("Error creating user. Likely duplicate User Principle Name.")
            i -= 1
        i += 1

    return
    

# Define a function to create users in an OU
def create_ou_users(domain, company_name, departments, number_of_users):
    # Create all Active Directory users
    i = 0
    while i < int(number_of_users):
        
        # Select a random OU for each user
        organization_unit = random.choice(list(departments.keys()))
    
        # Generate active directory attributes for a given user
        ad_user = generate_ad_user(domain, organization_unit, company_name, departments)
        
        # Powershell command to actually create the user
        user_command = "New-ADUser -SamAccountName '{}' -Name '{}' -Path '{}' -AccountPassword (ConvertTo-SecureString -AsPlainText '{}' -Force) -Enabled $true -GivenName '{}' -Surname '{}' -DisplayName '{}' -EmailAddress '{}' -StreetAddress '{}' -City '{}' -PostalCode '{}' -State '{}' -Country '{}' -UserPrincipalName '{}' -Company '{}' -Department '{}' -Title '{}' -OfficePhone '{}' -PasswordNeverExpires $true -ChangePasswordAtLogon $false | Out-Null".format(
            ad_user["SamAccountName"],
            ad_user["Name"],
            ad_user["Path"],
            ad_user["Password"],
            ad_user["GivenName"],
            ad_user["Surname"],
            ad_user["DisplayName"],
            ad_user["EmailAddress"],
            ad_user["StreetAddress"],
            ad_user["City"],
            ad_user["PostalCode"],
            ad_user["State"],
            ad_user["Country"],
            ad_user["UserPrincipalName"],
            ad_user["Company"],
            ad_user["Department"],
            ad_user["Title"],
            ad_user["OfficePhone"]
        )

        # Create user
        try:
            subprocess.check_output(["powershell.exe", user_command])
        except subprocess.CalledProcessError as e:
            print("Error creating user. Likely duplicate User Principle Name.")
            i -= 1
        i += 1
    
    return
    
    
# Define function to parse argument passed via the command line
def parse():
    parser = argparse.ArgumentParser(
        usage="adpop.py [-d 'your.domain'] [-u 10000] [-c 'Your Company'] [-m groups/ous] [-p 16]",
        description="Create realistic active directory users."
    )

    # Add argument that contains the domain name that users will be created in
    parser.add_argument("-d", dest="domain", action="store", type=str, required=False,
                        help="The fully qualified domain name where users should be created.")
    # Add argument that contains the number of users to create
    parser.add_argument("-u", dest="user_count", action="store", type=int, required=False,
                        help="The number of users to create.")
    # Add argument that contains the company name to assign to users                 
    parser.add_argument("-c", dest="company_name", action="store", type=str, required=False,
                        help="The company name to be assigned to users.")
    # Add argument that the creation mode, Organizational Units vs. Groups
    parser.add_argument("-m", dest="mode", action="store", type=str, required=False,
                        help="The mode to run the script in. Creating OUs vs Creating Groups.")
    # Add argument that the creation mode, Organizational Units vs. Groups
    parser.add_argument("-p", dest="password_length", action="store", type=int, required=False,
                        help="The password length for created users.")

    return parser.parse_args()


# Beginning of main
if __name__ == '__main__':
    # Get command line arguments
    args = parse()

    # Check arguments, and if they aren't passed, ask user for them
    # Create a list of argument keys
    argument_keys = vars(args).keys()

    # For each of the arguments, check to see if they are equal to None.
    # If equal to none, prompt user to input a values
    for key in argument_keys:
        if getattr(args, key) is None:
            if key == "domain":
                args.domain = input("The Domain to create users and OUs in: ")
            if key == "user_count":
                args.user_count = input("The total number of users to create: ")
            if key == "company_name":
                args.company_name = input("The company name to assign users to in Active Directory: ")
            if key == "mode":
                args.mode = input("The mode to run the script in. This determines whether OUs or Groups get created (ou for OUs and group for Groups): ")
            if key == "password_length":
                args.password_length = input("The default password length for all users (passwords are randomly generated): ")
    
    # Assign variables
    domain = args.domain
    user_count = args.user_count
    company_name = args.company_name
    mode = args.mode
    password_length = args.password_length
    
    # Determine whether to use groups or ou's for organization
    # Default to using groups and not ou's
    if "group" in str(mode).lower():
        print("Default to groups")
        # Groups needs to be created as well
        # Create users in groups
        #create_users(Domain, Company_Name, Departments, user_count)
        
    elif "ou" in str(mode).lower():
        print("Default to OUs")
        # Create the necessary OUs
        # Add in checks for existing OUs
        create_ou(domain, Departments)
        # Create ad users
        print("Creating users...")
        create_ou_users(domain, company_name, Departments, user_count)
        
    elif "organization unit" in str(mode).lower():
        print("Default to OUs")
        # Create the necessary OUs
        # Add in checks for existing OUs
        create_ou(domain, Departments)
        # Create ad users
        print("Creating users...")
        create_ou_users(domain, company_name, Departments, user_count)
        
    elif "organizational unit" in str(mode).lower():
        print("Default to OUs")
        # Create the necessary OUs
        # Add in checks for existing OUs
        create_ou(domain, Departments)
        # Create ad users
        print("Creating users...")
        create_ou_users(domain, company_name, Departments, user_count)
        
    else:
        print("Unknown mode specified. Exiting...")
    
    # Print message
    print("Finished.")


