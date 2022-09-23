import names
import string
import random
import subprocess
import area_code_nanp
import random_address


# Number of users to create (default is 10k)
global user_count
user_count = 10

# Length of passwords for users (default is 16)
global password_length
password_length = 16

# Domain name (default is lab.local)
Domain = "lab.local"

# Company name (default is Test Company)
Company_Name = "Test Company"

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

# Dictionary of US states and their abbreviations
global us_states
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


# Create OUs within the domain (OUs are taken from the departments)
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
        
    ou_list = list(departments.keys())
        
    # Create OUs with powershell
    for item in ou_list:
        #print(item) 
        ou_command = "New-ADOrganizationalUnit -Name '{}' -Path '{}'".format(str(item), dc_domain)
        print(ou_command)
        #subprocess.check_output(["powershell.exe", ou_command])
    
    return


# Function to generate random "real" user data
def generate_random_data():
    # Generate a random first and last names
    current_first_name = names.get_first_name()
    current_last_name = names.get_last_name()
    current_name = current_first_name + " " + current_last_name
    
    # Generates a random address
    current_address = random_address.real_random_address()
    
    required_keys = ["address1", "city", "state", "postalCode"]
    
    for key in required_keys:
        if key not in list(current_address.keys()):
            print("{} missing from generated address".format(key))
            current_address = random_address.real_random_address()
        else:
            #print("key exists")
            pass
            
    

    
    
    
    # Make sure all the require fields are returned from the address
    #while required_keys not in list(current_address.keys()):
    #    print("Missing fields")
    #    print(current_address)
    #    current_address = random_address.real_random_address()
        
    #print(current_address.keys())
    
    # not all of these always exist
    try:
        street_address = current_address["address1"]
        #print(street_address)
        city = current_address["city"]
        #print(city)
        state = current_address["state"]
        #print(state)
        postal_code = current_address["postalCode"]
        #print(postal_code)
        print("succeeded")
        print()
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


# Create a random password (default length is 16 characters)
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
    #print(password)
    
    return password


# Generate all active directory attributes for user
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

    # SamAccountName is first inital . last name
    SamAccountName = str(current_user["first name"][0] + "." + current_user["last name"])
    Name = str(current_user["full name"])
    Path = str("OU=" + organization_unit + "," + dc_domain)
    Password = generate_password(password_length)
    GivenName = str(current_user["first name"])
    Surname = str(current_user["last name"])
    DisplayName = Name
    EmailAddress = str(current_user["first name"] + "." + current_user["last name"] + "@" + domain)
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
    #print(ad_user_data)

    return ad_user_data

# Create the user in the domain using powershell
def create_users(domain, company_name, departments, number_of_users):
    # Create all Active Directory users
    i = 0
    while i < int(number_of_users):
        # Organization unit (default is People)
        organization_unit = "People"

        # Generate active directory attributes for a given user
        ad_user = generate_ad_user(domain, organization_unit, company_name, departments)
        #print(ad_user["Password"])

        # User powershell to convert plain test password to secure object
        password_command = "$securePassword = ConvertTo-SecureString -AsPlainText '{}' -Force".format(ad_user["Password"])
        #print(password_command)
        #subprocess.check_output(["powershell.exe", password_command])

        # Powershell command to actually create the user
        user_command = "New-ADUser -SamAccountName '{}' -Name '{}' -Path '{}' -AccountPassword $securePassword -Enabled $true -GivenName '{}' -Surname '{}' -DisplayName '{}' -EmailAddress '{}' -StreetAddress '{}' -City '{}' -PostalCode '{}' -State '{}' -Country '{}' -UserPrincipalName '{}' -Company '{}' -Department '{}' -Title '{}' -OfficePhone '{}' -PasswordNeverExpires $true -ChangePasswordAtLogon $false".format(
            ad_user["SamAccountName"],
            ad_user["Name"],
            ad_user["Path"],
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
        print(user_command)
        #subprocess.check_output(["powershell.exe", user_command])
        
        i += 1

    return
    
    
def create_ou_users(domain, company_name, departments, number_of_users):
    # Create all Active Directory users
    i = 0
    while i < int(number_of_users):
        
        # Select a random OU for each user
        organization_unit = random.choice(list(departments.keys()))
    
        # Generate active directory attributes for a given user
        ad_user = generate_ad_user(domain, organization_unit, company_name, departments)
        
        # User powershell to convert plain test password to secure object
        password_command = "$securePassword = ConvertTo-SecureString -AsPlainText '{}' -Force".format(ad_user["Password"])
    
        # Powershell command to actually create the user
        user_command = "New-ADUser -SamAccountName '{}' -Name '{}' -Path '{}' -AccountPassword $securePassword -Enabled $true -GivenName '{}' -Surname '{}' -DisplayName '{}' -EmailAddress '{}' -StreetAddress '{}' -City '{}' -PostalCode '{}' -State '{}' -Country '{}' -UserPrincipalName '{}' -Company '{}' -Department '{}' -Title '{}' -OfficePhone '{}' -PasswordNeverExpires $true -ChangePasswordAtLogon $false".format(
            ad_user["SamAccountName"],
            ad_user["Name"],
            ad_user["Path"],
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
        print(user_command)
        #subprocess.check_output(["powershell.exe", user_command])
        
        i += 1
    
    return



# Beginning of main
if __name__ == '__main__':
    
    # Determine whether to use groups or ou's for organization
    # Default to using groups and not ou's
    #divide_by_ou = "no"
    #divide_by_group = "yes"
    
    # Get input from user on groups vs ou's
    structure = input("Defaults to using groups. Use organization units instead? (y/n): ")
    if ((str(structure.lower()) == 'y') or (str(structure.lower()) == 'yes')):
        print("Continuing using organization units...")
        
        # Create the necessary OUs
        create_ou(Domain, Departments)
        
        # Create ad users
        #create_ou_users(Domain, Company_Name, Departments, user_count)
        
        
    elif ((str(structure.lower()) == 'n') or (str(structure.lower()) == 'no')):
        print("Continuing using groups...")
        
        # Create ad users
        #create_users(Domain, Company_Name, Departments, user_count)
        
    else:
        print("Unknown character entered. Use y for yes, and n for no.")
    

    

    #create_users(domain, organization_unit, dns_domain_name, company_name, departments)
    #generate_password(password_length)