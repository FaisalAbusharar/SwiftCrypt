# Import the SecureInputHandler class from the swiftcrypt module
from swiftcrypt import SecureInputHandler

# Create an instance of SecureInputHandler and specify the database path
input_handler = SecureInputHandler("my_database.db")

# Define the name of the table you want to create
table_name = "CoolTable"

# Create the specified table using the create_table method
input_handler.create_table(table=table_name)

# Prompt the user to enter a username and password
username = input("Enter username: ")
password = input("Enter password: ")

# Construct the SQL query to insert user data into the specified table
insert_query = f"INSERT INTO {table_name} (username, password) VALUES (?, ?)"
insert_params = (username, password)
    
# Execute the query to insert user data securely
if input_handler.execute_secure_query(insert_query, insert_params):
    print("User data inserted successfully.")
else:
    print("Failed to insert user data.")

# Prompt the user to enter a username to search for
search_username = input("Enter username to search: ")
    
# Retrieve user information from the specified table based on the entered username
user_info = input_handler.get_user_info(search_username, table=table_name)
    
if user_info:
    print("User Info:")
    print("ID:", user_info[0])
    print("Username:", user_info[1])
    print("Password:", user_info[2])
else:
    print("User not found.")

# Close the database connection
input_handler.close_connection()
