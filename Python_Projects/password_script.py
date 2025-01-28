import subprocess
import os

# Define the path to store known profiles
KNOWN_PROFILES_FILE = os.path.abspath('wifi_profiles.txt')
print(f"Known profiles file: {KNOWN_PROFILES_FILE}")
KNOWN_PROFILES_FILE = r'C:\Users\Lenovo\Desktop\Folders\My_Basic_To_Advanced_Python_Projects\wifi_profiles.txt'


# Function to get existing profiles
def get_existing_profiles():
    profiles = []
    try:
        result = subprocess.run(["netsh", "wlan", "show", "profile"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        profiles = [line.split(":")[1].strip() for line in result.stdout.splitlines() if "All User Profile" in line]
        print(f"Found profiles: {profiles}")  # Debugging: print the profiles found
    except Exception as e:
        print(f"Error getting profiles: {e}")
    return profiles

# Function to get the Wi-Fi password for a given profile
def get_wifi_password(profile):
    try:
        result = subprocess.run(["netsh", "wlan", "show", "profile", profile, "key=clear"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        for line in result.stdout.splitlines():
            if "Key Content" in line:
                return line.split(":")[1].strip()
    except Exception as e:
        print(f"Error getting password for {profile}: {e}")
    return None

# Function to save new profiles to a file
def save_new_profiles(new_profiles):
    try:
        print(f"Saving profiles to: {KNOWN_PROFILES_FILE}")  # Debugging: Print the path
        if not os.path.exists(KNOWN_PROFILES_FILE):
            print("File does not exist, creating a new one.")
        with open(KNOWN_PROFILES_FILE, 'a') as f:  # Open file in append mode
            for profile in new_profiles:
                f.write(profile + '\n')  # Write each profile on a new line
        print(f"Successfully saved {len(new_profiles)} profiles.")  # Debugging: Success message
    except OSError as e:
        print(f"Error while accessing the file: {e}")

# Main function to get profiles and save new ones
def main():
    existing_profiles = get_existing_profiles()
    new_profiles = []  # Logic to find new profiles that are not in the known list

    # For now, just check against existing profiles as a placeholder for "new profiles"
    for profile in existing_profiles:
        password = get_wifi_password(profile)
        if password:
            print(f"Password for {profile}: {password}")  # Debugging: Print password found
            new_profiles.append(profile)  # Add to new profiles if password found

    # Save new profiles to the file
    save_new_profiles(new_profiles)

if __name__ == "__main__":
    main()
