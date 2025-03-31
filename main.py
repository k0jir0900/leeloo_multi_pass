import os
import sys

sys.path.append(os.path.join(os.path.dirname(__file__), 'files'))
sys.path.append(os.path.join(os.path.dirname(__file__), 'scripts_main'))

import re
import json
import time
import requests
import pyfiglet
import ipaddress
import bye_message # type: ignore
import ip_check # type: ignore
import url_check # type: ignore
import hash_check # type: ignore

# GENERAL
BANNER = "Leeloo Multi Pass"
WIDTH = 80

def banner():
    os.system('cls' if os.name == 'nt' else 'clear')
    banner_text = pyfiglet.figlet_format(BANNER)
    print(banner_text)

def is_valid_hash(hash):
    hash_string = hash.lower()
    return bool(
        re.fullmatch(r'[a-f0-9]{32}', hash_string) or
        re.fullmatch(r'[a-f0-9]{64}', hash_string)
    )

def ip_single_back_menu():
    back_menu = """
    What would you like to do?

    1.- Check another single IP Address
    2.- Back to main menu
    3.- Quit

"""

    ip_menu_choices = ["1", "2", "3", "q"]
    print("#" * WIDTH)
    print(back_menu)
    ip_user_choice = input("choose!: ")

    if ip_user_choice in ip_menu_choices:

        if ip_user_choice == "1":
            new_ip_chk = input(f"Input new target IP: ")

            try:
                ip_obj = ipaddress.ip_address(new_ip_chk)
                ip_check.analyze_ip(new_ip_chk)
                ip_single_back_menu()
            except ValueError:
                ip_single_back_menu()
                return
            
        if ip_user_choice == "2":
            main_menu()

        if ip_user_choice.lower() in ["3", "q"]:

            bye_message.print_message()
            exit()
    else:
        ip_single_back_menu()

def ip_file_back_menu():
    back_menu = """
    What would you like to do?

    1.- Check another file with IP Address
    2.- Back to main menu
    3.- Quit

"""

    ip_menu_choices = ["1", "2", "3", "q"]
    print("#" * WIDTH)
    print(back_menu)
    ip_user_choice = input("choose!: ")

    if ip_user_choice in ip_menu_choices:

        if ip_user_choice == "1":
            new_file_chk = input(f"Input new file with IP: ")

            if os.path.exists(new_file_chk):
                ip_check.analyze_ip_file(new_file_chk)
                ip_file_back_menu()
            else:
                ip_file_back_menu()
            
        if ip_user_choice == "2":
            main_menu()

        if ip_user_choice.lower() in ["3", "q"]:

            bye_message.print_message()
            exit()
    else:
        ip_file_back_menu()

def url_single_back_menu():
    back_menu = """
    What would you like to do?

    1.- Check another URL
    2.- Back to main menu
    3.- Quit

"""

    ip_menu_choices = ["1", "2", "3", "q"]
    print("\n" + "#" * 80)
    print(back_menu)
    ip_user_choice = input("choose!: ")

    if ip_user_choice in ip_menu_choices:

        if ip_user_choice == "1":
            new_url_chk = input(f"Input new URL: ")
            url_check.analyze_url(new_url_chk)
            url_single_back_menu()

        if ip_user_choice == "2":
            main_menu()

        if ip_user_choice.lower() in ["3", "q"]:

            bye_message.print_message()
            exit()
    else:
        ip_single_back_menu()

def url_file_back_menu():
    back_menu = """
    What would you like to do?

    1.- Check another file with URL
    2.- Back to main menu
    3.- Quit

"""

    ip_menu_choices = ["1", "2", "3", "q"]
    print("\n" + "#" * 80)
    print(back_menu)
    ip_user_choice = input("choose!: ")

    if ip_user_choice in ip_menu_choices:

        if ip_user_choice == "1":
            new_file_chk = input(f"Input new file with URL: ")

            if os.path.exists(new_file_chk):
                url_check.analyze_url_file(new_file_chk)
                url_file_back_menu()
            else:
                url_file_back_menu()

        if ip_user_choice == "2":
            main_menu()

        if ip_user_choice.lower() in ["3", "q"]:

            bye_message.print_message()
            exit()
    else:
        url_file_back_menu()

def hash_single_back_menu():
    back_menu = """
    What would you like to do?

    1.- Check another single HASH
    2.- Back to main menu
    3.- Quit

"""

    hash_menu_choices = ["1", "2", "3", "q"]
    print("#" * WIDTH)
    print(back_menu)
    hash_user_choice = input("choose!: ")

    if hash_user_choice in hash_menu_choices:

        if hash_user_choice == "1":
            new_hash_chk = input(f"Input new target HASH: ")

            if is_valid_hash(new_hash_chk):
                hash_check.analyze_hash(new_hash_chk)
                hash_single_back_menu()
            else:
                run_hash_checker
            
        if hash_user_choice == "2":
            main_menu()

        if hash_user_choice.lower() in ["3", "q"]:

            bye_message.print_message()
            exit()
    else:
        hash_single_back_menu()

def hash_file_back_menu():
    back_menu = """
    What would you like to do?

    1.- Check another file with HASH
    2.- Back to main menu
    3.- Quit

"""

    hash_menu_choices = ["1", "2", "3", "q"]
    print("#" * WIDTH)
    print(back_menu)
    hash_user_choice = input("choose!: ")

    if hash_user_choice in hash_menu_choices:

        if hash_user_choice == "1":
            new_file_chk = input(f"Input new file with HASH: ")

            if os.path.exists(new_file_chk):
                hash_check.analyze_hash_file(new_file_chk)
                ip_file_back_menu()
            else:
                ip_file_back_menu()
            
        if hash_user_choice == "2":
            main_menu()

        if hash_user_choice.lower() in ["3", "q"]:

            bye_message.print_message()
            exit()
    else:
        ip_file_back_menu()

def run_ip_checker():

    ip_chk_menu = """
    What would you like to do?

    1.- Check single IP Address
    2.- Check file with IP address
    3.- Return
    4.- Quit

"""

    ip_menu_choices = ["1", "2", "3", "4", "q"]
    os.system('cls' if os.name == 'nt' else 'clear')
    banner()
    print(ip_chk_menu)
    ip_user_choice = input("choose!: ")

    if ip_user_choice in ip_menu_choices:

        if ip_user_choice == "1":
            single_ip = input(f"Input a single IP address: ")

            try:
                ip_obj = ipaddress.ip_address(single_ip)
                ip_check.analyze_ip(single_ip)
                ip_single_back_menu()
            except ValueError:
                run_ip_checker()
                return
                        
        if ip_user_choice == "2":
            ip_file_name = input(f"Input the file path: ")

            if os.path.exists(ip_file_name):
                ip_check.analyze_ip_file(ip_file_name)
                ip_file_back_menu()
            else:
                run_ip_checker()

        if ip_user_choice == "3":

            main_menu()

        if ip_user_choice.lower() in ["4", "q"]:

            bye_message.print_message()
            exit()
    else:

        run_ip_checker()

def run_url_checker():
    url_chk_menu = """
    What would you like to do?

    1.- Check single URL
    2.- Check file with URLs
    3.- Return
    4.- Quit

"""

    url_menu_choices = ["1", "2", "3", "4", "q"]
    os.system('cls' if os.name == 'nt' else 'clear')
    banner()
    print(url_chk_menu)
    url_user_choice = input("choose!: ")

    if url_user_choice in url_menu_choices:

        if url_user_choice == "1":
            single_url = input(f"Input a single URL: ")
            url_check.analyze_url(single_url)
            url_single_back_menu()

        if url_user_choice == "2":
            url_file_name = input(f"Input the file path: ")

            if os.path.exists(url_file_name):
                url_check.analyze_url_file(url_file_name)
                url_single_back_menu()
            else:
                run_url_checker()

        if url_user_choice == "3":
            main_menu()

        if url_user_choice.lower() in ["4", "q"]:
            bye_message.print_message()
            exit()

    else:
        run_url_checker()

def run_hash_checker():
    hash_chk_menu = """
    What would you like to do?

    1.- Check single HASH
    2.- Check file with HASHs
    3.- Return
    4.- Quit

"""

    hash_menu_choices = ["1", "2", "3", "4", "q"]
    os.system('cls' if os.name == 'nt' else 'clear')
    banner()
    print(hash_chk_menu)
    hash_user_choice = input("choose!: ")

    if hash_user_choice in hash_menu_choices:

        if hash_user_choice == "1":
            single_hash = input(f"Input a single HASH: ")

            if is_valid_hash(single_hash):
                hash_check.analyze_hash(single_hash)
                hash_single_back_menu()
            else:
                run_hash_checker()

        if hash_user_choice == "2":
            hash_file_name = input(f"Input the file path: ")

            if os.path.exists(hash_file_name):
                hash_check.analyze_hash_file(hash_file_name)
                hash_file_back_menu()
            else:
                run_hash_checker()

        if hash_user_choice == "3":
            main_menu()

        if hash_user_choice.lower() in ["4", "q"]:
            bye_message.print_message()
            exit()

    else:
        run_hash_checker()

def main_menu():

    menu_tui = """
    What would you like to do?

    1.- IP Checker
    2.- URL Checker
    3.- Hash Checker
    4.- Quit
"""

    menu_choices = ["1", "2", "3", "4", "q"]
    os.system('cls' if os.name == 'nt' else 'clear')
    banner()
    print(menu_tui)

    user_choice = input("Chose your destiny: ")

    if user_choice in menu_choices:

        if user_choice == "1":

            run_ip_checker()

        if user_choice == "2":

            run_url_checker()

        if user_choice == "3":

            run_hash_checker()

        if user_choice.lower() in ["4", "q"]:
            bye_message.print_message()
            exit()

    else:

        main_menu()

main_menu()