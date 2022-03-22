from itertools import count
import requests
import hashlib
import sys


def request_api_data(query_char):
    url = 'https://api.pwnedpasswords.com/range/' + query_char
    res = requests.get(url)
    if res.status_code != 200:
        raise RuntimeError(
            f'Error fetching: {res.status_code} check the API and try again.')
    return res


def get_pwd_leaks_count(hashes, hash_to_check):
    # returns all hashes that match the 5 char, :n how many times pwd has been hacked
    hashes = (line.split(':') for line in hashes.text.splitlines())
    for h, count in hashes:
        if h == hash_to_check:
            return count  # exits loop if count
    return 0


def pwned_api_check(password):
    sha1password = (hashlib.sha1(password.encode('utf-8'))).hexdigest().upper()
    first5_char, tail = sha1password[:5], sha1password[5:]
    response = request_api_data(first5_char)
    return get_pwd_leaks_count(response, tail)


def main(args):
    for password in args:
        count = pwned_api_check(password)
        if count:
            print(
                f'The password: {password} was found {count} times. You should probably use another one.')
        else:
            print(f'The password: {password} was not found. All good. ')
    return 'done !'


main(sys.argv[1:])
