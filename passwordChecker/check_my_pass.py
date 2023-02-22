import requests
import hashlib
import sys

def request_api_data(query_char):
    # Kullanacağımız API'nin url'i ve şifreyi vereceğimiz yer
    url = 'https://api.pwnedpasswords.com/range/' + query_char
    res = requests.get(url)
    # Burada API'yi kontrol ediyoruz
    if res.status_code != 200:
        raise RuntimeError(f"Error fetching: {res.status_code}, api'yi kontrol edin ve tekrar deneyin")
    return res

def get_password_leaks_count(hashes, hash_to_check):
    hashes = (line.split(':') for line in hashes.text.splitlines())
    for h, count in hashes:
        if h == hash_to_check:
            return count
    return 0

def pwned_api_check(password):
    # Şifremizi SHA fonksiyonuna dönüştürüyoruz 
    sha1password = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    # first5_char değişkenine şifremizin ilk 5 karakterini atıyoruz, tail değişkenine ise 5. karakterden sonrasını atıyoruz
    first5_char, tail = sha1password[:5], sha1password[5:]
    response = request_api_data(first5_char)
    return get_password_leaks_count(response, tail)

def main(args):
    for password in args:
        count = pwned_api_check(password)
        if count:
            print(f'{password} {count} kez bulundu.. muhtemelen şifreni değiştirmelisin !')
        else:
            print(f'{password} hiç bulunamadı. Devam edebilirsin !')
    return 'Tamamlandı !'


if __name__ == '__main__':
   sys.exit(main(sys.argv[1:]))