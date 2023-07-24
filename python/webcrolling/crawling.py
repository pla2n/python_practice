import requests
from bs4 import BeautifulSoup

url = 'http://www.cgv.co.kr/theaters/?areacode=11&theaterCode=0345&date=20230701'
html = requests.get(url)
#print(html.text)
soup= BeautifulSoup(html.text, 'html.parser')
print(soup.select('div.info-movie') )
