"""Rezolvarea exercițiilor 9-20 despre metode și atribute web."""

import time

import requests


BASE_URL = "https://cybercor.org"
ECHO_URL = "https://httpbin.org"
TIMEOUT = 10


def pause() -> None:
    """Respectă pauza cerută între cereri."""
    time.sleep(1)


def main() -> None:
    """Rulează demonstrațiile pentru exercițiile 9-20."""
    response = requests.get(BASE_URL, timeout=TIMEOUT)

    # Ex. 9: toate cele patru sunt atribute, nu metode.
    print("Ex. 9 - status_code (atribut):", response.status_code)
    print("ok (atribut):", response.ok)
    print("url (atribut):", response.url)
    print("encoding (atribut):", response.encoding)

    # Ex. 10: raise_for_status este metodă.
    response.raise_for_status()
    pause()
    try:
        missing = requests.get(ECHO_URL + "/status/404", timeout=TIMEOUT)
        missing.raise_for_status()
    except requests.HTTPError as error:
        print("Ex. 10 - pagina nu a putut fi încărcată:", error)
    else:
        print("Ex. 10 - serverul a răspuns fără eroare HTTP:", missing.status_code)

    # Ex. 11.
    print("Ex. 11 - antete:")
    for name, value in response.headers.items():
        print(f"{name}: {value}")

    # Ex. 12: CaseInsensitiveDict tratează numele antetelor fără diferență
    # între litere mari și mici.
    print("Ex. 12 - Server:", response.headers.get("Server", "lipsește"))
    print("Content-Type:", response.headers.get("Content-Type", "lipsește"))
    print("content-type:", response.headers.get("content-type", "lipsește"))

    # Ex. 13: lower() returnează tot un str, pe care poate fi apelat count().
    cyber_count = response.text.lower().count("cyber")
    print("Ex. 13 - apariții cyber:", cyber_count)

    # Ex. 14.
    html = response.text
    lower_html = html.lower()
    open_tag = lower_html.find("<title>")
    close_tag = lower_html.find("</title>", open_tag + 7)
    title = html[open_tag + len("<title>") : close_tag].strip() if open_tag >= 0 and close_tag >= 0 else ""
    print("Ex. 14 - titlu:", title)

    # Ex. 15.
    lines = html.splitlines()
    longest = max(lines, key=len, default="")
    print("Ex. 15 - linii:", len(lines), "| lungimea maximă:", len(longest))

    # Ex. 16.
    print("Ex. 16 -", "Conexiune securizată" if response.url.startswith("https://") else "Conexiune nesecurizată")

    # Ex. 17.
    pause()
    redirected = requests.get("http://cybercor.org", timeout=TIMEOUT)
    print("Ex. 17 - redirecționări:")
    for item in redirected.history:
        print(item.status_code, item.url)
    print("URL final:", redirected.url)

    # Ex. 18.
    pause()
    head_response = requests.head(BASE_URL, timeout=TIMEOUT)
    pause()
    get_response = requests.get(BASE_URL, timeout=TIMEOUT)
    print("Ex. 18 - HEAD bytes:", len(head_response.content))
    print("GET bytes:", len(get_response.content))
    # HEAD livrează antetele fără corp; GET livrează și corpul resursei.

    # Ex. 19.
    print("Ex. 19 - cookie-uri:")
    if response.cookies:
        for cookie in response.cookies:
            print(cookie.name, "secure=", cookie.secure)
    else:
        print("Niciun cookie setat")

    # Ex. 20.
    pause()
    with requests.Session() as session:
        session.headers.update({"User-Agent": "Brai-Roman-SI-263"})
        echoed = session.get(ECHO_URL + "/headers", timeout=TIMEOUT)
        echoed.raise_for_status()
        print("Ex. 20 - User-Agent primit:", echoed.json()["headers"].get("User-Agent"))

    # Verificați-vă: response.text este o proprietate calculată și se citește
    # fără paranteze; response.json este o metodă care execută conversia JSON.
    print("text este atribut/proprietate; json() este metodă.")


if __name__ == "__main__":
    main()
