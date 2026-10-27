"""Rezolvarea exercițiilor 1-8 despre importuri."""

import inspect
from importlib.metadata import version
import time
import urllib.request

import requests
import requests.adapters
import requests as rq
from requests import get


BASE_URL = "https://cybercor.org"
ECHO_URL = "https://httpbin.org"
TIMEOUT = 10


def pause() -> None:
    """Respectă pauza cerută între două cereri consecutive."""
    time.sleep(1)


def main() -> None:
    """Rulează demonstrațiile pentru exercițiile 1-8."""
    # Ex. 1: requests este un pachet extern și se instalează cu pip;
    # urllib face parte din biblioteca standard și vine împreună cu Python.
    print("Ex. 1 - requests:", version("requests"))
    print("urllib.request importat din biblioteca standard")

    # Ex. 2: import requests păstrează clară originea numelui get;
    # from requests import get este mai scurt, dar poate crea conflicte de nume.
    response = requests.get(BASE_URL, timeout=TIMEOUT)
    print("Ex. 2 - import requests:", response.status_code)
    pause()
    response = get(BASE_URL, timeout=TIMEOUT)
    print("Ex. 2 - from requests import get:", response.status_code)

    # Ex. 3: un alias ajută când numele este lung sau există o convenție bine
    # cunoscută. Un alias neobișnuit poate face codul mai greu de înțeles.
    pause()
    response = rq.get(BASE_URL, timeout=TIMEOUT)
    print("Ex. 3 - alias rq:", response.status_code)

    # Ex. 4: urllib.request.urlopen returnează bytes, apoi decode produce str.
    pause()
    std_request = urllib.request.Request(BASE_URL, headers={"User-Agent": "Brai-Roman-SI-263"})
    with urllib.request.urlopen(std_request, timeout=TIMEOUT) as std_response:
        html = std_response.read().decode("utf-8")
        print("Ex. 4 - status:", std_response.status)
        print("Primele 200 de caractere:", html[:200])

    # Ex. 5: exemple din dir(requests).
    names = dir(requests)
    print("Ex. 5 - primele nume:", names[:10])
    examples = {
        "get": "funcție" if inspect.isfunction(requests.get) else type(requests.get).__name__,
        "Session": "clasă" if inspect.isclass(requests.Session) else type(requests.Session).__name__,
        "adapters": "modul" if inspect.ismodule(requests.adapters) else type(requests.adapters).__name__,
    }
    print("Clasificare:", examples)

    # Ex. 6: parametrul este timeout.
    print("Ex. 6 - documentația requests.get:")
    print(inspect.getdoc(requests.get))
    pause()
    response = requests.get(BASE_URL, timeout=TIMEOUT)
    print("Cerere cu timeout:", response.status_code)

    # Ex. 7: perf_counter măsoară timpul total observat de program, iar
    # response.elapsed măsoară intervalul până la sosirea antetelor răspunsului.
    pause()
    start = time.perf_counter()
    response = requests.get(BASE_URL, timeout=TIMEOUT)
    measured = time.perf_counter() - start
    print(f"Ex. 7 - perf_counter: {measured:.3f} s")
    print(f"response.elapsed: {response.elapsed.total_seconds():.3f} s")

    # Ex. 8.
    try:
        import bs4  # noqa: F401
        print("Ex. 8 - beautifulsoup4 este instalat")
    except ImportError:
        print("Instalați modulul cu: pip install beautifulsoup4")

    # Verificați-vă: modul = un fișier Python; pachet = un director importabil
    # cu module; bibliotecă = termen general pentru cod reutilizabil, care poate
    # conține unul sau mai multe module și pachete.
    print("Modul = fișier; pachet = colecție importabilă; bibliotecă = ansamblu reutilizabil.")


if __name__ == "__main__":
    main()
