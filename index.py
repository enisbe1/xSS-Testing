import optparse, random, re, string, urllib, urllib.parse, urllib.request
from tkinter import *
import tkinter as tk
from tkinter import ttk
from tkinter.messagebox import askyesno
import requests
from pprint import pprint
from bs4 import BeautifulSoup as bs
from urllib.parse import urljoin
from patterns import REGULAR_PATTERNS
from patterns import DOM_PATTERNS

VERSION ="0.3c"

SMALLER_CHAR_POOL    = ('<', '>')                                                           # characters used for XSS tampering of parameter values (smaller set - for avoiding possible SQLi errors)
LARGER_CHAR_POOL     = ('\'', '"', '>', '<', ';')                                           # characters used for XSS tampering of parameter values (larger set)
GET, POST            = "GET", "POST"                                                        # enumerator-like values used for marking current phase
PREFIX_SUFFIX_LENGTH = 5                                                                    # length of random prefix/suffix used in XSS tampering
COOKIE, UA, REFERER = "Cookie", "User-Agent", "Referer"                                     # optional HTTP header names
TIMEOUT = 30                                                                                # connection timeout in seconds
DOM_FILTER_REGEX = r"(?s)<!--.*?-->|\bescape\([^)]+\)|\([^)]+==[^(]+\)|\"[^\"]+\"|'[^']+'"  # filtering regex used before DOM XSS search

_headers = {}                                                                               # used for storing dictionary with optional header values

def _retrieve_content(url, data=None):
    try:
        req = urllib.request.Request("".join(url[i].replace(' ', "%20") if i > url.find('?') else url[i] for i in range(len(url))), data.encode("utf8", "ignore") if data else None, _headers)
        retval = urllib.request.urlopen(req, timeout=TIMEOUT).read()
    except Exception as ex:
        retval = ex.read() if hasattr(ex, "read") else str(ex.args[-1])
    return (retval.decode("utf8", "ignore") if hasattr(retval, "decode") else "") or ""

def _contains(content, chars):
    content = re.sub(r"\\[%s]" % re.escape("".join(chars)), "", content) if chars else content
    return all(char in content for char in chars)

def scan_page(url, data=None):
    retval, usable = False, False
    url, data = re.sub(r"=(&|\Z)", "=1\g<1>", url) if url else url, re.sub(r"=(&|\Z)", "=1\g<1>", data) if data else data
    original = re.sub(DOM_FILTER_REGEX, "", _retrieve_content(url, data))
    dom = next(filter(None, (re.search(_, original) for _ in DOM_PATTERNS)), None)
    if dom:
        print(" (i) page itself appears to be XSS vulnerable (DOM)")
        print("  (o) ...%s..." % dom.group(0))
        retval = True
    try:
        for phase in (GET, POST):
            current = url if phase is GET else (data or "")
            for match in re.finditer(r"((\A|[?&])(?P<parameter>[\w\[\]]+)=)(?P<value>[^&#]*)", current):
                found, usable = False, True
                print("* scanning %s parameter '%s'" % (phase, match.group("parameter")))
                prefix, suffix = ("".join(random.sample(string.ascii_lowercase, PREFIX_SUFFIX_LENGTH)) for i in range(2))
                for pool in (LARGER_CHAR_POOL, SMALLER_CHAR_POOL):
                    if not found:
                        tampered = current.replace(match.group(0), "%s%s" % (match.group(0), urllib.parse.quote("%s%s%s%s" % ("'" if pool == LARGER_CHAR_POOL else "", prefix, "".join(random.sample(pool, len(pool))), suffix))))
                        content = (_retrieve_content(tampered, data) if phase is GET else _retrieve_content(url, tampered)).replace("%s%s" % ("'" if pool == LARGER_CHAR_POOL else "", prefix), prefix)
                        for regex, condition, info, content_removal_regex in REGULAR_PATTERNS:
                            filtered = re.sub(content_removal_regex or "", "", content)
                            for sample in re.finditer("%s([^ ]+?)%s" % (prefix, suffix), filtered, re.I):
                                context = re.search(regex % {"chars": re.escape(sample.group(0))}, filtered, re.I)
                                if context and not found and sample.group(1).strip():
                                    if _contains(sample.group(1), condition):
                                        print(" (i) %s parameter '%s' appears to be XSS vulnerable (%s)" % (phase, match.group("parameter"), info % dict((("filtering", "no" if all(char in sample.group(1) for char in LARGER_CHAR_POOL) else "some"),))))
                                        found = retval = True
                                    break
        if not usable:
            print(" (x) no usable GET/POST parameters found")
    except KeyboardInterrupt:
        print("\r (x) Ctrl-C pressed")
    return retval


if __name__ == "__main__":

    parser = optparse.OptionParser(version=VERSION)
    parser.add_option("-u",  dest="url", help="Target URL (e.g. \"http://www.target.com/page.php?id=1\")")
    parser.add_option("--data", dest="data", help="POST data (e.g. \"query=test\")")
    options, _ = parser.parse_args()


def get_all_forms(url):
    soup = bs(requests.get(url).content, "html.parser")
    return soup.find_all("form")

def get_form_details(form):

    details = {}
    # get the form action (target url)
    action = form.attrs.get("action").lower()
    # get the form method (POST, GET, etc.)
    method = form.attrs.get("method", "get").lower()
    # get all the input details such as type and name
    inputs = []
    for input_tag in form.find_all("input"):
        input_type = input_tag.attrs.get("type", "text")
        input_name = input_tag.attrs.get("name")
        inputs.append({"type": input_type, "name": input_name})
    # put everything to the resulting dictionary
    details["action"] = action
    details["method"] = method
    details["inputs"] = inputs
    return details

def submit_form(form_details, url, value):
    # construct the full URL (if the url provided in action is relative)
    target_url = urljoin(url, form_details["action"])
    # get the inputs
    inputs = form_details["inputs"]
    data = {}
    for input in inputs:
        # replace all text and search values with `value`
        if input["type"] == "text" or input["type"] == "search":
            input["value"] = value
        input_name = input.get("name")
        input_value = input.get("value")
        if input_name and input_value:
            data[input_name] = input_value

    if form_details["method"] == "post":
        return requests.post(target_url, data=data)
    else:
        # GET request
        return requests.get(target_url, params=data)

def scan_xss(url):

    # get all the forms from the URL
    forms = get_all_forms(url)
    print(f"[+] Detected {len(forms)} forms on {url}.")
    js_script = "<Script>alert('hi')</scripT>"
    # returning value
    is_vulnerable = False
    # iterate over all forms
    for form in forms:
        form_details = get_form_details(form)
        content = submit_form(form_details, url, js_script).content.decode()
        if js_script in content:
            print(f"[+] XSS Detected on {url}")
            print(f"[*] Form details:")
            pprint(form_details)
            is_vulnerable = True
            # won't break because we want to print available vulnerable forms
    return is_vulnerable


root= tk.Tk(className='XSS Testing sites')

canvas1 = tk.Canvas(root, width = 600, height = 500, relief = 'raised')
canvas1.pack()

label1 = tk.Label(root, text='Testing Cross-Site Scripting')
label1.config(font=('helvetica', 24))
canvas1.create_window(300, 40, window=label1)

label2 = tk.Label(root, text='Type your URL you want to test:')
label2.config(font=('helvetica', 16))
canvas1.create_window(300, 180, window=label2)

input_text = StringVar()
entry1 = ttk.Entry(root, textvariable = input_text, justify = CENTER)
entry1.focus_force()
entry1.pack(side = TOP, ipadx = 50, ipady = 10)
canvas1.create_window(300, 240, window=entry1)

def startTesting ():
    url = entry1.get()
    print(scan_xss(url))

def urlTestingForms():
    url = entry1.get()
    options.url = url
    result = scan_page(options.url if options.url.startswith("http") else "http://%s" % options.url, options.data)
    print("\nscan results: %s vulnerabilities found" % ("possible" if result else "no"))

button1 = tk.Button(text='XSS TEST', command=startTesting, bg='brown', fg='white', font=('helvetica', 9, 'bold'))
button1.pack(side = TOP, pady = 10)
canvas1.create_window(260, 270, window=button1)

button2 = tk.Button(text='Url TEST', command=urlTestingForms, bg='brown', fg='white', font=('helvetica', 9, 'bold'))
button2.pack(side = TOP, pady = 10)
canvas1.create_window(340, 270, window=button2)

root.mainloop()
