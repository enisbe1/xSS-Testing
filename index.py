import tkinter as tk
from tkinter import *
from tkinter import ttk
from tkinter.messagebox import askyesno
import requests
from pprint import pprint
from bs4 import BeautifulSoup as bs
from urllib.parse import urljoin
import pprint,optparse, random, re, string, urllib, urllib.parse, urllib.request
from patterns import REGULAR_PATTERNS
from patterns import DOM_PATTERNS

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
                url_step_1 = str("* scanning %s parameter '%s'" % (phase, match.group("parameter")))
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
                                        url_step_2 = str(" (i) %s parameter '%s' appears to be XSS vulnerable (%s)" % (phase, match.group("parameter"), info % dict((("filtering", "no" if all(char in sample.group(1) for char in LARGER_CHAR_POOL) else "some"),))))
                                        found = retval = True
                                    break
        if not usable:
            print(" (x) no usable GET/POST parameters found")
    except KeyboardInterrupt:
        print("\r (x) Ctrl-C pressed")
    return (url_step_1+ '\n' + url_step_2)


if __name__ == "__main__":

    parser = optparse.OptionParser(version=VERSION)
    parser.add_option("-u",  dest="url", help="Target URL (e.g. \"http://www.target.com/page.php?id=1\")")
    parser.add_option("--data", dest="data", help="POST data (e.g. \"query=test\")")
    options, _ = parser.parse_args()



def space(Frame):
    blank_label = tk.Label(Frame)
    blank_label.configure(bg = "#252526",padx = 10, pady = 10, height = 2, fg = "white")
    blank_label.pack( side = RIGHT)


def get_all_forms(url):
    """Given a `url`, it returns all forms from the HTML content"""
    soup = bs(requests.get(url).content, "html.parser")
    return soup.find_all("form")

def get_form_details(form):
    """
    This function extracts all possible useful information about an HTML `form`
    """
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
            # if input name and value are not None,
            # then add them to the data of form submission
            data[input_name] = input_value

    if form_details["method"] == "post":
        return requests.post(target_url, data=data)
    else:
        # GET request
        return requests.get(target_url, params=data)

def scan_xss(url):
   
    # get all the forms from the URL
    forms = get_all_forms(url)
    step_1 = str(f"[+] Detected {len(forms)} forms on {url}.")
    js_script = "<Script>alert('hi')</scripT>"
    # returning value
    is_vulnerable = False
    # iterate over all forms
    for form in forms:
        form_details = get_form_details(form)
        content = submit_form(form_details, url, js_script).content.decode()
        if js_script in content:
            step_2 = str(f"[+] XSS Detected on {url}")
            step_3 = str(f"[*] Form details:")
            step_4 = pprint.pformat(form_details)
            is_vulnerable = True
            # won't break because we want to print available vulnerable forms
    if True:        
        return (step_1 +"\n" + step_2 + "\n" + step_3 + "\n"+step_4) 
    else:
        return "something went worng"

 
window = tk.Tk()

#navBar
navBarFrame = Frame(master = window, width = 150, height = 650, bg =  "#252526")
navBarFrame.pack(fill = X, side = tk.TOP, anchor = "w")

space(navBarFrame)
url_label = tk.Label(navBarFrame, text="URL")
url_label.configure(bg = "#252526",padx = 10, pady = 10, width = 5, fg = "white",font =("Courier", 12))
url_label.pack( side = LEFT)



#mainFrame
mainFrame = Frame(master = window, width = 650, height = 750, bg = "#1E1E1E")
mainFrame.pack(fill = BOTH,anchor = "center")


input_text = StringVar()

url_entry = tk.Entry(navBarFrame,textvariable = input_text)
url_entry.configure(relief = RAISED, width = 50)
url_entry.focus_force()
url_entry.pack(side = LEFT)

def formTesting ():
    url = url_entry.get()
    output_text = tk.Text(mainFrame )
    output_text.config(font=('Courier', 16),fg = "white", bg = "#1e1e1e")
    output_text.pack()

    
    txt = str(scan_xss(url)) 
    output_text.insert(tk.END,txt)

def ulrTesting():
    url = url_entry.get()
    options.url = url
    result = scan_page(options.url if options.url.startswith("http") else "http://%s" % options.url, options.data)
    txt = str("\nscan results: %s vulnerabilities found" % ("possible" if result else "no"))  
    txt_res = str(result)
    text = txt_res + txt
    output_text = tk.Text(mainFrame )
    output_text.config(font=('Courier', 16),fg = "white", bg = "#1e1e1e")
    output_text.pack()  

    # txt = str(scan_xss(url)) 
    output_text.insert(tk.END,text)
     
dom_btn = tk.Button(navBarFrame, text = "DOM", command = formTesting, width = 10)
dom_btn.configure(padx = 5, pady = 5, relief = RAISED,font =("Courier", 8))
dom_btn.pack(side = RIGHT, anchor = "center")

# space(navBarFrame)

# form_btn = tk.Button(navBarFrame, text = "FORM", command = formTesting, width = 10)
# form_btn.configure(padx = 5, pady = 5, relief = RAISED,font =("Courier", 8))
# form_btn.pack(side = RIGHT, anchor = "center")

space(navBarFrame)

scan_btn = tk.Button(navBarFrame, text = "xSS Scan ", command = ulrTesting, width = 10,)
scan_btn.configure(padx = 5, pady = 5, relief = RAISED,font =("Courier", 8))
scan_btn.pack(side = RIGHT, anchor = "center")



window.geometry("900x550")
window.title("xSS Scanner")
window.mainloop()
