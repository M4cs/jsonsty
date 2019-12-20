import dns.resolver
import re

def verify_email(email):
    regex = '^\w+([\.-]?\w+)*@\w+([\.-]?\w+)*(\.\w{2,3})+$'
    if re.search(regex,email):
        pass
    else:
        return False
    domain = email.split('@')[1]
    records = []
    try:
        for x in dns.resolver.query(domain, 'MX'):
            records.append(x)
    except dns.resolver.NoAnswer:
        return False
    if len(records) > 0:
        return True
    return False
