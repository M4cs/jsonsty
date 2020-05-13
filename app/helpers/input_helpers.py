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
	except dns.resolver.NXDOMAIN:
		return False
	if len(records) > 0:
		return True
	return False

def verify_name(store_name):
    regex = '<\/?[A-Za-z0-9]{1,}>'
    if re.search(regex, store_name):
        return False
    else:
        return True
