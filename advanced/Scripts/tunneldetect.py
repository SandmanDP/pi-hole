from socket import AF_INET, SOCK_STREAM, socket
import sys


with socket(AF_INET, SOCK_STREAM) as s:
    s.connect(('localhost', 4711))
    s.send(b'>getallqueries\n')
    data = b''
    while True:
        data += s.recv(4096)
        if data[-12:] == b'\n---EOM---\n\n':
            break
# with open('/Users/fwahhab/Downloads/dns_test_data.txt', 'rb') as f:
#     data = f.read()


domains = {}


def process_domain(domain_elements, timestamp, parent_elements, parent_dict):
    domain, *subelements = domain_elements

    if domain not in parent_dict:
        parent_dict[domain] = {'count': 0, 'timestamps': [], 'subelements': {}}

    domain_dict = parent_dict[domain]
    domain_dict['count'] += 1
    domain_dict['timestamps'].append(timestamp)

    if subelements:
        process_domain(subelements, timestamp, [*parent_elements, domain], domain_dict['subelements'])


for line in data[:-12].decode("utf-8").split('\n'):
    timestamp_str, _, addr_str, *_ = line.split()
    addr_elements = addr_str.split('.')
    process_domain(['.'.join(addr_elements[-2:]), *reversed(addr_elements[:-2])], int(timestamp_str), [], domains)


def regex_convert(domain):
    return r'(\.|^)' + r'\.'.join(domain.split('.')) + r'$'


sys.stderr.write(' '.join([regex_convert(domain) for domain in domains.keys()]))
