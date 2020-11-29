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


def process_domain(domain_elements, timestamp, parent_domains, parent_dict):
    domain, *subdomains = domain_elements

    if domain not in parent_dict:
        parent_dict[domain] = {'count': 0, 'timestamps': [], 'subdomains': {}, 'top_level': False}

    domain_dict = parent_dict[domain]
    domain_dict['count'] += 1
    domain_dict['timestamps'].append(timestamp)

    if subdomains:
        process_domain(subdomains, timestamp, [*parent_domains, domain], domain_dict['subdomains'])
    else:
        domain_dict['top_level'] = True


domains = {}


for line in data[:-12].decode('utf-8').split('\n'):
    timestamp_str, _, addr_str, *_ = line.split()
    addr_elements = addr_str.split('.')
    process_domain(['.'.join(addr_elements[-2:]), *reversed(addr_elements[:-2])], int(timestamp_str), [], domains)


def make_all_domains(parent_dict, parent_domain=''):
    return_set = set()

    for domain in parent_dict:
        domain_dict = parent_dict[domain]
        if domain_dict['top_level']:
            return_set.add(domain + parent_domain)
        if domain_dict['subdomains']:
            return_set |= make_all_domains(domain_dict['subdomains'], f'.{domain}{parent_domain}')

    return return_set


def simplify_domains(parent_dict):
    replace_dict = {}

    for domain in parent_dict:
        domain_dict = parent_dict[domain]
        if domain_dict['subdomains'] and not domain_dict['top_level']:
            process_list = simplify_domains(domain_dict['subdomains'])
            if len(process_list) == 1:
                subdomain = process_list[0]
                replace_dict[domain] = {f'{subdomain}.{domain}': {
                    'count': domain_dict['count'],
                    'timestamps': domain_dict['timestamps'],
                    'top_level': domain_dict['subdomains'][subdomain]['top_level'],
                    'subdomains': domain_dict['subdomains'][subdomain]['subdomains']}}

    for key, value in replace_dict.items():
        parent_dict.pop(key)
        parent_dict.update(value)

    return list(parent_dict)


simplify_domains(domains)


import zlib
invalid_weight = 100
threshold_weight = 1500


def weigh_subdomains(subdomains):
    encoded_list = [domain.encode('utf-8') for domain in subdomains]
    score = len(zlib.compress(b'.'.join(encoded_list)))
    if score < threshold_weight and len(encoded_list) >= ((threshold_weight - score) / invalid_weight):
        for encoded in encoded_list:
            try:
                encoded.decode('idna')
            except UnicodeError as e:
                score += invalid_weight
    return score >= threshold_weight


def detect_tunneling(parent_dict, parent_domain=''):
    detect_list = []
    examine_list = []

    for domain in parent_dict:
        domain_dict = parent_dict[domain]
        if domain_dict['subdomains']:
            sub_detect_list, sub_examine_list = detect_tunneling(domain_dict['subdomains'], f'.{domain}{parent_domain}')
            if weigh_subdomains(sub_examine_list):
                detect_list.append(domain + parent_domain)
            else:
                detect_list.extend(sub_detect_list)
                examine_list.extend(f'{subdomain}.{domain}' for subdomain in sub_examine_list)
        else:
            examine_list.append(domain)

    return detect_list, examine_list


def regex_convert(domain):
    return r'(\.|^)' + r'\.'.join(domain.split('.')) + r'$'


sys.stderr.write(' '.join([regex_convert(domain) for domain in detect_tunneling(domains)[0]]))
