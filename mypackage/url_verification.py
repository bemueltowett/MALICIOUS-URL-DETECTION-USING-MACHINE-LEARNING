import re
import whois
import socket
import requests
import dns.resolver
from tld import get_tld


class URLVerification:
    def __init__(self, url):
        self.url = url.strip().lower()
        self.domain = None

    def valid_url(self):
        """
        Validate URL format using regex.
        """
        regex = re.compile(
            r'^(https?://)?'                      # http(s):// optional
            r'(([A-Za-z0-9-]+\.)+[A-Za-z]{2,6})'  # domain
            r'(:\d+)?'                            # optional port
            r'(/.*)?$'                            # optional path
        )
        return re.match(regex, self.url) is not None
    
    def get_domain(self):
        """
        Extract the domain from the URL.
        
        Returns:
            str: The domain if valid, empty string otherwise.
        """        
        if not self.valid_url():
            return "Please enter a valid URL."
        
        try:
            res = get_tld(self.url, as_object=True, fail_silently=False, fix_protocol=True)
            self.domain = res.parsed_url.netloc
            return self.domain
        except Exception:
            return False

    def socketVerification(self):
        """
        Check if the domain is reachable by attempting to connect to it.
        
        Returns:
            bool: True if the domain is reachable, False otherwise.
        """
        domain = self.get_domain()
        try:
            ip_address = socket.gethostbyname(domain)
            socket.create_connection((ip_address, 80), timeout=5)
            return True
        except (socket.gaierror, socket.timeout, OSError):
            return False

    def whoisVerification(self):
        """
        Check if the domain has a valid WHOIS record. 
        Confirms domain registration
        
        Returns:
            bool: True if the domain has a valid WHOIS record, False otherwise.
        """
        domain = self.get_domain()
        try:
            info = whois.whois(domain)
            return info.domain_name is not None and len(info.domain_name) > 0
        except Exception:
            return False

    def dnsresolverVerification(self):
        """
        Check if the domain can be resolved to an IP address.
        
        Returns:
            bool: True if the domain can be resolved, False otherwise.
        """
        domain = self.get_domain()
        try:
            dns.resolver.resolve(domain, 'A')
            return True
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.Timeout):
            return False
        
    def contentVerification(self):
        """
        Check if the domain is reachable by making an HTTP request.
        
        Returns:
            bool: True if the domain is reachable and returns a valid response, False otherwise.
        """
        domain = self.get_domain()
        try:
            response = requests.get(f"http://{domain}", timeout=5)
            return response.status_code == 200
        except requests.exceptions.RequestException:
            return False
        
    def verify(self):
        """
        Perform all verification checks on the domain.
        
        Returns:
            bool: True if all verification checks pass, False otherwise.
        """
        return self.socketVerification() and self.whoisVerification() and self.dnsresolverVerification() and self.contentVerification()
    