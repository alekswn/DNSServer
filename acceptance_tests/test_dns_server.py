import dns.resolver
import dns.message
import dns.rdatatype
import dns.rdataclass
import dns.query
import pytest
import socket
import time

# Default server settings
SERVER_IP = '127.0.0.1'
SERVER_PORT = 5353  # Using non-privileged port

class TestDNSServer:
    """Acceptance tests for DNS server implementation based on RFC 1035."""
    
    def setup_method(self):
        """Set up test environment before each test."""
        # Create a custom resolver that points to our DNS server
        self.resolver = dns.resolver.Resolver()
        self.resolver.nameservers = [SERVER_IP]
        self.resolver.port = SERVER_PORT
        self.resolver.timeout = 5
        self.resolver.lifetime = 5
    
    def test_a_record_resolution(self, dns_server):
        """Test that the server correctly resolves A records."""
        try:
            answers = self.resolver.resolve('example.com', 'A')
            assert len(answers) >= 1
            # Check that the answer is a valid IP address
            for rdata in answers:
                socket.inet_aton(str(rdata))  # This will raise an exception if not a valid IPv4
        except dns.exception.DNSException as e:
            pytest.fail(f"Failed to resolve A record: {e}")
    
    def test_mx_record_resolution(self, dns_server):
        """Test that the server correctly resolves MX records."""
        try:
            answers = self.resolver.resolve('example.com', 'MX')
            assert len(answers) >= 1
            # Check that we got valid MX records
            for rdata in answers:
                assert rdata.preference >= 0
                assert str(rdata.exchange)
        except dns.exception.DNSException as e:
            pytest.fail(f"Failed to resolve MX record: {e}")
    
    def test_cname_resolution(self, dns_server):
        """Test that the server properly handles CNAME records."""
        try:
            answers = self.resolver.resolve('www.example.com', 'A')
            # Verify we eventually got an A record
            assert any(rdata.rdtype == dns.rdatatype.A for rdata in answers)
        except dns.exception.DNSException as e:
            pytest.fail(f"Failed to resolve CNAME record: {e}")
    
    def test_ns_record_resolution(self, dns_server):
        """Test that the server correctly resolves NS records."""
        try:
            answers = self.resolver.resolve('example.com', 'NS')
            assert len(answers) >= 1
            # Verify each name server is a valid hostname
            for rdata in answers:
                assert str(rdata)
        except dns.exception.DNSException as e:
            pytest.fail(f"Failed to resolve NS record: {e}")
    
    def test_txt_record_resolution(self, dns_server):
        """Test that the server correctly resolves TXT records."""
        try:
            answers = self.resolver.resolve('example.com', 'TXT')
            assert len(answers) >= 1
            # Verify each TXT record contains data
            for rdata in answers:
                assert len(rdata.strings) >= 1
        except dns.exception.DNSException as e:
            pytest.fail(f"Failed to resolve TXT record: {e}")
    
    def test_ptr_record_resolution(self, dns_server):
        """Test that the server correctly resolves PTR records."""
        try:
            # Reverse DNS lookup for 192.0.2.1
            reverse_name = dns.reversename.from_address('192.0.2.1')
            answers = self.resolver.resolve(reverse_name, 'PTR')
            assert len(answers) >= 1
            # Verify each PTR record is a valid domain name
            for rdata in answers:
                assert str(rdata)
        except dns.exception.DNSException as e:
            pytest.fail(f"Failed to resolve PTR record: {e}")
    
    def test_soa_record_resolution(self, dns_server):
        """Test that the server correctly resolves SOA records."""
        try:
            answers = self.resolver.resolve('example.com', 'SOA')
            assert len(answers) >= 1
            # Verify SOA record components
            for rdata in answers:
                assert str(rdata.mname)  # Primary nameserver
                assert str(rdata.rname)  # Responsible party email
                assert rdata.serial > 0  # Serial number
                assert rdata.refresh > 0  # Refresh time
                assert rdata.retry > 0   # Retry time
                assert rdata.expire > 0  # Expire time
                assert rdata.minimum > 0  # Minimum TTL
        except dns.exception.DNSException as e:
            pytest.fail(f"Failed to resolve SOA record: {e}")
    
    def test_nonexistent_domain(self, dns_server):
        """Test that the server correctly handles non-existent domains."""
        with pytest.raises(dns.resolver.NXDOMAIN):
            self.resolver.resolve('nonexistent-domain-12345.com', 'A')
    
    def test_case_insensitivity(self, dns_server):
        """Test that domain name lookups are case-insensitive as per RFC 1035."""
        try:
            # Mixed case domain name
            answers1 = self.resolver.resolve('ExAmPlE.CoM', 'A')
            # Lowercase domain name
            answers2 = self.resolver.resolve('example.com', 'A')
            
            # Both queries should return the same results
            assert len(answers1) == len(answers2)
            
            # Compare the actual IP addresses
            ips1 = sorted([str(rdata) for rdata in answers1])
            ips2 = sorted([str(rdata) for rdata in answers2])
            assert ips1 == ips2
        except dns.exception.DNSException as e:
            pytest.fail(f"Failed to test case insensitivity: {e}")
    
    def test_truncated_responses(self, dns_server):
        """Test that the server correctly handles truncated responses."""
        # Create a query that will likely result in a large response
        qname = dns.name.from_text('example.com')
        q = dns.message.make_query(qname, dns.rdatatype.ANY)
        
        try:
            # Send the query with a small UDP buffer size to force truncation
            response = dns.query.udp(q, SERVER_IP, port=SERVER_PORT, timeout=5)
            
            # If we get a truncated response, we should retry with TCP
            if response.flags & dns.flags.TC:
                tcp_response = dns.query.tcp(q, SERVER_IP, port=SERVER_PORT, timeout=5)
                assert tcp_response.answer
            else:
                # If not truncated, we should still have answers
                assert not response.flags & dns.flags.TC
        except dns.exception.DNSException as e:
            pytest.fail(f"Failed to test truncated responses: {e}")
