import redis
import socket
from datetime import datetime

class RedisScanner:
    def __init__(self, config):
        self.config = config
        self.timeout = config.get('timeout', 5)

    def scan(self, target):
        vulnerabilities = []

        host = target['host']
        port = target['port'] or 6379
        password = target.get('password')

        # Test unauthorized access
        try:
            r = redis.Redis(host=host, port=port, password=None, socket_timeout=self.timeout)
            r.ping()
            # If ping succeeds without password, unauthorized access
            vuln = {
                'title': 'Redis Unauthorized Access',
                'address': f'{host}:{port}',
                'severity': 'high',
                'description': 'Redis server allows connections without authentication.',
                'exploitation': 'An attacker can connect to the Redis server and execute commands.',
                'fix': 'Configure Redis with authentication (requirepass) and bind to localhost or trusted IPs.',
                'packets': [
                    {
                        'request': f'PING to {host}:{port}',
                        'response': 'PONG (success without auth)'
                    }
                ]
            }
            vulnerabilities.append(vuln)
        except redis.AuthenticationError:
            # Requires password
            pass
        except (redis.ConnectionError, socket.timeout, OSError):
            # Connection failed, not vulnerable
            pass
        except Exception as e:
            # Other errors
            pass

        # Test weak password if password provided
        if password:
            try:
                r = redis.Redis(host=host, port=port, password=password, socket_timeout=self.timeout)
                r.ping()
                # If ping succeeds with password, check if password is weak
                if self.is_weak_password(password):
                    vuln = {
                        'title': 'Redis Weak Password',
                        'address': f'{host}:{port}',
                        'severity': 'medium',
                        'description': 'Redis server uses a weak password.',
                        'exploitation': 'An attacker can brute-force or guess the password.',
                        'fix': 'Use a strong, complex password.',
                        'packets': [
                            {
                                'request': f'AUTH {password} to {host}:{port}',
                                'response': 'OK'
                            }
                        ]
                    }
                    vulnerabilities.append(vuln)
            except (redis.ConnectionError, socket.timeout, OSError):
                pass
            except Exception as e:
                pass

        return vulnerabilities

    def is_weak_password(self, password):
        # Simple check for weak passwords
        weak_passwords = ['password', '123456', 'admin', 'redis', '']
        return password in weak_passwords