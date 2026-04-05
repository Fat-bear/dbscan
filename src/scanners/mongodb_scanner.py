from pymongo import MongoClient
from pymongo.errors import ConnectionFailure, OperationFailure

class MongoDBScanner:
    def __init__(self, config):
        self.config = config
        self.timeout = config.get('timeout', 5)

    def scan(self, target):
        vulnerabilities = []

        host = target['host']
        port = target['port'] or 27017
        username = target.get('username')
        password = target.get('password')
        database = target.get('database')

        # Test unauthorized access
        try:
            client = MongoClient(host=host, port=port, serverSelectionTimeoutMS=self.timeout*1000)
            # Try to list databases without auth
            db_list = client.list_database_names()
            vuln = {
                'title': 'MongoDB Unauthorized Access',
                'address': f'{host}:{port}',
                'severity': 'high',
                'description': 'MongoDB server allows connections without authentication.',
                'exploitation': 'An attacker can access and modify data without credentials.',
                'fix': 'Enable authentication and bind to localhost or configure firewall.',
                'packets': [
                    {
                        'request': f'CONNECT to {host}:{port} (no auth)',
                        'response': f'Databases: {db_list}'
                    }
                ]
            }
            vulnerabilities.append(vuln)
            client.close()
        except (ConnectionFailure, OperationFailure):
            pass

        # Test with credentials if provided
        if username and password:
            try:
                client = MongoClient(
                    host=host,
                    port=port,
                    username=username,
                    password=password,
                    authSource=database or 'admin',
                    serverSelectionTimeoutMS=self.timeout*1000
                )
                db_list = client.list_database_names()
                # If successful, check for weak password
                if self.is_weak_password(password):
                    vuln = {
                        'title': 'MongoDB Weak Password',
                        'address': f'{host}:{port}',
                        'severity': 'medium',
                        'description': 'MongoDB server uses a weak password.',
                        'exploitation': 'Password can be easily guessed or brute-forced.',
                        'fix': 'Use strong, complex passwords.',
                        'packets': [
                            {
                                'request': f'AUTH with user={username}, password={password}',
                                'response': f'Databases: {db_list}'
                            }
                        ]
                    }
                    vulnerabilities.append(vuln)
                client.close()
            except (ConnectionFailure, OperationFailure):
                pass

        return vulnerabilities

    def is_weak_password(self, password):
        weak_passwords = ['password', '123456', 'admin', 'mongo', '']
        return password in weak_passwords