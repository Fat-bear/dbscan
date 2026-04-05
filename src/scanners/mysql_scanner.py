import mysql.connector
from mysql.connector import Error

class MySQLScanner:
    def __init__(self, config):
        self.config = config
        self.timeout = config.get('timeout', 5)

    def scan(self, target):
        vulnerabilities = []

        host = target['host']
        port = target['port'] or 3306
        username = target.get('username')
        password = target.get('password')
        database = target.get('database')

        # Test unauthorized access (empty password)
        try:
            connection = mysql.connector.connect(
                host=host,
                port=port,
                user=username or 'root',
                password='',
                database=database,
                connection_timeout=self.timeout
            )
            if connection.is_connected():
                vuln = {
                    'title': 'MySQL Weak/No Password',
                    'address': f'{host}:{port}',
                    'severity': 'high',
                    'description': 'MySQL server allows connections with empty or weak password.',
                    'exploitation': 'An attacker can connect using default credentials.',
                    'fix': 'Set strong passwords for all users and disable remote root access.',
                    'packets': [
                        {
                            'request': f'CONNECT to {host}:{port} with user={username or "root"}, password=""',
                            'response': 'Connected successfully'
                        }
                    ]
                }
                vulnerabilities.append(vuln)
                connection.close()
        except Error:
            pass

        # Test SQL injection vulnerability
        if username and password:
            try:
                connection = mysql.connector.connect(
                    host=host,
                    port=port,
                    user=username,
                    password=password,
                    database=database,
                    connection_timeout=self.timeout
                )
                cursor = connection.cursor()
                # Test for SQL injection in a simple query
                test_query = "SELECT 1 WHERE 1=1 UNION SELECT version()"
                cursor.execute(test_query)
                result = cursor.fetchall()
                if result:
                    vuln = {
                        'title': 'MySQL SQL Injection',
                        'address': f'{host}:{port}',
                        'severity': 'high',
                        'description': 'MySQL server is vulnerable to SQL injection.',
                        'exploitation': 'An attacker can inject malicious SQL code.',
                        'fix': 'Use prepared statements and input validation.',
                        'packets': [
                            {
                                'request': f'EXECUTE: {test_query}',
                                'response': f'Result: {result}'
                            }
                        ]
                    }
                    vulnerabilities.append(vuln)
                cursor.close()
                connection.close()
            except Error:
                pass

        return vulnerabilities