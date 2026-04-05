import psycopg2
from psycopg2 import Error

class PostgreSQLScanner:
    def __init__(self, config):
        self.config = config
        self.timeout = config.get('timeout', 5)

    def scan(self, target):
        vulnerabilities = []

        host = target['host']
        port = target['port'] or 5432
        username = target.get('username')
        password = target.get('password')
        database = target.get('database') or 'postgres'

        # Test unauthorized access
        try:
            connection = psycopg2.connect(
                host=host,
                port=port,
                user=username or 'postgres',
                password=password or '',
                database=database,
                connect_timeout=self.timeout
            )
            if connection:
                vuln = {
                    'title': 'PostgreSQL Weak/No Password',
                    'address': f'{host}:{port}',
                    'severity': 'high',
                    'description': 'PostgreSQL server allows connections with weak or no password.',
                    'exploitation': 'An attacker can connect using default or weak credentials.',
                    'fix': 'Set strong passwords and configure pg_hba.conf properly.',
                    'packets': [
                        {
                            'request': f'CONNECT to {host}:{port} with user={username or "postgres"}, password={password or ""}',
                            'response': 'Connected successfully'
                        }
                    ]
                }
                vulnerabilities.append(vuln)
                connection.close()
        except Error:
            pass

        # Test for exposed sensitive data
        if username and password:
            try:
                connection = psycopg2.connect(
                    host=host,
                    port=port,
                    user=username,
                    password=password,
                    database=database,
                    connect_timeout=self.timeout
                )
                cursor = connection.cursor()
                # Check for information_schema access
                cursor.execute("SELECT table_name FROM information_schema.tables LIMIT 5")
                result = cursor.fetchall()
                if result:
                    vuln = {
                        'title': 'PostgreSQL Information Disclosure',
                        'address': f'{host}:{port}',
                        'severity': 'medium',
                        'description': 'PostgreSQL server exposes database schema information.',
                        'exploitation': 'An attacker can enumerate database structure.',
                        'fix': 'Restrict access to information_schema and use proper permissions.',
                        'packets': [
                            {
                                'request': 'SELECT table_name FROM information_schema.tables LIMIT 5',
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