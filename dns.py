import subprocess
import re

class DNS: 
    def web_server(self, domain):
        webserver = subprocess.call(['curl', '-I', domain])
        return webserver