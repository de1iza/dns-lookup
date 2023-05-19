# Google DNS
dns_ip := '8.8.8.8'

r ip domain_name:
    python3 main.py {{ip}} {{domain_name}}

google:
    python3 main.py {{dns_ip}} google.com

telegram:
    python3 main.py {{dns_ip}} telegram.org

tutorialspoimain:
    python3 main.py {{dns_ip}} tutorialspoint.com