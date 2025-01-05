# scanqli.py

import argparse
from function import SQLInjector
import logging
from rich.console import Console
from rich.logging import RichHandler
import json
import time
import sys
import os

# Configure logging with RichHandler and rich_tracebacks
logging.basicConfig(
    level=logging.INFO,  # Niveau de log défini à INFO
    format="%(message)s",
    datefmt="[%X]",
    handlers=[RichHandler(rich_tracebacks=True)]
)
logger = logging.getLogger("SQLInjector")

# Initialize Rich console
console = Console()

def print_warning():
    console.print("[bold yellow]⚠️  ATTENTION: Utilisez cet outil uniquement dans des environnements de test autorisés. Toute utilisation non autorisée est illégale et contraire à l'éthique.[/bold yellow]\n")

def validate_post_data(post_data_str):
    """
    Valide et convertit la chaîne de données POST en dictionnaire.
    """
    post_data = {}
    try:
        post_data_pairs = post_data_str.split('&')
        for pair in post_data_pairs:
            if '=' not in pair:
                raise ValueError
            key, value = pair.split('=', 1)
            post_data[key] = value
        return post_data
    except ValueError:
        logger.error("Format invalide pour --post-data. Utilisez le format key=value&key2=value2.")
        sys.exit(1)

def validate_output_file(output_path):
    """
    Valide que le fichier de sortie a une extension supportée (.json ou .html).
    """
    if not (output_path.endswith('.json') or output_path.endswith('.html')):
        logger.error("Format de sortie non supporté. Utilisez une extension .json ou .html.")
        sys.exit(1)

def main():
    print_warning()
    parser = argparse.ArgumentParser(
        description='Advanced SQL Injection Scanner (similar to sqlmap)'
    )
    parser.add_argument('-u', '--url', required=True, help='URL cible à scanner (e.g., http://example.com/page.php?id=1)')
    parser.add_argument('-p', '--param', required=True, help='Paramètre vulnérable à tester (e.g., id)')
    parser.add_argument('-m', '--method', choices=['GET', 'POST'], default='GET', help='Méthode HTTP à utiliser (default: GET)')
    parser.add_argument('-t', '--threads', type=int, default=10, help='Nombre de threads concurrentiels (default: 10)')
    parser.add_argument('--timeout', type=int, default=10, help='Timeout des requêtes en secondes (default: 10)')
    parser.add_argument('--proxies', type=str, help='URL du proxy (e.g., http://127.0.0.1:8080)')
    parser.add_argument('--user-agents', nargs='+', help='Liste de User-Agents à faire tourner')
    parser.add_argument('-o', '--output', type=str, help='Fichier de sortie pour sauvegarder les résultats (format JSON ou HTML)')
    parser.add_argument('--crawl', action='store_true', help='Activer le crawling pour découvrir des URLs')
    parser.add_argument('--depth', type=int, default=2, help='Profondeur de crawl (default: 2)')
    parser.add_argument('--tests', nargs='+', choices=[
        "basic", "blind", "timebase", "gbkquotes", "allalpha", "union",
        "banner", "current_user", "current_database", "hostname",
        "dbs_count", "dbs_names", "tbls_count", "tbls_names", "cols_count", "cols_names"
    ], help='Spécifiez les tests à exécuter (default: tous)')
    parser.add_argument('--db', type=str, help='Spécifiez une base de données à cibler')
    parser.add_argument('--tbl', type=str, help='Spécifiez une table à cibler')
    parser.add_argument('--post-data', type=str, help='Données POST au format key=value&key2=value2')

    args = parser.parse_args()

    # Validation des fichiers de sortie
    if args.output:
        validate_output_file(args.output)

    # Configuration des proxies
    proxies = {
        "http": args.proxies,
        "https": args.proxies
    } if args.proxies else None

    # Configuration des tests sélectionnés
    selected_tests = args.tests if args.tests else [
        "basic", "blind", "timebase", "gbkquotes", "allalpha", "union",
        "banner", "current_user", "current_database", "hostname",
        "dbs_count", "dbs_names", "tbls_count", "tbls_names", "cols_count", "cols_names"
    ]

    # Traitement des données POST
    post_data = {}
    if args.method == 'POST':
        if args.post_data:
            post_data = validate_post_data(args.post_data)
        else:
            logger.warning("Aucune donnée POST fournie. Utilisation de données POST vides.")

    # Initialisation de SQLInjector avec les tests sélectionnés
    injector = SQLInjector(
        url=args.url,
        param=args.param,
        method=args.method,
        threads=args.threads,
        timeout=args.timeout,
        proxies=proxies,
        user_agents=args.user_agents,
        output=args.output,
        selected_tests=selected_tests,
        post_data=post_data,
        db=args.db,
        tbl=args.tbl
    )

    start_time = time.time()

    try:
        if args.crawl:
            console.rule("[bold red]Démarrage du Crawl et des Tests d'Injection SQL[/bold red]")
            logger.info("Commencement du crawling des URLs...")
            discovered_urls = injector.crawl(max_depth=args.depth)
            logger.info(f"{len(discovered_urls)} URLs découvertes.")
            for url in discovered_urls:
                logger.info(f"Scanning URL : {url}")
                console.print(f"[bold blue]Scanning URL : {url}[/bold blue]")
                test_injector = SQLInjector(
                    url=url,
                    param=args.param,
                    method=args.method,
                    threads=args.threads,
                    timeout=args.timeout,
                    proxies=proxies,
                    user_agents=args.user_agents,
                    output=None,  # Ne pas sauvegarder les résultats intermédiaires
                    selected_tests=selected_tests,
                    post_data=post_data,
                    db=args.db,
                    tbl=args.tbl
                )
                test_injector.run_all_tests()
                injector.results.extend(test_injector.results)
        else:
            logger.info(f"Début des tests d'injection SQL sur {args.url}")
            console.print(f"[bold blue]Début des tests d'injection SQL sur {args.url}[/bold blue]")
            injector.run_all_tests()
    except KeyboardInterrupt:
        logger.error("Scan interrompu par l'utilisateur.")
        injector.save_results()
        sys.exit(1)
    except Exception as e:
        logger.exception("Une erreur inattendue s'est produite.")
        injector.save_results()
        sys.exit(1)

    end_time = time.time()
    duration = end_time - start_time
    console.rule("[bold green]Scan Terminé[/bold green]")
    console.print(f"Total de vulnérabilités trouvées : [bold red]{len(injector.results)}[/bold red] en [bold yellow]{duration:.2f} secondes[/bold yellow].")
    injector.display_results()
    injector.save_results()

if __name__ == "__main__":
    main()
