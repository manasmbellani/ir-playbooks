# Snowflake - Compromised Account

## Containment

### Disable user 

#### via UI

Login as `ACCOUNTADMIN` > Users & Roles > Select the user > `Disable User`

#### via SQL Query

```
set user_name = "SUSPECTED_USER";
ALTER USER IDENTIFIER($user_name) SET DISABLED = TRUE
```

Taken from [here](https://community.snowflake.com/s/article/Communication-ID-0108977-Additional-Information)

### Reset User Password

#### via UI

Login as `ACCOUNTADMIN` > Users & Roles > Modify User

#### via SQL Query

```
ALTER USER IDENTIFIER($user_name) RESET PASSWORD;
```

Taken from [here](https://community.snowflake.com/s/article/Communication-ID-0108977-Additional-Information)

### Unset SSH Keys

#### via SQL Query

```
ALTER USER IDENTIFIER($user_name) UNSET RSA_PUBLIC_KEY;
ALTER USER IDENTIFIER($user_name) UNSET RSA_PUBLIC_KEY_2;
```

Taken from [here](https://community.snowflake.com/s/article/Communication-ID-0108977-Additional-Information), [here](https://docs.snowflake.com/en/user-guide/key-pair-auth)

### Restrict SnowFlake account to network IP ranges

#### via Network Policy / Network Rules

Taken from [here](https://docs.snowflake.com/en/user-guide/network-policies#about-network-policies)

## Collection

## Analysis

### Privilege Escalation Actions

#### via SQL  / QUERY_HISTORY table

```
select user_name || ' granted the ' || role_name || ' role on ' || end_time ||' [' || query_text ||']' as Grants
   from query_history where execution_status = 'SUCCESS'
   and query_type = 'GRANT' and
   query_text ilike '%grant%accountadmin%to%'
   order by end_time desc;
```

```
SELECT
    query_text,
    user_name,
    role_name,
    start_time,
    end_time
  FROM snowflake.account_usage.query_history
    WHERE execution_status = 'SUCCESS'
      AND query_type NOT in ('SELECT')
      AND (query_text ILIKE '%create role%'
          OR query_text ILIKE '%manage grants%'
          OR query_text ILIKE '%create integration%'
          OR query_text ILIKE '%alter integration%'
          OR query_text ILIKE '%create share%'
          OR query_text ILIKE '%create account%'
          OR query_text ILIKE '%monitor usage%'
          OR query_text ILIKE '%ownership%'
          OR query_text ILIKE '%drop table%'
          OR query_text ILIKE '%drop database%'
          OR query_text ILIKE '%create stage%'
          OR query_text ILIKE '%drop stage%'
          OR query_text ILIKE '%alter stage%'
          OR query_text ILIKE '%create user%'
          OR query_text ILIKE '%alter user%'
          OR query_text ILIKE '%drop user%'
          OR query_text ILIKE '%create_network_policy%'
          OR query_text ILIKE '%alter_network_policy%'
          OR query_text ILIKE '%drop_network_policy%'
          OR query_text ILIKE '%copy%'
          )
  ORDER BY end_time desc;
```

Taken from [here](https://community.snowflake.com/s/article/Communication-ID-0108977-Additional-Information)

### External Network Connections from Queries

Each row represents a query made to a procedure or UDF that makes external access requests.

#### via SQL / EXTERNAL_ACCESS_HISTORY table

```
SELECT * FROM SNOWFLAKE.ACCOUNT_USAGE.EXTERNAL_ACCESS_HISTORY;
```

Taken from [here](https://community.snowflake.com/s/article/Communication-ID-0108977-Additional-Information), [here](https://docs.snowflake.com/en/release-notes/2024/8_00#account-usage-new-external-access-history-view)

### View Excessive Cost by Day

#### via SQL / METERING_HISTORY table

```
SELECT 
    DATE_TRUNC('DAY', START_TIME) AS day,
    SUM(CREDITS_USED) AS daily_credits_used
FROM 
    SNOWFLAKE.ACCOUNT_USAGE.METERING_HISTORY
GROUP BY 
    DATE_TRUNC('DAY', START_TIME)
```

### Get objects accessed

Provides some indication of the objects / files modified due to SQL Queries run and how they were run (eg SQL Worksheet)

#### via SQL / ACCESS_HISTORY table
```
select * FROM SNOWFLAKE.ACCOUNT_USAGE.ACCESS_HISTORY;
```

### Get the SQL queries run including unusual queries

Look for any unusual SQL queries which return large volumes of data.

#### via SQL / QUERY_HISTORY table

```
# QUERY_TEXT has the specific query run
select * FROM SNOWFLAKE.ACCOUNT_USAGE.QUERY_HISTORY ORDER BY BYTES_WRITTEN_TO_RESULT DESC;

# SQL Queries that return unusually high data volume
select * FROM SNOWFLAKE.ACCOUNT_USAGE.QUERY_HISTORY WHERE NOT DATABASE_NAME IS NULL ORDER BY BYTES_WRITTEN_TO_RESULT DESC;

# SQL Queries that scans unusually high data volume
select * FROM SNOWFLAKE.ACCOUNT_USAGE.QUERY_HISTORY WHERE NOT DATABASE_NAME IS NULL ORDER BY BYTES_SCANNED DESC;

# SQL Query to detect if attempts were made to copy data into a database e.g. to external s3 bucket
select * FROM SNOWFLAKE.ACCOUNT_USAGE.QUERY_HISTORY WHERE LOWER(QUERY_TEXT) LIKE '%copy into%'
```

Taken from [here](https://www.mitiga.io/blog/tactical-guide-to-threat-hunting-in-snowflake-environments)

### Get login history and sessions

#### via SQL / LOGIN_HISTORY table / SESSIONS table

Search for unusual login attempts e.g. from unusual IPs. 

```
select * FROM SNOWFLAKE.ACCOUNT_USAGE.LOGIN_HISTORY;

# Contains the indication of the app used via CLIENT_ENVIRONMENT column
select * FROM SNOWFLAKE.ACCOUNT_USAGE.SESSIONS;
```

#### via UI

Login as `ACCOUNTADMIN` > Users & Roles > `Last Login`

Login as `ACCOUNTADMIN` > Security > `Sessions`

### List the users

#### via SQL / USERS table

Includes the time when the users were created

```
# Use SQL Worksheet to run this SQL query
select * FROM SNOWFLAKE.ACCOUNT_USAGE.USERS;
```

### List the roles assigned to users

#### via SQL / GRANTS_TO_USERS table

```
# Use SQL Worksheet to run this SQL query
select * FROM SNOWFLAKE.ACCOUNT_USAGE.GRANTS_TO_USERS;
```

## Eradication

## Recovery

### Enable MFA

#### via UI

Login to the Snowflake tenant > Click on Username > My Profile > Multi-Factor Authentication
