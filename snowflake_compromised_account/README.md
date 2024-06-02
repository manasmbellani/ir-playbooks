# Snowflake - Compromised Account

## Containment

### Disable user 

#### via UI

Login as `ACCOUNTADMIN` > Users & Roles > Select the user > `Disable User`

## Collection

## Analysis

### Get objects accessed

Provides some indication of the objects / files modified due to SQL Queries run and how they were run (eg SQL Worksheet)

#### via SQL / ACCESS_HISTORY
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
