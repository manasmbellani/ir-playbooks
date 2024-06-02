# Snowflake - Compromised Account

## Containment

## Collection

## Analysis

### Get the SQL queries run

Look for any unusual SQL queries which return large volumes of data.

#### via SQL / QUERY_HISTORY table

```
# QUERY_TEXT has the specific query run
select * FROM SNOWFLAKE.ACCOUNT_USAGE.QUERY_HISTORY ORDER BY BYTES_WRITTEN_TO_RESULT DESC;
```

### Get login history and sessions

#### via SQL / LOGIN_HISTORY table / SESSIONS table

Search for unusual login attempts e.g. from unusual IPs. 

```
select * FROM SNOWFLAKE.ACCOUNT_USAGE.LOGIN_HISTORY;

# Contains the indication of the app used via CLIENT_ENVIRONMENT column
select * FROM SNOWFLAKE.ACCOUNT_USAGE.SESSIONS;
```

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
