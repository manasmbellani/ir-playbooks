# Snowflake - Compromised Account

## Containment

## Collection

## Analysis

### Get login history

#### via SQL / LOGIN_HISTORY table

Search for unusual login attempts e.g. from unusual IPs. 

```
select * FROM SNOWFLAKE.ACCOUNT_USAGE.LOGIN_HISTORY;
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
