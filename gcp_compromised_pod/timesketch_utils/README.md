# timesketch_utils

A script to perform various miscellaneous functions for uploading files to timesketch

## Setup

No special `requirements.txt` file required, other than default python installed on the OS

## Usage

### Adding a new field to CSV file

To add a new field called `testfield` to a CSV file with value `testvalue` in file `~/Downloads/event_history.csv` and write the rows to output file `/tmp/event_history_2.csv`:

```
python3 main.py -a add_field -it ~/Downloads/event_history.csv -ot /tmp/event_history_2.csv -nf testfield -v testvalue
```

### Converting the timestamp to a given format

To add a new field `Event time ISO8601` in input file `~/Downloads/event_history.csv` which converts the timestamp in field `Event time` in format `%Y-%m-%dT%H:%M:%SZ` with `UTC` timezone to `ISO8601` format in `Australia Sydney` timezone and write the results to output file `/tmp/event_history_2.csv`:

```
python3 main.py -a modify_timestamp_format -it ~/Downloads/event_history.csv -ot /tmp/event_history_2.csv -tc "Event time" -ntc "Event time ISO8601" -itf "%Y-%m-%dT%H:%M:%SZ" -otf "iso8601" -itz "UTC" -otz "Australia/Sydney"
```

To instead convert to a different time instead of `is8601` eg to `%Y-%m-%dT%H:%M:%S%z` which is ISO8601 format for timestamp field as described in [Timesketch guide](https://timesketch.org/guides/user/import-from-json-csv/):
```
python3 main.py -a modify_timestamp_format -it ~/Downloads/event_history.csv -ot /tmp/event_history_2.csv -tc "Event time" -ntc "Event time ISO8601" -itf "%Y-%m-%dT%H:%M:%SZ" -otf "%Y-%m-%dT%H:%M:%S%z" -itz "UTC" -otz "Australia/Sydney"
```

### Example of preparing a CSV file for timesketch

Given a CSV file path `$IN_FILE` , we can run the following commands to add all necessary fields with generic values and standard eg `message`, `datetime`, `timestamp_desc` column without overwriting initial input file:

```
IN_FILE=...<add-filename-here>...
OUT_FILE=...<output-file>...
IN_TIME_COLUMN=...<input timestamp column>...
IN_TIME_FORMAT=...<input timestamp format>...
IN_TIME_ZONE=...<input timezone>...
LOG_TYPE=...<type of log eg cloudtrail event history>...

python3 main.py -a modify_timestamp_format -it $IN_FILE -ot /tmp/event_history_2.csv -tc "Event time" -ntc "datetime_timesketch" -itf "%Y-%m-%dT%H:%M:%SZ" -otf "%Y-%m-%dT%H:%M:%S%z" -itz "$IN_TIME_ZONE" -otz "Australia/Sydney"
python3 main.py -a add_field -it /tmp/event_history_2.csv -ot /tmp/event_history_3.csv -nf "message_timesketch" -v "$LOG_TYPE"
python3 main.py -a add_field -it /tmp/event_history_3.csv -ot "$OUT_FILE" -nf "timestamp_desc_timesketch" -v "$LOG_TYPE timestamp"
rm /tmp/event_history_*.csv 2>/dev/null
```