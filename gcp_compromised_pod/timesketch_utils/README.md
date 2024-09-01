# timesketch_utils

A script to perform various miscellaneous functions on CSV and JSON files for uploading files to timesketch. 
For JSON input files, the input must be newline delimited JSON and the output will be written as JSONL which is supported by timesketch. For e.g. for newline delimited JSON, use `jq` to pull out individual events only:

```
# pulls out individual events only 
jq -r ".Events[]" $INFILE
```

## Setup

No special `requirements.txt` file required for CSV files, other than default python installed on the OS

For JSON files, additional requirements are involved which are installed inside `virtualenv`:

```
python3 -m virtualenv venv
source venv/bin/activate
python3 -m pip install -r requirements.txt
```

To exit virtualenv:

```
deactivate
```

## Usage

### Adding a new field to CSV or JSON file

To add a new field called `testfield` to a CSV file with value `testvalue` in file `~/Downloads/event_history.csv` and write the rows to output file `/tmp/event_history_2.csv`:

```
python3 main.py -a add_field -it ~/Downloads/event_history.csv -ot /tmp/event_history_2.csv -nf testfield -v testvalue
```

To add a new field called `testfield` to a newline delimited JSON file with value `testvalue` in file `~/Downloads/event_history.json` and write the rows to output file `/tmp/event_history_2.json`:

```
python3 main.py -a add_field -it ~/Downloads/event_history.json -ot /tmp/event_history_2.json -nf testfield -v testvalue
```

### Converting the timestamp to a given format

To add a new field `Event time ISO8601` in input file `~/Downloads/event_history.csv` which converts the timestamp in field `Event time` in format `%Y-%m-%dT%H:%M:%SZ` with `UTC` timezone to `ISO8601` format in `Australia Sydney` timezone and write the results to output file `/tmp/event_history_2.csv`:

```
# For CSV
python3 main.py -a modify_timestamp_format -it ~/Downloads/event_history.csv -ot /tmp/event_history_2.csv -tc "Event time" -ntc "Event time ISO8601" -itf "%Y-%m-%dT%H:%M:%SZ" -otf "iso8601" -itz "UTC" -otz "Australia/Sydney"
 
# For newline delimited JSON
python3 main.py -a modify_timestamp_format -it ~/Downloads/event_history.json -ot /tmp/event_history_2.json -tc "Event time" -ntc "Event time ISO8601" -itf "%Y-%m-%dT%H:%M:%SZ" -otf "iso8601" -itz "UTC" -otz "Australia/Sydney"
```

To instead convert to a different time instead of `is8601` eg to `%Y-%m-%dT%H:%M:%S%z` which is ISO8601 format for timestamp field as described in [Timesketch guide](https://timesketch.org/guides/user/import-from-json-csv/):
```
# For CSV
python3 main.py -a modify_timestamp_format -it ~/Downloads/event_history.csv -ot /tmp/event_history_2.csv -tc "Event time" -ntc "Event time ISO8601" -itf "%Y-%m-%dT%H:%M:%SZ" -otf "%Y-%m-%dT%H:%M:%S%z" -itz "UTC" -otz "Australia/Sydney"

# For newline delimited JSON
python3 main.py -a modify_timestamp_format -it ~/Downloads/event_history.json -ot /tmp/event_history_2.json -tc "Event time" -ntc "Event time ISO8601" -itf "%Y-%m-%dT%H:%M:%SZ" -otf "%Y-%m-%dT%H:%M:%S%z" -itz "UTC" -otz "Australia/Sydney"
```


### Example of preparing a CSV or JSON file for timesketch

Given a CSV file path `$IN_FILE` , we can run the following commands to add all necessary fields with generic values and standard eg `message`, `datetime`, `timestamp_desc` column without overwriting initial input file:

```
IN_FILE=...<add-filename-here>...
OUT_FILE=...<output-file>...
FILE_EXTN=...<csv/json>...
IN_TIME_COLUMN=...<input timestamp column>...
IN_TIME_FORMAT=...<input timestamp format>...
IN_TIME_ZONE=...<input timezone>...
LOG_TYPE=...<type of log eg cloudtrail event history>...

python3 main.py -a modify_timestamp_format -it $IN_FILE -ot /tmp/event_history_2.$FILE_EXTN -tc "$IN_TIME_COLUMN" -ntc "datetime_timesketch" -itf "$IN_TIME_FORMAT" -otf "%Y-%m-%dT%H:%M:%S%z" -itz "$IN_TIME_ZONE" -otz "UTC"
python3 main.py -a add_field -it /tmp/event_history_2.$FILE_EXTN -ot /tmp/event_history_3.$FILE_EXTN -nf "message_timesketch" -v "$LOG_TYPE"
python3 main.py -a add_field -it /tmp/event_history_3.$FILE_EXTN -ot "$OUT_FILE" -nf "timestamp_desc_timesketch" -v "$LOG_TYPE timestamp"
rm /tmp/event_history_*.csv 2>/dev/null
```