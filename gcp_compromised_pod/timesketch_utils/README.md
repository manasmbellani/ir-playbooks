# timesketch_utils

A script to perform various miscellaneous functions for uploading files to timesketch

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

To instead convert to a different 
```
python3 main.py -a modify_timestamp_format -it ~/Downloads/event_history.csv -ot /tmp/event_history_2.csv -tc "Event time" -ntc "Event tim ISO8601" -itf "%Y-%m-%dT%H:%M:%SZ" -otf "%Y-%m-%d %H:%M" -itz "UTC" -otz "Australia/Sydney"
```