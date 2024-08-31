#!/usr/bin/env python3
import argparse
import csv
import os
import shutil
import sys
import time

import tempfile
from datetime import datetime as dt

CHOICES = ["modify_timestamp_format", "add_field"]

DESCRIPTION = "Utility to perform various Timesketch operations such as changing time formats"

"""After how many rows to flush?"""
FLUSH_ROWS_COUNT = 100

def convert_timestamp_format(timestamp, in_timestamp_format, out_timestamp_format, in_timezone, out_timezone, row_id):
  """Convert the timestamp to epoch time
  """
  converted_timestamp = ""

  try:
    # Set timezone
    

    if out_timestamp_format == 'iso8601':
      os.environ['TZ'] = in_timezone
      time.tzset() 
      converted_timestamp = dt.strptime(timestamp, in_timestamp_format).timestamp()
      os.environ['TZ'] = out_timezone
      time.tzset() 
      converted_timestamp = dt.fromtimestamp(converted_timestamp).isoformat()
    else:
      os.environ['TZ'] = in_timezone
      time.tzset() 
      converted_timestamp = dt.strptime(timestamp, in_timestamp_format).timestamp()
      os.environ['TZ'] = out_timezone
      time.tzset()
      converted_timestamp = dt.fromtimestamp(converted_timestamp).strftime(out_timestamp_format)

  except Exception as e:
    print(f"Error converting timestamp: {timestamp} with format: {in_timestamp_format} on row_id: {row_id}. Error: {e.__class__}, {e}")
  return converted_timestamp


def get_data_rows(csv_file, header, delimiter=","):
  """Read rows from the CSV file and convert it to data"""
  with open(csv_file, newline='') as csvfile:
    csv_reader = csv.reader(csvfile, delimiter=delimiter)
    for i, row in enumerate(csv_reader):
      if i != 0:
        data = {}
        for k, h in enumerate(header):
          try:
            data[h] = row[k]
          except:
            pass
        yield data


def get_header_row(csv_file, delimiter=","):
  """Gets the header row from the CSV file"""
  header = []
  with open(csv_file, newline='') as csvfile:
    csv_reader = csv.reader(csvfile, delimiter=delimiter)
    for row in csv_reader:
      header = row
      print(row)
      break
  return header


def main():
  parser = argparse.ArgumentParser(description=DESCRIPTION)
  parser.add_argument("-it", "--input-timeline", help="Path to the input CSV timeline file to modify", required=True)
  parser.add_argument("-ot", "--output-timeline", help="Path to the output CSV timeline file. If none specified, data is written back on to the same CSV file")
  parser.add_argument("-a", "--action", help="Action to perform", choices=CHOICES, required=True)
  parser.add_argument("-tc", "--timestamp-column", help="Timestamp field name (e.g. column name in CSV, field name in JSON file)")
  parser.add_argument("-ntc", "--new-timestamp-column", help="New Timestamp field name (e.g. column name in CSV, field name in JSON file)")
  parser.add_argument("-itf", "--in-timestamp-format", help="Format of the time in the timestamp field")
  parser.add_argument("-otf", "--out-timestamp-format", help="Format of the new timestamp", default="iso8601")
  parser.add_argument("-v", "--value", help="Value for the new field")
  parser.add_argument("-nf", "--new-field", help="Name for the new field")
  parser.add_argument("-d", "--delimiter", default=",", help="Delimiter")
  parser.add_argument("-q", "--quote", default='"', help="Quote char")
  parser.add_argument("-itz", "--in-timezone", default="Australia/Sydney", help="Input Timezone")
  parser.add_argument("-otz", "--out-timezone", default="Australia/Sydney", help="Output Timezone")
  
  args = parser.parse_args()

  print(f'[*] Checking if input timeline file: {args.input_timeline} exists...')
  if not os.path.isfile(args.input_timeline):
    print(f"[-] Input timeline file: {args.input_timeline} must exist")
    return 1

  print("[*] Check input args for various actions...")
  if args.action == "modify_timestamp_format":
    if not (args.timestamp_column and args.new_timestamp_column and args.in_timestamp_format and args.out_timestamp_format):
      print(f'[-] Not all required fields provided for action: {args.action}. See README.md for more details')
      return 1
  elif args.action == "add_field":
    if not (args.value and args.new_field):
      print(f'[-] Not all required fields provided for action: {args.action}. See README.md for more details')
      return 1
  else:
    print(f"[-] Unknown action: {args.action}")
    return 1

  header = get_header_row(args.input_timeline)

  print("[*] Reviewing headers...")
  if args.action == "modify_timestamp_format":
    header.append(args.new_timestamp_column)
  elif args.action == "add_field":
    header.append(args.new_field)
  else:
    print(f"[-] Unknown action: {args.action}")
    return 1

  print(f"[*] Processing input timeline: {args.input_timeline} and writing content to ")
  tmp_file = tempfile.mktemp()
  with open(tmp_file, "w+") as of:
    ofw = csv.writer(of, delimiter=args.delimiter, quotechar=args.quote, quoting=csv.QUOTE_MINIMAL)

    print(f"[*] Adding headers to output file...")
    ofw.writerow(header)

    print(f"[*] Processing rows in input file: {args.input_timeline}...")
    for i, data_row in enumerate(get_data_rows(args.input_timeline, header, delimiter=args.delimiter)):
      
      if args.action == "modify_timestamp_format":
        new_timestamp = convert_timestamp_format(data_row[args.timestamp_column], args.in_timestamp_format, 
                                                args.out_timestamp_format, args.in_timezone, args.out_timezone, i)
        data_row[args.new_timestamp_column] = new_timestamp

      elif args.action == "add_field":
        data_row[args.new_field] = args.value
      
      else:
        print(f"[-] Unknown action: {args.action}")
        return 1
      
      print(f"[*] Writing row: {i} to outfile: {tmp_file}...")
      ofw.writerow( data_row[h] for h in header )

      if i % FLUSH_ROWS_COUNT == 0:
        of.flush()

  if not args.output_timeline:
    print(f"[*] Setting output file: {args.input_timeline}...")
    args.output_timeline = args.input_timeline

  print(f"[*] Moving file: {tmp_file} to outfile: {args.output_timeline}...")
  shutil.move(tmp_file, args.output_timeline)

if __name__ == "__main__":
  sys.exit(main())
  