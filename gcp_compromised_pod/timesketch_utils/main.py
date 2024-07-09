#!/usr/bin/env python3
import argparse
import csv
import sys

from datetime import datetime

CHOICES = ["modify_timestamp_format", "add_field"]

DESCRIPTION = "Utility to perform various Timesketch operations such as changing time formats"

def convert_timestamp_to_epoch(timestamp, timestamp_format):
  """Convert the timestamp to epoch time
  """
  converted_timestamp = ""

  try:
    converted_timestamp = datetime.strptime(timestamp, timestamp_format).
  except Exception as e:
    print(f"Error converting timestamp: {timestamp} with format: {timestamp_format}. Error: {e.__class__}, {e}")
  return converted_timestamp

def read_csv_file(csv_file):
  with open(csv_file, newline='') as csvfile:
    spamreader = csv.reader(csvfile, delimiter=' ', quotechar='|')
    
  
def main():
  parser = argparse.ArgumentParser(description=DESCRIPTION)
  parser.add_argument("-it", "--input-timeline", description="Path to the input CSV or JSON timeline file to modify", required=True)
  parser.add_argument("-ot", "--output-timeline", description="Path to the output CSV or JSON timeline file", required=True)
  parser.add_argument("-a", "--action", description="Action to perform", choices=CHOICES, required=True)
  parser.add_argument("-tc", "--timestamp-column", description="Timestamp field name (e.g. column name in CSV, field name in JSON file)")
  parser.add_argument("-tf", "--timestamp-format", description="Format of the time in the timestamp field")
  parser.add_argument("-v", "--value", description="Value for the new field")
  args = parser.parse_args()

  if action == "modify_timestamp_format":

  elif action == "":

  

if __name__ == "__main__":
  sys.exit(main())
  
