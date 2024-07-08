#!/usr/bin/env python3
import argparse
import sys

CHOICES = ["modify_timestamp_format", "add_field", ]

DESCRIPTION = "Utility to perform various Timesketch operations such as changing time formats"

def main():
  parser = argparse.ArgumentParser(description=DESCRIPTION)
  parser.add_argument("-it", "--input-timeline", description="Path to the input CSV or JSON timeline file to modify", required=True)
  parser.add_argument("-ot", "--output-timeline", description="Path to the output CSV or JSON timeline file", required=True)
  parser.add_argument("-a", "--action", description="Action to perform", choices=CHOICES, required=True)
  parser.add_argument("-tc", "--timestamp-column", description="Timestamp field name (e.g. column name in CSV, field name in JSON file)")
  parser.add_argument("-tf", "--timestamp-format", description="Format of the time in the timestamp field")
  args = parser.parse_args()

  if action == "":
    

if __name__ == "__main__":
  sys.exit(main())
  
