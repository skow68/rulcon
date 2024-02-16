import csv

with open('./csv/local2.csv', 'r') as csv_file:
    reader = csv.reader(csv_file)
    input_rules = [row for row in reader]
print(input_rules)