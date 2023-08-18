# Simple event boiling point scoring example w/ example of web tracking use case

The purpose of this code is to show a basic example of a boiling point trigger. 

What are these types of triggers good for?
* Extremly fast when paired with Redis
* Meant to work best with very large event samples
* Use cases in virtually any industry
* Lightweight: used best in-line where ML is too costly, slow, or heavy

Testing it out

Ubuntu:

    $ sudo apt -y install lua-cjson lua-md5 luarocks libhiredis-dev
    $ sudo luarocks install lua-hiredis




