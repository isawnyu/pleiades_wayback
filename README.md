Consults datasetter pleiades dataset for places modified within a certain time frame, then checks those pleiades URIs live on the web to make sure the place hasn't been withdrawn or deleted, then checks the internet archive to see if their snapshot of that page has been updated since the last pleiades revision and, if not, asks internet archive to grab a new snapshot.

Run it like:

`python waybackit.py`

That will run silently. To get some feedback, try:

`python waybackit.py -v`

By default, the script looks back over the past week. If you want to change that horizon:

`python waybackit.py -s 2022-07-20`

There are more options:

```
python waybackit.py -h
                    [-f FROM] [-u USERAGENT]

Ensure recently added/changed Pleiades places are archived

options:
  -h, --help            show this help message and exit
  -l LOGLEVEL, --loglevel LOGLEVEL
                        desired logging level (case-insensitive string: DEBUG, INFO,
                        WARNING, or ERROR (default: NOTSET)
  -v, --verbose         verbose output (logging level == INFO) (default: False)
  -w, --veryverbose     very verbose output (logging level == DEBUG) (default: False)
  -s START, --start START
                        date when to start archiving (default: one week ago)
  -e END, --end END     date when to end archiving (default: today)
  -d DATASETTER, --datasetter DATASETTER
                        path to location of datasetter cache (default:
                        ~/Documents/files/D/datasetter/data/cache)
  -f FROM, --from FROM  email address for http request headers (default:
                        pleiades.admin@nyu.edu)
  -u USERAGENT, --useragent USERAGENT
                        user agent for http request headers (default:
                        PleiadesGazetteer/today (+https://pleiades.stoa.org))
```
