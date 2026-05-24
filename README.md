# deno-kv-admin

This is a set of web service endpoints to support  [kvadmin.py](https://www.pg4e.com/code/kvadmin.py) in
the [Deno](https://docs.deno.com/deploy/kv/manual/) module
of PostgreSQL for Everybody (www.pg4e.com)

It is designed to be installed in a developer account on [Deno Deploy](https://dash.deno.com).

# Installation Instructions

You will need a github account to use Deno Deploy. To create or access your
Deno Deploy dashboard, go to:

https://dash.deno.com/

At the `Overview` section, create a `New Playground`.  Copy the contents of this file into the new
Deno Playground application:

https://github.com/csev/deno-kv-admin/blob/main/main.ts

Paste it into the code panel of your Deno playground.  Before you `Save and Deploy`,
scroll to the bottom and delete the `Deno.cron()` method so your data does not get wiped out
every day.  Or you could change the CRON string to something like `"0 0 1 * *"` to clear your
data once per month.

Also note the `checkToken()` code near the end.  The autograder will ask you to change the token
to a particular value in order to submit your assignments for evaluation and credit.

Once you have removed the CRON entry, you can `Save and Deploy`. It can take 30 seconds to get your code
deployed to the Deno Deploy cloud.  Check the logs to make sure you did not introduce a syntax error.

Once it is up you will get a URL to access your application like:

https://comfortable-starling-12.deno.dev

If you access this URL, you will (correctly) get a `404 Not Found`.  

# Initial testing

You can test the application by adding `/dump` to the end of the URL as follows (make sure to change the host
name to match your Deno instance):

https://comfortable-starling-12.deno.dev/dump

You should get an output that looks as follows:

    {
      "method": "GET",
      "url": "https://comfortable-starling-12.deno.dev/dump",
      "path": "/dump",
      "headers": {
        "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "accept-encoding": "gzip, deflate, br, zstd",
        "accept-language": "en-US,en;q=0.5",
        "host": "comfortable-starling-12.deno.dev",
        "priority": "u=0, i",
        "sec-fetch-dest": "document",
        "sec-fetch-mode": "navigate",
        "sec-fetch-site": "none",
        "sec-fetch-user": "?1",
        "te": "trailers",
        "traceparent": "00-ac9e975daac67625527f3a3da6b1dfdd-5274315352c7753c-01",
        "upgrade-insecure-requests": "1",
        "user-agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:140.0) Gecko/20100101 Firefox/140.0"
      },
      "query": {},
      "body": ""
  }

The `/dump` url does not require a token, but the URLs that access Deno KV require a token.
You can test to see if your token works by going to the following URL (make sure to change the host
name and token to match your Deno instance):

https://comfortable-starling-12.deno.dev/kv/list/books?token=123

If it works and you have no books the output will look as follows:

    {
      "records": [],
      "cursor": ""
    }

Which means "no records exist with prefix of books".  If your token is wrong you should get a
`401` response code and a message of

    Missing or invalid token

At this point you have verified that your KVAdmin web service end points are up and running.

# Unit tests

If you clone this repository and have [Deno](https://deno.com/) installed, you can run the automated tests for query-token verification (`dn_token.ts`). From the project root:

    deno task test

That runs `deno test --allow-env .`, which picks up `dn_token_test.ts` and checks valid tokens, expiry, bad signatures, and related failure cases. You need network access the first time so Deno can cache dependencies (for example `jsr:@std/assert`). For starting the HTTP server and manual checks with `curl`, see [Running locally](#running-locally-for-testing-and-development) below.

# Environment variables

Optional settings read at startup (for example in [Deno Deploy](https://dash.deno.com/) under your project’s **Settings → Environment Variables**, or in your shell before `deno run`):

| Variable | Purpose |
| -------- | ------- |
| `KV_TOKEN_SECRET` | Shared secret used to verify signed `?token=` values (must match the secret your PHP `dn_maketoken` uses). If unset, the app defaults to `'42'`. |
| `KV_ADMIN_DEBUG` | Set to `1`, `true`, or `yes` (case-insensitive) to print extra `console.debug` lines for token checks and startup. If unset or any other value, those debug messages are suppressed. |

# Using kvadmin.py

We have built a simple Python client for this server that allows you to execute simple DENO KV commands
like `set`, `get`, `list`, or `delete` from the command line on your computer.  This is a very simplistic
equivalent of the `psql` command line client for PostgreSQL.

Download the following files to a folder on your computer.  If you you have been taking the PostgreSql for
Everybody course you may already have a folder and a `hidden.py` with your secrets.

https://www.pg4e.com/code/kvadmin.py

https://www.pg4e.com/code/hidden-dist.py

If you don't already have a `hidden.py`, copy `hidden-dist.py` to `hidden.py` and edit the `deno()` function
to set your host name and token value:

    def denokv():
        return { 'token' : '99123',
             "url": "https://comfortable-starling-12.deno.dev" }

Then navigate into the folder using terminal, command line, or a shell and run `python kvadmin.py` or 
`python3 kvadmin.py`.  You might see the following:

    python kvadmin.py 
    Verifying connection to https://comfortable-starling-12.deno.dev/dump
    
    Unable to communicate with Deno.  Sometimes it takes a while to start the
    the Deno instance after it has been idle.  You might want to access the url
    below in a browser, wait 30 seconds, and then restart kvadmin.
    
    https://comfortable-starling-12.deno.dev/dump

This checks if your `denokv()` values are correct and being read.  Sometimes if your Deno application 
has been idle for a while it can take up to 30 seconds to cold start your application.  If you pay
for your Deno deployment or if the application is not idle - startup is very quick.

After about 30 seconds, you should start `kvadmin.py` and get the `Enter Command:` prompt. The following
are the `kvadmin.py` commands and a few sample commands:

    $ python kvadmin.py 
    Verifying connection to https://kv-admin-api.pg4e.com/dump

    Enter Command: help
      quit
      samples
      set /books/Hamlet
      get /books/Hamlet
      list /books
      delete /books/Hamlet
      delete_prefix /books

    Enter command: samples
    
    {"author": "Bill", "title": "Hamlet", "isbn": "42", "lang": "ang"}
    
    Enter command: set /books/Hamlet 
    Enter json (finish with a blank line:
    {"author": "Bill", "title": "Hamlet", "isbn": "42", "lang": "ang"}
    
    https://kv-admin-api.pg4e.com/kv/set/books/Hamlet?token=42
    {
      "ok": true,
      "versionstamp": "010000000591ef100000"
    }
    
    Enter command: list /books
    https://kv-admin-api.pg4e.com/kv/list/books?token=42
    200
    {
        "records": [
            {
                "key": [
                    "books",
                    "Hamlet"
                ],
                "value": {
                    "author": "Bill",
                    "title": "Hamlet",
                    "isbn": "42",
                    "lang": "ang"
                },
                "versionstamp": "010000000591ef100000"
            }
        ],
        "cursor": ""
    }
    
    Enter command: quit

If the auto grader tells you to change your `token` value, make sure to change it on your
Deploy Playground instance and do a `Save and Deploy` and then also change your `hidden.py` so
that your `kvadmin.py` continues to work.

# Running locally for testing and development

You can run the same Hono app and Deno KV API on your machine without Deno Deploy. This is useful for development, debugging, and exercising the endpoints before you paste `main.ts` into a Playground.

## Prerequisites

- [Deno](https://deno.com/) 2.x (KV and cron unstable features are enabled via `deno.json`)
- A clone of this repository

## Start the server

From the project root:

    deno run -A main.ts

The server listens on **http://127.0.0.1:8000/** (shown in the console as `http://0.0.0.0:8000/`). The `-A` flag grants permissions needed for Deno KV and the HTTP listener; `deno.json` already enables the `kv` and `cron` unstable features.

Optional environment variables (same as [Environment variables](#environment-variables) above):

    KV_TOKEN_SECRET=42 KV_ADMIN_DEBUG=1 deno run -A main.ts

`KV_ADMIN_DEBUG=1` prints extra lines when tokens are checked.

### Disable the daily CRON job locally

`main.ts` includes a `Deno.cron()` handler that deletes **all** KV data once per day (midnight UTC, `0 0 * * *`). For local work, comment out or remove that block (same advice as for Deno Deploy in [Installation Instructions](#installation-instructions)), or change the schedule to something rare (for example `0 0 1 * *` for monthly). Otherwise your local database will be wiped daily.

## Manual HTTP testing

These checks mirror [Initial testing](#initial-testing) on Deno Deploy, but use `127.0.0.1`.

**`/dump` (no token required)**

    curl -s http://127.0.0.1:8000/dump

You should get JSON with `method`, `url`, `path`, `headers`, `query`, and `body`.

**`/kv/list/...` (signed `?token=` required)**

KV routes expect a signed token in the query string (same format as PHP `dn_maketoken`: `YYMM_user` + `:` + first 6 hex chars of `md5(payload:secret)`). With the default secret `42`, a valid example for 2026 is:

    curl -s "http://127.0.0.1:8000/kv/list/books?token=2606_test:39dc06"

An empty prefix returns `{"records":[],"cursor":""}`. A bad or missing token returns HTTP `401` with `Missing or invalid token`.

To build a token for your own payload and secret:

    deno eval "import { createHash } from 'node:crypto'; const p='2606_myuser'; const s='42'; const sig=createHash('md5').update(p+':'+s).digest('hex').slice(0,6); console.log(p+':'+sig);"

Use a `YYMM` prefix that has not expired (valid through 00:00 UTC on the first day of the following month). Set `KV_TOKEN_SECRET` when starting the server if you use a non-default secret.

**Set and list a record**

    curl -s -X POST "http://127.0.0.1:8000/kv/set/books/Hamlet?token=2606_test:39dc06" \
      -H "Content-Type: application/json" \
      -d '{"author":"Bill","title":"Hamlet"}'

    curl -s "http://127.0.0.1:8000/kv/list/books?token=2606_test:39dc06"

## Automated unit tests

From the project root:

    deno task test

See [Unit tests](#unit-tests) for what is covered. No server needs to be running for these tests.

## Using kvadmin.py against localhost

In `hidden.py`, point `url` at your local server:

    def denokv():
        return { 'token' : '2606_test:39dc06',
             "url": "http://127.0.0.1:8000" }

Use a token signed with the same secret as the running server (`KV_TOKEN_SECRET` or default `42`). Then run `python kvadmin.py` or `python3 kvadmin.py` as described in [Using kvadmin.py](#using-kvadminpy).

