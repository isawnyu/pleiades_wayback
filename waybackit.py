#
# This file is part of waybackit
# by Tom Elliott for the Institute for the Study of the Ancient World
# and the Pleiades gazetteer of ancient places
# (c) Copyright 2022 by New York University
# Licensed under the AGPL-3.0; see LICENSE.txt file.
#

"""
Ensure recently added/changed Pleiades places are archived
"""

import re
from airtight.cli import configure_commandline
from datasetter.pleiades import PleiadesDataset
from datetime import date, timedelta
import logging
from pathlib import Path
from pprint import pprint
import re
import requests
from requests.adapters import HTTPAdapter
from requests.exceptions import RetryError, TooManyRedirects, ConnectionError
from time import sleep
from urllib3.util.retry import Retry

ITERATIVE_DELAY_FACTOR = 3
MAX_TOTAL_FAILURES = 13
INTERSTITIAL_DELAY = 5

ARCHIVE_MAX_REDIRECTS = 6
ARCHIVE_MAX_RETRIES = 3
ARCHIVE_BACKOFF = 23
ARCHIVE_OUTER_RETRIES = 23
ARCHIVE_OUTER_BACKOFF = 467
ARCHIVE_RETRY_ERRORS = [429, 500, 502, 503, 504, 520, 523]
ARCHIVE_CHECK_URI = "https://web.archive.org/web/"
ARCHIVE_SAVE_URI = "https://web.archive.org/save/"

PLEIADES_MAX_REDIRECTS = 0
PLEIADES_MAX_RETRIES = 2
PLEIADES_BACKOFF = 1
PLEIADES_RETRY_ERRORS = []

logger = logging.getLogger(__name__)
today = date.today()
last_week = today - timedelta(days=7)

pleiades_session = None
archive_session = None

DEFAULT_LOG_LEVEL = logging.WARNING
OPTIONAL_ARGUMENTS = [
    [
        "-l",
        "--loglevel",
        "NOTSET",
        "desired logging level ("
        + "case-insensitive string: DEBUG, INFO, WARNING, or ERROR",
        False,
    ],
    ["-v", "--verbose", False, "verbose output (logging level == INFO)", False],
    [
        "-w",
        "--veryverbose",
        False,
        "very verbose output (logging level == DEBUG)",
        False,
    ],
    ["-s", "--start", last_week.isoformat(), "date when to start archiving", False],
    ["-e", "--end", today.isoformat(), "date when to end archiving", False],
    [
        "-d",
        "--datasetter",
        str(
            Path.home() / "Documents" / "files" / "D" / "datasetter" / "data" / "cache"
        ),
        "path to location of datasetter cache",
        False,
    ],
    [
        "-f",
        "--from",
        "pleiades.admin@nyu.edu",
        "email address for http request headers",
        False,
    ],
    [
        "-u",
        "--useragent",
        f"PleiadesGazetteerWaybackBot/0.3 (+https://pleiades.stoa.org)",
        "user agent for http request headers",
        False,
    ],
    ["-c", "--validate", False, "validate pleiades URL before archiving", False],
    ["-p", "--pause", 0.0, "pause float seconds between requests", False],
]
POSITIONAL_ARGUMENTS = [
    # each row is a list with 3 elements: name, type, help
]


class TotalFailure(Exception):
    def __init__(self, msg: str, uri: str):
        self.uri = uri
        super().__init__(msg)


def status(msg: str, **kwargs):
    if kwargs["veryverbose"] or kwargs["verbose"]:
        print(msg)


def valid(pid):
    global pleiades_session
    url = f"https://pleiades.stoa.org/places/{pid}"
    logger.debug(f"Validating Pleiades URI {url}...")
    r = pleiades_session.head(url, allow_redirects=False)
    if not r.status_code == 200:
        logger.error(f"Invalid Pleiades URI {url}. HTTP status: {r.status_code}")
        return False
    else:
        logger.debug("... VALID")
        return True


def archive(pid, since, pdata, **kwargs):
    pleiades_uri = f"https://pleiades.stoa.org/places/{pid}"
    status(
        "\n"
        + "=" * 78
        + "\n"
        + f"Checking archive status since {since} of {pleiades_uri} and its subordinate components.",
        **kwargs,
    )
    status(
        "-" * 78 + "\n" f"Verifying archive status since {since} of {pleiades_uri}.",
        **kwargs,
    )
    result = _archive_this(pleiades_uri, since, **kwargs)
    sleep(INTERSTITIAL_DELAY)
    juri = pleiades_uri + "/json"
    status(
        "-" * 78 + "\n" f"Verifying archive status since {since} of {juri}.", **kwargs
    )
    result_j = _archive_this(pleiades_uri + "/json", since, **kwargs)
    result_c = archive_children(since, pdata, **kwargs)
    return result | result_j | result_c


def archive_children(since, pdata, **kwargs):
    result = False
    for k in ["names", "locations", "connections"]:
        for child in pdata[k]:
            uri = child["uri"]
            slug = "/".join([p.strip() for p in uri.split("/") if p.strip()][-2:])
            latest = sorted(child["history"], key=lambda h: h["modified"])[-1][
                "modified"
            ].split("T")[0]
            if latest >= since:
                status(
                    "-" * 78 + "\n" f"Verifying archive status since {since} of {uri}.",
                    **kwargs,
                )
                sleep(INTERSTITIAL_DELAY)
                success = False
                try:
                    success = _archive_this(uri, since, **kwargs)
                except (TooManyRedirects, RetryError):
                    pass
                result = result | success
    return result


def _archive_this(uri, since, **kwargs):
    global archive_session

    # see if the URI is already in the archive
    check_uri = ARCHIVE_CHECK_URI + uri
    redirect_failures = 0
    redirect_backoff = 0
    while True:
        try:
            r = archive_session.head(check_uri, allow_redirects=True)
        except (RetryError, TooManyRedirects, ConnectionError):
            redirect_failures += 1
            if redirect_failures > max(round(ARCHIVE_MAX_RETRIES / 2), 2):
                raise TotalFailure(
                    f"Too many redirects, retries, and/or connection errors ({redirect_failures}) "
                    f"while trying {check_uri}.",
                    check_uri,
                )
            redirect_backoff = ARCHIVE_OUTER_BACKOFF * redirect_failures
            sleep_time = max(redirect_backoff, kwargs["pause"])
            status(
                f"   - Wayback check attempt failed after {ARCHIVE_MAX_RETRIES} retries. Sleeping for {sleep_time} seconds before next attempt...",
                **kwargs,
            )
            sleep(sleep_time)
        else:
            break
    if r.status_code != 200:
        r.raise_for_status
    rx = re.compile(rf"^{ARCHIVE_CHECK_URI}(\d+)/{uri}/?.*$")
    m = rx.match(r.url)
    if m is None:
        # No it is not
        status(f"   - Resource not yet archived.", **kwargs)
    else:
        status(f"   - A version of this resource is already in the archive.", **kwargs)

    # if in archive, see if it is up-to-date
    try:
        snapshot = int(m.group(1)[:8])
    except AttributeError:
        archive_it = True
    else:
        try:
            archive_it = snapshot < int(since.replace("-", ""))
        except TypeError:
            archive_it = snapshot < int(since)
        if archive_it:
            status(
                f"   - Resource copy in archive is out-of-date.",
                **kwargs,
            )
    if archive_it:
        status(
            f"   - Attempting to archive new version.",
            **kwargs,
        )
        save_uri = ARCHIVE_SAVE_URI + uri
        save_failures = 0
        save_backoff = max(0, redirect_backoff)
        sleep_time = max(save_backoff, kwargs["pause"])
        if sleep_time > 0:
            status(
                f"   - Sleeping for {sleep_time} seconds before sending save request to the archive api.",
                **kwargs,
            )
            sleep(sleep_time)
        while True:
            try:
                r = archive_session.head(save_uri, allow_redirects=True)
            except (RetryError, TooManyRedirects, ConnectionError) as e:
                save_failures += 1
                if save_failures > ARCHIVE_MAX_RETRIES:
                    raise TotalFailure(
                        f"Too many redirects, retries, and/or connection errors ({save_failures}) "
                        f"while trying {save_uri}.",
                        save_uri,
                    )
                save_backoff = ARCHIVE_OUTER_RETRIES * save_failures
                sleep_time = max(save_backoff, kwargs["pause"])
                if sleep_time > 0:
                    status(
                        f"   - Wayback save attempt failed after {ARCHIVE_MAX_RETRIES} retries. Sleeping for {sleep_time} seconds before next attempt...",
                        **kwargs,
                    )
                    sleep(sleep_time)
            else:
                break
        if r.status_code != 200:
            r.raise_for_status
        status(f"   - Successfully saved up-to-date snapshot in the archive.", **kwargs)
        return True
    status(f"   - There is already an up-to-date snapshot in the archive.", **kwargs)
    return False


def set_session_defaults(**kwargs):
    global archive_session
    global pleiades_session

    headers = {"from": kwargs["from"], "user-agent": kwargs["useragent"]}

    s = requests.Session()
    s.headers.update(headers)
    s.max_redirects = ARCHIVE_MAX_REDIRECTS
    retries = Retry(
        total=ARCHIVE_MAX_RETRIES,
        backoff_factor=ARCHIVE_BACKOFF,
        respect_retry_after_header=True,
        status_forcelist=ARCHIVE_RETRY_ERRORS,
        backoff_jitter=ARCHIVE_BACKOFF / 2,
    )
    s.mount("https://", HTTPAdapter(max_retries=retries))
    s.mount("http://", HTTPAdapter(max_retries=retries))
    archive_session = s

    s = requests.Session()
    s.headers.update(headers)
    s.max_redirects = PLEIADES_MAX_REDIRECTS
    retries = Retry(
        total=PLEIADES_MAX_RETRIES,
        backoff_factor=PLEIADES_BACKOFF,
        respect_retry_after_header=True,
        status_forcelist=PLEIADES_RETRY_ERRORS,
    )
    s.mount("https://", HTTPAdapter(max_retries=retries))
    s.mount("http://", HTTPAdapter(max_retries=retries))
    pleiades_session = s


def main(**kwargs):
    """
    main function
    """
    pprint(kwargs, indent=4)
    set_session_defaults(**kwargs)

    status(
        f"Verifying archival status of all changes between {kwargs['start']} and {kwargs['end']} (inclusive)",
        **kwargs,
    )
    where = Path(kwargs["datasetter"]).expanduser().resolve()
    status(f"Using datasetter cache at {where}", **kwargs)
    pd = PleiadesDataset(cache_root=where)
    activity = pd.catalog.get_index("activity")
    act_d2p = activity.index
    # pprint(act_d2p, indent=4)
    pids = dict()  # key => pid; value => date
    keys = [k for k in act_d2p.keys() if k >= kwargs["start"] and k <= kwargs["end"]]
    for k in keys:
        for pid in act_d2p[k]:
            pids[pid] = k
    pprint(pids, indent=4)
    archived_pids = list()
    attempted_pids = list()
    skipped_uris = list()
    total_failures = 0
    pid_list = sorted([(pid, when) for pid, when in pids.items()], key=lambda x: x[1])
    try:
        for pid, when in pid_list:
            # status(f"{pid}: checking {when}", **kwargs)
            if valid(pid) or not kwargs["validate"]:
                attempted_pids.append(pid)
                if kwargs["validate"]:
                    status(f"{pid}: valid", **kwargs)
                try:
                    if archive(pid, when, pd.get(pid)[0], **kwargs):
                        archived_pids.append(pid)
                except TotalFailure as err:
                    logger.error(str(err))
                    skipped_uris.append(err.uri)
                    total_failures += 1
                    if total_failures > MAX_TOTAL_FAILURES:
                        logger.fatal(
                            f"\n>>>>> Too many total failures ({total_failures}). Quitting.",
                        )
                        break
                    sleep_time = ARCHIVE_OUTER_BACKOFF * (
                        total_failures / len(attempted_pids) + 1.0
                    )
                    status(
                        f"   - Sleeping for {sleep_time} seconds in hopes things get better.",
                        **kwargs,
                    )
                    sleep(sleep_time)
                    continue
                sleep_time = ITERATIVE_DELAY_FACTOR + ITERATIVE_DELAY_FACTOR * (
                    total_failures / len(attempted_pids)
                )
                status(
                    f"\nSleeping for {sleep_time} before processing next place.",
                    **kwargs,
                )
                sleep(sleep_time)
            elif kwargs["validate"]:
                logger.error(f"{pid}: Invalid")
    except KeyboardInterrupt:
        status("Manual termination.", **kwargs)

    status(f"Archived PIDS: {', '.join(archived_pids)}", **kwargs)
    status(f"Attempted: {len(attempted_pids)}", **kwargs)
    status(f"Archived: {len(archived_pids)}", **kwargs)
    status(f"Skipped URIs: {len(skipped_uris)}", **kwargs)
    for suri in skipped_uris:
        status(f" - {suri}", **kwargs)


if __name__ == "__main__":
    main(
        **configure_commandline(
            OPTIONAL_ARGUMENTS, POSITIONAL_ARGUMENTS, DEFAULT_LOG_LEVEL
        )
    )
