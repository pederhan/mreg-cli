import json
import os
from typing import Any, Dict, List
from urllib.parse import urlparse, urlencode
from .types import ResponseLike
import requests


class MockResponse:
    def __init__(self, json_data, status_code, ok, reason):
        self.json_data = json_data
        self.status_code = status_code
        self.ok = ok
        self.reason = reason

    def json(self, *args, **kwargs):
        return self.json_data


class Singleton(type):
    __instances = {}  # type: dict["Singleton", object]

    def __call__(cls: "Singleton", *args, **kwargs) -> object:
        if cls not in cls.__instances:
            cls.__instances[cls] = super(Singleton, cls).__call__(*args, **kwargs)
        return cls.__instances[cls]


class MockTraffic(metaclass=Singleton):
    def __init__(self) -> None:
        self.recording = False
        self.playback = False
        self.filename = ""
        self.mock_data = []  # type: List[dict]
        self.line_num = 0

    """ Start recording http traffic, commands and console output to the given filename.
        Warning! If the file exists, it will be deleted/overwritten. """
    def start_recording(self, filename):

        self.recording = True
        self.filename = filename
        try:
            os.remove(filename)
        except:
            pass

    """ Prepare to read back commands, http traffic and console output from the given file. """

    def start_playback(self, filename: str):
        self.playback = True
        self.filename = filename
        self.line_num = 0
        f = open(self.filename, "r")
        lns = f.readlines()
        f.close()
        self.mock_data = []
        for ln in lns:
            self.mock_data.append(json.loads(ln))

    def is_recording(self) -> bool:
        return self.recording

    def is_playback(self) -> bool:
        return self.playback

    def record_command(self, cmd: str) -> None:
        if not self.is_recording():
            return
        # trim spaces, remove comments
        cmd = cmd.lstrip()
        if cmd.find("#")>-1:
            cmd = cmd[0:cmd.find("#")].rstrip()
        # don't log empty commands
        if cmd == '':
            return
        x = {'command':cmd}
        with open(self.filename, "a+") as f:
            f.write("%s\n" % json.dumps(x))


    def record_output(self, output: str):
        if not self.is_recording():
            return
        x = {"output": output}
        with open(self.filename, "a+") as f:
            f.write("%s\n" % json.dumps(x))

    """ Returns only the path + query string components of a url """

    def urlpath(self, url: str, params: Dict[str, str]):
        if params:
            url = f"{url}?{urlencode(params)}"
        up = urlparse(url)
        if up.query != '':
            return up.path + '?' + up.query
        else:
            return up.path

    """ Pretends to perform the http call (method, url and post data),
        verifies that it was the expected http call at this point in time,
        and returns an object that can pass for a http response. """

    def get_mock_result(
        self, method: str, url: str, params: Dict[str, str], data: Dict[str, Any]
    ) -> ResponseLike:
        if not self.playback:
            raise Exception("Did not call start_playback() before get_mock_result()")
        #
        self.line_num += 1
        if self.line_num >= len(self.mock_data):
            raise Exception("Ran out of mock data, did not expect any more http calls!")
        #
        obj = self.mock_data[self.line_num - 1]
        method = method.upper()
        url = self.urlpath(url, params)
        if method != obj["method"] or url != obj["url"] or data != obj["data"]:
            raise Exception(
                "%s(%d):\nExpected: %s %s %s\nDid:      %s %s %s"
                % (
                    self.filename,
                    self.line_num,
                    obj["method"],
                    obj["url"],
                    obj["data"],
                    method,
                    url,
                    data,
                )
            )
        return MockResponse(obj.get('json_data',None), obj.get('status',0), obj.get('ok',False), obj.get('reason',''))

    """ Records an http call (method, url and postdata) and the response. """

    def record(
        self,
        method: str,
        url: str,
        params: Dict[str, str],
        data: Dict[str, Any],
        result: requests.Response,
    ) -> None:
        if not self.is_recording():
            return
        x = {
            'method': method.upper(),
            'url': self.urlpath(url, params),
            'data': data,
            'ok': result.ok,
            'status': result.status_code,
            'reason': result.reason,
        }
        try:
            x['json_data'] = result.json()
        except:
            if len(result.content)>0:
                x['body'] = result.content.decode('utf-8')
        with open(self.filename, "a+") as f:
            f.write("%s\n" % json.dumps(x))

    """ Returns the next command from the playback data. """

    def get_next_command(self) -> None:
        if not self.playback:
            raise Exception("Did not call start_playback() before get_next_command()")
        self.line_num += 1
        if self.line_num >= len(self.mock_data):
            return None
        obj = self.mock_data[self.line_num - 1]
        if "command" not in obj:
            if "method" in obj:
                raise Exception(
                    "%s(%d): Expected a http call" % (self.filename, self.line_num)
                )
            elif "output" in obj:
                raise Exception(
                    "%s(%d): Expected some output" % (self.filename, self.line_num)
                )
        return obj["command"]

    """ Compares actual console output to what was the expected output at this point """

    def compare_with_expected_output(self, actual_output: str) -> None:
        if not self.playback:
            raise Exception("Did not call start_playback() before expect_output()")
        self.line_num += 1
        if self.line_num >= len(self.mock_data):
            raise Exception(
                'Didn\'t expect any more output after end of script:\n"%s"'
                % actual_output
            )
        if not "output" in self.mock_data[self.line_num - 1]:
            raise Exception(
                '%s: Didn\'t expect any output on line %d:\n"%s"'
                % (self.filename, self.line_num, actual_output)
            )
        expected = self.mock_data[self.line_num - 1]["output"]
        if actual_output != expected:
            raise Exception(
                '%s(%d): The actual output differs from the expected output.\nGot:      "%s"\nExpected: "%s"'
                % (self.filename, self.line_num, actual_output, expected)
            )
