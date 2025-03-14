# -*- coding: utf-8 -*-
# Copyright (c) 2019-2025, 北京遨奇思特文化有限责任公司, alternate name Orchestra Culture Co., ltd. All rights reserved.

import sys
import os
import re
import time
import math
import random
import ssl
import pytz
import certifi
import urllib3
import json
import logging
import yaml

from typing import List
from future.types.newbytes import newbytes
from datetime import datetime, timedelta
from collections import OrderedDict
from urllib3._collections import HTTPHeaderDict
from urllib3.util.url import parse_url

from six.moves import urllib, http_cookiejar, http_client

from . import exceptions
from .utils import (
    patch,
    _parse_iso8601_string,
    _md5sum_hash,
    _sha256_hash,
    _hmac_hash,
    _to_signer_date,
    _to_amz_date,
    _generate_headers,
)


urllib3.disable_warnings()
patch()


if sys.version_info[0] > 2:
    from datetime import timezone
    urllib_support_method = True

else:
    from pytz import timezone, utc
    timezone.utc = utc
    urllib_support_method = False


__VERSION__ = "0.0.6"


REQUEST_TIMEOUT = 10
POLLING_INTERVAL = 2
CSRF_MIDDLEWARE_TOKEN_NAME = "csrfmiddlewaretoken"
CSRF_TOKEN_NAME = "csrftoken"
X_CSRFTOKEN_NAME = "X-CSRFToken"
SESSION_ID_NAME = "sessionid"
try:
    OPENSSL_VERSION = ssl.OPENSSL_VERSION
except:
    OPENSSL_VERSION = "not found"
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:92.0) Gecko/20100101 Firefox/92.0",
    "orchestra-api (%s)" % __VERSION__,
    "Python %s (%s)" % (os.path.extsep.join(
        str(x) for x in sys.version_info[:3]), sys.platform.lower().capitalize()),
    "ssl %s (%s)" % (OPENSSL_VERSION, "no-validate")
]


__LOG__ = logging.getLogger("orchestra_api3")
__LOG__.setLevel(logging.WARN)


class Api(object):
    def __init__(self, site_url, email=None, password=None, api_key=None, proxy=None, sessionid=None, csrftoken=None):
        """
        :param site_url: format like http://trial.orchestra-technology.com
        :param email: api user should also login with email.
        :param password: password of human user or client user.
        :param api_key: secret key of api user.
        :param proxy: format like 127.0.0.1:8080.
        :param session_id: with this id, you do not need login again.
        """
        self._async_mode = False
        self._schema = None

        _, host = urllib.parse.splituser(
            urllib.parse.urlsplit(site_url).netloc)
        self.site_url = site_url
        self.domain, self.port = urllib.parse.splitport(host)
        self.email = email
        self.password = password
        self.api_key = api_key
        self.proxy = proxy
        self.sessionid = sessionid

        self._credentials = {}

        if self.email and self.api_key:
            self._credentials = {
                "email": self.email,
                "api_key": self.api_key
            }
        elif self.email and self.password:
            self._credentials = {
                "email": self.email,
                "password": self.password
            }
        elif self.sessionid:
            self._credentials = {
                "sessionid": self.sessionid
            }
            if csrftoken:
                self._credentials["csrftoken"] = csrftoken

        self._s3_credentials = {}

        # TODO: validate input arguments like site_url, email, proxy, etc.
        self.install_opener()

    def build_opener(self, *handlers):
        _handlers = []
        if self.proxy == "HTTP_PROXY":
            "Do Nothing, urllib.request will get proxy from registry's internet setting section by default."
        elif self.proxy != None:
            proxy_handler = urllib.request.ProxyHandler(
                {"https": self.proxy, "http": self.proxy})
            _handlers.append(proxy_handler)
        else:
            proxy_handler = urllib.request.ProxyHandler()
            _handlers.append(proxy_handler)

        _handlers.extend(handlers)
        return urllib.request.build_opener(*_handlers)

    def install_opener(self):
        cookiejar = http_cookiejar.CookieJar()
        port_spec = True if self.port else False
        cookie = http_cookiejar.Cookie("0", "language", "zh-hans", self.port, port_spec, self.domain, False,
                                       False, "/", True, False, None, False, None, None, {})
        cookiejar.set_cookie(cookie)
        cookie_handler = urllib.request.HTTPCookieProcessor(cookiejar)
        # in py26/27, _opener is not exited.
        urllib.request._opener = opener = self.build_opener(cookie_handler)
        urllib.request.install_opener(opener)

    def find_cookiejar(self, ):
        global_opener = urllib.request._opener
        handlers = global_opener.handlers
        for handler in handlers:
            if isinstance(handler, urllib.request.HTTPCookieProcessor):
                return handler.cookiejar
        return None

    def save_session(self, yml_path):
        """
        Only save CSRF_TOKEN_NAME, SESSION_ID_NAME

        Api module has logout method so session will not always valid.
        """
        with open(yml_path, "w+") as f:
            data = []
            self.find_cookiejar()
            cookiejar = self.find_cookiejar() or []

            for item in cookiejar:
                if item.name in [CSRF_TOKEN_NAME, SESSION_ID_NAME]:
                    data.append({
                        "name": item.name,
                        "value": item.value,
                        "expired": item.expires})

            yaml.dump(data, f)

    def get_cached_csrftoken(self, ):
        cookiejar = self.find_cookiejar()
        if cookiejar is not None:
            for item in cookiejar:
                if item.name == CSRF_TOKEN_NAME:
                    return item.value
        return

    def add_x_csrftoken_header(self, request):
        csrftoken = self.get_cached_csrftoken()
        if not csrftoken:
            raise ValueError("csrftoken is empty.")

        request.add_header(X_CSRFTOKEN_NAME, csrftoken)

    def add_general_header(self, request):
        request.add_header("user-agent", "; ".join(USER_AGENTS))
        request.add_header("Accept", "*/*")
        request.add_header("Accept-Encoding", "gzip, deflate")
        request.add_header(
            "Accept-Language", "zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2")
        request.add_header("Cache-Control", "no-cache")
        request.add_header("Connection", "keep-alive")
        request.add_header(
            "Content-Type", "application/x-www-form-urlencoded; charset=UTF-8")
        request.add_header("Content-Length", len(request.data)
                           if request.data else 0)
        request.add_header("Sec-Fetch-Dest", "empty",)
        request.add_header("Sec-Fetch-Mode", "cors",)
        request.add_header("Sec-Fetch-Site", "same-origin",)
        request.add_header("X-Requested-With", "XMLHttpRequest")
        request.add_header("Referer", self.site_url)

    def get_login_url(self):
        return urllib.parse.urljoin(self.site_url, "user/login")

    def get_logout_url(self):
        return urllib.parse.urljoin(self.site_url, "user/logout")

    def get_api_url(self):
        return urllib.parse.urljoin(self.site_url, "crud/requests")

    def get_async_task_url(self):
        return urllib.parse.urljoin(self.site_url, "/queue/task")

    def get_csrf_url(self):
        return urllib.parse.urljoin(self.site_url, "crud/csrftoken")

    def get_schema_url(self):
        return urllib.parse.urljoin(self.site_url, "/page/schema")

    def get_ack_url(self):
        return urllib.parse.urljoin(self.site_url, "/cloud/ack")

    def get_action_url(self, action):
        if action in ["read", "follow", "favor"]:
            return urllib.parse.urljoin(self.site_url, "/action/%s" % action)
        raise Exception("Unaccepted action.")

    # GET CSRFTOKEN.
    def cache_csrftoken(self):
        kwargs = {}
        if urllib_support_method:
            kwargs["method"] = "GET"
        request = urllib.request.Request(self.get_csrf_url(), **kwargs)
        self.add_general_header(request)

        try:
            response = urllib.request.urlopen(request, timeout=REQUEST_TIMEOUT)

        except urllib.error.HTTPError as e:
            __LOG__.debug("HTTPError", e.code, e.read())
            raise e

        except urllib.error.URLError as e:
            __LOG__.debug("URLError", e.reason)
            raise e

        else:
            payload = self.decode_payload(response)
            if "payload" in payload:
                payload = payload["payload"]

            csrftoken = payload[CSRF_TOKEN_NAME]
            path = payload["path"]
            expires = payload["expires"]
            if expires:
                expires = int(time.time()) + int(expires)

            port_spec = True if self.port else False
            cookie = http_cookiejar.Cookie("0", CSRF_TOKEN_NAME, csrftoken, self.port, port_spec, self.domain, False,
                                           False, path, True, False, expires, True, None, None, {})

            cookiejar = self.find_cookiejar()
            if cookiejar is not None:
                __LOG__.debug("Get csrftoken:", cookie.value)
                cookiejar.set_cookie(cookie)

    def login(self):
        """
        LOGIN.
        Cache sessionid in CookieJar.
        """
        self.cache_csrftoken()

        content_string = urllib.parse.urlencode(self._credentials)
        content_string = newbytes(content_string, encoding="utf-8")

        kwargs = {}
        if urllib_support_method:
            kwargs["method"] = "POST"
        request = urllib.request.Request(
            self.get_login_url(), data=content_string, **kwargs)
        self.add_x_csrftoken_header(request)

        return self._send_authenticate_request(request)

    def logout(self):
        """
        Log out.
        """
        request = urllib.request.Request(
            self.get_logout_url())

        try:
            urllib.request.urlopen(request, timeout=REQUEST_TIMEOUT)

        except urllib.error.HTTPError as e:
            __LOG__.debug("HTTPError", e.code, e.read())
            raise e

        except urllib.error.URLError as e:
            __LOG__.debug("URLError", e.reason)
            raise e

        else:
            # urllib.request will cache sessionid automatically.
            return True

    def _send_authenticate_request(self, request):
        self.add_general_header(request)

        try:
            resp = urllib.request.urlopen(request, timeout=REQUEST_TIMEOUT)

            # NOTE: url changed means login success.
            splitResult = urllib.parse.urlsplit(self.get_login_url())
            splitResultLater = urllib.parse.urlsplit(resp.geturl())

            if splitResult.netloc == splitResultLater.netloc and splitResult.path == splitResultLater.path:
                return False
            else:
                return True

        except urllib.error.HTTPError as e:
            __LOG__.debug("HTTPError", e.code, e.read())
            raise e

        except urllib.error.URLError as e:
            __LOG__.debug("URLError", e.reason)
            raise e

        else:
            # urllib.request will cache sessionid automatically.
            return True

    def connect(self):
        port_spec = True if self.port else False
        cookiejar = self.find_cookiejar()

        csrftoken = self._credentials.get(CSRF_TOKEN_NAME)
        if csrftoken:
            cookiejar.set_cookie(
                http_cookiejar.Cookie("0", CSRF_TOKEN_NAME, csrftoken, self.port, port_spec, self.domain, False,
                                      False, "/",  True, False, None, True, None, None, {})
            )
        else:
            self.cache_csrftoken()

        sessionid = self._credentials.get(SESSION_ID_NAME)
        cookiejar.set_cookie(
            http_cookiejar.Cookie("0", SESSION_ID_NAME, sessionid, self.port, port_spec, self.domain, False,
                                  False, "/",  True, False, None, True, None, None, {})
        )

        return True

    def is_valid(self):
        kwargs = {}
        if urllib_support_method:
            kwargs["method"] = "GET"
        request = urllib.request.Request(self.get_login_url(), **kwargs)

        return self._send_authenticate_request(request)

    def set_async_mode(self, async_mode=False):
        """
        All your requests will be treat as background tasks since you set self._async_mode to True.
        """
        self._async_mode = async_mode

    def get_async_mode(self):
        return self._async_mode

    @property
    def schema(self):
        if self._schema and "global" in self._schema:
            return self._schema["global"]
        return self._schema

    @schema.setter
    def schema(self, schema):
        self._schema = schema
        return self._schema

    def read_schema_md5(self):
        url = urllib.parse.urljoin(self.get_schema_url() + "/", "md5")

        kwargs = {}
        if urllib_support_method:
            kwargs["method"] = "POST"
        else:
            kwargs["data"] = self.encode_payload({})
        request = urllib.request.Request(url, **kwargs)
        self.add_x_csrftoken_header(request)
        self.add_general_header(request)
        response = self._http_request(request)
        data = self.decode_payload(response)
        return data["md5"]

    def read_schema(self, force=False):
        """
        read local cache by default or fetch from server.

        Args:
            force (bool, optional): force server reload schema. Defaults to False.

        Returns:
            string: md5.
        """
        refresh = False

        if force:
            refresh = True
        else:
            md5 = self.read_schema_md5()
            if md5 == False:
                refresh = True
            elif self.schema and self._schema["md5"] != md5:
                refresh = True

        return self.load_schema(refresh)

    def load_schema(self, refresh=False):
        url = self.get_schema_url()
        if refresh:
            url = urllib.parse.urljoin(self.get_schema_url() + "/", "reload")

        kwargs = {}
        if urllib_support_method:
            kwargs["method"] = "POST"
        else:
            kwargs["data"] = self.encode_payload({})
        request = urllib.request.Request(url, **kwargs)
        self.add_x_csrftoken_header(request)
        self.add_general_header(request)
        response = self._http_request(request)
        self.schema = self.decode_payload(response)
        return self.schema

    def create_entity_type_std(self,
                               name,
                               help="",
                               can_read=False,
                               can_follow=False,
                               can_favor=False,
                               can_publish=False,
                               has_page=True,
                               has_notes=False,
                               has_project=False,
                               has_pipeline=False,
                               has_tags=False,
                               has_pipeline_config_cache=False,
                               has_versions=False,
                               ):
        """
        Async Request.
        Create specified entity type.

        Example:
            api.create(data)

        :param name                     : this argument can contains only letters and numbers.
        :param help                     : option
        :param can_read                 : option
        :param can_follow               : option
        :param can_favor                : option
        :param can_publish              : option
        :param has_page                 : option
        :param has_notes                : option
        :param has_project              : option
        :param has_pipeline             : option
        :param has_tags                 : option
        :param has_pipeline_config_cache: option
        :param has_versions             : option
        :returns                        : async task id.
        """
        entity_type = "EntityType"
        data = [{
            "name": name,
            "help": help,
            "can_read": can_read,
            "can_follow": can_follow,
            "can_favor": can_favor,
            "can_publish": can_publish,
            "has_page": has_page,
            "has_notes": has_notes,
            "has_project": has_project,
            "has_pipeline": has_pipeline,
            "has_pipeline_config_cache": has_pipeline_config_cache,
            "has_tags": has_tags,
            "has_versions": has_versions,
        }]
        self.set_async_mode(True)
        task_id = self.create(entity_type, data)
        self.set_async_mode(False)
        return task_id

    def _request_schema(self, request_type, entity_type, data):
        # type: (str, str, List[dict]) -> str
        assert isinstance(data, list), "data should be list."
        assert data, "data should not be empty."
        assert entity_type in [
            "EntityType", "Field"], "_request_schema only receive two types of entity_type: 'EntityType', 'Field'."

        method = getattr(self, request_type)
        assert method, "Invalid request type: " + request_type

        self.set_async_mode(True)
        task_id = method(entity_type, data)
        self.set_async_mode(False)
        return task_id

    def create_entity_type(self, data):
        # type: (List[dict]) -> str
        """
        Async Request.
        Create specified entity type.

        Example:
            api.create_entity_type(
                [{"name": "NewEntity", "help": "description"}])

        :param data : new entity type data.
        :returns    : async task id.
        """
        assert all(["name" in d for d in data]
                   ), "item in data should has 'name' attribute."
        return self._request_schema("create", "EntityType", data)

    def update_entity_type(self, data):
        # type: (List[dict]) -> str
        """
        Async Request.
        Update specified entity type.

        Example:
            api.update_entity_type(
                [{"name": "NewEntity", "help": "test update description"}])

        :param data : new entity type data.
        :returns    : async task id.
        """
        assert all(["id" in d or "name" in d for d in data]
                   ), "item in data should has 'id' or 'name' attribute."
        return self._request_schema("update", "EntityType", data)

    def delete_entity_type(self, data):
        # type: (List[dict]) -> str
        """
        Async Request.
        Update specified entity type.

        Example:
            api.delete_entity_type([{'id': 1053}])

        :param data : [{'id': 1053}].
        :returns    : async task id, solved result looks like [{'id': 1053}].
        """
        assert all(["id" in d for d in data]
                   ), "item in data should has 'id' attribute."
        return self._request_schema("delete", "EntityType", data)

    def create_field(self, data):
        # type: (List[dict]) -> str
        """
        Async Request.
        Create specified field.

        Example:
            api.create_field(
                [{"entity_type": "Task", "name": "text", "data_type": "text"}])

        :param data : must contain 'entity_type', 'name' and 'data_type'.
        :returns    : async task id.
        """
        assert all(["entity_type" in d and "name" in d and "data_type" in d for d in data]
                   ), "item in data should has 'entity_type', 'name' and 'data_type."
        return self._request_schema("create", "Field", data)

    def update_field(self, data):
        # type: (List[dict]) -> str
        """
        Async Request.
        Update specified field.

        Example:
            api.update_field(
                [{"entity_type": "Task", "name": "text", "help": "test modify help attribute."}])

        :param data : must contain 'entity_type' and 'name' to ensure field location in table.
        :returns    : async task id.
        """
        assert all([("entity_type" in d and "name" in d) or "id" in d for d in data]
                   ), "item in data should has either 'entity_type' & 'name' or 'id."
        return self._request_schema("update", "Field", data)

    def delete_field(self, data):
        # type: (List[dict]) -> str
        """
        Async Request.
        Delete specified field.

        Example:
            api.delete_field([{"id": 1537}])

        :param data : new field data must contain 'id' to ensure field location in table.
        :returns    : async task id.
        """
        assert all(["id" in d for d in data]), "item in data should has 'id'."
        return self._request_schema("delete", "Field", data)

    def read(self, entity_type, fields=[], filters={}, sorts=[], groups=[], pages={}, additional_filters=None):
        """
        Read entities by specified rules.

        Example:
            api.read("Task",
                fields=["id", "name", "status"],
                filters=["project", "is", {"id": 1, "type": "Project"}],
                sorts=[{ "column": "name", "direction": "ASC" }],
                groups=[
                    {
                        "column": "entity",
                        "method": "exact",
                        "direction": "asc",
                    },
                ],
                pages={"page": 1, "page_size": 5}
            )

        Checks in examples.py to find more examples.

        :param request_type         : 'read'
        :param entity_type          : type of entity you will read.
        :param columns              : returned entities will have this fields.
        :param filters              : specify filter condition here.
        :param sorts                : specify sort mode here.
        :param groups               : specify group mode here.
        :param pages                : specify page mode here, for example: {"page": 1, "page_size": 5} is just perfect.
        :param additional_filters   : support RecycleFilter in backend, pass '{"recycle": {"method": "exclude"}}' to get alive entity,
                                      '{"recycle": {"method": "include"}}' to get retired entity.
        :param local_timezone_offset: ignore
        :param append               : ignore
        :param storeId              : ignore
        :returns                    : will be dict if page_size equals to 1 else list.
        """
        requests = self.build_read_payload(
            entity_type, fields, filters, sorts, groups, pages, additional_filters)
        try:
            data = self._send_request(requests)
        except:
            raise
        else:
            return data

    def create(self, entity_type, data):
        # type: (str, List[dict]) -> list or dict
        """
        Create specified entities.

        Example:
            api.create(entity_type, data)

        :param request_type         : 'create'
        :param entity_type          : type of entity you will create.
        :param columns              : ignore
        :param data                 : pass data like '[{"name": "new entity", "status": "wtg"}]'
        :param local_timezone_offset: ignore
        :param storeId              : ignore
        """
        payload = self.build_payload("create", entity_type, None, data)
        try:
            data = self._send_request(payload)
        except:
            raise
        else:
            return data

    def update(self, entity_type, data):
        # type: (str, List[dict]) -> list or dict
        """
        Update specified entities.

        Example:
            api.update("Task", data=[{"name":"Layout Modified","id":1}])

        Checks in examples.py to find more examples.

        :param request_type         : 'update'
        :param entity_type          : type of entity you will update.
        :param columns              : ignore
        :param data                 : []
        :param local_timezone_offset: ignore
        :param storeId              : ignore
        """
        payload = self.build_payload("update", entity_type, None, data)
        try:
            data = self._send_request(payload)
        except:
            raise
        else:
            return data

    def delete(self, entity_type, data):
        """
        Delete specified entities.

        Example:
            api.delete(entity_type, data)

        :param request_type         : 'delete'
        :param entity_type          : type of entity you will delete.
        :param columns              : ignore
        :param data                 : pass data like '[{"id": 1}, {"id": 2}]'.
        :param local_timezone_offset: ignore
        :param storeId              : ignore
        """
        payload = self.build_payload("delete", entity_type, None, data)
        try:
            data = self._send_request(payload)
        except:
            raise
        else:
            return data

    def duplicate(self, entity_type, fields, data):
        """
        TODO: Duplicate specified entities.

        Example:
            api.duplicate(entity_type, fields, data)

        :param request_type         : 'duplicate'
        :param entity_type          : type of entity you will duplicate.
        :param columns              : you can specify which fields will be duplicated, or pass a empty list to duplicate all fields.
        :param data                 : pass data like '[{"id": 1}, {"id": 2}]'.
        :param sorts                : ignore
        :param grouping             : ignore
        :param local_timezone_offset: ignore
        :param append               : ignore
        :param storeId              : ignore
        """
        return

    def find_project(self, entity):
        """
        request_type: "find_project",
        entity_type: "Project",
        data: [entity],
        columns: [
            "id",
            "code",
            "name",
            "description",
            "status",
            "project_type",
        ],
        local_timezone_offset:
            Orch.util.reduxStore.getState().preference
                .localization.timezone,
        """
        payload = self.build_payload("find_project", "Project", [
                                     "id", "code"], [entity])
        try:
            data = self._send_request(payload)
        except:
            raise
        else:
            return data

    def solve_async_task(self, task_id):
        """
        Resolve task result from server.

        Example:
            api.solve_async_task(task_id)

        :param task_id: task id returned by server.

        :returns: raise exceptions.RequestFailed if async task is not finished.
        """
        data = {"task_id": task_id}
        request = self._build_async_task_request(data)
        response = self._http_request(request)
        return self._process_async_task_response(response)

    def polling_async_task(self, task_id):
        """
        Polling task result from server until it finished.

        Example:
            api.solve_async_task(task_id)

        :param task_id: task id returned by server.

        :returns: async task result.
        """
        data = {"task_id": task_id}
        request = self._build_async_task_request(data)
        response = self._polling_http_request(request)
        return self._process_async_task_response(response)

    def action(self, action_name, entity_id, entity_type):
        url = self.get_action_url(action_name)

        kwargs = {}
        if urllib_support_method:
            kwargs["method"] = "POST"

        payload_encoded = self.encode_payload(
            {"entity": json.dumps({"id": entity_id, "type": entity_type})})

        request = urllib.request.Request(url, data=payload_encoded, **kwargs)
        self.add_x_csrftoken_header(request)
        self.add_general_header(request)
        response = self._http_request(request)
        return self.decode_payload(response)

    def build_payload(self, request_type, entity_type, fields, data):
        payload = {
            "request_type": request_type,
            "entity_type": entity_type,
        }
        if fields:
            payload["columns"] = fields
        if data:
            payload["data"] = data

        return [payload]

    def build_read_payload(self,
                           entity_type,
                           fields,
                           filters,
                           sorts,
                           groups,
                           pages,
                           additional_filters):
        payload = {
            "request_type": "read",
            "entity_type": entity_type,
        }
        if fields:
            payload["columns"] = fields
        if filters:
            payload["filters"] = self.process_filters(filters)
        if sorts:
            payload["sorts"] = sorts
        if groups:
            payload["grouping"] = groups

        payload["paging"] = self.get_pages(pages)

        if additional_filters:
            payload["filter_setting"] = additional_filters

        return [payload]

    def get_request_id(self):
        return math.floor(random.random() * time.time())

    def get_relations(self):
        """
        in and not_in need pass list type right value.

        Returns:
            list: all supported relations.
        """
        return ["is", "is_not", "less_than", "greater_than", "contains", "excludes", "in", "not_in", "starts_with", "ends_with"]

    def process_filters(self, filters):
        # type: (list, ) -> dict
        """
        Convert list to dict which server can recognize.

        :param filters: simple writing.

        Example 1: convert ["name", "is", "Layout"] to
        {
            "operator": "and",
            "conditions": [
                {
                    "path": "name",
                    "relation": "is",
                    "values": "Layout"
                },
            ]
        }

        Example 2: convert [["name", "is", "Layout"], ["status", "is", "wtg"]] to
        {
            "operator": "and",
            "conditions": [
                {
                    "path": "name",
                    "relation": "is",
                    "values": Layout
                },
                {
                    "path": "status",
                    "relation": "is",
                    "values": "wtg"
                },
            ]
        }

        Example 3: convert ["or", ["name", "is", "Layout"], ["status", "is", "wtg"]] to
        {
            "operator": "or",
            "conditions": [
                {
                    "path": "name",
                    "relation": "is",
                    "values": Layout
                },
                {
                    "path": "status",
                    "relation": "is",
                    "values": "wtg"
                },
            ]
        }

        You can construct event more complex filter condition with above usages.
        """
        # record which floor we iterated to.
        inject = 0
        fallback_filters = filters

        # ensure operator.
        operator = filters[0]
        if operator in ["or", "and"]:
            filters = filters[1:]
        else:
            operator = "and"

        # recognize injected filters.
        if all(map(lambda f: isinstance(f, list), filters)):
            inject += 1
            union = {"operator": operator}
            conditions = []
            for flt in filters:
                result = self.process_filters(flt)

                # TODO: add result to conditions
                conditions.append(result)
            union["conditions"] = conditions
            return union
        else:
            # maybe operator name is equal to field name.
            filters = fallback_filters

        # Valid length.
        assert len(
            filters) == 3, "%s does not conform [field, relation, values]." % filters
        # Valid field, relation.
        assert filters[1], "%s is not valid." % filters[1]

        condition = {
            "path": filters[0],
            "relation": filters[1],
            "values": filters[2] if isinstance(filters[2], list) else [filters[2]]
        }

        # process ["name", "is", "Layout"] instead of [["name", "is", "Layout"]].
        if inject == 0:
            condition = {
                "operator": operator,
                "conditions": [condition]
            }
        return condition

    def get_pages(self, pages):
        """
        Server will determine 'pages' if it is absence.
        maximum page_size is 200, minimnum is 50.
        """
        return pages

    def process_payload(self, requests):
        requests_encoded = json.dumps(requests)
        async_mode = json.dumps(self.get_async_mode())

        return {
            "requestId": self.get_request_id(),
            "requests": requests_encoded,
            "async": async_mode,
        }

    def encode_payload(self, payload):
        payload_encoded = urllib.parse.urlencode(payload)
        return newbytes(payload_encoded, encoding="utf-8")

    def decode_payload(self, response):
        string = response.read()
        try:
            return json.loads(string.decode())
        except:
            raise Exception(string.decode())

    def get_rows(self, payload):
        """
        :returns: list type, or dict if page_size equals to 1.
        """
        rows = payload.get("rows")
        pages = payload.get("paging", {})
        page_size = pages.get("page_size", None)
        if page_size == 1 and rows:
            return rows[0]
        return rows

    def group_by(self, payload):
        # type: (dict,) -> list
        grouped_rows = []
        rows = self.get_rows(payload)
        groups = payload.get("groups")
        for group in groups:
            ids = group.get("ids")
            display_name = group.get("display_name")
            new_group = {"display_name": display_name, "children": []}
            for id in ids:
                for row in rows:
                    if row.get("id") == id:
                        new_group["children"].append(row)
                        break
            grouped_rows.append(new_group)
        return grouped_rows

    def _build_async_task_request(self, payload):
        # type: (dict,) -> urllib.request.Request
        payload_string = json.dumps(payload)
        payload_encoded = newbytes(payload_string, encoding="utf-8")

        kwargs = {}
        if urllib_support_method:
            kwargs["method"] = "POST"
        request = urllib.request.Request(
            self.get_async_task_url(), data=payload_encoded, **kwargs)
        self.add_x_csrftoken_header(request)
        self.add_general_header(request)

        return request

    def _build_crud_request(self, payload):
        payload = self.process_payload(payload)
        payload_encoded = self.encode_payload(payload)

        kwargs = {}
        if urllib_support_method:
            kwargs["method"] = "POST"
        request = urllib.request.Request(
            self.get_api_url(), data=payload_encoded, **kwargs)
        self.add_x_csrftoken_header(request)
        self.add_general_header(request)

        return request

    def _http_request(self, request):
        # type: (urllib.request.Request,) -> http_client.HTTPResponse
        try:
            return urllib.request.urlopen(request, timeout=REQUEST_TIMEOUT)

        except urllib.error.HTTPError as e:
            return self._process_http_error(e)

        except urllib.error.URLError as e:
            __LOG__.debug("URLError", e.reason)
            raise e

    def _polling_http_request(self, request):
        # type: (urllib.request.Request,) -> http_client.HTTPResponse
        running = True
        response = None

        while running:
            __LOG__.debug("Polling...")
            response = self._http_request(request)
            running = response.status == 202
            time.sleep(POLLING_INTERVAL)

        return response

    def _send_request(self, payload, multi=False):
        """
        send single or a boundle of request.

        Args:
            payload (List[dict]): _description_
            multi (bool, optional): _description_. Defaults to False.

        Returns:
            list or dict:   You know payload inclues multiple rows.
                            if multi is False, page_size is 1, return single row dictionary.
                            if multi is False, page_size is larger that 1, return multiple rows list.
                            if multi is True, page_size is 1, return rows list, row is dictionary.
                            if multi is True, page_size is larger that 1, return payloads list, each of payload includes a rows list.
        """
        request = self._build_crud_request(payload)
        response = self._http_request(request)
        return self._process_response(response, multi=multi)

    def _process_request(self):
        """
        TODO
        """
        return

    def _process_response(self, response, multi=False):
        """
        TODO: lock async_mode in period between request and response.
        """
        payload = self.decode_payload(response)

        if self.get_async_mode():
            return self._processs_async_payload(payload, multi=multi)

        return self._extract_payloads(payload, multi=multi)

    def _process_async_task_response(self, response, multi=False):
        payload = self.decode_payload(response)
        if not payload["success"]:
            msg = payload.get("message")
            raise exceptions.RequestFailed(
                "Request Failed: " + self._extract_message(msg))

        task_payload = payload["data"]
        return self._extract_payloads(task_payload, multi=multi)

    def _extract_payloads(self, payloads, multi=False):
        # hard code by multi argument.
        # actually we should extract every items in payload.

        ret = []
        if not multi:
            return self._extract_payload(payloads[0])
        else:
            for payload in payloads:
                ret.append(self._extract_payload(payload))
        return ret

    def _extract_payload(self, payload):
        if payload:
            if payload["success"]:
                if payload.get("groups"):
                    return self.group_by(payload)
                return self.get_rows(payload)
            else:
                msg = payload.get("message")
                raise exceptions.RequestFailed(
                    "Request Failed: " + self._extract_message(msg))
        raise exceptions.UnknownError(
            "Should has failed detail but payload is empty.")

    def _processs_async_payload(self, payload):
        if payload["success"]:
            return payload["task_id"]
        msg = payload.get("message")
        raise exceptions.RequestFailed(
            "Request Failed: " + self._extract_message(msg))

    def _process_http_error(self, http_error):
        """
        TODO
        """
        payload = self.decode_payload(http_error)
        __LOG__.debug("HTTPError", payload)

        if isinstance(payload, list):
            payload = payload[0]

        if payload:
            if payload.get("success"):
                raise exceptions.UnknownError(
                    "This request should be failed, maybe server get confused.")
            else:
                raise exceptions.RequestFailed(
                    "ERROR: " + payload.get("message", {}).get("detail", str(payload)))
        raise exceptions.UnknownError(
            "Should has failed detail but payload is empty.")

    def _extract_message(self, message):
        if isinstance(message, str):
            return message
        elif isinstance(message, dict) and "detail" in message:
            return message.get("detail") or ""
        else:
            return json.dumps(message)

    def upload_attachment(self, path, url=None, project=None, entity=None):
        """
        Upload attachment to orchestra oss and create attachment entity to record oss url, 
        then create entity linked to attachment.

        :param path   : file path.
        :param url    : url behind bucket name, it can be relative path like 'project/sequence/shot/task/version/mov/sample.mov'.
                        you'd better convert it to md5 string with crypto and uuid module to keep string unique.
        :param list   : link to generated attachment: {'id': 1, 'type': 'Version'}.
        :returns      : async task id.
        """
        try:
            self.enable_s3()
            response = self._s3_upload(url, path)

            if response.status != 200:
                raise urllib.error.HTTPError(response.geturl(
                ), response.status, response.reason, response.getheaders(), response)

        except:
            raise

        original_fname = os.path.basename(path)
        filename = os.path.basename(url)
        display_name, _ = os.path.splitext(filename)
        _, file_extension = os.path.splitext(path)
        file_extension = file_extension.lower()
        file_size = os.stat(path).st_size
        attachment_links = [entity] if entity else []

        attachments = self.create("Attachment", data=[{
            "this_file": url,
            "filename": filename,
            "display_name": display_name,
            "original_fname": original_fname,
            "file_extension": file_extension,
            "file_size": file_size,
            "thumbnail": "",  # TODO
            "status": "act",
            "project": project,
            "attachment_type": "cloud",
            "attachment_links": attachment_links}])

        # attachment = attachments[0]
        # attachment["type"] = "Attachment"

        return attachments[0]

    def enable_s3(self):
        if self._is_s3_expired():
            self._get_s3_security_token()

    def _get_s3_security_token(self):
        """
        Prepare S3 security token.

        :returns    : credential dictionary.
        """
        kwargs = {}
        if urllib_support_method:
            kwargs["method"] = "POST"
        else:
            kwargs["data"] = self.encode_payload({})
        request = urllib.request.Request(
            self.get_ack_url(), **kwargs)
        self.add_x_csrftoken_header(request)
        self.add_general_header(request)

        response = self._http_request(request)
        payload = self.decode_payload(response)
        self._setup_s3_client(payload)
        return payload

    def _setup_s3_client(self, data):
        if sys.version_info[0] > 2:
            self._s3_credentials["EndPoint"] = data["EndPoint"]
            self._s3_credentials["Secure"] = data["Secure"]
            self._s3_credentials["Bucket"] = data["Bucket"]
            self._s3_credentials["Region"] = data["Region"]
            self._s3_credentials["AccessKeyId"] = data["ack"]["AccessKeyId"]
            self._s3_credentials["SecretAccessKey"] = data["ack"]["SecretAccessKey"]
            self._s3_credentials["SessionToken"] = data["ack"]["SessionToken"]
            # utc time.
            self._s3_credentials["Expiration"] = data["ack"]["Expiration"]
        else:
            # NOTE:
            # In Python2:
            # Keep all arguments' type are same or 'urlunsplit' function will raise 'Cannot mix str and non-str arguments'.
            # Here I convert all argument to utf8 string explicitly.
            self._s3_credentials["EndPoint"] = data["EndPoint"].encode()
            self._s3_credentials["Secure"] = data["Secure"]
            self._s3_credentials["Bucket"] = data["Bucket"].encode()
            self._s3_credentials["Region"] = data["Region"].encode()
            self._s3_credentials["AccessKeyId"] = data["ack"]["AccessKeyId"].encode(
            )
            self._s3_credentials["SecretAccessKey"] = data["ack"]["SecretAccessKey"].encode(
            )
            self._s3_credentials["SessionToken"] = data["ack"]["SessionToken"].encode(
            )
            # utc time.
            self._s3_credentials["Expiration"] = data["ack"]["Expiration"].encode(
            )

        self._s3_client = self._create_client()

    def _create_client(self):
        timeout = timedelta(minutes=1).seconds
        if self.proxy:
            # NOTE:
            # 'urllib.parse.urlparse' will return different result in Python3.9-3.10.
            # we use 'parse_url' to substitute for it.
            # ret = urllib.parse.urlparse(self.proxy)
            url_obj = parse_url(self.proxy)
            proxy_scheme = url_obj.scheme or "http"
            proxy_host = url_obj.host or "127.0.0.1"
            proxy_port = url_obj.port or 80
            proxy_url = proxy_scheme + "://" + \
                proxy_host + ":" + str(proxy_port)

            return urllib3.ProxyManager(
                proxy_url=proxy_url,
                timeout=urllib3.util.Timeout(connect=timeout, read=timeout),
                maxsize=10,
                cert_reqs="CERT_REQUIRED",
                ca_certs=os.environ.get("SSL_CERT_FILE") or certifi.where(),
                retries=urllib3.Retry(
                    total=4,
                    backoff_factor=0.2,
                    status_forcelist=[500, 502, 503, 504]
                )
            )
        else:
            return urllib3.PoolManager(
                timeout=urllib3.util.Timeout(connect=timeout, read=timeout),
                maxsize=10,
                cert_reqs="CERT_REQUIRED",
                ca_certs=os.environ.get("SSL_CERT_FILE") or certifi.where(),
                retries=urllib3.Retry(
                    total=4,
                    backoff_factor=0.2,
                    status_forcelist=[500, 502, 503, 504]
                )
            )

    def _is_s3_expired(self):
        expiration = self._s3_credentials.get("Expiration")
        if not expiration:
            return True
        dt_expiration = _parse_iso8601_string(expiration)
        return dt_expiration < datetime.now(pytz.utc)

    def _s3_upload(self, object_name, path):
        """
        Do not contain '\\' or '//' in object name, that will cause MaxRetryError.

        Args:
            object_name (str): url stored on oss server.
            path (str): file path.

        Returns:
            urllib3.response.HTTPResponse: _description_
        """
        if re.search(r"(:|\\|/{2,})", object_name):
            raise Exception("Do not include ':', '\\' or '//' in object name.")

        with open(path, "rb") as file_object:
            return self._s3_request("PUT", object_name, file_object, preload_content=True)

    def download_byte_array(self, object_name, byte_array):
        if byte_array is None:
            raise ValueError(
                "byte_array should be QByteArray or bytearray object.")

        try:
            self.enable_s3()
        except:
            raise

        object_name = object_name or ""

        if object_name.startswith("/media") or object_name.startswith("/static"):
            response = self._s3_client.request(
                "GET", urllib.parse.urljoin(self.site_url, object_name), preload_content=False)
        else:
            response = self._s3_request(
                "GET", object_name, preload_content=False)

        if response.status != 200:
            raise urllib.error.HTTPError(response.geturl(
            ), response.status, response.reason, response.getheaders(), response)

        for data in response.stream(amt=1024*1024):

            if isinstance(byte_array, bytearray):
                byte_array += bytearray(data)
            else:
                byte_array.append(data)

        response.close()
        response.release_conn()

    def download_file(self, object_name, path):
        try:
            self.enable_s3()
        except:
            raise

        object_name = object_name or ""

        if object_name.startswith("/media") or object_name.startswith("/static"):
            response = self._s3_client.request(
                "GET", urllib.parse.urljoin(self.site_url, object_name), preload_content=False)
        else:
            response = self._s3_request(
                "GET", object_name, preload_content=False)

        if response.status != 200:
            raise urllib.error.HTTPError(response.geturl(
            ), response.status, response.reason, response.getheaders(), response)

        with open(path, "ab") as file_object:
            for data in response.stream(amt=1024*1024):
                file_object.write(data)

        response.close()
        response.release_conn()

    def _s3_download(self, object_name, path):
        with open(path, "ab") as file_object:
            response = self._s3_request(
                "GET", object_name, preload_content=False)

            if response.status != 200:
                raise urllib.error.HTTPError(response.geturl(
                ), response.status, response.reason, response.getheaders(), response)

            for data in response.stream(amt=1024*1024):
                file_object.write(data)

            if response:
                response.close()
                response.release_conn()

    def _s3_request(self, method, object_name, file_object=None, preload_content=True):
        service_name = "s3"
        end_point = self._s3_credentials["EndPoint"]
        region = self._s3_credentials["Region"]
        bucket = self._s3_credentials["Bucket"]
        access_key = self._s3_credentials["AccessKeyId"]
        secret_key = self._s3_credentials["SecretAccessKey"]

        # NOTE:
        # In Python2:
        # Uniform encoding of string that pass to 'request' method.
        # To avoid the error below, here must encode given str.
        # File "../httplib.py", line 812, in _send_output
        # msg += message_body
        # In Python3 this encode method will return bytes which is not what we expected.
        if sys.version_info[0] < 3:
            object_name = object_name and object_name.encode()

        path = "/%s/%s" % (bucket, object_name)

        # NOTE:
        # In Python2:
        # Keep all arguments' type are same or 'urlunsplit' function will raise 'Cannot mix str and non-str arguments'.
        # Here I convert all argument to unicode string explicitly.
        url = urllib.parse.SplitResult(
            "https" if self._s3_credentials["Secure"] else "http",
            end_point,
            path,
            "",
            ""
        )

        """Build headers with given parameters."""
        headers = _generate_headers(None, None, None, None, False)
        headers["Content-Type"] = "application/octet-stream"
        md5sum_added = headers.get("Content-MD5")
        headers["Host"] = url.netloc
        headers["User-Agent"] = "; ".join(USER_AGENTS)
        sha256 = None
        md5sum = None

        body = file_object.read() if file_object else None

        if body:
            headers["Content-Length"] = str(len(body))

        md5sum = None if md5sum_added else _md5sum_hash(body)
        if md5sum:
            headers["Content-MD5"] = md5sum

        sha256 = "UNSIGNED-PAYLOAD"
        headers["x-amz-content-sha256"] = sha256
        headers["X-Amz-Security-Token"] = self._s3_credentials["SessionToken"]
        date = datetime.utcnow().replace(tzinfo=timezone.utc)
        headers["x-amz-date"] = _to_amz_date(date)

        # Do signature V4 of given request for given service name.
        scope = "%s/%s/%s/aws4_request" % (_to_signer_date(date),
                                           region, service_name)

        # Get canonical headers.
        canonical_headers = {}
        for key, values in headers.items():
            key = key.lower()
            if key not in (
                    "authorization", "content-type",
                    "content-length", "user-agent",
            ):
                values = values if isinstance(
                    values, (list, tuple)) else [values]
                canonical_headers[key] = ",".join([
                    re.compile(r"( +)").sub(" ", value) for value in values
                ])

        canonical_headers = OrderedDict(sorted(canonical_headers.items()))
        signed_headers = ";".join(canonical_headers.keys())
        canonical_headers = "\n".join(
            ["%s:%s" % (key, value)
             for key, value in canonical_headers.items()],
        )
        canonical_query_string = ""
        content_sha256 = sha256
        canonical_request = "%s\n%s\n%s\n%s\n\n%s\n%s" % (
            method, url.path, canonical_query_string, canonical_headers, signed_headers, content_sha256)

        canonical_request_hash = _sha256_hash(canonical_request)

        string_to_sign = "AWS4-HMAC-SHA256\n%s\n%s\n%s" % (
            _to_amz_date(date), scope, canonical_request_hash)

        # Get signing key.
        date_key = _hmac_hash(
            ("AWS4" + secret_key).encode(),
            _to_signer_date(date).encode(),
        )
        date_region_key = _hmac_hash(date_key, region.encode())
        date_region_service_key = _hmac_hash(
            date_region_key, service_name.encode(),
        )
        signing_key = _hmac_hash(date_region_service_key, b"aws4_request")

        # Get signature.
        signature = _hmac_hash(
            signing_key, string_to_sign.encode(), hexdigest=True)

        authorization = "AWS4-HMAC-SHA256 Credential=%s/%s, SignedHeaders=%s, Signature=%s" % (
            access_key, scope, signed_headers, signature)

        headers["Authorization"] = authorization

        http_headers = HTTPHeaderDict()
        for key, value in (headers or {}).items():
            if isinstance(value, (list, tuple)):
                _ = [http_headers.add(key, val) for val in value]
            else:
                http_headers.add(key, value)

        return self._s3_client.request(
            method,
            urllib.parse.urlunsplit(url),
            body=body,
            headers=http_headers,
            preload_content=preload_content,
        )

    def event_stream(self, callback=None, filters=None, interval=None):
        """
        Start a long polling request to get latest event log entries.

        :param callback    : receive two parameters include api object and message.
        :param filters     : additional filter condition like ["project", "is", {"id": 1, "type": "Project"}]
        :param interval    : specify a polling interval.

        :returns           :  
        """
        client = self._create_client()

        headers = {}
        USER_AGENTS = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:92.0) Gecko/20100101 Firefox/92.0", ]
        cookie = ""
        cookiejar = self.find_cookiejar()
        if cookiejar is not None:
            for item in cookiejar:
                cookie += "%s=%s;" % (item.name, item.value)

                if item.name == CSRF_TOKEN_NAME:
                    headers[X_CSRFTOKEN_NAME] = item.value

        headers["Cookie"] = cookie
        headers["user-agent"] = "; ".join(USER_AGENTS)
        headers["Accept"] = "*/*"
        headers["Accept-Encoding"] = "gzip, deflate"
        headers["Accept-Language"] = "zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2"
        headers["Content-Type"] = "text/event-stream"
        headers["Cache-Control"] = "no-cache"
        headers["Connection"] = "keep-alive"
        headers["Sec-Fetch-Dest"] = "empty"
        headers["Sec-Fetch-Mode"] = "cors"
        headers["Sec-Fetch-Site"] = "same-origin"
        headers["X-Requested-With"] = "XMLHttpRequest"
        headers["Referer"] = self.site_url

        http_headers = HTTPHeaderDict()
        for key, value in (headers or {}).items():
            if isinstance(value, (list, tuple)):
                _ = [http_headers.add(key, val) for val in value]
            else:
                http_headers.add(key, value)

        # Generate json data.
        params = {}
        if interval is not None:
            params["interval"] = interval
        if filters is not None:
            params["filters"] = self.process_filters(filters)

        # Do request.
        response = client.request(
            "POST",
            urllib.parse.urljoin(self.site_url, "sse/event_log_entry"),
            body=json.dumps(params).encode(),
            headers=http_headers,
            preload_content=False,
            encode_multipart=False
        )

        def generate():
            while True:
                if hasattr(response, "_fp") and \
                        hasattr(response._fp, "fp") and \
                        hasattr(response._fp.fp, "read1"):
                    chunk = response._fp.fp.read1(1024)
                else:
                    chunk = response.read(1024)
                if not chunk:
                    break
                yield chunk

        iterator = generate()
        buff = b""

        sse_line_pattern = re.compile(b"(?P<name>[^:]*):?( ?(?P<value>.*))?")
        end_tag = re.compile(br"\r\n\r\n|\r\r|\n\n")

        # Start Listener.
        while True:
            if re.search(end_tag, buff) is None:
                try:
                    next_chunk = next(iterator)
                    if not next_chunk:
                        raise EOFError()
                    buff += next_chunk
                except Exception as e:
                    raise e
            else:
                msg = {}
                for line in buff.splitlines():
                    m = sse_line_pattern.match(line)
                    if m is None:
                        __LOG__.warning("Invalid SSE line: \"%s\"" %
                                        line, SyntaxWarning)
                        continue
                    else:
                        name = m.group("name")
                        if not name:
                            continue

                        value = m.group("value")
                        if value:
                            value = value.decode()

                        if name == b"data":
                            if "data" in msg:
                                msg["data"] = "%s\n%s" % (msg["data"], value)
                            else:
                                msg["data"] = value

                        elif name == b"event":
                            msg["event"] = value

                        elif name == b"id":
                            msg["id"] = value

                        elif name == b"retry":
                            msg["retry"] = int(value)

                if callback:
                    try:
                        msg["data"] = json.loads(msg["data"])
                    except:
                        pass

                    callback(self, msg)

                # Rest
                buff = b""
