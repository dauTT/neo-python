import json
import gzip
from functools import wraps
from collections import OrderedDict 

COMPRESS_FASTEST = 1
BASE_STRING_SIZE = 49
MTU_TCP_PACKET_SIZE = 1500
COMPRESS_THRESHOLD = MTU_TCP_PACKET_SIZE + BASE_STRING_SIZE


from twisted.internet import reactor, defer

# @json_response decorator for class methods
def json_response(func):
    """ @json_response decorator adds header and dumps response object """

    @wraps(func)
    def wrapper(self, request, *args, **kwargs):
        defer_res = func(self, request, *args, **kwargs)

        def _response_data(res, request):

            response_data = json.dumps(res) if isinstance(res, (dict, list)) else res
            request.setHeader('Content-Type', 'application/json')

            if len(response_data) > COMPRESS_THRESHOLD:
                accepted_encodings = request.requestHeaders.getRawHeaders('Accept-Encoding')
                if accepted_encodings:
                    use_gzip = any("gzip" in encoding for encoding in accepted_encodings)

                    if use_gzip:
                        response_data = gzip.compress(bytes(response_data, 'utf-8'), compresslevel=COMPRESS_FASTEST)
                        request.setHeader('Content-Encoding', 'gzip')
                        request.setHeader('Content-Length', len(response_data))
            return response_data

        defer_res.addCallback(_response_data, request)

        return defer_res

    return wrapper


# @cors_header decorator to add the CORS headers
def cors_header(func):
    """ @cors_header decorator adds CORS headers """

    @wraps(func)
    def wrapper(self, request, *args, **kwargs):
        defer_res = func(self, request, *args, **kwargs)

        def _request(res, request):
            request.setHeader('Access-Control-Allow-Origin', '*')
            request.setHeader('Access-Control-Allow-Headers', 'Content-Type, Access-Control-Allow-Headers, Authorization, X-Requested-With')
            return res

        return defer_res.addCallback(_request, request)

    return wrapper


class LimitedSizeDict(OrderedDict):
    """ This is an OrderedDict list which tracks only the most recent entries. Its size is defined
        by the key ward parameter 'size_limit'.
        Example: LimitedSizeDict(size_limit=100) track only the most recent 100 entries
    """
    def __init__(self, *args, **kwds):
        self.size_limit = kwds.pop("size_limit", None)
        super(OrderedDict, self).__init__(self, *args, **kwds)
        self._check_size_limit()

    def __setitem__(self, key, value):
        OrderedDict.__setitem__(self, key, value)
        self._check_size_limit()

    def _check_size_limit(self):
        if self.size_limit is not None:
            while len(self) > self.size_limit:
                self.popitem(last=False)
