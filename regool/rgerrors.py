import sys

class MainError(Exception):
    pass


class ChannelError(Exception):
    pass


class ConnectError(Exception):
    pass


class GetZoneError(Exception):
    pass


class ToManyElementsError(Exception):
    pass


class UnexpectedExistsError(Exception):
    pass


class NoRouteSource(Exception):
    pass


class EntryDataError(Exception):
    pass