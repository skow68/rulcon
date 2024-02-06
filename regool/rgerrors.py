#!/usr/bin/env python3
import sys

class MainError(Exception):
    pass


class ChannelError(Exception):
    pass


class ConnectError(Exception):
    sys.exit(1)


class GetZoneError(Exception):
    sys.exit(1)


class ToManyElementsError(Exception):
    sys.exit(1)
0

class UnexpectedExistsError(Exception):
    pass


class NoRouteSource(Exception):
    sys.exit(1)


class EntryDataError(Exception):
    sys.exit(1)