#!/usr/bin/env python3
import sys

class MainError(Exception):
    pass


class ChannelError(Exception):
    pass


class ToManyElementsError(Exception):
    pass
0

class UnexpectedExistsError(Exception):
    pass


class NoRouteSource(Exception):
    sys.exit(1)


class EntryDataError(Exception):
    sys.exit(1)