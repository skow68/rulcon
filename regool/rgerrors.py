#!/usr/bin/env python3
import sys

class MainError(Exception):
    pass


class ChannelError(Exception):
    pass


class ToManyElementsError(Exception):
    pass


class UnexpectedExistsError(Exception):
    pass


class NoRouteSource(Exception):
    sys.exit(1)