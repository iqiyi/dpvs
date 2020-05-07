#!/usr/bin/env python3
# -*- coding: utf-8 -*-

""" Error Code Module.

    Private errno used in the project.

    __author__      = 'wencyu'
    __email__       = 'yuwenchao@qiyi.com'
    __date__        = '2020/05/06'
    __version__     = '0.1.0'
    __copyright__   = 'Copyright 2020, iQiYi/DPVS'
"""

class ErrorCode():
    """
    Self-defined error code.
    """
    OK          = 0
    UNKOWN      = -0x10000
    SSHERROR    = -0x10001
    TIMEOUT     = -0x10002
    EXIST       = -0x10003
    NOTEXIST    = -0x10004
    INVALID     = -0x10005

    @staticmethod
    def strerror(code):
        if (code == ErrorCode.UNKOWN):
            return "unexpect error"
        if (code == ErrorCode.SSHERROR):
            return "ssh error"
        if (code == ErrorCode.TIMEOUT):
            return "timeout"
        if (code == ErrorCode.EXIST):
            return "already exist"
        if (code == ErrorCode.NOTEXIST):
            return "not exist"
        if (code == ErrorCode.INVALID):
            return "invalid params"
