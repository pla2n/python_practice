# encoding: utf-8
# module cairo._cairo calls itself cairo
# from /usr/lib/python3/dist-packages/cairo/_cairo.cpython-311-x86_64-linux-gnu.so
# by generator 1.147
# no doc

# imports
import cairo as __cairo


class PDFOutlineFlags(__cairo._IntEnum):
    # no doc
    def __init__(self, *args, **kwargs): # real signature unknown
        pass

    BOLD = 2
    ITALIC = 4
    OPEN = 1
    __map = {
        1: 'OPEN',
        2: 'BOLD',
        4: 'ITALIC',
    }


