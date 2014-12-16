#!/usr/bin/env python2.7
# -*- coding:utf-8 -*-

def to_string(obj):
    t_list = ["%s\n" % obj.__class__]
    for k in dir(obj):
        type_k = str(eval("obj.%s.__class__" % k))
        if type_k not in ["<type 'NoneType'>", "<type 'instancemethod'>", "<type 'function'>"] and k != '__module__':
            t_list.append("%s=%s " % (k, str(eval("obj.%s" % k))))
    return "".join(t_list)

def to_dict(obj):
    ret_dict = {}
    for k in dir(obj):
        type_k = str(eval("obj.%s.__class__" % k))
        if type_k not in ["<type 'NoneType'>", "<type 'instancemethod'>", "<type 'function'>"] and k != '__module__':
            ret_dict[k] = str(eval("obj.%s" % k))
    return ret_dict


def __str__(self):
# repr() to escape binaries
    return self.__class__.__name__ + '(' + \
        ','.join("%s=%s" % (k, repr(v)) for k, v in
                self.stringify_attrs()) + ')'

__repr__ = __str__  # note: str(list) uses __repr__ for elements
