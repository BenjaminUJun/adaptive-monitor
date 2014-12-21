#!/usr/bin/env python2.7
# -*- coding:utf-8 -*-


#is possible to add extra key-values for some type, have not test on all possible class
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


def dict_sort(dict_f):
    pass


def __str__(obj):
# repr() to escape binaries
    return obj.__class__.__name__ + '(' + \
        ','.join('%s=%s' % (k, repr(v)) for k, v in
                obj.stringify_attrs()) + ')'

__repr__ = __str__
